/**
 * /api/approve-access?token=...
 *
 * Two-phase approval flow to defend against email-prefetch scanners that
 * would otherwise blindly fire the GET in this link:
 *
 *   GET  → renders a tiny self-contained confirmation page. The visible
 *          "Confirm & send code" button submits a form back to the same URL
 *          with a method override. No side effects on GET.
 *   POST → validates the token, atomically transitions the request from
 *          pending → approved, derives a code from the requester's email
 *          domain, stores its bcrypt hash, and emails the plaintext code to
 *          the requester (with Jonathan CC'd).
 *
 * Tokens are HMAC-signed and TTL-bound, so even with the link they can't be
 * reused after expiry. Approval is idempotent: clicking the confirm button
 * twice surfaces the previously-issued code rather than minting a new one.
 *
 * Note: we render the response as HTML so Jonathan can complete the flow on
 * any device without needing the gated site to even be reachable. The page
 * is intentionally minimal — no JS, no external assets.
 */

'use strict';

const gate = require('../lib/gate-backend.js');
const email = require('../lib/email.js');

const PAGE_TITLE = 'Portal access · review request';
const PAGE_LANG = 'en';

module.exports = async function approveAccess(req, res) {
    try {
        const method = (req.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'POST') {
            res.setHeader('Allow', 'GET, POST');
            return res.status(405).send(plain('Method not allowed.'));
        }
        res.setHeader('Cache-Control', 'no-store, private');
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Robots-Tag', 'noindex, nofollow');

        const token = extractToken(req);
        if (!token) {
            return res.status(400).send(renderErrorPage('Missing approval token.'));
        }

        const verified = gate.verifyApprovalToken(token);
        if (!verified) {
            return res.status(400).send(
                renderErrorPage(
                    'Approval link is invalid or has expired. Ask the visitor to resubmit the form, or issue a code manually.',
                ),
            );
        }

        if (!email.isEmailConfigured()) {
            console.error(
                'approve-access: RESEND_* env vars not all set; cannot send the code email.',
            );
            return res
                .status(503)
                .send(
                    renderErrorPage(
                        'Email service is not configured. Set RESEND_API_KEY, RESEND_FROM_EMAIL, and RESEND_NOTIFY_EMAIL, then click the link again.',
                    ),
                );
        }

        const sql = gate.getSql();
        const secrets = gate.loadGateSecrets();
        if (!sql || !secrets) {
            return res
                .status(503)
                .send(renderErrorPage('Database or session secret not configured.'));
        }

        let request;
        try {
            request = await gate.getPendingRequestById(sql, verified.requestId);
        } catch (err) {
            if (err && err.code === '42P01') {
                return res
                    .status(503)
                    .send(
                        renderErrorPage(
                            'Database tables missing. Run neon/migration-004-access-requests.sql, then click the link again.',
                        ),
                    );
            }
            throw err;
        }
        if (!request) {
            return res
                .status(404)
                .send(renderErrorPage('That request no longer exists.'));
        }

        // Idempotent: if already approved, show the prior status.
        if (request.status === 'approved') {
            return res
                .status(200)
                .send(
                    renderAlreadyApprovedPage({
                        name: request.name,
                        email: request.email,
                        approvedAt: request.approved_at,
                    }),
                );
        }

        if (method === 'GET') {
            return res
                .status(200)
                .send(renderConfirmationPage({ request: request, token: token }));
        }

        // ---- POST: actually approve and issue the code -----------------
        const generated = gate.generateCodeFromEmail(request.email);
        if (!generated) {
            return res
                .status(500)
                .send(renderErrorPage('Could not derive a code from that email address.'));
        }

        const expiresAt = new Date(
            Date.now() + gate.ISSUED_CODE_TTL_DAYS * 24 * 60 * 60 * 1000,
        );
        const label =
            'Auto-issued for ' +
            request.email +
            ' (request ' +
            String(request.id).slice(0, 8) +
            ')';

        let inserted = null;
        try {
            inserted = await gate.insertAutoIssuedAccessCode(sql, {
                normalizedCode: generated.normalized,
                label: label,
                expiresAt: expiresAt,
            });
        } catch (err) {
            console.error('approve-access: code insert failed', err && err.message);
            return res
                .status(500)
                .send(renderErrorPage('Failed to save the new access code. Try again.'));
        }
        if (!inserted) {
            return res
                .status(500)
                .send(
                    renderErrorPage(
                        'Failed to save the new access code (bcrypt collision — unlikely). Reload the page and try again.',
                    ),
                );
        }

        await gate.markRequestApproved(sql, request.id, inserted.id);

        const siteOrigin = inferSiteOrigin(req);
        try {
            await email.sendEmail({
                to: request.email,
                subject: 'Your portal access code',
                html: renderRecipientEmailHtml({
                    name: request.name,
                    code: generated.display,
                    siteOrigin: siteOrigin,
                    expiresAt: expiresAt,
                }),
                text: renderRecipientEmailText({
                    name: request.name,
                    code: generated.display,
                    siteOrigin: siteOrigin,
                    expiresAt: expiresAt,
                }),
            });
        } catch (sendErr) {
            console.error(
                'approve-access: requester email send failed',
                sendErr && sendErr.message,
            );
            return res
                .status(503)
                .send(
                    renderErrorPage(
                        'Code was saved, but the email to the requester failed to send. Code: ' +
                            email.escapeHtml(generated.display) +
                            ' — copy it and send manually.',
                    ),
                );
        }

        // Best-effort FYI to Jonathan; failure here doesn't block.
        try {
            await email.sendEmail({
                to: email.getNotifyEmail(),
                subject: 'Code issued: ' + request.name + ' (' + request.email + ')',
                html: renderJonathanFyiHtml({
                    name: request.name,
                    email: request.email,
                    code: generated.display,
                    expiresAt: expiresAt,
                }),
                text: renderJonathanFyiText({
                    name: request.name,
                    email: request.email,
                    code: generated.display,
                    expiresAt: expiresAt,
                }),
            });
        } catch (notifyErr) {
            console.error(
                'approve-access: fyi email send failed (non-fatal)',
                notifyErr && notifyErr.message,
            );
        }

        return res.status(200).send(
            renderApprovedPage({
                name: request.name,
                email: request.email,
                code: generated.display,
                expiresAt: expiresAt,
            }),
        );
    } catch (fatal) {
        console.error('approve-access:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            return res.status(500).send(renderErrorPage('Unexpected error.'));
        }
    }
};

function extractToken(req) {
    if (req.body && typeof req.body === 'object' && typeof req.body.token === 'string') {
        return req.body.token;
    }
    const url = req.url || '';
    const q = url.indexOf('?');
    if (q < 0) return null;
    const params = new URLSearchParams(url.slice(q + 1));
    const t = params.get('token');
    return t ? String(t) : null;
}

function inferSiteOrigin(req) {
    if (process.env.SITE_URL) {
        return process.env.SITE_URL.replace(/\/+$/, '');
    }
    const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
    const host = req.headers['x-forwarded-host'] || req.headers.host || '';
    return proto + '://' + host;
}

// ---------------------------------------------------------------------------
// HTML responses
// ---------------------------------------------------------------------------

function pageShell(bodyHtml) {
    return [
        '<!doctype html><html lang="' + PAGE_LANG + '"><head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="robots" content="noindex,nofollow">',
        '<title>' + PAGE_TITLE + '</title>',
        '<style>',
        ':root{color-scheme:dark light;}',
        'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#06060f;color:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Arial,sans-serif;line-height:1.5;padding:24px;}',
        '.card{max-width:520px;width:100%;background:rgba(17,17,40,0.6);border:1px solid rgba(99,102,241,0.18);border-radius:16px;padding:32px;box-shadow:0 20px 60px rgba(0,0,0,0.4);}',
        '.pill{display:inline-flex;align-items:center;gap:0.45rem;padding:0.3rem 0.7rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);border-radius:2rem;font-size:0.7rem;font-weight:500;letter-spacing:0.05em;color:#a5b4fc;margin-bottom:14px;text-transform:uppercase;}',
        'h1{margin:0 0 12px;font-size:22px;font-weight:700;letter-spacing:-0.02em;}',
        'p{margin:0 0 14px;color:#cbd5e1;}',
        'dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0 0 20px;font-size:14px;}',
        'dt{color:#94a3b8;}',
        'dd{margin:0;color:#f1f5f9;word-break:break-word;}',
        'code,.code{font-family:"JetBrains Mono",ui-monospace,monospace;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);padding:2px 8px;border-radius:6px;color:#a5b4fc;letter-spacing:0.05em;}',
        '.code-large{display:block;font-size:1.4rem;font-weight:700;text-align:center;padding:14px;margin:8px 0 18px;}',
        '.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:12px 22px;border-radius:10px;border:none;background:linear-gradient(135deg,#6366f1,#06b6d4);color:white;font-weight:600;font-size:15px;cursor:pointer;text-decoration:none;}',
        '.btn:disabled{opacity:0.6;cursor:not-allowed;}',
        '.btn--ghost{background:transparent;border:1px solid rgba(99,102,241,0.3);color:#a5b4fc;}',
        '.muted{font-size:12px;color:#64748b;margin-top:18px;line-height:1.5;}',
        '.error{color:#fca5a5;}',
        '.row-actions{display:flex;gap:10px;flex-wrap:wrap;}',
        '@media (prefers-color-scheme: light){body{background:#f8fafc;color:#0f172a;}.card{background:#fff;border-color:#e2e8f0;}p{color:#475569;}dt{color:#64748b;}.pill{background:rgba(79,70,229,0.08);border-color:rgba(79,70,229,0.2);color:#4f46e5;}code,.code{background:rgba(79,70,229,0.08);border-color:rgba(79,70,229,0.2);color:#4f46e5;}.muted{color:#94a3b8;}.error{color:#dc2626;}.btn--ghost{color:#4f46e5;border-color:rgba(79,70,229,0.3);}}',
        '</style>',
        '</head><body><main class="card">',
        bodyHtml,
        '</main></body></html>',
    ].join('');
}

function renderConfirmationPage(opts) {
    const esc = email.escapeHtml;
    const r = opts.request;
    const formAction =
        '/api/approve-access?token=' + encodeURIComponent(opts.token);
    return pageShell(
        [
            '<span class="pill">Pending request</span>',
            '<h1>Approve access for ' + esc(r.name) + '?</h1>',
            '<p>Confirming will generate a new access code derived from <code>@' +
                esc((r.email.split('@')[1] || '').toLowerCase()) +
                '</code>, email it to the requester, and CC you on the issued code. The code expires in ' +
                gate.ISSUED_CODE_TTL_DAYS +
                ' days; you can revoke it anytime via <code>npm run gate:disable</code>.</p>',
            '<dl>',
            '<dt>Name</dt><dd>' + esc(r.name) + '</dd>',
            '<dt>Email</dt><dd>' + esc(r.email) + '</dd>',
            '<dt>Found me via</dt><dd>' + esc(r.referral || '').replace(/\n/g, '<br>') + '</dd>',
            '<dt>Submitted</dt><dd>' + esc(formatDate(r.created_at)) + '</dd>',
            '</dl>',
            '<form method="post" action="' + esc(formAction) + '" class="row-actions">',
            '<input type="hidden" name="token" value="' + esc(opts.token) + '">',
            '<button type="submit" class="btn">Approve &amp; send code →</button>',
            '<a href="mailto:' + esc(r.email) + '" class="btn btn--ghost">Reply via email</a>',
            '</form>',
            '<p class="muted">This page does nothing on load — the code is only issued when you click the button above. The link expires automatically.</p>',
        ].join(''),
    );
}

function renderApprovedPage(opts) {
    const esc = email.escapeHtml;
    return pageShell(
        [
            '<span class="pill">Code issued</span>',
            '<h1>Done. Code sent to ' + esc(opts.name) + '.</h1>',
            '<p>' +
                esc(opts.email) +
                ' should receive the code within a minute. Here it is for your records:</p>',
            '<code class="code code-large">' + esc(opts.code) + '</code>',
            '<dl>',
            '<dt>Expires</dt><dd>' + esc(formatDate(opts.expiresAt)) + '</dd>',
            '<dt>Revoke</dt><dd><code>npm run gate:disable -- "Auto-issued for ' +
                esc(opts.email) +
                '"</code></dd>',
            '</dl>',
            '<p class="muted">You can close this tab.</p>',
        ].join(''),
    );
}

function renderAlreadyApprovedPage(opts) {
    const esc = email.escapeHtml;
    return pageShell(
        [
            '<span class="pill">Already approved</span>',
            '<h1>Request from ' + esc(opts.name) + ' was already handled.</h1>',
            '<p>A code was issued for ' +
                esc(opts.email) +
                (opts.approvedAt
                    ? ' on ' + esc(formatDate(opts.approvedAt)) + '.'
                    : '.') +
                '</p>',
            '<p class="muted">If you need to resend it, issue a fresh code via <code>npm run gate:add</code> and email it manually — the original plaintext is not retrievable from the database.</p>',
        ].join(''),
    );
}

function renderErrorPage(message) {
    const esc = email.escapeHtml;
    return pageShell(
        [
            '<span class="pill">Approval link</span>',
            '<h1 class="error">Could not process this link.</h1>',
            '<p>' + esc(message) + '</p>',
        ].join(''),
    );
}

function plain(text) {
    return pageShell('<p>' + email.escapeHtml(text) + '</p>');
}

function formatDate(value) {
    if (!value) return 'unknown';
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

// ---------------------------------------------------------------------------
// Outgoing email templates
// ---------------------------------------------------------------------------

function renderRecipientEmailHtml(opts) {
    const esc = email.escapeHtml;
    return [
        '<!doctype html><html><body style="margin:0;padding:0;background:#06060f;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Arial,sans-serif;color:#f1f5f9;">',
        '<div style="max-width:520px;margin:0 auto;padding:32px 24px;">',
        '<div style="background:rgba(17,17,40,0.6);border:1px solid rgba(99,102,241,0.18);border-radius:16px;padding:28px;">',
        '<div style="font-size:13px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;">Portal access</div>',
        '<h1 style="margin:0 0 12px;font-size:22px;font-weight:700;">Hi ' + esc(opts.name.split(' ')[0]) + ',</h1>',
        '<p style="margin:0 0 18px;color:#cbd5e1;line-height:1.5;">Here is your access code for ' +
            '<a href="' + esc(opts.siteOrigin) + '" style="color:#818cf8;text-decoration:none;">jonathansbrownstein.com</a>:',
        '</p>',
        '<div style="text-align:center;margin:0 0 22px;">',
        '<div style="display:inline-block;font-family:\'JetBrains Mono\',ui-monospace,monospace;font-size:22px;font-weight:700;letter-spacing:0.08em;color:#a5b4fc;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);padding:14px 22px;border-radius:10px;">' +
            esc(opts.code) +
            '</div>',
        '</div>',
        '<a href="' + esc(opts.siteOrigin) + '/#access=' + encodeURIComponent(opts.code) + '" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#06b6d4);color:white;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:600;font-size:14px;">Open the portal →</a>',
        '<p style="margin:22px 0 0;font-size:13px;color:#94a3b8;line-height:1.5;">The code is single-context but you can use it on as many devices as you need. It expires on <strong>' +
            esc(formatDate(opts.expiresAt)) +
            '</strong>.</p>',
        '<p style="margin:14px 0 0;font-size:12px;color:#64748b;line-height:1.5;">Reply to this email if anything looks off.</p>',
        '</div>',
        '<p style="margin:18px 0 0;text-align:center;font-size:11px;color:#475569;">Jonathan Brownstein · MSe · FLMI</p>',
        '</div>',
        '</body></html>',
    ].join('');
}

function renderRecipientEmailText(opts) {
    return [
        'Hi ' + opts.name.split(' ')[0] + ',',
        '',
        'Here is your access code for jonathansbrownstein.com:',
        '',
        '    ' + opts.code,
        '',
        'Open the portal:',
        opts.siteOrigin + '/#access=' + encodeURIComponent(opts.code),
        '',
        'The code expires on ' + formatDate(opts.expiresAt) + '.',
        '',
        '— Jonathan',
    ].join('\n');
}

function renderJonathanFyiHtml(opts) {
    const esc = email.escapeHtml;
    return [
        '<!doctype html><html><body style="margin:0;padding:0;background:#06060f;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Arial,sans-serif;color:#f1f5f9;">',
        '<div style="max-width:520px;margin:0 auto;padding:32px 24px;">',
        '<div style="background:rgba(17,17,40,0.6);border:1px solid rgba(99,102,241,0.18);border-radius:16px;padding:24px;">',
        '<div style="font-size:13px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;">FYI · code issued</div>',
        '<h1 style="margin:0 0 10px;font-size:18px;font-weight:700;">Issued <code style="font-family:\'JetBrains Mono\',ui-monospace,monospace;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);padding:2px 8px;border-radius:6px;color:#a5b4fc;">' +
            esc(opts.code) +
            '</code></h1>',
        '<table cellpadding="0" cellspacing="0" style="width:100%;font-size:14px;line-height:1.5;">',
        '<tr><td style="padding:4px 12px 4px 0;color:#94a3b8;">For</td><td>' + esc(opts.name) + ' &lt;' + esc(opts.email) + '&gt;</td></tr>',
        '<tr><td style="padding:4px 12px 4px 0;color:#94a3b8;">Expires</td><td>' + esc(formatDate(opts.expiresAt)) + '</td></tr>',
        '<tr><td style="padding:4px 12px 4px 0;color:#94a3b8;">Revoke</td><td><code style="font-family:\'JetBrains Mono\',ui-monospace,monospace;font-size:12px;">npm run gate:disable -- "Auto-issued for ' + esc(opts.email) + '"</code></td></tr>',
        '</table>',
        '</div>',
        '</div>',
        '</body></html>',
    ].join('');
}

function renderJonathanFyiText(opts) {
    return [
        'Issued code: ' + opts.code,
        '',
        'For:     ' + opts.name + ' <' + opts.email + '>',
        'Expires: ' + formatDate(opts.expiresAt),
        '',
        'Revoke: npm run gate:disable -- "Auto-issued for ' + opts.email + '"',
    ].join('\n');
}
