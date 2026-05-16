/**
 * POST /api/request-access
 *
 * Visitor-facing endpoint for the "Request access" form. Layered defenses:
 *
 *   1. Method / payload shape
 *   2. Honeypot field (`accessRequestWebsite` — humans never see it)
 *   3. Minimum dwell time between page load and submission (anti-form-fill bot)
 *   4. PoW challenge (re-uses the gate's existing challenge table; same nonce
 *      bookkeeping so a stolen challenge can't be reused across endpoints)
 *   5. Global / IP / fingerprint lockouts already maintained by the gate
 *   6. Per-IP / per-email / per-fingerprint daily caps on requests
 *   7. Strict email + length validation
 *   8. Email send to Jonathan; on success the row is persisted and the
 *      client gets a generic ack ("we'll be in touch") regardless of
 *      whether the email matched a known user — so the form can't be used
 *      to enumerate which addresses have requested access.
 */

'use strict';

const gate = require('../lib/gate-backend.js');
const email = require('../lib/email.js');

// Minimum time between the challenge being issued and the request submission.
// Trips on bots that instantly POST without rendering the form. Gate also
// requires a PoW solution, which adds organic delay on top of this.
const MIN_DWELL_MS = 2500;

function genericAck(res) {
    // Single response shape for all "we accepted (or pretended to)" cases.
    // Used for happy path, rate-limit shenanigans, and silently-dropped
    // honeypot trips, so attackers can't distinguish them.
    return res.status(200).json({ ok: true });
}

module.exports = async function requestAccess(req, res) {
    try {
        if (req.method !== 'POST') {
            res.setHeader('Allow', 'POST');
            return res.status(405).json({ error: 'method_not_allowed' });
        }
        res.setHeader('Cache-Control', 'no-store');

        if (!email.isEmailConfigured()) {
            console.error(
                'request-access: RESEND_API_KEY / RESEND_FROM_EMAIL / RESEND_NOTIFY_EMAIL not all set.',
            );
            return res
                .status(503)
                .json({ ok: false, error: 'service_unavailable', reason: 'email_not_configured' });
        }

        const sql = gate.getSql();
        const secrets = gate.loadGateSecrets();
        if (!sql || !secrets) {
            return res
                .status(503)
                .json({ ok: false, error: 'service_unavailable' });
        }

        let body;
        try {
            body = await gate.readJsonBody(req);
        } catch (e) {
            return res.status(400).json({ ok: false, error: 'invalid_request' });
        }
        if (!body || typeof body !== 'object') {
            return res.status(400).json({ ok: false, error: 'invalid_request' });
        }

        // Honeypot — silently 200 so bots think they succeeded.
        if (body.accessRequestWebsite) {
            return genericAck(res);
        }

        // Dwell time check (anti-form-fill).
        const issuedAt = Number(body.challengeIssuedAt);
        if (
            !Number.isFinite(issuedAt) ||
            Date.now() - issuedAt < MIN_DWELL_MS ||
            Date.now() - issuedAt > 30 * 60 * 1000
        ) {
            // Force the client to fetch a fresh challenge before retrying.
            try {
                const ip0 = gate.getClientIp(req);
                const ch = await gate.issueChallenge(sql, ip0);
                return res.status(400).json({
                    ok: false,
                    error: 'dwell_too_short',
                    challenge: ch,
                });
            } catch (_) {
                return res.status(400).json({ ok: false, error: 'dwell_too_short' });
            }
        }

        const emailLower = gate.validateEmail(body.email);
        const name = gate.sanitizeText(body.name, gate.REQUEST_NAME_MAX_LEN);
        const referral = gate.sanitizeText(body.referral, gate.REQUEST_REFERRAL_MAX_LEN);
        if (!emailLower || name.length < 2 || referral.length < 2) {
            return res.status(400).json({ ok: false, error: 'invalid_request' });
        }

        const ip = gate.getClientIp(req);
        const fingerprint = gate.sanitizeFingerprint(body.fingerprint);
        const userAgent = gate.sanitizeText(
            req.headers['user-agent'] || '',
            gate.REQUEST_USER_AGENT_MAX_LEN,
        );

        // PoW + CSRF check (shared challenge table with the gate).
        const challengeResult = await gate.validateChallenge(
            sql,
            body.challengeId,
            body.nonce,
        );
        if (!challengeResult.valid) {
            const fresh = await gate.issueChallenge(sql, ip);
            return res.status(400).json({
                ok: false,
                error: 'challenge_failed',
                reason: challengeResult.reason,
                challenge: fresh,
            });
        }

        // Global / IP / fingerprint lockouts that already power the gate.
        const limitTriplet = await Promise.all([
            gate.checkGlobalRateLimit(sql),
            gate.getLockoutUntil(sql, ip),
            fingerprint
                ? gate.getFingerprintLockoutUntil(sql, fingerprint)
                : Promise.resolve(0),
        ]);
        if (limitTriplet[0]) {
            res.setHeader('Retry-After', '60');
            return res.status(429).json({
                ok: false,
                error: 'rate_limited',
                retryAfterSec: 60,
            });
        }
        const lockedUntilMs = limitTriplet[1];
        const fpLockedUntilMs = limitTriplet[2];
        if (lockedUntilMs > Date.now()) {
            const retryAfterSec = gate.retryAfterSecFromUntil(lockedUntilMs);
            res.setHeader('Retry-After', String(retryAfterSec));
            return res.status(429).json({
                ok: false,
                error: 'rate_limited',
                retryAfterSec: retryAfterSec,
            });
        }
        if (fingerprint && fpLockedUntilMs > Date.now()) {
            const retryAfterSec = gate.retryAfterSecFromUntil(fpLockedUntilMs);
            res.setHeader('Retry-After', String(retryAfterSec));
            return res.status(429).json({
                ok: false,
                error: 'rate_limited',
                retryAfterSec: retryAfterSec,
            });
        }

        // Per-key daily caps. Quietly succeed (genericAck) so attackers can't
        // probe whether a given email has already requested — Jonathan still
        // gets one email regardless.
        let counts;
        try {
            counts = await gate.countRecentRequests(sql, {
                email: emailLower,
                ip: ip,
                fingerprint: fingerprint,
            });
        } catch (err) {
            // 42P01: table missing. Tell the client to run the migration.
            if (err && err.code === '42P01') {
                console.error(
                    'request-access: portfolio_gate_access_requests table missing — run neon/migration-004-access-requests.sql.',
                );
                return res.status(503).json({
                    ok: false,
                    error: 'service_unavailable',
                    reason: 'database_tables_missing',
                });
            }
            throw err;
        }
        if (
            counts.byEmail >= gate.REQUEST_RATE_PER_EMAIL_DAY ||
            counts.byIp >= gate.REQUEST_RATE_PER_IP_DAY ||
            (fingerprint && counts.byFingerprint >= gate.REQUEST_RATE_PER_FP_DAY)
        ) {
            return genericAck(res);
        }

        const requestId = await gate.recordAccessRequest(sql, {
            email: emailLower,
            name: name,
            referral: referral,
            ip: ip,
            fingerprint: fingerprint,
            userAgent: userAgent,
        });

        const token = gate.signApprovalToken(requestId);
        if (!token) {
            console.error(
                'request-access: could not sign approval token — GATE_SESSION_SECRET (or REQUEST_APPROVAL_SECRET) must be >= 32 chars.',
            );
            return res.status(503).json({ ok: false, error: 'service_unavailable' });
        }

        const siteOrigin = inferSiteOrigin(req);
        const approveUrl = siteOrigin + '/api/approve-access?token=' + encodeURIComponent(token);

        const subject = 'Portal access request: ' + name;
        const html = renderNotifyEmailHtml({
            name: name,
            email: emailLower,
            referral: referral,
            ip: ip,
            userAgent: userAgent,
            approveUrl: approveUrl,
        });
        const text = renderNotifyEmailText({
            name: name,
            email: emailLower,
            referral: referral,
            ip: ip,
            userAgent: userAgent,
            approveUrl: approveUrl,
        });

        try {
            await email.sendEmail({
                to: email.getNotifyEmail(),
                replyTo: emailLower,
                subject: subject,
                html: html,
                text: text,
            });
        } catch (sendErr) {
            console.error('request-access: email send failed', sendErr && sendErr.message);
            // Row is already persisted — Jonathan can still see it in the DB
            // and approve manually, but tell the client to retry later so
            // they don't think the form silently swallowed their request.
            return res
                .status(503)
                .json({ ok: false, error: 'service_unavailable', reason: 'email_send_failed' });
        }

        gate.maybePruneOldRecords(sql).catch(function () {});
        return genericAck(res);
    } catch (fatal) {
        console.error('request-access:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Cache-Control', 'no-store');
            return res.status(503).json({ ok: false, error: 'service_unavailable' });
        }
    }
};

function inferSiteOrigin(req) {
    if (process.env.SITE_URL) {
        return process.env.SITE_URL.replace(/\/+$/, '');
    }
    const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
    const host = req.headers['x-forwarded-host'] || req.headers.host || '';
    return proto + '://' + host;
}

function renderNotifyEmailHtml(opts) {
    const esc = email.escapeHtml;
    return [
        '<!doctype html><html><body style="margin:0;padding:0;background:#06060f;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Inter,Arial,sans-serif;color:#f1f5f9;">',
        '<div style="max-width:560px;margin:0 auto;padding:32px 24px;">',
        '<div style="background:rgba(17,17,40,0.6);border:1px solid rgba(99,102,241,0.18);border-radius:16px;padding:28px;">',
        '<div style="font-size:13px;letter-spacing:0.08em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;">Portal access request</div>',
        '<h1 style="margin:0 0 16px;font-size:22px;font-weight:700;color:#f1f5f9;">' + esc(opts.name) + ' wants in.</h1>',
        '<table cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 20px;font-size:14px;line-height:1.5;">',
        row('Name', esc(opts.name)),
        row('Email', '<a href="mailto:' + esc(opts.email) + '" style="color:#818cf8;text-decoration:none;">' + esc(opts.email) + '</a>'),
        row('Found me via', esc(opts.referral).replace(/\n/g, '<br>')),
        row('IP', esc(opts.ip || 'unknown')),
        row('User-Agent', '<span style="color:#94a3b8;font-size:12px;">' + esc(opts.userAgent || 'unknown') + '</span>'),
        '</table>',
        '<a href="' + esc(opts.approveUrl) + '" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#06b6d4);color:white;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:600;font-size:14px;">Review &amp; approve →</a>',
        '<p style="margin:20px 0 0;font-size:12px;color:#64748b;line-height:1.5;">The button opens a confirmation page. From there one click issues a code derived from <code style="color:#94a3b8;">@' + esc((opts.email.split('@')[1] || '').toLowerCase()) + '</code> and emails it to ' + esc(opts.email) + '.</p>',
        '<p style="margin:14px 0 0;font-size:11px;color:#475569;line-height:1.5;">Approval link expires in 14 days. Ignore this email to leave the request pending.</p>',
        '</div>',
        '</div>',
        '</body></html>',
    ].join('');

    function row(label, value) {
        return (
            '<tr>' +
            '<td valign="top" style="padding:6px 12px 6px 0;color:#94a3b8;width:120px;">' + label + '</td>' +
            '<td valign="top" style="padding:6px 0;color:#f1f5f9;">' + value + '</td>' +
            '</tr>'
        );
    }
}

function renderNotifyEmailText(opts) {
    return [
        'Portal access request',
        '',
        opts.name + ' wants in.',
        '',
        'Name:         ' + opts.name,
        'Email:        ' + opts.email,
        'Found me via: ' + opts.referral,
        'IP:           ' + (opts.ip || 'unknown'),
        'User-Agent:   ' + (opts.userAgent || 'unknown'),
        '',
        'Review & approve:',
        opts.approveUrl,
        '',
        'Link expires in 14 days. Ignore this email to leave the request pending.',
    ].join('\n');
}
