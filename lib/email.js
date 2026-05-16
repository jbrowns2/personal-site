/**
 * Resend transactional email wrapper.
 *
 * Uses the Resend HTTP API directly via fetch so we don't pull in another
 * dep on a server that already has Neon + bcryptjs. Configuration lives in
 * env vars:
 *
 *   RESEND_API_KEY        — Resend API key (re_xxx).
 *   RESEND_FROM_EMAIL     — `Display Name <you@verified-domain.com>`.
 *                            Domain must be verified in Resend.
 *   RESEND_NOTIFY_EMAIL   — Address that receives request notifications
 *                            and CCs on issued codes. Usually Jonathan.
 *
 * isEmailConfigured() returns false if any of those are missing so callers
 * can degrade gracefully (the access-request flow refuses early with a
 * 503 + reason: 'email_not_configured').
 */

'use strict';

const RESEND_URL = 'https://api.resend.com/emails';

function isEmailConfigured() {
    return Boolean(
        process.env.RESEND_API_KEY &&
            process.env.RESEND_FROM_EMAIL &&
            process.env.RESEND_NOTIFY_EMAIL,
    );
}

function getNotifyEmail() {
    return process.env.RESEND_NOTIFY_EMAIL || '';
}

async function sendEmail(opts) {
    const apiKey = process.env.RESEND_API_KEY;
    const from = process.env.RESEND_FROM_EMAIL;
    if (!apiKey || !from) {
        const err = new Error('email_not_configured');
        err.code = 'EMAIL_NOT_CONFIGURED';
        throw err;
    }
    if (!opts || !opts.to || !opts.subject) {
        throw new Error('email: missing to/subject');
    }
    const payload = {
        from: from,
        to: Array.isArray(opts.to) ? opts.to : [opts.to],
        subject: opts.subject,
    };
    if (opts.html) payload.html = opts.html;
    if (opts.text) payload.text = opts.text;
    if (opts.replyTo) payload.reply_to = opts.replyTo;

    let res;
    try {
        res = await fetch(RESEND_URL, {
            method: 'POST',
            headers: {
                Authorization: 'Bearer ' + apiKey,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });
    } catch (networkErr) {
        const wrapped = new Error('email_network_error: ' + networkErr.message);
        wrapped.code = 'EMAIL_NETWORK_ERROR';
        throw wrapped;
    }

    if (!res.ok) {
        let bodyText = '';
        try {
            bodyText = await res.text();
        } catch (_) {}
        const err = new Error(
            'email_send_failed: ' + res.status + (bodyText ? ' ' + bodyText.slice(0, 240) : ''),
        );
        err.code = 'EMAIL_SEND_FAILED';
        err.status = res.status;
        throw err;
    }

    try {
        return await res.json();
    } catch (_) {
        return { ok: true };
    }
}

/** Escape user-supplied strings before they go into HTML email bodies. */
function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

module.exports = {
    isEmailConfigured,
    getNotifyEmail,
    sendEmail,
    escapeHtml,
};
