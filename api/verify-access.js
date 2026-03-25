const bcrypt = require('bcryptjs');
const gate = require('../lib/gate-backend.js');

module.exports = async function verifyAccess(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: 'method_not_allowed' });
    }

    res.setHeader('Cache-Control', 'no-store');

    const sql = gate.getSql();
    const secrets = gate.loadGateSecrets();
    if (!sql || !secrets) {
        return res.status(503).json({ ok: false, error: 'service_unavailable' });
    }

    let body;
    try {
        body = await gate.readJsonBody(req);
    } catch (e) {
        return res.status(400).json({ ok: false, error: 'invalid_request' });
    }

    if (!body || typeof body.code !== 'string') {
        return res.status(400).json({ ok: false, error: 'invalid_request' });
    }

    const normalized = gate.normalizePhrase(body.code);
    if (normalized.length < 6 || normalized.length > 8 || body.code.length > gate.MAX_CODE_LEN) {
        return res.status(400).json({ ok: false, error: 'invalid_request' });
    }

    const ip = gate.getClientIp(req);

    try {
        const lockedUntilMs = await gate.getLockoutUntil(sql, ip);
        if (lockedUntilMs > Date.now()) {
            const retryAfterSec = gate.retryAfterSecFromUntil(lockedUntilMs);
            res.setHeader('Retry-After', String(retryAfterSec));
            return res.status(429).json({
                ok: false,
                locked: true,
                retryAfterSec: retryAfterSec,
            });
        }

        const match = await bcryptCompareSafe(normalized, secrets.bcryptHash);
        if (!match) {
            const fail = await gate.recordFailureAndMaybeLock(sql, ip);
            if (fail.locked) {
                const retryAfterSec = gate.retryAfterSecFromUntil(fail.lockedUntilMs);
                res.setHeader('Retry-After', String(retryAfterSec));
                return res.status(429).json({
                    ok: false,
                    locked: true,
                    retryAfterSec: retryAfterSec,
                });
            }
            return res.status(401).json({ ok: false });
        }

        await gate.recordSuccess(sql, ip);
        const token = gate.signSession(secrets.secret);
        res.setHeader('Set-Cookie', gate.buildSessionCookie(token, req));
        return res.status(200).json({ ok: true });
    } catch (err) {
        console.error('verify-access', err);
        return res.status(503).json({ ok: false, error: 'service_unavailable' });
    }
};

function bcryptCompareSafe(plain, hash) {
    return new Promise(function (resolve, reject) {
        bcrypt.compare(plain, hash, function (err, same) {
            if (err) {
                reject(err);
                return;
            }
            resolve(!!same);
        });
    });
}
