const gate = require('../lib/gate-backend.js');

module.exports = async function accessStatus(req, res) {
    if (req.method !== 'GET') {
        res.setHeader('Allow', 'GET');
        return res.status(405).json({ error: 'method_not_allowed' });
    }

    res.setHeader('Cache-Control', 'no-store');

    const sql = gate.getSql();
    const secrets = gate.loadGateSecrets();
    if (!sql || !secrets) {
        return res.status(200).json({ unlocked: false, ready: false });
    }

    const ip = gate.getClientIp(req);

    try {
        const rateLimited = await gate.checkStatusRateLimit(sql, ip);
        if (rateLimited) {
            return res.status(429).json({ error: 'too_many_requests' });
        }
    } catch (err) {
        console.error('access-status rate-limit', err);
    }

    const unlocked = gate.sessionUnlocked(req);
    let blockedUntilSec = 0;
    try {
        const lockedUntilMs = await gate.getLockoutUntil(sql, ip);
        if (lockedUntilMs > Date.now()) {
            blockedUntilSec = gate.retryAfterSecFromUntil(lockedUntilMs);
        }
    } catch (err) {
        console.error('access-status lockout', err);
    }

    return res.status(200).json({
        unlocked: unlocked,
        ready: true,
        blockedUntilSec: blockedUntilSec,
    });
};
