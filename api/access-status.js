const gate = require('../lib/gate-backend.js');
const { applyGateCors, handleGateCorsPreflight } = require('../lib/gate-cors.js');

module.exports = async function accessStatus(req, res) {
    try {
        if (handleGateCorsPreflight(req, res)) {
            return;
        }
        applyGateCors(req, res);
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

        // Soft rate limit: skip recording the check when over cap, but still
        // return a normal 200 so the gate stays usable (verify-access has its
        // own stricter limits for actual code attempts).
        try {
            await gate.checkStatusRateLimit(sql, ip);
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

        let challenge = null;
        if (!unlocked) {
            try {
                challenge = await gate.issueChallenge(sql, ip);
            } catch (err) {
                console.error('access-status challenge', err);
            }
        }

        return res.status(200).json({
            unlocked: unlocked,
            ready: true,
            blockedUntilSec: blockedUntilSec,
            challenge: challenge,
        });
    } catch (fatal) {
        console.error('access-status:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Cache-Control', 'no-store');
            return res.status(200).json({
                unlocked: false,
                ready: false,
                blockedUntilSec: 0,
                challenge: null,
            });
        }
    }
};
