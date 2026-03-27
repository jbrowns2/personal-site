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
        if (!process.env.DATABASE_URL) {
            console.error('verify-access: DATABASE_URL is not set (Vercel → Env).');
        }
        if (!process.env.ACCESS_CODE_BCRYPT) {
            console.error('verify-access: ACCESS_CODE_BCRYPT is not set.');
        }
        const gss = process.env.GATE_SESSION_SECRET;
        if (!gss || gss.length < 32) {
            console.error('verify-access: GATE_SESSION_SECRET must be set and at least 32 characters.');
        }
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

    // 1. Honeypot: bots fill hidden fields humans never see
    if (body.accessCodeConfirm) {
        return res.status(401).json({ ok: false });
    }

    const normalized = gate.normalizePhrase(body.code);
    if (normalized.length < 6 || normalized.length > 8 || body.code.length > gate.MAX_CODE_LEN) {
        return res.status(400).json({ ok: false, error: 'invalid_request' });
    }

    const ip = gate.getClientIp(req);
    const fingerprint = gate.sanitizeFingerprint(body.fingerprint);

    try {
        // 2. Validate PoW challenge (also serves as CSRF token)
        var challengeResult = await gate.validateChallenge(
            sql,
            body.challengeId,
            body.nonce,
            ip,
        );
        if (!challengeResult.valid) {
            var newChallenge = await gate.issueChallenge(sql, ip);
            return res.status(400).json({
                ok: false,
                error: 'challenge_failed',
                reason: challengeResult.reason,
                challenge: newChallenge,
            });
        }

        // 3. Global rate limit (distributed attack protection)
        var globalLimited = await gate.checkGlobalRateLimit(sql);
        if (globalLimited) {
            res.setHeader('Retry-After', '15');
            var retryChallenge = await gate.issueChallenge(sql, ip);
            return res.status(429).json({
                ok: false,
                locked: true,
                retryAfterSec: 15,
                challenge: retryChallenge,
            });
        }

        // 4. IP lockout check
        var lockedUntilMs = await gate.getLockoutUntil(sql, ip);
        if (lockedUntilMs > Date.now()) {
            var retryAfterSec = gate.retryAfterSecFromUntil(lockedUntilMs);
            res.setHeader('Retry-After', String(retryAfterSec));
            var lockChallenge = await gate.issueChallenge(sql, ip);
            return res.status(429).json({
                ok: false,
                locked: true,
                retryAfterSec: retryAfterSec,
                challenge: lockChallenge,
            });
        }

        // 5. Fingerprint lockout check
        if (fingerprint) {
            var fpLockedUntilMs = await gate.getFingerprintLockoutUntil(sql, fingerprint);
            if (fpLockedUntilMs > Date.now()) {
                var fpRetryAfterSec = gate.retryAfterSecFromUntil(fpLockedUntilMs);
                res.setHeader('Retry-After', String(fpRetryAfterSec));
                var fpChallenge = await gate.issueChallenge(sql, ip);
                return res.status(429).json({
                    ok: false,
                    locked: true,
                    retryAfterSec: fpRetryAfterSec,
                    challenge: fpChallenge,
                });
            }
        }

        // 6. Progressive delay based on recent failures
        var recentFails = await gate.getRecentFailCount(sql, ip);
        var delayMs = gate.computeProgressiveDelay(recentFails);
        if (delayMs > 0) {
            await gate.sleep(delayMs);
        }

        // 7. Bcrypt compare
        var match = await bcryptCompareSafe(normalized, secrets.bcryptHash);
        if (!match) {
            var fail = await gate.recordFailureAndMaybeLock(sql, ip, fingerprint);
            var failChallenge = await gate.issueChallenge(sql, ip);
            if (fail.locked) {
                var failRetryAfterSec = gate.retryAfterSecFromUntil(fail.lockedUntilMs);
                res.setHeader('Retry-After', String(failRetryAfterSec));
                return res.status(429).json({
                    ok: false,
                    locked: true,
                    retryAfterSec: failRetryAfterSec,
                    challenge: failChallenge,
                });
            }
            gate.maybePruneOldRecords(sql).catch(function () {});
            return res.status(401).json({ ok: false, challenge: failChallenge });
        }

        await gate.recordSuccess(sql, ip, fingerprint);
        var token = gate.signSession(secrets.secret);
        res.setHeader('Set-Cookie', gate.buildSessionCookie(token, req));
        gate.maybePruneOldRecords(sql).catch(function () {});
        return res.status(200).json({ ok: true });
    } catch (err) {
        console.error('verify-access', err && err.message, err);
        var body = { ok: false, error: 'service_unavailable' };
        var code = err && err.code;
        if (code === '42P01') {
            body.reason = 'database_tables_missing';
        } else if (code === '42703') {
            body.reason = 'database_schema_outdated';
        }
        return res.status(503).json(body);
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
