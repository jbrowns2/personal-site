const bcrypt = require('bcryptjs');
const gate = require('../lib/gate-backend.js');

module.exports = async function verifyAccess(req, res) {
    try {
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
    if (normalized.length < gate.MIN_CODE_LEN || body.code.length > gate.MAX_CODE_LEN) {
        return res.status(400).json({ ok: false, error: 'invalid_request' });
    }

    const ip = gate.getClientIp(req);
    const fingerprint = gate.sanitizeFingerprint(body.fingerprint);

    try {
        // 2. Validate PoW challenge (also serves as CSRF token)
        var challengeResult = await gate.validateChallenge(sql, body.challengeId, body.nonce);
        if (!challengeResult.valid) {
            var failReason = challengeResult.reason;
            if (failReason === 'pow_invalid') {
                var powFail = await gate.recordFailureAndMaybeLock(sql, ip, fingerprint);
                var powChallenge = await gate.issueChallenge(sql, ip);
                if (powFail.locked) {
                    var powRa = gate.retryAfterSecFromUntil(powFail.lockedUntilMs);
                    res.setHeader('Retry-After', String(powRa));
                    return res.status(429).json({
                        ok: false,
                        locked: true,
                        retryAfterSec: powRa,
                        challenge: powChallenge,
                    });
                }
                return res.status(400).json({
                    ok: false,
                    error: 'challenge_failed',
                    reason: failReason,
                    challenge: powChallenge,
                });
            }
            var newChallenge = await gate.issueChallenge(sql, ip);
            return res.status(400).json({
                ok: false,
                error: 'challenge_failed',
                reason: failReason,
                challenge: newChallenge,
            });
        }

        // 3–5. Global / IP / fingerprint limits in parallel (fewer Neon round trips)
        var limitTriplet = await Promise.all([
            gate.checkGlobalRateLimit(sql),
            gate.getLockoutUntil(sql, ip),
            fingerprint
                ? gate.getFingerprintLockoutUntil(sql, fingerprint)
                : Promise.resolve(0),
        ]);
        var globalLimited = limitTriplet[0];
        var lockedUntilMs = limitTriplet[1];
        var fpLockedUntilMs = limitTriplet[2];

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

        if (fingerprint && fpLockedUntilMs > Date.now()) {
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

        // 6. Bcrypt — check against all active hashes (DB + env fallback) in parallel.
        var activeHashes = await gate.loadAllGateAccessHashes(sql);
        if (activeHashes.length === 0) {
            console.error(
                'verify-access: no active access codes configured (table portfolio_gate_access_codes is empty and ACCESS_CODE_BCRYPT is unset).',
            );
            return res.status(503).json({
                ok: false,
                error: 'service_unavailable',
                reason: 'no_access_codes_configured',
            });
        }
        var matchedHash = await bcryptFindMatch(normalized, activeHashes);
        if (!matchedHash) {
            var recentFails = await gate.getRecentFailCount(sql, ip);
            var delayMs = gate.computeProgressiveDelay(recentFails);
            if (delayMs > 0) {
                await gate.sleep(delayMs);
            }
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
        gate.recordAccessCodeUsed(sql, matchedHash).catch(function () {});
        var token = gate.signSession(secrets.secret);
        res.setHeader('Set-Cookie', gate.buildSessionCookie(token, req));
        gate.maybePruneOldRecords(sql).catch(function () {});
        return res.status(200).json({ ok: true });
    } catch (err) {
        console.error('verify-access', err && err.message, err);
        var errBody = { ok: false, error: 'service_unavailable' };
        var code = err && err.code;
        if (code === '42P01') {
            errBody.reason = 'database_tables_missing';
        } else if (code === '42703') {
            errBody.reason = 'database_schema_outdated';
        }
        return res.status(503).json(errBody);
    }
    } catch (fatal) {
        console.error('verify-access:unhandled', fatal && fatal.message, fatal);
        if (!res.headersSent) {
            res.setHeader('Cache-Control', 'no-store');
            return res.status(503).json({ ok: false, error: 'service_unavailable' });
        }
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

// Check plain against every hash in parallel; resolves with the matched hash
// (so callers can update last_used_at), or null if no hash matched.
function bcryptFindMatch(plain, hashes) {
    return Promise.all(hashes.map(function (h) {
        return bcryptCompareSafe(plain, h).then(function (same) {
            return same ? h : null;
        });
    })).then(function (results) {
        for (var i = 0; i < results.length; i++) {
            if (results[i]) return results[i];
        }
        return null;
    });
}
