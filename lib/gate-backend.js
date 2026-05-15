/**
 * Shared server-side access gate logic (Vercel + Neon).
 * Env: DATABASE_URL, GATE_SESSION_SECRET (>= 32 chars).
 *      ACCESS_CODE_BCRYPT (optional; legacy env-based code, still honored as a fallback).
 *
 * Active access codes live in the `portfolio_gate_access_codes` table and are
 * fetched on demand with a short in-memory TTL cache so adding / disabling a
 * code doesn't require a redeploy.
 */

const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const net = require('net');

const COOKIE_NAME = 'portfolio_gate_sess';
/** Minimum length after normalization (trim, uppercase, strip non-alphanumeric). */
const MIN_CODE_LEN = 3;
const MAX_CODE_LEN = 32;
const FAIL_WINDOW_MINUTES = 10;
const MAX_FAILS_BEFORE_LOCK = 5;
const LOCKOUT_MINUTES = 30;
const MAX_LOCKOUT_MINUTES = 60 * 24;
const SESSION_MAX_AGE_SEC = 60 * 60 * 24 * 7;
const STATUS_CHECK_WINDOW_MINUTES = 10;
const MAX_STATUS_CHECKS = 30;

// Base PoW kept moderate for UX; escalates quickly after failures (see issueChallenge).
const POW_BASE_DIFFICULTY = 16;
const POW_ESCALATED_DIFFICULTY = 20;
const POW_ESCALATION_THRESHOLD = 2;
const CHALLENGE_TTL_MINUTES = 3;

const FP_MAX_FAILS_BEFORE_LOCK = 7;
const MAX_FINGERPRINT_LEN = 64;

const GLOBAL_RATE_LIMIT_WINDOW_SEC = 60;
const GLOBAL_RATE_LIMIT_MAX = 50;

const PROGRESSIVE_DELAY_MS_PER_FAIL = 1500;
const PROGRESSIVE_DELAY_MAX_MS = 8000;

// Active access-code hashes are read from Neon and cached briefly so we don't
// pay a round-trip on every verify. New / revoked codes propagate within this
// window across warm function instances.
const ACCESS_CODE_CACHE_TTL_MS = 30 * 1000;
let cachedAccessCodeHashes = null;
let cachedAccessCodeHashesAt = 0;

const UUID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuidString(s) {
    return typeof s === 'string' && UUID_RE.test(s);
}

function bufferToBase64Url(buf) {
    return buf
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}

function randomUuidV4() {
    if (typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    var b = crypto.randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var hex = b.toString('hex');
    return (
        hex.slice(0, 8) +
        '-' +
        hex.slice(8, 12) +
        '-' +
        hex.slice(12, 16) +
        '-' +
        hex.slice(16, 20) +
        '-' +
        hex.slice(20)
    );
}

function normalizePhrase(s) {
    return String(s)
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, '');
}

function getSql() {
    const url = process.env.DATABASE_URL;
    if (!url) {
        return null;
    }
    return neon(url);
}

function sanitizeIp(raw) {
    if (!raw || typeof raw !== 'string') {
        return '0.0.0.0';
    }
    const ip = raw.split(',')[0].trim();
    if (ip.length > 45) {
        return '0.0.0.0';
    }
    return net.isIP(ip) ? ip : '0.0.0.0';
}

function getClientIp(req) {
    const xf = req.headers['x-forwarded-for'];
    if (typeof xf === 'string' && xf.length) {
        return sanitizeIp(xf);
    }
    const ri = req.headers['x-real-ip'];
    if (typeof ri === 'string' && ri.length) {
        return sanitizeIp(ri);
    }
    return '0.0.0.0';
}

function loadEnvBcryptHashes() {
    const raw = process.env.ACCESS_CODE_BCRYPT;
    if (!raw) {
        return [];
    }
    // Newline-separated bcrypt hashes were the legacy multi-tenant mechanism
    // before the DB-backed table; still honored as a bootstrap fallback.
    return raw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
}

function loadGateSecrets() {
    const secret = process.env.GATE_SESSION_SECRET;
    if (!secret || secret.length < 32) {
        return null;
    }
    // bcryptHashes here is only the env fallback. The verify path should call
    // loadAllGateAccessHashes(sql) to get the union of DB + env hashes.
    return { bcryptHashes: loadEnvBcryptHashes(), secret };
}

async function loadActiveAccessCodeHashes(sql) {
    if (!sql) {
        return [];
    }
    const now = Date.now();
    if (
        cachedAccessCodeHashes &&
        now - cachedAccessCodeHashesAt < ACCESS_CODE_CACHE_TTL_MS
    ) {
        return cachedAccessCodeHashes;
    }
    try {
        const rows = await sql`
            SELECT bcrypt_hash FROM portfolio_gate_access_codes
            WHERE active = true
              AND (expires_at IS NULL OR expires_at > now())
        `;
        const hashes = rows
            .map(function (r) { return r.bcrypt_hash; })
            .filter(Boolean);
        cachedAccessCodeHashes = hashes;
        cachedAccessCodeHashesAt = now;
        return hashes;
    } catch (err) {
        // 42P01 = relation missing; surface that explicitly so verify-access
        // can return a useful diagnostic instead of silently falling back.
        if (err && err.code === '42P01') {
            throw err;
        }
        console.error('loadActiveAccessCodeHashes', err && err.message);
        return cachedAccessCodeHashes || [];
    }
}

function invalidateAccessCodeCache() {
    cachedAccessCodeHashes = null;
    cachedAccessCodeHashesAt = 0;
}

async function loadAllGateAccessHashes(sql) {
    const dbHashes = await loadActiveAccessCodeHashes(sql);
    const envHashes = loadEnvBcryptHashes();
    if (envHashes.length === 0) {
        return dbHashes;
    }
    const seen = new Set(dbHashes);
    const merged = dbHashes.slice();
    for (const h of envHashes) {
        if (h && !seen.has(h)) {
            seen.add(h);
            merged.push(h);
        }
    }
    return merged;
}

async function recordAccessCodeUsed(sql, hash) {
    if (!sql || !hash) {
        return;
    }
    try {
        await sql`
            UPDATE portfolio_gate_access_codes
            SET last_used_at = now()
            WHERE bcrypt_hash = ${hash}
        `;
    } catch (err) {
        console.error('recordAccessCodeUsed', err && err.message);
    }
}

function parseCookies(cookieHeader) {
    const out = {};
    if (!cookieHeader || typeof cookieHeader !== 'string') {
        return out;
    }
    cookieHeader.split(';').forEach(function (part) {
        const i = part.indexOf('=');
        if (i === -1) {
            return;
        }
        const k = part.slice(0, i).trim();
        const v = part.slice(i + 1).trim();
        try {
            out[k] = decodeURIComponent(v);
        } catch (e) {
            out[k] = v;
        }
    });
    return out;
}

function signSession(secret) {
    const exp = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SEC;
    const nonce = crypto.randomBytes(16).toString('hex');
    const payload = exp + '.' + nonce;
    const sigBuf = crypto.createHmac('sha256', secret).update(payload).digest();
    const sig = bufferToBase64Url(sigBuf);
    return payload + '.' + sig;
}

function verifySessionToken(token, secret) {
    try {
        if (!token || typeof token !== 'string' || !secret || secret.length < 32) {
            return false;
        }
        const parts = token.split('.');
        if (parts.length !== 3) {
            return false;
        }
        const expStr = parts[0];
        const nonce = parts[1];
        const sig = parts[2];
        const payload = expStr + '.' + nonce;
        const expectedBuf = crypto.createHmac('sha256', secret).update(payload).digest();
        const expected = bufferToBase64Url(expectedBuf);
        const a = Buffer.from(sig, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        if (a.length !== b.length) {
            return false;
        }
        if (!crypto.timingSafeEqual(a, b)) {
            return false;
        }
        if (Number(expStr) < Math.floor(Date.now() / 1000)) {
            return false;
        }
        return true;
    } catch (e) {
        return false;
    }
}

function buildSessionCookie(token, req) {
    const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const secure = proto === 'https' || process.env.VERCEL === '1';
    const parts = [
        COOKIE_NAME + '=' + token,
        'HttpOnly',
        'Path=/',
        'Max-Age=' + SESSION_MAX_AGE_SEC,
        'SameSite=Lax',
    ];
    if (secure) {
        parts.push('Secure');
    }
    return parts.join('; ');
}

function buildClearSessionCookie(req) {
    const proto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const secure = proto === 'https' || process.env.VERCEL === '1';
    const parts = [COOKIE_NAME + '=; Path=/; Max-Age=0', 'HttpOnly', 'SameSite=Lax'];
    if (secure) {
        parts.push('Secure');
    }
    return parts.join('; ');
}

function sessionUnlocked(req) {
    try {
        const secrets = loadGateSecrets();
        if (!secrets) {
            return false;
        }
        const cookies = parseCookies(req.headers.cookie);
        const token = cookies[COOKIE_NAME];
        return verifySessionToken(token, secrets.secret);
    } catch (e) {
        return false;
    }
}

async function readJsonBody(req) {
    if (typeof req.body === 'string') {
        try {
            return req.body ? JSON.parse(req.body) : {};
        } catch (e) {
            return null;
        }
    }
    if (req.body != null && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
        return req.body;
    }
    return new Promise(function (resolve, reject) {
        let buf = '';
        req.on('data', function (chunk) {
            buf += chunk;
            if (buf.length > 65536) {
                req.destroy();
                reject(new Error('payload_too_large'));
            }
        });
        req.on('end', function () {
            if (!buf) {
                resolve({});
                return;
            }
            try {
                resolve(JSON.parse(buf));
            } catch (e) {
                resolve(null);
            }
        });
        req.on('error', reject);
    });
}

async function getLockoutUntil(sql, ip) {
    const rows = await sql`
    SELECT locked_until FROM portfolio_gate_lockout
    WHERE ip = ${ip}::inet AND locked_until > now()
    LIMIT 1
  `;
    return rows[0] ? new Date(rows[0].locked_until).getTime() : 0;
}

async function applyLockout(sql, ip) {
    const existing = await sql`
    SELECT lockout_count FROM portfolio_gate_lockout
    WHERE ip = ${ip}::inet LIMIT 1
  `;
    const prevCount = existing[0] ? existing[0].lockout_count : 0;
    const newCount = prevCount + 1;
    const escalatedMinutes = Math.min(
        LOCKOUT_MINUTES * Math.pow(2, newCount - 1),
        MAX_LOCKOUT_MINUTES,
    );
    const until = new Date(Date.now() + escalatedMinutes * 60 * 1000);
    await sql`
    INSERT INTO portfolio_gate_lockout (ip, locked_until, lockout_count, updated_at)
    VALUES (${ip}::inet, ${until.toISOString()}, ${newCount}, now())
    ON CONFLICT (ip) DO UPDATE SET
      locked_until = EXCLUDED.locked_until,
      lockout_count = EXCLUDED.lockout_count,
      updated_at = now()
  `;
    return until.getTime();
}

async function clearLockout(sql, ip) {
    await sql`DELETE FROM portfolio_gate_lockout WHERE ip = ${ip}::inet`;
}

async function recordFailureAndMaybeLock(sql, ip, fingerprint) {
    const fp = sanitizeFingerprint(fingerprint);
    const failWindowLabel = String(FAIL_WINDOW_MINUTES) + ' minutes';
    const countRows = await sql`
    WITH ins AS (
      INSERT INTO portfolio_gate_attempts (ip, success, fingerprint)
      VALUES (${ip}::inet, false, ${fp})
      RETURNING 1
    )
    SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
    WHERE ip = ${ip}::inet
      AND success = false
      AND attempted_at > now() - ${failWindowLabel}::interval
  `;
    const c = countRows[0] ? countRows[0].c : 0;
    var result = { locked: false, failCount: c };
    if (c >= MAX_FAILS_BEFORE_LOCK) {
        const untilMs = await applyLockout(sql, ip);
        result = { locked: true, lockedUntilMs: untilMs, failCount: c };
    }
    if (fp) {
        const fpResult = await maybeLockFingerprint(sql, fp);
        if (fpResult.locked && !result.locked) {
            result = { locked: true, lockedUntilMs: fpResult.lockedUntilMs, failCount: c };
        }
    }
    return result;
}

async function recordSuccess(sql, ip, fingerprint) {
    var fp = sanitizeFingerprint(fingerprint);
    await sql`
    INSERT INTO portfolio_gate_attempts (ip, success, fingerprint)
    VALUES (${ip}::inet, true, ${fp})
  `;
    await clearLockout(sql, ip);
    if (fp) {
        await clearFingerprintLockout(sql, fp);
    }
}

function retryAfterSecFromUntil(lockedUntilMs) {
    return Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 1000));
}

function sanitizeFingerprint(fp) {
    if (!fp || typeof fp !== 'string') {
        return null;
    }
    var cleaned = fp.replace(/[^a-fA-F0-9]/g, '').slice(0, MAX_FINGERPRINT_LEN);
    return cleaned.length >= 16 ? cleaned : null;
}

async function issueChallenge(sql, ip) {
    var prefix = crypto.randomBytes(16).toString('hex');
    var failWindowLabel = String(FAIL_WINDOW_MINUTES) + ' minutes';
    var ttlLabel = String(CHALLENGE_TTL_MINUTES) + ' minutes';
    var challengeId = randomUuidV4();
    var rows = await sql`
    WITH recent AS (
      SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
      WHERE ip = ${ip}::inet AND success = false
        AND attempted_at > now() - ${failWindowLabel}::interval
    ),
    ins AS (
      INSERT INTO portfolio_gate_challenges (id, prefix, difficulty, ip, expires_at)
      SELECT ${challengeId}::uuid, ${prefix},
        (CASE WHEN recent.c >= ${POW_ESCALATION_THRESHOLD}
          THEN ${POW_ESCALATED_DIFFICULTY} ELSE ${POW_BASE_DIFFICULTY} END)::int,
        ${ip}::inet, now() + ${ttlLabel}::interval
      FROM recent
      RETURNING id, difficulty
    )
    SELECT id, difficulty FROM ins
  `;
    var diff = rows[0] ? Number(rows[0].difficulty) : POW_BASE_DIFFICULTY;
    return { id: String(rows[0].id), prefix: prefix, difficulty: diff };
}

async function validateChallenge(sql, challengeId, nonce) {
    var cid =
        challengeId == null || challengeId === ''
            ? ''
            : String(challengeId).trim();
    if (!isUuidString(cid) || !nonce || typeof nonce !== 'string' || nonce.length > 64) {
        return { valid: false, reason: 'invalid_challenge' };
    }
    var rows = await sql`
    SELECT prefix, difficulty, ip, used, expires_at
    FROM portfolio_gate_challenges
    WHERE id = ${cid}::uuid
    LIMIT 1
  `;
    if (!rows[0]) {
        return { valid: false, reason: 'challenge_not_found' };
    }
    var row = rows[0];
    if (row.used) {
        return { valid: false, reason: 'challenge_used' };
    }
    if (new Date(row.expires_at).getTime() < Date.now()) {
        return { valid: false, reason: 'challenge_expired' };
    }
    // Do not bind challenges to client IP: X-Forwarded-For often differs between
    // GET /access-status and POST /verify-access (CDN / reordering), which skipped
    // bcrypt and prevented lockout counters from advancing. UUID + one-time PoW is enough.
    var hash = crypto
        .createHash('sha256')
        .update(row.prefix + nonce)
        .digest();
    if (!hasLeadingZeroBits(hash, row.difficulty)) {
        return { valid: false, reason: 'pow_invalid' };
    }
    await sql`UPDATE portfolio_gate_challenges SET used = true WHERE id = ${cid}::uuid`;
    return { valid: true };
}

function hasLeadingZeroBits(buf, bits) {
    var fullBytes = Math.floor(bits / 8);
    var remainBits = bits % 8;
    for (var i = 0; i < fullBytes; i++) {
        if (buf[i] !== 0) return false;
    }
    if (remainBits > 0) {
        var mask = 0xff << (8 - remainBits);
        if ((buf[fullBytes] & mask) !== 0) return false;
    }
    return true;
}

async function getFingerprintLockoutUntil(sql, fingerprint) {
    var fp = sanitizeFingerprint(fingerprint);
    if (!fp) return 0;
    var rows = await sql`
    SELECT locked_until FROM portfolio_gate_fingerprint_lockout
    WHERE fingerprint = ${fp} AND locked_until > now()
    LIMIT 1
  `;
    return rows[0] ? new Date(rows[0].locked_until).getTime() : 0;
}

async function applyFingerprintLockout(sql, fp) {
    var existing = await sql`
    SELECT lockout_count FROM portfolio_gate_fingerprint_lockout
    WHERE fingerprint = ${fp} LIMIT 1
  `;
    var prevCount = existing[0] ? existing[0].lockout_count : 0;
    var newCount = prevCount + 1;
    var escalatedMinutes = Math.min(LOCKOUT_MINUTES * Math.pow(2, newCount - 1), MAX_LOCKOUT_MINUTES);
    var until = new Date(Date.now() + escalatedMinutes * 60 * 1000);
    await sql`
    INSERT INTO portfolio_gate_fingerprint_lockout (fingerprint, locked_until, lockout_count, updated_at)
    VALUES (${fp}, ${until.toISOString()}, ${newCount}, now())
    ON CONFLICT (fingerprint) DO UPDATE SET
      locked_until = EXCLUDED.locked_until,
      lockout_count = EXCLUDED.lockout_count,
      updated_at = now()
  `;
    return until.getTime();
}

async function clearFingerprintLockout(sql, fp) {
    if (!fp) return;
    await sql`DELETE FROM portfolio_gate_fingerprint_lockout WHERE fingerprint = ${fp}`;
}

async function maybeLockFingerprint(sql, fp) {
    if (!fp) return { locked: false };
    var failWindowLabel = String(FAIL_WINDOW_MINUTES) + ' minutes';
    var countRows = await sql`
    SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
    WHERE fingerprint = ${fp}
      AND success = false
      AND attempted_at > now() - ${failWindowLabel}::interval
  `;
    var c = countRows[0] ? countRows[0].c : 0;
    if (c >= FP_MAX_FAILS_BEFORE_LOCK) {
        var untilMs = await applyFingerprintLockout(sql, fp);
        return { locked: true, lockedUntilMs: untilMs };
    }
    return { locked: false };
}

async function checkGlobalRateLimit(sql) {
    var windowLabel = String(GLOBAL_RATE_LIMIT_WINDOW_SEC) + ' seconds';
    var rows = await sql`
    SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
    WHERE success = false
      AND attempted_at > now() - ${windowLabel}::interval
  `;
    var c = rows[0] ? rows[0].c : 0;
    return c >= GLOBAL_RATE_LIMIT_MAX;
}

async function getRecentFailCount(sql, ip) {
    var failWindowLabel = String(FAIL_WINDOW_MINUTES) + ' minutes';
    var rows = await sql`
    SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
    WHERE ip = ${ip}::inet AND success = false
      AND attempted_at > now() - ${failWindowLabel}::interval
  `;
    return rows[0] ? rows[0].c : 0;
}

function computeProgressiveDelay(recentFailCount) {
    if (recentFailCount <= 0) return 0;
    return Math.min(recentFailCount * PROGRESSIVE_DELAY_MS_PER_FAIL, PROGRESSIVE_DELAY_MAX_MS);
}

function sleep(ms) {
    return new Promise(function (resolve) {
        setTimeout(resolve, ms);
    });
}

async function checkStatusRateLimit(sql, ip) {
    const windowLabel = String(STATUS_CHECK_WINDOW_MINUTES) + ' minutes';
    const rows = await sql`
    WITH ins AS (
      INSERT INTO portfolio_gate_status_checks (ip)
      VALUES (${ip}::inet)
      RETURNING 1
    )
    SELECT COUNT(*)::int AS c FROM portfolio_gate_status_checks
    WHERE ip = ${ip}::inet
      AND checked_at > now() - ${windowLabel}::interval
  `;
    const c = rows[0] ? rows[0].c : 0;
    return c > MAX_STATUS_CHECKS;
}

async function maybePruneOldRecords(sql) {
    if (Math.random() > 0.05) {
        return;
    }
    try {
        await sql`DELETE FROM portfolio_gate_attempts WHERE attempted_at < now() - interval '30 days'`;
        await sql`DELETE FROM portfolio_gate_lockout WHERE locked_until < now() - interval '7 days'`;
        await sql`DELETE FROM portfolio_gate_status_checks WHERE checked_at < now() - interval '1 day'`;
        await sql`DELETE FROM portfolio_gate_challenges WHERE expires_at < now() - interval '1 day'`;
        await sql`DELETE FROM portfolio_gate_fingerprint_lockout WHERE locked_until < now() - interval '7 days'`;
    } catch (e) {
        console.error('gate prune error', e);
    }
}

module.exports = {
    COOKIE_NAME,
    normalizePhrase,
    getSql,
    getClientIp,
    loadGateSecrets,
    loadEnvBcryptHashes,
    loadActiveAccessCodeHashes,
    loadAllGateAccessHashes,
    invalidateAccessCodeCache,
    recordAccessCodeUsed,
    signSession,
    verifySessionToken,
    buildSessionCookie,
    buildClearSessionCookie,
    sessionUnlocked,
    readJsonBody,
    getLockoutUntil,
    recordFailureAndMaybeLock,
    recordSuccess,
    retryAfterSecFromUntil,
    checkStatusRateLimit,
    maybePruneOldRecords,
    issueChallenge,
    validateChallenge,
    getFingerprintLockoutUntil,
    checkGlobalRateLimit,
    getRecentFailCount,
    computeProgressiveDelay,
    sleep,
    sanitizeFingerprint,
    MIN_CODE_LEN,
    MAX_CODE_LEN,
};
