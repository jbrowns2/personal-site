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

// Base PoW kept low for UX (~4k SHA-256 hashes, ~50–100ms in a worker on a phone);
// escalates after failures to ~65k hashes (~1–3s) to slow brute force without
// punishing the typical first-try user. The IP / fingerprint lockouts and global
// rate limit do the heavy lifting against bots.
const POW_BASE_DIFFICULTY = 12;
const POW_ESCALATED_DIFFICULTY = 16;
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
    // One round-trip instead of three: log the attempt, drop any IP lockout,
    // and drop any fingerprint lockout in a single CTE. The fingerprint
    // delete is a no-op when fp is null, which is fine.
    await sql`
    WITH ins AS (
      INSERT INTO portfolio_gate_attempts (ip, success, fingerprint)
      VALUES (${ip}::inet, true, ${fp})
      RETURNING 1
    ),
    del_ip AS (
      DELETE FROM portfolio_gate_lockout WHERE ip = ${ip}::inet
      RETURNING 1
    ),
    del_fp AS (
      DELETE FROM portfolio_gate_fingerprint_lockout
      WHERE ${fp}::text IS NOT NULL AND fingerprint = ${fp}
      RETURNING 1
    )
    SELECT 1
  `;
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
    // Atomically claim the challenge: one round-trip instead of SELECT-then-UPDATE.
    // We mark it used regardless of PoW outcome so a single challenge can't be
    // brute-forced on the server; the verify endpoint always returns a fresh
    // challenge in the response so the client can immediately retry.
    var rows = await sql`
    WITH target AS (
      SELECT prefix, difficulty, used, expires_at
      FROM portfolio_gate_challenges
      WHERE id = ${cid}::uuid
      FOR UPDATE
    ),
    upd AS (
      UPDATE portfolio_gate_challenges
      SET used = true
      WHERE id = ${cid}::uuid
        AND NOT (SELECT used FROM target)
      RETURNING 1
    )
    SELECT prefix, difficulty, used, expires_at,
           (SELECT count(*) FROM upd)::int AS claimed
    FROM target
  `;
    if (!rows[0]) {
        return { valid: false, reason: 'challenge_not_found' };
    }
    var row = rows[0];
    if (row.used && row.claimed === 0) {
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
        // Old expired pending requests we never approved; drop after 90d.
        await sql`
            DELETE FROM portfolio_gate_access_requests
            WHERE status = 'pending' AND created_at < now() - interval '90 days'
        `;
    } catch (e) {
        console.error('gate prune error', e);
    }
}

// ----------------------------------------------------------------------------
// Access-request workflow helpers
// ----------------------------------------------------------------------------

const REQUEST_NAME_MAX_LEN = 80;
const REQUEST_EMAIL_MAX_LEN = 254;
const REQUEST_REFERRAL_MAX_LEN = 500;
const REQUEST_USER_AGENT_MAX_LEN = 400;

// Rate-limit windows for the request-access endpoint. These are intentionally
// strict — the form is high-impact (issues a code if Jonathan approves), so we
// favor friction for repeat senders over throughput.
const REQUEST_RATE_PER_IP_DAY = 3;
const REQUEST_RATE_PER_EMAIL_DAY = 1;
const REQUEST_RATE_PER_FP_DAY = 3;

// Approval token lifetime. Approvals older than this are rejected so an
// inbox compromise weeks later can't quietly issue new codes.
const APPROVAL_TOKEN_TTL_SEC = 60 * 60 * 24 * 14;

// Lifetime of an auto-issued access code. Long enough that a recipient can
// come back without rushing, short enough that abandoned codes auto-expire.
const ISSUED_CODE_TTL_DAYS = 30;

// Unambiguous alphabet for auto-generated code suffixes (no 0/O/1/I/L).
const CODE_SUFFIX_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// RFC-5321 says local-part can be quoted/contain dots, but in practice we only
// care that something@something.tld is plausibly a real address. Strict enough
// to reject obvious junk, loose enough to accept tag-style and subdomain mail.
const EMAIL_RE = /^[A-Z0-9._%+-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;

function validateEmail(raw) {
    if (typeof raw !== 'string') return null;
    const trimmed = raw.trim();
    if (trimmed.length < 5 || trimmed.length > REQUEST_EMAIL_MAX_LEN) return null;
    if (!EMAIL_RE.test(trimmed)) return null;
    return trimmed.toLowerCase();
}

function sanitizeText(raw, maxLen) {
    if (typeof raw !== 'string') return '';
    // Strip control chars (except newline/tab), collapse whitespace, trim.
    const cleaned = raw
        .replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, '')
        .replace(/[ \t]+/g, ' ')
        .replace(/\r\n?/g, '\n')
        .trim();
    if (cleaned.length === 0) return '';
    return cleaned.slice(0, maxLen);
}

function approvalTokenSecret() {
    // Reuse the gate session secret unless an explicit override is set.
    return (
        process.env.REQUEST_APPROVAL_SECRET ||
        process.env.GATE_SESSION_SECRET ||
        ''
    );
}

function signApprovalToken(requestId) {
    const secret = approvalTokenSecret();
    if (!secret || secret.length < 32 || !isUuidString(requestId)) {
        return null;
    }
    const exp = Math.floor(Date.now() / 1000) + APPROVAL_TOKEN_TTL_SEC;
    const payload = requestId + '.' + exp;
    const sig = bufferToBase64Url(
        crypto.createHmac('sha256', secret).update(payload).digest(),
    );
    return payload + '.' + sig;
}

function verifyApprovalToken(token) {
    const secret = approvalTokenSecret();
    if (!secret || secret.length < 32 || typeof token !== 'string') {
        return null;
    }
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const requestId = parts[0];
    const expStr = parts[1];
    const sig = parts[2];
    if (!isUuidString(requestId)) return null;
    const expSec = Number(expStr);
    if (!Number.isFinite(expSec) || expSec < Math.floor(Date.now() / 1000)) {
        return null;
    }
    const payload = requestId + '.' + expStr;
    const expected = bufferToBase64Url(
        crypto.createHmac('sha256', secret).update(payload).digest(),
    );
    const a = Buffer.from(sig, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;
    return { requestId: requestId };
}

/**
 * Turn an email address into a memorable, friendly access code.
 *   john@acme.com           -> ACME-K7XQ2P
 *   jane@labs.example.com   -> LABS-3MNPRT
 *   joe@gmail.com           -> GMAIL-X4FRT9
 *
 * The "stem" is the first DNS label of the domain, uppercased and stripped
 * of anything that wouldn't pass our normalization (A-Z0-9 only). The suffix
 * is 6 random characters from an unambiguous alphabet (no 0/O/1/I/L). The
 * dash is purely cosmetic — the verify endpoint normalizes it out.
 */
function generateCodeFromEmail(email) {
    if (typeof email !== 'string' || email.indexOf('@') < 0) {
        return null;
    }
    const domain = email.slice(email.indexOf('@') + 1).toLowerCase();
    const stemRaw = domain.split('.')[0] || '';
    let stem = stemRaw.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    if (stem.length < 2) {
        // Pathological domain — fall back to a stem that still hints at email.
        stem = 'GUEST';
    }
    const buf = crypto.randomBytes(6);
    let suffix = '';
    for (let i = 0; i < buf.length; i++) {
        suffix += CODE_SUFFIX_ALPHABET[buf[i] % CODE_SUFFIX_ALPHABET.length];
    }
    const display = stem + '-' + suffix;
    return { display: display, normalized: stem + suffix };
}

async function recordAccessRequest(sql, fields) {
    const id = randomUuidV4();
    await sql`
        INSERT INTO portfolio_gate_access_requests
            (id, email, name, referral, ip, fingerprint, user_agent, status, last_notified_at)
        VALUES
            (${id}::uuid,
             ${fields.email},
             ${fields.name},
             ${fields.referral || null},
             ${fields.ip || null}::inet,
             ${fields.fingerprint || null},
             ${fields.userAgent || null},
             'pending',
             now())
    `;
    return id;
}

async function countRecentRequests(sql, opts) {
    // 24h windows by email / ip / fingerprint. Done as a single query so the
    // endpoint doesn't pay three round-trips just to decide whether to throttle.
    const rows = await sql`
        SELECT
            SUM(CASE WHEN LOWER(email) = ${opts.email} THEN 1 ELSE 0 END)::int AS by_email,
            SUM(CASE WHEN ip = ${opts.ip || null}::inet AND ${opts.ip || null}::inet IS NOT NULL THEN 1 ELSE 0 END)::int AS by_ip,
            SUM(CASE WHEN fingerprint = ${opts.fingerprint || null} AND ${opts.fingerprint || null}::text IS NOT NULL THEN 1 ELSE 0 END)::int AS by_fp
        FROM portfolio_gate_access_requests
        WHERE created_at > now() - interval '24 hours'
    `;
    const r = rows[0] || { by_email: 0, by_ip: 0, by_fp: 0 };
    return {
        byEmail: r.by_email || 0,
        byIp: r.by_ip || 0,
        byFingerprint: r.by_fp || 0,
    };
}

async function getPendingRequestById(sql, requestId) {
    if (!isUuidString(requestId)) return null;
    const rows = await sql`
        SELECT id, email, name, referral, status, code_id, created_at, approved_at
        FROM portfolio_gate_access_requests
        WHERE id = ${requestId}::uuid
        LIMIT 1
    `;
    return rows[0] || null;
}

async function insertAutoIssuedAccessCode(sql, opts) {
    // bcryptjs is a per-endpoint require — keep this lib free of that dep so
    // status / read paths don't load it.
    const bcrypt = require('bcryptjs');
    const hash = bcrypt.hashSync(opts.normalizedCode, opts.bcryptCost || 10);
    const expiresIso =
        opts.expiresAt instanceof Date
            ? opts.expiresAt.toISOString()
            : opts.expiresAt || null;
    const rows = await sql`
        INSERT INTO portfolio_gate_access_codes (label, bcrypt_hash, active, expires_at)
        VALUES (${opts.label}, ${hash}, true, ${expiresIso})
        ON CONFLICT (bcrypt_hash) DO NOTHING
        RETURNING id, label, expires_at
    `;
    invalidateAccessCodeCache();
    return rows[0] || null;
}

async function markRequestApproved(sql, requestId, codeId) {
    await sql`
        UPDATE portfolio_gate_access_requests
        SET status = 'approved', code_id = ${codeId}, approved_at = now()
        WHERE id = ${requestId}::uuid AND status = 'pending'
    `;
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
    // Access-request workflow
    REQUEST_NAME_MAX_LEN,
    REQUEST_EMAIL_MAX_LEN,
    REQUEST_REFERRAL_MAX_LEN,
    REQUEST_USER_AGENT_MAX_LEN,
    REQUEST_RATE_PER_IP_DAY,
    REQUEST_RATE_PER_EMAIL_DAY,
    REQUEST_RATE_PER_FP_DAY,
    APPROVAL_TOKEN_TTL_SEC,
    ISSUED_CODE_TTL_DAYS,
    validateEmail,
    sanitizeText,
    signApprovalToken,
    verifyApprovalToken,
    generateCodeFromEmail,
    recordAccessRequest,
    countRecentRequests,
    getPendingRequestById,
    insertAutoIssuedAccessCode,
    markRequestApproved,
};
