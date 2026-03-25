/**
 * Shared server-side access gate logic (Vercel + Neon).
 * Env: DATABASE_URL, ACCESS_CODE_BCRYPT, GATE_SESSION_SECRET (>= 32 chars).
 */

const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const net = require('net');

const COOKIE_NAME = 'portfolio_gate_sess';
const MAX_CODE_LEN = 32;
const FAIL_WINDOW_MINUTES = 10;
const MAX_FAILS_BEFORE_LOCK = 5;
const LOCKOUT_MINUTES = 30;
const MAX_LOCKOUT_MINUTES = 60 * 24;
const SESSION_MAX_AGE_SEC = 60 * 60 * 24 * 7;
const STATUS_CHECK_WINDOW_MINUTES = 10;
const MAX_STATUS_CHECKS = 30;

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

function loadGateSecrets() {
    const bcryptHash = process.env.ACCESS_CODE_BCRYPT;
    const secret = process.env.GATE_SESSION_SECRET;
    if (!bcryptHash || !secret || secret.length < 32) {
        return null;
    }
    return { bcryptHash, secret };
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
    const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
    return payload + '.' + sig;
}

function verifySessionToken(token, secret) {
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
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
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
    const secrets = loadGateSecrets();
    if (!secrets) {
        return false;
    }
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[COOKIE_NAME];
    return verifySessionToken(token, secrets.secret);
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

async function recordFailureAndMaybeLock(sql, ip) {
    const failWindowLabel = String(FAIL_WINDOW_MINUTES) + ' minutes';
    const countRows = await sql`
    WITH ins AS (
      INSERT INTO portfolio_gate_attempts (ip, success)
      VALUES (${ip}::inet, false)
      RETURNING 1
    )
    SELECT COUNT(*)::int AS c FROM portfolio_gate_attempts
    WHERE ip = ${ip}::inet
      AND success = false
      AND attempted_at > now() - ${failWindowLabel}::interval
  `;
    const c = countRows[0] ? countRows[0].c : 0;
    if (c >= MAX_FAILS_BEFORE_LOCK) {
        const untilMs = await applyLockout(sql, ip);
        return { locked: true, lockedUntilMs: untilMs, failCount: c };
    }
    return { locked: false, failCount: c };
}

async function recordSuccess(sql, ip) {
    await sql`
    INSERT INTO portfolio_gate_attempts (ip, success)
    VALUES (${ip}::inet, true)
  `;
    await clearLockout(sql, ip);
}

function retryAfterSecFromUntil(lockedUntilMs) {
    return Math.max(1, Math.ceil((lockedUntilMs - Date.now()) / 1000));
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
    MAX_CODE_LEN,
};
