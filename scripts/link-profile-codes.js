#!/usr/bin/env node
/**
 * Link access codes in Neon to site profile slugs from site-profiles/index.json
 *
 * Usage:
 *   node scripts/link-profile-codes.js
 *   node scripts/link-profile-codes.js --dry-run
 */

const fs = require('fs');
const path = require('path');
const { neon } = require('@neondatabase/serverless');
const { invalidateAccessCodeCache } = require('../lib/gate-backend.js');

loadDotEnvIfPresent(path.join(__dirname, '..', '.env'));

/** Gate codes without tailored resumes — leave profile_slug null */
const SKIP_CODES = new Set(['JBOWNER2026', 'RGA']);

/** Codes without resume access codes but same role family */
const EXTRA_LINKS = [{ code: 'MICHAELPAGECT', slug: 'michael-page' }];

function normalizeCode(raw) {
    return String(raw).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

async function linkOne(sql, accessCode, slug) {
    const code = normalizeCode(accessCode);
    if (!code) {
        console.log('SKIP ' + slug + ' (no access code in resume)');
        return { linked: 0, missing: 0 };
    }
    if (SKIP_CODES.has(code)) {
        console.log('SKIP ' + code + ' (owner/legacy)');
        return { linked: 0, missing: 0 };
    }

    const rows = await sql`
        UPDATE portfolio_gate_access_codes
        SET profile_slug = ${slug}
        WHERE access_code = ${code}
        RETURNING id, label, access_code, profile_slug
    `;

    if (rows.length === 0) {
        console.log('MISSING CODE ' + code + ' for profile ' + slug);
        return { linked: 0, missing: 1 };
    }

    rows.forEach(function (r) {
        console.log('LINKED ' + r.access_code + ' → ' + r.profile_slug + ' (id=' + r.id + ')');
    });
    return { linked: rows.length, missing: 0 };
}

async function main() {
    const dryRun = process.argv.includes('--dry-run');
    const indexPath = path.join(__dirname, '..', 'site-profiles', 'index.json');
    if (!fs.existsSync(indexPath)) {
        console.error('Run npm run profile:generate-all first.');
        process.exit(1);
    }
    const manifest = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
    const url = process.env.DATABASE_URL;
    if (!url) {
        console.error('DATABASE_URL not set.');
        process.exit(1);
    }
    const sql = neon(url);

    let linked = 0;
    let missing = 0;

    for (const entry of manifest.profiles) {
        if (dryRun) {
            console.log('WOULD LINK ' + (entry.accessCode || '?') + ' → ' + entry.slug);
            continue;
        }
        const result = await linkOne(sql, entry.accessCode, entry.slug);
        linked += result.linked;
        missing += result.missing;
    }

    for (const extra of EXTRA_LINKS) {
        if (dryRun) {
            console.log('WOULD LINK ' + extra.code + ' → ' + extra.slug);
            continue;
        }
        const result = await linkOne(sql, extra.code, extra.slug);
        linked += result.linked;
        missing += result.missing;
    }

    if (!dryRun) {
        invalidateAccessCodeCache();
    }

    console.log('\nLinked ' + linked + ' code(s).' + (missing ? ' ' + missing + ' not in gate.' : ''));
}

function loadDotEnvIfPresent(file) {
    try {
        if (!fs.existsSync(file)) return;
        fs.readFileSync(file, 'utf8')
            .split('\n')
            .forEach(function (line) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) return;
                const eq = trimmed.indexOf('=');
                if (eq < 0) return;
                const key = trimmed.slice(0, eq).trim();
                let val = trimmed.slice(eq + 1).trim();
                if (
                    (val.startsWith('"') && val.endsWith('"')) ||
                    (val.startsWith("'") && val.endsWith("'"))
                ) {
                    val = val.slice(1, -1);
                }
                if (!(key in process.env)) process.env[key] = val;
            });
    } catch (e) {}
}

main().catch(function (err) {
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
});
