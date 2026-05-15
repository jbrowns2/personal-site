#!/usr/bin/env node
/**
 * Manage portfolio access codes in Neon (table: portfolio_gate_access_codes).
 *
 * Usage:
 *   node scripts/manage-gate-codes.js list
 *   node scripts/manage-gate-codes.js add    "RAW CODE" "Label / company"
 *   node scripts/manage-gate-codes.js add    "RAW CODE" "Label" --expires 2026-12-31
 *   node scripts/manage-gate-codes.js rotate "RAW CODE" "Label"   # replace existing label with a fresh hash
 *   node scripts/manage-gate-codes.js disable <id|label>
 *   node scripts/manage-gate-codes.js enable  <id|label>
 *   node scripts/manage-gate-codes.js remove  <id|label>
 *
 * Reads DATABASE_URL from process.env or, as a convenience for local CLI use,
 * from the project's `.env` file. Codes are normalized the same way the
 * server normalizes them (trim, uppercase, strip non-alphanumeric) before
 * being bcrypt-hashed.
 *
 * Note: the server caches active hashes for ~30s, so adds / disables can take
 * up to that long to propagate across warm Vercel function instances.
 */

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { neon } = require('@neondatabase/serverless');
const { MIN_CODE_LEN, MAX_CODE_LEN } = require('../lib/gate-backend.js');

loadDotEnvIfPresent(path.join(__dirname, '..', '.env'));

// Cost 10 = OWASP minimum for bcrypt; ~4× faster than cost 12 with no
// meaningful security loss for a personal portfolio gate. Re-hash existing
// codes via the `rotate` command to pick up the speedup.
const BCRYPT_COST = 10;

main().catch(function (err) {
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
});

async function main() {
    const argv = process.argv.slice(2);
    const cmd = argv[0];
    if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
        printUsage();
        process.exit(cmd ? 0 : 1);
    }

    const sql = getSql();

    switch (cmd) {
        case 'list':
            await cmdList(sql);
            break;
        case 'add':
            await cmdAdd(sql, argv.slice(1));
            break;
        case 'rotate':
            await cmdRotate(sql, argv.slice(1));
            break;
        case 'disable':
            await cmdSetActive(sql, argv.slice(1), false);
            break;
        case 'enable':
            await cmdSetActive(sql, argv.slice(1), true);
            break;
        case 'remove':
        case 'delete':
            await cmdRemove(sql, argv.slice(1));
            break;
        default:
            console.error('Unknown command: ' + cmd + '\n');
            printUsage();
            process.exit(1);
    }
}

function printUsage() {
    process.stdout.write(
        [
            'Manage portfolio access codes in Neon.',
            '',
            'Commands:',
            '  list                                  Show every access code (active + disabled).',
            '  add    "RAW CODE" "Label" [--expires YYYY-MM-DD]',
            '                                        Hash and insert a new code.',
            '  rotate "RAW CODE" "Label" [--expires YYYY-MM-DD]',
            '                                        Replace any existing code(s) with this label by',
            '                                        a freshly-hashed entry (used to drop bcrypt cost).',
            '  disable <id|label>                    Mark an access code inactive.',
            '  enable  <id|label>                    Re-activate a disabled access code.',
            '  remove  <id|label>                    Permanently delete an access code.',
            '',
            'Examples:',
            '  npm run gate:list',
            '  npm run gate:add -- "openthegate" "RGA"',
            '  npm run gate:disable -- "RGA"',
            '',
            'Reads DATABASE_URL from .env or process.env. The server caches active hashes',
            'for ~30s, so changes propagate within that window.',
            '',
        ].join('\n'),
    );
}

async function cmdList(sql) {
    const rows = await sql`
        SELECT id, label, active, expires_at, last_used_at, created_at
        FROM portfolio_gate_access_codes
        ORDER BY active DESC, created_at DESC, id DESC
    `;
    if (rows.length === 0) {
        console.log(
            'No access codes yet. Add one with:\n  npm run gate:add -- "YOURCODE" "Label"',
        );
        return;
    }
    const table = rows.map(function (r) {
        return {
            id: r.id,
            label: r.label,
            active: r.active,
            expires_at: r.expires_at ? toIso(r.expires_at) : '',
            last_used_at: r.last_used_at ? toIso(r.last_used_at) : '',
            created_at: toIso(r.created_at),
        };
    });
    console.table(table);
}

async function cmdAdd(sql, args) {
    const { rawCode, label, expiresIso } = parseAddArgs(args, 'add');
    const normalized = normalizeAndValidateCode(rawCode);
    const hash = bcrypt.hashSync(normalized, BCRYPT_COST);
    const inserted = await sql`
        INSERT INTO portfolio_gate_access_codes (label, bcrypt_hash, active, expires_at)
        VALUES (${label}, ${hash}, true, ${expiresIso})
        ON CONFLICT (bcrypt_hash) DO NOTHING
        RETURNING id, label, active, expires_at, created_at
    `;
    if (inserted.length === 0) {
        console.error(
            'That bcrypt hash already exists in the table — did you add this code already?',
        );
        process.exit(1);
    }
    const row = inserted[0];
    console.log(
        'Added access code id=' +
            row.id +
            ' label="' +
            row.label +
            '" at bcrypt cost ' +
            BCRYPT_COST +
            (row.expires_at ? ' expires=' + toIso(row.expires_at) : '') +
            '. Propagates within ~30s.',
    );
}

function parseAddArgs(args, cmdName) {
    const positional = [];
    let expiresAt = null;
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--expires' || a === '-e') {
            expiresAt = args[++i] || null;
        } else if (a.startsWith('--expires=')) {
            expiresAt = a.slice('--expires='.length);
        } else {
            positional.push(a);
        }
    }
    const rawCode = positional[0];
    const label = positional[1];
    if (!rawCode || !label) {
        console.error(
            'Usage: node scripts/manage-gate-codes.js ' +
                cmdName +
                ' "RAW CODE" "Label" [--expires YYYY-MM-DD]',
        );
        process.exit(1);
    }
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) {
        console.error('Invalid --expires value (use YYYY-MM-DD or full ISO timestamp).');
        process.exit(1);
    }
    return {
        rawCode: rawCode,
        label: label,
        expiresIso: expiresAt ? new Date(expiresAt).toISOString() : null,
    };
}

function normalizeAndValidateCode(rawCode) {
    const normalized = normalizeCode(rawCode);
    if (normalized.length < MIN_CODE_LEN || normalized.length > MAX_CODE_LEN) {
        console.error(
            'Code must be between ' +
                MIN_CODE_LEN +
                ' and ' +
                MAX_CODE_LEN +
                ' alphanumeric characters after normalization.',
        );
        process.exit(1);
    }
    return normalized;
}

async function cmdRotate(sql, args) {
    const { rawCode, label, expiresIso } = parseAddArgs(args, 'rotate');
    const normalized = normalizeAndValidateCode(rawCode);
    const newHash = bcrypt.hashSync(normalized, BCRYPT_COST);

    const removed = await sql`
        DELETE FROM portfolio_gate_access_codes
        WHERE label = ${label}
        RETURNING id
    `;
    const inserted = await sql`
        INSERT INTO portfolio_gate_access_codes (label, bcrypt_hash, active, expires_at)
        VALUES (${label}, ${newHash}, true, ${expiresIso})
        ON CONFLICT (bcrypt_hash) DO NOTHING
        RETURNING id, label, active, expires_at, created_at
    `;
    if (inserted.length === 0) {
        console.error(
            'Insert failed (bcrypt hash collision). Try again — bcrypt salting should make this near-impossible.',
        );
        process.exit(1);
    }
    const row = inserted[0];
    console.log(
        'Rotated label="' +
            label +
            '": removed ' +
            removed.length +
            ' old row(s), added id=' +
            row.id +
            ' at bcrypt cost ' +
            BCRYPT_COST +
            (row.expires_at ? ' expires=' + toIso(row.expires_at) : '') +
            '. Propagates within ~30s.',
    );
}

async function cmdSetActive(sql, args, active) {
    const target = args[0];
    if (!target) {
        console.error(
            'Usage: node scripts/manage-gate-codes.js ' +
                (active ? 'enable' : 'disable') +
                ' <id|label>',
        );
        process.exit(1);
    }
    const isId = /^\d+$/.test(target);
    const rows = isId
        ? await sql`
              UPDATE portfolio_gate_access_codes
              SET active = ${active}
              WHERE id = ${Number(target)}
              RETURNING id, label, active
          `
        : await sql`
              UPDATE portfolio_gate_access_codes
              SET active = ${active}
              WHERE label = ${target}
              RETURNING id, label, active
          `;
    if (rows.length === 0) {
        console.error('No access code matched id/label "' + target + '".');
        process.exit(1);
    }
    rows.forEach(function (r) {
        console.log(
            (active ? 'Enabled' : 'Disabled') +
                ' id=' +
                r.id +
                ' label="' +
                r.label +
                '". Propagates within ~30s.',
        );
    });
}

async function cmdRemove(sql, args) {
    const target = args[0];
    if (!target) {
        console.error('Usage: node scripts/manage-gate-codes.js remove <id|label>');
        process.exit(1);
    }
    const isId = /^\d+$/.test(target);
    const rows = isId
        ? await sql`
              DELETE FROM portfolio_gate_access_codes
              WHERE id = ${Number(target)}
              RETURNING id, label
          `
        : await sql`
              DELETE FROM portfolio_gate_access_codes
              WHERE label = ${target}
              RETURNING id, label
          `;
    if (rows.length === 0) {
        console.error('No access code matched id/label "' + target + '".');
        process.exit(1);
    }
    rows.forEach(function (r) {
        console.log('Removed id=' + r.id + ' label="' + r.label + '".');
    });
}

function normalizeCode(raw) {
    return String(raw).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function toIso(value) {
    try {
        return new Date(value).toISOString();
    } catch (e) {
        return String(value);
    }
}

function getSql() {
    const url = process.env.DATABASE_URL;
    if (!url) {
        console.error(
            'DATABASE_URL is not set. Add it to .env or export it before running this script.',
        );
        process.exit(1);
    }
    return neon(url);
}

function loadDotEnvIfPresent(file) {
    try {
        if (!fs.existsSync(file)) return;
        const content = fs.readFileSync(file, 'utf8');
        content.split('\n').forEach(function (line) {
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
            if (!(key in process.env)) {
                process.env[key] = val;
            }
        });
    } catch (e) {
        // best-effort; silent
    }
}
