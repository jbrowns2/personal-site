#!/usr/bin/env node
/**
 * Reset invitation reporting data (local CLI only).
 *
 * Clears portfolio_gate_access_code_events and nulls last_used_at on all codes.
 * Access codes, lookup hashes, and outreach metadata are kept.
 *
 * Usage:
 *   npm run gate:report:reset
 *   npm run gate:report:reset -- --yes
 */

const fs = require('fs');
const path = require('path');
const { neon } = require('@neondatabase/serverless');

loadDotEnvIfPresent(path.join(__dirname, '..', '.env'));

main().catch(function (err) {
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
});

async function main() {
    const args = process.argv.slice(2);
    if (args.indexOf('-h') >= 0 || args.indexOf('--help') >= 0) {
        printUsage();
        process.exit(0);
    }

    const confirmed = args.indexOf('--yes') >= 0 || args.indexOf('-y') >= 0;
    if (!confirmed) {
        console.error(
            'This deletes all access-code event history and clears last_used_at.\n' +
                'Access codes are not removed.\n\n' +
                'Re-run with --yes to confirm:\n' +
                '  npm run gate:report:reset -- --yes',
        );
        process.exit(1);
    }

    const url = process.env.DATABASE_URL;
    if (!url) {
        console.error('DATABASE_URL is not set.');
        process.exit(1);
    }

    const sql = neon(url);
    const before = await sql`
        SELECT COUNT(*)::int AS events FROM portfolio_gate_access_code_events
    `;
    const eventCount = before[0] && before[0].events ? before[0].events : 0;

    await sql`DELETE FROM portfolio_gate_access_code_events`;
    const cleared = await sql`
        UPDATE portfolio_gate_access_codes
        SET last_used_at = NULL
        WHERE last_used_at IS NOT NULL
        RETURNING id
    `;

    console.log(
        'Report reset complete: removed ' +
            eventCount +
            ' event(s), cleared last_used_at on ' +
            cleared.length +
            ' code(s).',
    );
    console.log('Run npm run gate:report to verify.');
}

function printUsage() {
    process.stdout.write(
        [
            'Reset invitation reporting data (events + last_used_at).',
            '',
            'Usage:',
            '  npm run gate:report:reset -- --yes',
            '',
        ].join('\n'),
    );
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
        // best-effort
    }
}
