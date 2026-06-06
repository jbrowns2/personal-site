#!/usr/bin/env node
/**
 * CLI invitation report for portfolio access gate.
 *
 * Usage:
 *   node scripts/gate-report.js [--status pending] [--min-days 14] [--csv] [--json]
 */

const fs = require('fs');
const path = require('path');
const { neon } = require('@neondatabase/serverless');
const { getInvitationReport, invitationsToCsv } = require('../lib/gate-report.js');

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

    const filters = {
        status: 'all',
        since: null,
        minDaysPending: null,
        includeEvents: false,
    };
    let asCsv = false;
    let asJson = false;

    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--status') filters.status = args[++i] || 'all';
        else if (a.startsWith('--status=')) filters.status = a.slice('--status='.length);
        else if (a === '--min-days') filters.minDaysPending = parseInt(args[++i], 10);
        else if (a.startsWith('--min-days=')) {
            filters.minDaysPending = parseInt(a.slice('--min-days='.length), 10);
        } else if (a === '--csv') asCsv = true;
        else if (a === '--json') asJson = true;
    }

    const url = process.env.DATABASE_URL;
    if (!url) {
        console.error('DATABASE_URL is not set.');
        process.exit(1);
    }

    const sql = neon(url);
    const report = await getInvitationReport(sql, filters);

    if (asJson) {
        console.log(JSON.stringify(report, null, 2));
        return;
    }
    if (asCsv) {
        process.stdout.write(invitationsToCsv(report.invitations));
        return;
    }

    const s = report.summary;
    console.log('=== Invitation Report (generated ' + report.generatedAt + ') ===');
    console.log(
        'Total: ' +
            s.totalInvitations +
            ' | Responded: ' +
            s.responded +
            ' (' +
            s.responseRatePct +
            '%) | Pending: ' +
            s.pending +
            ' | Expired unused: ' +
            s.expiredUnused,
    );
    console.log(
        'Failed entries: ' +
            s.totalFailedEntries +
            ' | Tried-but-never-succeeded: ' +
            s.employersFailedButNeverSucceeded +
            ' | Avg days to first use: ' +
            (s.avgDaysToFirstUse != null ? s.avgDaysToFirstUse : '—'),
    );
    console.log('');

    if (report.invitations.length === 0) {
        console.log('No invitations match the filter.');
        return;
    }

    const header =
        pad('STATUS', 10) +
        pad('CODE', 18) +
        pad('EMPLOYER', 22) +
        pad('CONTACT', 24) +
        pad('INVITED', 12) +
        pad('FIRST USE', 12) +
        pad('USES', 5) +
        pad('FAILED', 7) +
        pad('BEFORE', 7) +
        'DAYS';
    console.log(header);
    console.log('-'.repeat(header.length));

    report.invitations.forEach(function (inv) {
        const contact = inv.contactEmail || inv.contactName || '—';
        const days =
            inv.responseStatus === 'pending'
                ? inv.daysOutstanding
                : inv.daysToFirstUse;
        console.log(
            pad(inv.responseStatus, 10) +
                pad(inv.accessCode || '—', 18) +
                pad(inv.employerLabel, 22) +
                pad(contact, 24) +
                pad(fmtDate(inv.invitedAt), 12) +
                pad(fmtDate(inv.firstUsedAt), 12) +
                pad(String(inv.useCount), 5) +
                pad(String(inv.failedAttemptCount), 7) +
                pad(
                    inv.failedBeforeFirstSuccess ? String(inv.failedBeforeFirstSuccess) : '—',
                    7,
                ) +
                (days != null ? days : '—'),
        );
    });
}

function pad(str, len) {
    const s = String(str == null ? '' : str);
    return s.length >= len ? s.slice(0, len - 1) + ' ' : s + ' '.repeat(len - s.length);
}

function fmtDate(iso) {
    if (!iso) return '—';
    return iso.slice(0, 10);
}

function printUsage() {
    process.stdout.write(
        [
            'Invitation report CLI for portfolio access gate.',
            '',
            'Usage:',
            '  npm run gate:report',
            '  npm run gate:report -- --status pending',
            '  npm run gate:report -- --min-days 14',
            '  npm run gate:report -- --csv',
            '  npm run gate:report -- --json',
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
