#!/usr/bin/env node
/**
 * Generate site profile JSON for every resume in job-applications/.
 *
 * Usage:
 *   node scripts/generate-all-profiles.js
 *   node scripts/generate-all-profiles.js --dry-run
 */

const fs = require('fs');
const path = require('path');
const {
    parseResumeToProfile,
    extractAccessCode,
    folderToSlug,
} = require('../lib/resume-profile-parser.js');

const ROOT = path.join(__dirname, '..');
const JOBS_DIR = path.join(ROOT, 'job-applications');
const PROFILES_DIR = path.join(ROOT, 'site-profiles');

/** Shorter, stable slugs for known folders */
const SLUG_OVERRIDES = {
    'Beacon-Hill-UAT-Analyst-1461840_1780948197': 'beacon-hill-uat',
    'JPMorganChase-Quant-Analytics-Manager-VP-210741105': 'jpmc-quant',
    'Wintrust-AVP-Finance-FPA-26795': 'wintrust-fpa',
    'West-Bend-Sr-Data-Scientist-2026-3518': 'west-bend',
    'LexisNexis-Risk-Data-Scientist-R111919': 'lexis-nexis',
    'Motorola-PM-BI-Analytics-R62892': 'motorola-bi',
    'Michael-Page': 'michael-page',
    'Syneos-Survey-Data-Insights-Analyst-16239': 'syneos-survey',
    'Brunswick-Mgr-Enterprise-Finance-JR-050065': 'brunswick-finance',
    'CapitalOne-GPN-R239058': 'capital-one',
    'Culligan-Mgr-Financial-Analytics-MANAG008156': 'culligan',
    'Grainger-Reporting-Analytics-Mgr-330137': 'grainger',
    'Markel-Sr-Actuarial-Analyst-R0023059': 'markel',
    'Steward-Partners-Mgr-Finance-Data-Analytics': 'steward',
    'HUB-Mgr-Sales-Reporting-R0036086': 'hub-sales',
    'ITW-Controller-JR7846': 'itw',
    'Verve-Data-Engineer-8474867002': 'verve',
    'Flock-Full-Stack-Engineer-ML-Tooling': 'flock-full-stack-engineer-ml-tooling',
    'Upwork-General-Consulting': 'upwork',
    'Motion-Recruitment-AI-Tools-Automation-Specialist-6117': 'motion-ai-tools-automation-specialist',
    'MMD-Remote-Data-Architect': 'mmd-remote-data-architect',
    'Insight-Global-Senior-Data-Analyst-Data-Engineer-549347':
        'insight-global-senior-data-analyst-data-engineer',
    'Insight-Global-Remote-Junior-Data-Engineer-435519':
        'insight-global-remote-junior-data-engineer',
    'Randstad-Senior-Application-Development-Engineer-1338422':
        'randstad-senior-application-development-engineer',
    'Kforce-Senior-SQL-Developer-2176943': 'kforce-senior-sql-developer',
    'Brooksource-Jr-Data-Engineer-JN-062026-574854': 'brooksource-jr-data-engineer',
    'Akkodis-Consultant-1634792': 'akkodis-consultant',
    'Summit-Consultant-Future-Roles': 'summit-consultant',
    'MCC-AI-Enhanced-Business-Analytics': 'mcc-ai-business-analytics',
    'KornFerry-Reporting-FPA-Support-1688929': 'kornferry-reporting-fpa-support',
    'Hays-Sr-Data-Analyst-1185351': 'hays-sr-data-analyst',
};

function findResumeFiles() {
    if (!fs.existsSync(JOBS_DIR)) return [];
    return fs
        .readdirSync(JOBS_DIR, { withFileTypes: true })
        .filter(function (d) {
            return d.isDirectory();
        })
        .map(function (d) {
            const folder = path.join(JOBS_DIR, d.name);
            const md = fs
                .readdirSync(folder)
                .filter(function (f) {
                    return /Resume.*\.md$/i.test(f);
                });
            if (md.length === 0) return null;
            return {
                folderName: d.name,
                folderPath: folder,
                resumePath: path.join(folder, md[0]),
            };
        })
        .filter(Boolean);
}

function validateProfile(profile) {
    if (!profile.experience.items || profile.experience.items.length === 0) {
        throw new Error('No experience items parsed');
    }
    if (!profile.meta.title || !profile.hero.description) {
        throw new Error('Missing meta or hero content');
    }
}

function main() {
    const dryRun = process.argv.includes('--dry-run');
    const entries = findResumeFiles();
    const manifest = { generatedAt: new Date().toISOString(), profiles: [] };
    let ok = 0;
    let fail = 0;

    if (!fs.existsSync(PROFILES_DIR)) {
        fs.mkdirSync(PROFILES_DIR, { recursive: true });
    }

    entries.forEach(function (entry) {
        const slug =
            SLUG_OVERRIDES[entry.folderName] || folderToSlug(entry.folderName);
        const markdown = fs.readFileSync(entry.resumePath, 'utf8');
        const accessCode = extractAccessCode(markdown);

        try {
            const profile = parseResumeToProfile(markdown, { slug: slug, accessCode: accessCode });
            const overridesPath = path.join(entry.folderPath, 'site-profile.overrides.json');
            if (fs.existsSync(overridesPath)) {
                Object.assign(profile, JSON.parse(fs.readFileSync(overridesPath, 'utf8')));
                profile.slug = slug;
            }
            validateProfile(profile);
            const outPath = path.join(PROFILES_DIR, slug + '.json');
            if (!dryRun) {
                fs.writeFileSync(outPath, JSON.stringify(profile, null, 2) + '\n');
            }
            manifest.profiles.push({
                slug: slug,
                accessCode: accessCode || profile.accessCode || '',
                folder: entry.folderName,
                employmentType: profile.employmentType,
                role: profile.meta.title,
            });
            console.log('OK  ' + slug + (accessCode ? ' → ' + accessCode : ''));
            ok++;
        } catch (err) {
            console.error('FAIL ' + slug + ': ' + (err && err.message));
            fail++;
        }
    });

    if (!dryRun) {
        fs.writeFileSync(
            path.join(PROFILES_DIR, 'index.json'),
            JSON.stringify(manifest, null, 2) + '\n',
        );
    }

    console.log('\nGenerated ' + ok + ' profiles' + (fail ? ', ' + fail + ' failed' : '') + '.');
    if (fail > 0) process.exit(1);
}

main();
