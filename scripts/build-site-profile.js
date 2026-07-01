#!/usr/bin/env node
/**
 * Build a site profile JSON from a job application resume markdown.
 *
 * Usage:
 *   node scripts/build-site-profile.js <job-folder> [slug]
 *   node scripts/build-site-profile.js --validate site-profiles/beacon-hill-uat.json
 *   npm run profile:generate-all
 */

const fs = require('fs');
const path = require('path');
const {
    parseResumeToProfile,
    extractAccessCode,
    folderToSlug,
    PROFILE_SLUG_RE,
} = require('../lib/resume-profile-parser.js');

function validateProfile(profile, label) {
    const required = ['profileVersion', 'slug', 'employmentType', 'meta', 'hero', 'experience', 'contact'];
    for (const key of required) {
        if (!profile[key]) {
            console.error('Missing required field "' + key + '" in ' + label);
            process.exit(1);
        }
    }
    if (profile.profileVersion !== 1) {
        console.error('Unsupported profileVersion in ' + label);
        process.exit(1);
    }
    if (!PROFILE_SLUG_RE.test(profile.slug)) {
        console.error('Invalid profile.slug in ' + label);
        process.exit(1);
    }
    if (!Array.isArray(profile.experience.items) || profile.experience.items.length === 0) {
        console.error('experience.items must be a non-empty array in ' + label);
        process.exit(1);
    }
}

function findResumeInFolder(folder) {
    const files = fs.readdirSync(folder).filter(function (f) {
        return /Resume.*\.md$/i.test(f);
    });
    return files.length ? path.join(folder, files[0]) : null;
}

function main() {
    const argv = process.argv.slice(2);
    if (argv[0] === '--validate') {
        const file = argv[1];
        if (!file) {
            console.error('Usage: node scripts/build-site-profile.js --validate <profile.json>');
            process.exit(1);
        }
        validateProfile(JSON.parse(fs.readFileSync(file, 'utf8')), file);
        console.log('Valid: ' + file);
        return;
    }

    const jobFolder = argv[0];
    if (!jobFolder) {
        console.error(
            'Usage: node scripts/build-site-profile.js <job-folder> [slug]\n' +
                '       npm run profile:generate-all',
        );
        process.exit(1);
    }

    const folderPath = path.isAbsolute(jobFolder)
        ? jobFolder
        : path.join(process.cwd(), jobFolder);
    const folderName = path.basename(folderPath);
    const slug = argv[1] || folderToSlug(folderName);
    const resumePath = findResumeInFolder(folderPath);
    if (!resumePath) {
        console.error('No resume markdown found in ' + folderPath);
        process.exit(1);
    }

    const markdown = fs.readFileSync(resumePath, 'utf8');
    const profile = parseResumeToProfile(markdown, {
        slug: slug,
        accessCode: extractAccessCode(markdown),
    });

    const overridesPath = path.join(folderPath, 'site-profile.overrides.json');
    if (fs.existsSync(overridesPath)) {
        Object.assign(profile, JSON.parse(fs.readFileSync(overridesPath, 'utf8')));
        profile.slug = slug;
    }

    const outPath = path.join(__dirname, '..', 'site-profiles', slug + '.json');
    validateProfile(profile, outPath);
    fs.writeFileSync(outPath, JSON.stringify(profile, null, 2) + '\n');
    console.log('Wrote ' + outPath);
}

main();
