/**
 * Parse tailored resume markdown into a site profile JSON object.
 */

const PROFILE_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function stripMd(s) {
    return String(s || '')
        .replace(/\*\*/g, '')
        .replace(/\*/g, '')
        .trim();
}

function splitListLine(line) {
    return line
        .split(/\s*[•|]\s*/)
        .map(function (s) {
            return stripMd(s);
        })
        .filter(Boolean);
}

function extractAccessCode(text) {
    const m = text.match(/(?:portfolio\s+)?access\s+code:?\s*([A-Za-z0-9]+)/i);
    return m ? m[1].replace(/[^A-Za-z0-9]/g, '').toUpperCase() : null;
}

function extractMetadata(text) {
    const meta = {};
    const roleM = text.match(/\*\*Role:\*\*\s*(.+)/i);
    const employerM = text.match(/\*\*Employer:\*\*\s*(.+)/i);
    const institutionM = text.match(/\*\*Institution:\*\*\s*(.+)/i);
    const audienceM = text.match(/\*\*Audience:\*\*\s*(.+)/i);
    const agencyM = text.match(/\*\*Agency:\*\*\s*(.+)/i);
    if (roleM) meta.role = stripMd(roleM[1]);
    if (employerM) meta.employer = stripMd(employerM[1]);
    if (institutionM) meta.employer = stripMd(institutionM[1]);
    if (audienceM) meta.employer = stripMd(audienceM[1]);
    if (agencyM) meta.agency = stripMd(agencyM[1]);
    return meta;
}

function extractTagline(text) {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line.startsWith('**JONATHAN') || line.startsWith('**Jonathan')) {
            const next = lines[i + 1];
            if (next && next.includes('|')) {
                return stripMd(next);
            }
        }
    }
    return '';
}

function extractEmail(text) {
    const m = text.match(/[\w.+-]+@[\w.-]+\.\w+/);
    return m ? m[0] : 'JonathanBrownstein12@icloud.com';
}

function detectEmploymentType(text) {
    const lower = text.toLowerCase();
    if (
        lower.includes('## contract overview') ||
        lower.includes('## selected contract assignments') ||
        lower.includes('independent contractor') ||
        lower.includes('your website in 7 days llc') ||
        lower.includes('temporary / contract') ||
        lower.includes('temporary contract') ||
        lower.includes('part time contract') ||
        lower.includes('remote contract')
    ) {
        return 'contract';
    }
    return 'full_time';
}

function sectionBody(text, heading) {
    const re = new RegExp(
        '##\\s+' + heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\n([\\s\\S]*?)(?=\\n##\\s|$)',
        'i',
    );
    const m = text.match(re);
    return m ? m[1].trim() : '';
}

function firstParagraph(body) {
    if (!body) return '';
    return body
        .split('\n\n')[0]
        .replace(/^-\s+/gm, '')
        .replace(/\*\*/g, '')
        .trim();
}

function parseCompetencies(text) {
    const body =
        sectionBody(text, 'CORE COMPETENCIES') ||
        sectionBody(text, 'SERVICES & DELIVERABLES') ||
        sectionBody(text, 'TARGET ROLES');
    if (!body) return [];
    const lines = body.split('\n').filter(function (l) {
        return l.trim();
    });
    const items = [];
    lines.forEach(function (line) {
        splitListLine(line).forEach(function (item) {
            if (item.length > 2) items.push(item);
        });
    });
    return items;
}

function parseSummary(text) {
    return (
        firstParagraph(sectionBody(text, 'PROFESSIONAL SUMMARY')) ||
        firstParagraph(sectionBody(text, 'CONTRACT OVERVIEW')) ||
        ''
    );
}


function parseBoldTitleLine(line) {
    const trimmed = line.trim();
    const inner = trimmed.match(/^\*\*(.+)\*\*/);
    if (!inner) return null;

    const content = inner[1].trim();
    const trailing = trimmed.slice(inner[0].length).trim();
    const trailingSuffix = trailing.replace(/^[·|]\s*/, '');

    const dateSplit = content.match(/^(.+?)\s*[|·]\s*((?:19|20)\d{2}.+)$/);
    if (dateSplit) {
        return { title: stripMd(dateSplit[1]), suffix: stripMd(dateSplit[2]) };
    }

    const orgSplit = content.match(/^(.+?)\s*·\s*(.+)$/);
    if (orgSplit && !hasDateRange(orgSplit[2])) {
        return { title: stripMd(orgSplit[1]), suffix: stripMd(orgSplit[2]) };
    }

    if (trailingSuffix && !hasDateRange(trailingSuffix)) {
        return { title: stripMd(content), suffix: stripMd(trailingSuffix) };
    }

    return { title: stripMd(content), suffix: '' };
}

function isItalicContext(line) {
    const t = line.trim();
    return (
        (t.startsWith('*') && t.endsWith('*') && !t.startsWith('**')) ||
        (t.startsWith('_') && t.endsWith('_'))
    );
}

function stripItalic(line) {
    return stripMd(line.trim().replace(/^[*_]|[*_]$/g, ''));
}

function hasDateRange(text) {
    return /\b(19|20)\d{2}\b/i.test(text) && (/present/i.test(text) || /\bto\b|[–-]/.test(text));
}

function normalizeDates(text) {
    return String(text || '')
        .replace(/\s+to\s+/gi, ' – ')
        .replace(/\s*-\s*/g, ' – ')
        .trim();
}

function stripEngagementDates(text) {
    return String(text || '')
        .replace(/\s*[·|]\s*(?:(?:19|20)\d{2}.+)$/i, '')
        .replace(
            /\s+(?:19|20)\d{2}\s*(?:to|–|-|—)\s*(?:(?:19|20)\d{2}|Present|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+(?:19|20)\d{2})\s*$/i,
            '',
        )
        .trim();
}

function isBulletLine(t) {
    return t.startsWith('-') || t.startsWith('•') || t.startsWith('*');
}

function stripBulletPrefix(t) {
    return stripMd(t.replace(/^\s*[-•*]\s+/, ''));
}

function parseContractExperienceItems(body) {
    const items = [];
    const blocks = body.split(/\n(?=\*\*)/);

    blocks.forEach(function (block) {
        block = block.trim();
        if (!block.startsWith('**')) return;

        const parsed = parseBoldTitleLine(block.split('\n')[0]);
        if (!parsed) return;

        let title = parsed.title;
        let organization = '';
        let context = '';
        const bullets = [];

        if (parsed.suffix && !hasDateRange(parsed.suffix)) {
            organization = parsed.suffix;
        }

        const lines = block.split('\n').slice(1);
        lines.forEach(function (line) {
            const t = line.trim();
            if (!t) return;
            if (isItalicContext(t)) {
                context = stripEngagementDates(stripItalic(t));
                return;
            }
            if (!organization && t.includes('|') && !isBulletLine(t)) {
                organization = stripMd(t.split('|')[0]);
                return;
            }
            if (!organization && !isBulletLine(t) && t.length < 140) {
                organization = stripMd(t);
                return;
            }
            if (!context && !isBulletLine(t) && t.length >= 40) {
                context = stripEngagementDates(stripMd(t));
                return;
            }
            if (isBulletLine(t)) {
                bullets.push(stripBulletPrefix(t));
            }
        });

        if (!organization && context && context.length < 80) {
            organization = context;
            context = '';
        }

        if (title && (bullets.length > 0 || organization)) {
            items.push({
                title: stripEngagementDates(title),
                organization: organization || '',
                context: context,
                bullets: bullets.length ? bullets.slice(0, 10) : [context || organization].filter(Boolean),
            });
        }
    });

    return items;
}

function parseFullTimeExperienceItems(body) {
    const lines = body.split('\n');
    const jobs = [];
    let current = null;
    let currentSubsection = null;

    function pushJob() {
        if (!current) return;
        if (currentSubsection && currentSubsection.bullets.length) {
            current.subsections.push(currentSubsection);
            currentSubsection = null;
        }
        jobs.push(current);
        current = null;
    }

    lines.forEach(function (line) {
        const t = line.trim();
        if (!t) return;

        if (/^\*\*.+\*\*/.test(t)) {
            const parsed = parseBoldTitleLine(t);
            if (!parsed) return;

            if (hasDateRange(parsed.suffix || '')) {
                pushJob();
                current = {
                    title: parsed.title,
                    dates: normalizeDates(parsed.suffix),
                    context: '',
                    organization: '',
                    intro: '',
                    subsections: [],
                    bullets: [],
                };
                currentSubsection = null;
                return;
            }

            if (current) {
                if (currentSubsection && currentSubsection.bullets.length) {
                    current.subsections.push(currentSubsection);
                }
                currentSubsection = { title: parsed.title, bullets: [] };
            }
            return;
        }

        if (!current) return;

        if (isItalicContext(t)) {
            current.context = stripItalic(t);
            return;
        }
        if (!current.organization && t.includes('|') && !t.startsWith('-')) {
            current.organization = stripMd(t.split('|')[0]);
            return;
        }
        if (isBulletLine(t)) {
            const bullet = stripBulletPrefix(t);
            if (currentSubsection) {
                currentSubsection.bullets.push(bullet);
            } else {
                current.bullets.push(bullet);
            }
            return;
        }
        if (!current.intro && !t.startsWith('*') && t.length >= 40) {
            current.intro = stripMd(t);
        }
    });

    pushJob();

    return jobs.map(function (job) {
        const item = {
            title: job.title,
            organization: job.organization || '',
            context: job.context || '',
            dates: job.dates || '',
            bullets: job.bullets.slice(0, 10),
        };
        if (job.intro) item.intro = job.intro;
        if (job.subsections.length) {
            item.subsections = job.subsections
                .filter(function (s) {
                    return s.bullets.length > 0;
                })
                .map(function (s) {
                    return { title: s.title, bullets: s.bullets.slice(0, 8) };
                });
        }
        return item;
    });
}

function parseExperienceIntro(body) {
    if (!body) return '';
    const lines = body.split('\n').map(function (l) {
        return l.trim();
    });
    for (let i = 0; i < lines.length; i++) {
        const t = lines[i];
        if (!t) continue;
        if (t.startsWith('**')) break;
        if (isBulletLine(t)) continue;
        return stripMd(t);
    }
    return '';
}

function parseExperienceItems(text, employmentType) {
    const body =
        sectionBody(text, 'PROFESSIONAL EXPERIENCE') ||
        sectionBody(text, 'SELECTED CONTRACT ASSIGNMENTS') ||
        sectionBody(text, 'CLIENT ENGAGEMENTS');
    if (!body) return { intro: '', items: [] };

    const intro = employmentType === 'contract' ? parseExperienceIntro(body) : '';
    const items =
        employmentType === 'contract'
            ? parseContractExperienceItems(body)
            : parseFullTimeExperienceItems(body);
    return { intro: intro, items: items };
}

function parseSkillGroups(text) {
    const body = sectionBody(text, 'TECHNICAL SKILLS');
    if (!body) {
        const comps = parseCompetencies(text);
        if (comps.length === 0) return [];
        const chunk = Math.ceil(comps.length / 3);
        const groups = [];
        for (let i = 0; i < comps.length; i += chunk) {
            groups.push({
                title: i === 0 ? 'Core Competencies' : 'Additional Skills',
                items: comps.slice(i, i + chunk),
            });
        }
        return groups.slice(0, 3);
    }

    return body
        .split('\n')
        .filter(function (l) {
            return l.trim();
        })
        .map(function (line) {
            const parts = line.split(/\s*\|\s*/);
            if (parts.length >= 2) {
                return {
                    title: stripMd(parts[0].replace(/:$/, '')),
                    items: splitListLine(parts.slice(1).join(' | ')),
                };
            }
            const colon = line.indexOf(':');
            if (colon > 0) {
                return {
                    title: stripMd(line.slice(0, colon)),
                    items: splitListLine(line.slice(colon + 1)),
                };
            }
            return { title: 'Technical Skills', items: splitListLine(line) };
        })
        .filter(function (g) {
            return g.items.length > 0;
        });
}

function shortRoleTitle(role) {
    if (!role) return 'Data & Analytics Leader';
    const cleaned = role.replace(/\([^)]*\)/g, '').replace(/Job ID.+/i, '').trim();
    if (cleaned.length <= 48) return cleaned;
    return cleaned.slice(0, 45) + '…';
}

function buildHighlights(competencies) {
    return competencies.slice(0, 4).map(function (item) {
        return { label: item };
    });
}

function buildContact(employmentType, email, role, employer) {
    if (employmentType === 'contract') {
        return {
            label: '06 / Hire',
            title: 'Available for Contract Engagements',
            intro:
                'Open to contract roles through agencies and direct clients. Based in Illinois; available for remote and hybrid engagements.',
            engagementPills: ['Contract', 'Remote', 'Defined Deliverables'],
            valueItems: [
                {
                    label: 'Fast ramp',
                    body: 'Deep domain experience across regulated enterprise environments',
                },
                {
                    label: 'Scoped delivery',
                    body: 'Milestone-driven work with documented handoffs',
                },
                {
                    label: 'Independent execution',
                    body: 'Self-directed within matrix teams across finance, IT, and compliance',
                },
                {
                    label: 'Audit-ready',
                    body: 'Governance-aligned documentation and knowledge transfer',
                },
            ],
            email: email,
        };
    }
    return {
        label: '06 / Contact',
        title: "Let's Connect",
        intro: employer
            ? 'Interested in the ' + shortRoleTitle(role) + ' opportunity with ' + employer + '.'
            : 'Open to senior leadership roles in data, analytics, and AI.',
        email: email,
    };
}

function parseResumeToProfile(markdown, opts) {
    opts = opts || {};
    const text = String(markdown);
    const slug = opts.slug;
    if (!slug || !PROFILE_SLUG_RE.test(slug)) {
        throw new Error('Invalid or missing profile slug');
    }

    const metadata = extractMetadata(text);
    const accessCode = opts.accessCode || extractAccessCode(text);
    const employmentType = opts.employmentType || detectEmploymentType(text);
    const tagline = extractTagline(text);
    const summary = parseSummary(text);
    const competencies = parseCompetencies(text);
    const experienceParsed = parseExperienceItems(text, employmentType);
    const experienceItems = experienceParsed.items;
    const experienceIntro = experienceParsed.intro;
    const skillGroups = parseSkillGroups(text);
    const email = extractEmail(text);
    const role = metadata.role || 'Data & Analytics Leader';
    const employer = metadata.employer || metadata.agency || '';
    const typingPhrases = tagline
        ? tagline.split(/\s*\|\s*/).map(stripMd).filter(Boolean).slice(0, 5)
        : ['Data & Analytics', 'MSE, FLMI'];

    const roleShort = shortRoleTitle(role);
    const isUat =
        /uat|user acceptance/i.test(role + ' ' + tagline + ' ' + summary) ||
        slug.includes('uat');

    const profile = {
        profileVersion: 1,
        slug: slug,
        accessCode: accessCode || '',
        employmentType: employmentType,
        meta: {
            title: 'Jonathan Brownstein — ' + roleShort,
            description: summary.slice(0, 220),
        },
        hero: {
            badge:
                employmentType === 'contract'
                    ? roleShort + ' · Contract'
                    : roleShort,
            typingPhrases: typingPhrases,
            description: summary,
            primaryCta: employmentType === 'contract' ? 'Discuss This Role' : 'Get In Touch',
            secondaryCta:
                employmentType === 'contract' ? 'View Delivery Record' : 'View Experience',
        },
        highlights: buildHighlights(competencies),
        experience: {
            title: employmentType === 'contract' ? 'Delivery Record' : 'Professional Experience',
            intro: experienceIntro || undefined,
            items: experienceItems,
        },
        skills: {
            title: 'Skills & Expertise',
            groups: skillGroups.length
                ? skillGroups
                : [{ title: 'Core Competencies', items: competencies.slice(0, 12) }],
        },
        sections: {
            projects: { visible: !isUat },
            education: { visible: true },
        },
        contact: buildContact(employmentType, email, role, employer),
    };

    return profile;
}

function folderToSlug(folderName) {
    return folderName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 48);
}

module.exports = {
    PROFILE_SLUG_RE,
    parseResumeToProfile,
    extractAccessCode,
    detectEmploymentType,
    folderToSlug,
    stripMd,
};
