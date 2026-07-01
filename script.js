// ============================================
// ACCESS GATE + PRELOADER BOOTSTRAP
// ============================================
(function initAccessGateAndPreloader() {
    const STORAGE_KEY = 'portfolio_unlocked';
    const EMPLOYMENT_TYPE_KEY = 'portfolio_employment_type';
    const PROFILE_SLUG_KEY = 'portfolio_profile_slug';
    const EMPLOYMENT_FULL_TIME = 'full_time';
    const EMPLOYMENT_CONTRACT = 'contract';
    /** Deployed API used when /api is missing on localhost (static preview). */
    const GATE_PRODUCTION_API_BASE = 'https://www.jonathansbrownstein.com/api';
    const gateApiBaseMetaEl = document.querySelector('meta[name="gate-api-base"]');
    const gateApiBaseMetaContent =
        gateApiBaseMetaEl && gateApiBaseMetaEl.getAttribute('content')
            ? gateApiBaseMetaEl.getAttribute('content').trim()
            : '';
    const API_BASE_FROM_META = gateApiBaseMetaContent.length > 0;
    const API_BASE = API_BASE_FROM_META
        ? gateApiBaseMetaContent.replace(/\/+$/, '')
        : '/api';
    /** API host that served the session challenge (must match verify/request POSTs). */
    let gateActiveApiBase = API_BASE;
    /** Must match lib/gate-backend.js MIN_CODE_LEN */
    const MIN_GATE_CODE_LEN = 3;
    function normalizeEmploymentType(value) {
        return value === EMPLOYMENT_CONTRACT ? EMPLOYMENT_CONTRACT : EMPLOYMENT_FULL_TIME;
    }

    function persistEmploymentType(type) {
        try {
            sessionStorage.setItem(EMPLOYMENT_TYPE_KEY, normalizeEmploymentType(type));
        } catch (e) {}
    }

    function readStoredEmploymentType() {
        try {
            return normalizeEmploymentType(sessionStorage.getItem(EMPLOYMENT_TYPE_KEY));
        } catch (e) {
            return EMPLOYMENT_FULL_TIME;
        }
    }

    const EMPLOYMENT_CTAS = {
        full_time: {
            primary: 'Get In Touch',
            secondary: 'View Experience',
            nav: 'Contact',
        },
        contract: {
            primary: 'Discuss a Contract Role',
            secondary: 'View Delivery Record',
            nav: 'Hire',
        },
    };

    function dedupeHeroButtons() {
        var container = document.querySelector('.hero-buttons');
        if (!container) return;

        var buttons = Array.prototype.slice.call(container.querySelectorAll('a.btn, button.btn'));
        if (buttons.length <= 2) return;

        var primary =
            document.getElementById('hero-primary-cta') ||
            document.getElementById('profile-hero-primary-cta') ||
            container.querySelector('a.btn-primary');
        var secondary =
            document.getElementById('hero-secondary-cta') ||
            document.getElementById('profile-hero-secondary-cta') ||
            container.querySelector('a.btn-secondary');

        buttons.forEach(function (btn) {
            if (btn !== primary && btn !== secondary) btn.remove();
        });
    }

    function setHeroCtas(primaryLabel, secondaryLabel) {
        dedupeHeroButtons();
        const primary = document.getElementById('hero-primary-cta-label');
        const secondary = document.getElementById('hero-secondary-cta-label');
        if (primary && primaryLabel) primary.textContent = primaryLabel;
        if (secondary && secondaryLabel) secondary.textContent = secondaryLabel;
    }

    function setNavCta(label) {
        const nav = document.getElementById('nav-cta-label');
        if (nav && label) nav.textContent = label;
    }

    function applyEmploymentVariant(type) {
        const normalized = normalizeEmploymentType(type);
        document.documentElement.setAttribute('data-employment-type', normalized);
        persistEmploymentType(normalized);
        updateEmploymentMeta(normalized);
        if (document.documentElement.getAttribute('data-profile-mode') !== 'tailored') {
            const ctas = EMPLOYMENT_CTAS[normalized] || EMPLOYMENT_CTAS.full_time;
            setHeroCtas(ctas.primary, ctas.secondary);
            setNavCta(ctas.nav);
        }
        document.dispatchEvent(
            new CustomEvent('portfolio:employment-type', { detail: { type: normalized } }),
        );
    }

    const EMPLOYMENT_META = {
        full_time: {
            title: 'Jonathan Brownstein — Senior Data & Analytics Leader',
            description:
                'Senior data & analytics leader with 15+ years building enterprise-scale, audit-ready analytics in regulated industries.',
        },
        contract: {
            title: 'Jonathan Brownstein — Senior Contract Data & Analytics Specialist',
            description:
                'Senior contract data & analytics specialist for regulated industries. Fast ramp, defined deliverables, production handoffs.',
        },
    };

    function updateEmploymentMeta(type) {
        const meta = EMPLOYMENT_META[type] || EMPLOYMENT_META.full_time;
        document.title = meta.title;
        const descEl = document.querySelector('meta[name="description"]');
        if (descEl) {
            descEl.setAttribute('content', meta.description);
        }
        const titleEl = document.querySelector('meta[name="title"]');
        if (titleEl) {
            titleEl.setAttribute('content', meta.title);
        }
        const ogTitle = document.querySelector('meta[property="og:title"]');
        if (ogTitle) {
            ogTitle.setAttribute('content', meta.title);
        }
        const ogDesc = document.querySelector('meta[property="og:description"]');
        if (ogDesc) {
            ogDesc.setAttribute('content', meta.description);
        }
        const twTitle = document.querySelector('meta[name="twitter:title"]');
        if (twTitle) {
            twTitle.setAttribute('content', meta.title);
        }
        const twDesc = document.querySelector('meta[name="twitter:description"]');
        if (twDesc) {
            twDesc.setAttribute('content', meta.description);
        }
    }

    function persistProfileSlug(slug) {
        try {
            if (slug) {
                sessionStorage.setItem(PROFILE_SLUG_KEY, slug);
            } else {
                sessionStorage.removeItem(PROFILE_SLUG_KEY);
            }
        } catch (e) {}
    }

    function readStoredProfileSlug() {
        try {
            return sessionStorage.getItem(PROFILE_SLUG_KEY) || null;
        } catch (e) {
            return null;
        }
    }

    function updateProfileMeta(meta) {
        if (!meta) return;
        if (meta.title) {
            document.title = meta.title;
        }
        const pairs = [
            ['meta[name="description"]', meta.description],
            ['meta[name="title"]', meta.title],
            ['meta[property="og:title"]', meta.title],
            ['meta[property="og:description"]', meta.description],
            ['meta[name="twitter:title"]', meta.title],
            ['meta[name="twitter:description"]', meta.description],
        ];
        pairs.forEach(function (pair) {
            const el = document.querySelector(pair[0]);
            if (el && pair[1]) {
                el.setAttribute('content', pair[1]);
            }
        });
    }

    function profileEscapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderProfileExperienceItem(item) {
        const context = item.context
            ? '<span class="role-focus">' + profileEscapeHtml(item.context) + '</span>'
            : '';
        const dates = item.dates
            ? '<span class="date">' +
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' +
              '<rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect>' +
              '<line x1="16" y1="2" x2="16" y2="6"></line>' +
              '<line x1="8" y1="2" x2="8" y2="6"></line>' +
              '<line x1="3" y1="10" x2="21" y2="10"></line></svg> ' +
              profileEscapeHtml(item.dates) +
              '</span>'
            : '';
        const org = item.organization
            ? '<span class="company">' +
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' +
              '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>' +
              '<polyline points="9 22 9 12 15 12 15 22"></polyline></svg> ' +
              profileEscapeHtml(item.organization) +
              '</span>'
            : '';
        const intro = item.intro
            ? '<p class="timeline-intro">' + profileEscapeHtml(item.intro) + '</p>'
            : '';

        function renderBullets(bullets) {
            return (bullets || [])
                .map(function (b) {
                    return '<li>' + profileEscapeHtml(b) + '</li>';
                })
                .join('');
        }

        let achievements = '';
        if (item.subsections && item.subsections.length) {
            achievements = item.subsections
                .map(function (section) {
                    return (
                        '<p class="timeline-subsection-title">' +
                        profileEscapeHtml(section.title) +
                        '</p>' +
                        '<ul class="achievements">' +
                        renderBullets(section.bullets) +
                        '</ul>'
                    );
                })
                .join('');
        } else if (item.bullets && item.bullets.length) {
            achievements = '<ul class="achievements">' + renderBullets(item.bullets) + '</ul>';
        }

        return (
            '<div class="timeline-item reveal">' +
            '<div class="timeline-marker"><span class="marker-ring"></span></div>' +
            '<div class="timeline-content glass-card">' +
            '<div class="timeline-header">' +
            '<div class="timeline-title-group">' +
            '<h3>' +
            profileEscapeHtml(item.title) +
            '</h3>' +
            context +
            '</div>' +
            '<div class="timeline-meta">' +
            org +
            dates +
            '</div></div>' +
            intro +
            achievements +
            '</div></div>'
        );
    }

    function applySiteProfile(profile) {
        if (!profile || !profile.slug) return;

        document.documentElement.setAttribute('data-profile-mode', 'tailored');
        document.documentElement.setAttribute('data-site-profile', profile.slug);
        persistProfileSlug(profile.slug);

        if (profile.meta) {
            updateProfileMeta(profile.meta);
        }

        document.querySelectorAll('[data-site-fallback]').forEach(function (el) {
            el.hidden = true;
        });

        if (profile.hero) {
            const badge = document.getElementById('profile-hero-badge');
            if (badge && profile.hero.badge) {
                badge.textContent = profile.hero.badge;
                badge.hidden = false;
            }
            const desc = document.getElementById('profile-hero-description');
            if (desc && profile.hero.description) {
                desc.textContent = profile.hero.description;
                desc.hidden = false;
            }
            if (profile.hero.primaryCta || profile.hero.secondaryCta) {
                setHeroCtas(profile.hero.primaryCta, profile.hero.secondaryCta);
            }
            const navLabel =
                profile.employmentType === 'contract' || profile.hero.primaryCta === 'Discuss This Role'
                    ? 'Hire'
                    : 'Contact';
            setNavCta(navLabel);
            if (profile.hero.typingPhrases && profile.hero.typingPhrases.length) {
                document.dispatchEvent(
                    new CustomEvent('portfolio:profile-typing', {
                        detail: { phrases: profile.hero.typingPhrases },
                    }),
                );
            }
        }

        if (profile.highlights && profile.highlights.length) {
            const grid = document.getElementById('profile-highlights');
            if (grid) {
                grid.innerHTML = profile.highlights
                    .map(function (item) {
                        const label = item.label || item.value || '';
                        const value =
                            item.value && item.label && item.label.indexOf(item.value.replace(/…$/, '')) !== 0
                                ? item.value
                                : '';
                        return (
                            '<div class="highlight-item reveal">' +
                            '<div class="highlight-item-icon">' +
                            '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' +
                            '<path d="M9 12l2 2 4-4"></path>' +
                            '<path d="M21 12c0 4.97-4.03 9-9 9s-9-4.03-9-9 4.03-9 9-9c2.39 0 4.68.94 6.36 2.64"></path>' +
                            '</svg></div>' +
                            '<div class="highlight-item-text">' +
                            (value
                                ? '<span class="highlight-item-value">' +
                                  profileEscapeHtml(value) +
                                  '</span>'
                                : '') +
                            '<span class="highlight-item-label' +
                            (value ? '' : ' highlight-item-label--solo') +
                            '">' +
                            profileEscapeHtml(label) +
                            '</span></div></div>'
                        );
                    })
                    .join('');
                grid.hidden = false;
            }
        }

        const aboutSection = document.getElementById('about');
        const aboutNav = document.querySelector('.nav-links a[data-section="about"]');
        if (aboutSection) aboutSection.hidden = true;
        if (aboutNav && aboutNav.parentElement) aboutNav.parentElement.hidden = true;

        if (profile.experience) {
            const expTitle = document.getElementById('profile-experience-title');
            if (expTitle && profile.experience.title) {
                expTitle.textContent = profile.experience.title;
                expTitle.hidden = false;
            }
            const expIntro = document.getElementById('profile-experience-intro');
            if (expIntro) {
                expIntro.hidden = true;
            }
            const timeline = document.getElementById('profile-experience');
            if (timeline && profile.experience.items) {
                timeline.innerHTML = profile.experience.items
                    .map(renderProfileExperienceItem)
                    .join('');
                timeline.hidden = false;
            }
        }

        if (profile.skills) {
            const skillsTitle = document.getElementById('profile-skills-title');
            if (skillsTitle && profile.skills.title) {
                skillsTitle.textContent = profile.skills.title;
                skillsTitle.hidden = false;
            }
            const skillsIntro = document.getElementById('profile-skills-intro');
            if (skillsIntro) {
                skillsIntro.hidden = true;
            }
            const grid = document.getElementById('profile-skills');
            if (grid && profile.skills.groups) {
                grid.innerHTML = profile.skills.groups
                    .map(function (group) {
                        const items = (group.items || [])
                            .map(function (item) {
                                return '<li>' + profileEscapeHtml(item) + '</li>';
                            })
                            .join('');
                        return (
                            '<div class="skill-category glass-card reveal">' +
                            '<h3>' +
                            profileEscapeHtml(group.title) +
                            '</h3>' +
                            '<ul class="skill-list">' +
                            items +
                            '</ul></div>'
                        );
                    })
                    .join('');
                grid.hidden = false;
            }
        }

        if (profile.sections) {
            if (profile.sections.projects && profile.sections.projects.visible === false) {
                const projects = document.getElementById('projects');
                if (projects) projects.hidden = true;
            }
            if (profile.sections.education && profile.sections.education.visible === false) {
                const education = document.getElementById('education');
                if (education) education.hidden = true;
            }
        }

        if (profile.contact) {
            const contactLabel = document.getElementById('profile-contact-label');
            if (contactLabel && profile.contact.label) {
                contactLabel.textContent = profile.contact.label;
            }
            const contactTitle = document.getElementById('profile-contact-title');
            if (contactTitle && profile.contact.title) {
                contactTitle.textContent = profile.contact.title;
            }
            const contactIntro = document.getElementById('profile-contact-intro');
            if (contactIntro && profile.contact.intro) {
                contactIntro.textContent = profile.contact.intro;
            }
            const advisory = document.getElementById('profile-contact-advisory');
            if (advisory && profile.contact.valueItems && profile.contact.valueItems.length) {
                let html = '';
                html +=
                    '<div class="contractor-value-grid" aria-label="What hiring managers get">' +
                    profile.contact.valueItems
                        .map(function (item) {
                            return (
                                '<div class="contractor-value-item glass-card">' +
                                '<span class="contractor-value-label">' +
                                profileEscapeHtml(item.label) +
                                '</span><p>' +
                                profileEscapeHtml(item.body) +
                                '</p></div>'
                            );
                        })
                        .join('') +
                    '</div>';
                if (profile.contact.engagementPills && profile.contact.engagementPills.length) {
                    html +=
                        '<div class="engagement-types" aria-label="Engagement types">' +
                        profile.contact.engagementPills
                            .map(function (pill) {
                                return (
                                    '<span class="engagement-type-pill">' +
                                    profileEscapeHtml(pill) +
                                    '</span>'
                                );
                            })
                            .join('') +
                        '</div>';
                }
                advisory.innerHTML = html;
                advisory.hidden = false;
            }
            const contactBlock = document.getElementById('profile-contact-block');
            if (contactBlock) contactBlock.hidden = false;
            if (profile.contact.email) {
                const emailCard = document.querySelector('#contact .contact-card[href^="mailto:"]');
                if (emailCard) {
                    emailCard.href = 'mailto:' + profile.contact.email;
                    const valueEl = emailCard.querySelector('.contact-value');
                    if (valueEl) valueEl.textContent = profile.contact.email;
                }
            }
        }

        dedupeHeroButtons();
    }

    async function fetchSiteProfile(slug) {
        if (!slug) return null;
        try {
            var res = await gateFetchJson('/site-profile', { method: 'GET' }, gateActiveApiBase);
            if (
                shouldFallbackToProductionApi() &&
                gateActiveApiBase !== GATE_PRODUCTION_API_BASE &&
                (res.status === 404 || res.status === 502 || res.status === 503)
            ) {
                res = await gateFetchJson('/site-profile', { method: 'GET' }, GATE_PRODUCTION_API_BASE);
            }
            if (res.status === 200 && res.body && res.body.ok && res.body.profile) {
                return res.body.profile;
            }
        } catch (e) {}
        return null;
    }

    async function hydrateSiteProfile(profileSlug, employmentType) {
        if (!profileSlug) return;
        const profile = await fetchSiteProfile(profileSlug);
        if (profile) {
            applySiteProfile(profile);
            applyEmploymentVariant(profile.employmentType || employmentType || EMPLOYMENT_CONTRACT);
        }
    }

    /** JPMC Quant Analytics interview access code — minimal demo launcher for interviewers. */
    const DEMO_INVITE_ACCESS_CODE = 'JPMC210741105';

    let gateApiReady = false;
    let serverBlockUntil = 0;
    let gateThrottleUiTimer = null;
    let gateThrottleCountdownId = null;

    let currentChallenge = null;
    let powSolution = null;
    let powWorker = null;
    let clientFingerprint = null;

    // -- PoW Web Worker (inline via Blob) --
    var POW_WORKER_SRC = [
        'self.onmessage = async function(e) {',
        '  var prefix = e.data.prefix;',
        '  var difficulty = e.data.difficulty;',
        '  var nonce = 0;',
        '  while (true) {',
        '    var candidate = prefix + nonce.toString(16);',
        '    var buf = new Uint8Array(candidate.length);',
        '    for (var i = 0; i < candidate.length; i++) buf[i] = candidate.charCodeAt(i);',
        '    var hash = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));',
        '    var ok = true;',
        '    var fullBytes = Math.floor(difficulty / 8);',
        '    var remainBits = difficulty % 8;',
        '    for (var j = 0; j < fullBytes; j++) { if (hash[j] !== 0) { ok = false; break; } }',
        '    if (ok && remainBits > 0) {',
        '      var mask = 0xff << (8 - remainBits);',
        '      if ((hash[fullBytes] & mask) !== 0) ok = false;',
        '    }',
        '    if (ok) { self.postMessage({ nonce: nonce.toString(16) }); return; }',
        '    nonce++;',
        '    if (nonce % 10000 === 0) await new Promise(function(r) { setTimeout(r, 0); });',
        '  }',
        '};',
    ].join('\n');

    function startPowSolver(challenge) {
        if (!challenge || !challenge.prefix || !challenge.difficulty) return;
        powSolution = null;
        currentChallenge = challenge;
        if (powWorker) {
            powWorker.terminate();
        }
        try {
            var blob = new Blob([POW_WORKER_SRC], { type: 'application/javascript' });
            var url = URL.createObjectURL(blob);
            powWorker = new Worker(url);
            URL.revokeObjectURL(url);
            powWorker.onmessage = function (ev) {
                powSolution = ev.data.nonce;
            };
            powWorker.postMessage({ prefix: challenge.prefix, difficulty: challenge.difficulty });
        } catch (e) {
            powWorker = null;
        }
    }

    function waitForPowSolution(timeoutMs) {
        if (powSolution) return Promise.resolve(powSolution);
        var elapsed = 0;
        var interval = 50;
        return new Promise(function (resolve) {
            var check = function () {
                if (powSolution) return resolve(powSolution);
                elapsed += interval;
                if (elapsed >= timeoutMs) return resolve(null);
                setTimeout(check, interval);
            };
            setTimeout(check, interval);
        });
    }

    // -- Browser Fingerprint --
    function collectFingerprint() {
        if (clientFingerprint) return Promise.resolve(clientFingerprint);
        var signals = [];
        signals.push('sw=' + screen.width);
        signals.push('sh=' + screen.height);
        signals.push('dpr=' + (window.devicePixelRatio || 1));
        signals.push('lang=' + (navigator.language || ''));
        signals.push('plat=' + (navigator.platform || ''));
        signals.push('tz=' + new Date().getTimezoneOffset());
        signals.push('cores=' + (navigator.hardwareConcurrency || 0));
        try {
            var c = document.createElement('canvas');
            c.width = 200;
            c.height = 50;
            var ctx = c.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(50, 0, 100, 25);
                ctx.fillStyle = '#069';
                ctx.fillText('fp:canvas', 2, 15);
                ctx.fillStyle = 'rgba(102,204,0,0.7)';
                ctx.fillText('fp:canvas', 4, 17);
                signals.push('cv=' + c.toDataURL());
            }
        } catch (e) {}
        try {
            var gl =
                document.createElement('canvas').getContext('webgl') ||
                document.createElement('canvas').getContext('experimental-webgl');
            if (gl) {
                var dbg = gl.getExtension('WEBGL_debug_renderer_info');
                if (dbg) {
                    signals.push('glr=' + gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
                }
            }
        } catch (e) {}
        var raw = signals.join('|');
        if (!crypto.subtle || !crypto.subtle.digest) {
            clientFingerprint = raw.slice(0, 64);
            return Promise.resolve(clientFingerprint);
        }
        var buf = new TextEncoder().encode(raw);
        return crypto.subtle.digest('SHA-256', buf).then(function (hashBuf) {
            var arr = new Uint8Array(hashBuf);
            var hex = '';
            for (var i = 0; i < arr.length; i++) {
                hex += ('0' + arr[i].toString(16)).slice(-2);
            }
            clientFingerprint = hex;
            return hex;
        });
    }

    function normalizeGateCode(s) {
        return String(s).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    }

    function isDemoInviteAccessCode(code) {
        return normalizeGateCode(code) === DEMO_INVITE_ACCESS_CODE;
    }

    const DEMO_ACCESS_FLAG_KEY = 'portfolio_demo_access_granted';

    function markDemoAccess() {
        try { localStorage.setItem(DEMO_ACCESS_FLAG_KEY, '1'); } catch (e) {}
    }

    function hasDemoAccess() {
        try { return localStorage.getItem(DEMO_ACCESS_FLAG_KEY) === '1'; } catch (e) { return false; }
    }

    const CAPACITY_WELCOME_ENTRY_KEY = 'capacity-workforce-welcome-entry';

    function markCapacityWorkforceWelcomeEntry() {
        try { sessionStorage.setItem(CAPACITY_WELCOME_ENTRY_KEY, '1'); } catch (e) {}
    }

    document.addEventListener('click', function (ev) {
        const link = ev.target.closest('a[href*="capacity-workforce"]');
        if (link) markCapacityWorkforceWelcomeEntry();
    }, true);

    function scheduleDemoInvitePopup() {
        window.setTimeout(showDemoInvitePopup, 950);
    }

    function injectDemoAccessButton() {
        if (document.getElementById('demo-access-fab')) return;
        const fab = document.createElement('a');
        fab.id = 'demo-access-fab';
        fab.className = 'demo-access-fab';
        fab.href = '/demos/capacity-workforce/';
        fab.target = '_blank';
        fab.rel = 'noopener noreferrer';
        fab.setAttribute('aria-label', 'Open Capacity & Workforce Modeling Lab Dashboard sample');
        fab.innerHTML =
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>' +
            '<polyline points="15 3 21 3 21 9"></polyline>' +
            '<line x1="10" y1="14" x2="21" y2="3"></line>' +
            '</svg>' +
            '<span>Open demo</span>';
        document.body.appendChild(fab);
        requestAnimationFrame(function () { fab.classList.add('demo-access-fab--visible'); });
    }

    function showDemoInvitePopup() {
        if (document.getElementById('demo-invite-modal')) return;

        const overlay = document.createElement('div');
        overlay.id = 'demo-invite-modal';
        overlay.className = 'demo-invite-modal';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-labelledby', 'demo-invite-title');

        overlay.innerHTML =
            '<div class="demo-invite-backdrop" data-demo-invite-dismiss aria-hidden="true"></div>' +
            '<div class="demo-invite-card">' +
            '<button type="button" class="demo-invite-close" aria-label="Close" data-demo-invite-dismiss>' +
            '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' +
            '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>' +
            '</svg></button>' +
            '<div class="demo-invite-header">' +
            '<div class="demo-invite-icon" aria-hidden="true">' +
            '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M3 3v18h18"></path><path d="M18 17V9"></path><path d="M13 17V5"></path><path d="M8 17v-3"></path>' +
            '</svg></div>' +
            '<p class="demo-invite-eyebrow">Portfolio sample</p>' +
            '</div>' +
            '<p class="demo-invite-lead"><strong>Jonathan Brownstein</strong> invites you to view a sample</p>' +
            '<h2 id="demo-invite-title" class="demo-invite-title">Capacity &amp; Workforce Modeling Lab Dashboard</h2>' +
            '<div class="demo-invite-actions">' +
            '<a href="/demos/capacity-workforce/" class="btn btn-primary" target="_blank" rel="noopener noreferrer">' +
            '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' +
            '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>' +
            '<polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line>' +
            '</svg>View dashboard</a>' +
            '<button type="button" class="btn btn-secondary" data-demo-invite-dismiss>Not now</button>' +
            '</div>' +
            '</div>';

        function closeDemoInvitePopup() {
            overlay.classList.add('demo-invite-modal--exiting');
            overlay.addEventListener('transitionend', function onExit(ev) {
                if (ev.target !== overlay || ev.propertyName !== 'opacity') return;
                overlay.removeEventListener('transitionend', onExit);
                overlay.remove();
                if (!document.documentElement.classList.contains('access-locked')) {
                    document.body.style.overflow = '';
                }
            });
        }

        overlay.addEventListener('click', function (ev) {
            if (ev.target.closest('[data-demo-invite-dismiss]')) {
                closeDemoInvitePopup();
            }
        });

        overlay.addEventListener('keydown', function (ev) {
            if (ev.key === 'Escape') {
                ev.preventDefault();
                closeDemoInvitePopup();
            }
        });

        document.body.appendChild(overlay);
        document.body.style.overflow = 'hidden';

        window.requestAnimationFrame(function () {
            overlay.classList.add('demo-invite-modal--open');
            const primary = overlay.querySelector('.btn-primary');
            if (primary) primary.focus();
        });
    }

    function gateIsPlausibleGuess(phrase) {
        return normalizeGateCode(phrase).length >= MIN_GATE_CODE_LEN;
    }

    async function gateFetchJson(path, options, baseOverride, timeoutMs) {
        const baseUrl = baseOverride != null ? baseOverride : API_BASE;
        const opts = Object.assign({ method: 'GET', credentials: 'include' }, options);
        const waitMs = typeof timeoutMs === 'number' && timeoutMs > 0 ? timeoutMs : 20000;
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        let timer = null;
        if (controller) {
            opts.signal = controller.signal;
            timer = setTimeout(function () {
                controller.abort();
            }, waitMs);
        }
        let r;
        try {
            r = await fetch(baseUrl + path, opts);
        } catch (e) {
            return {
                ok: false,
                status: 0,
                body: null,
                retryAfter: 0,
                isJson: false,
                fetchError: true,
                timedOut: !!(controller && e && e.name === 'AbortError'),
            };
        } finally {
            if (timer) {
                clearTimeout(timer);
            }
        }
        const ct = r.headers.get('content-type') || '';
        const isJson = ct.indexOf('application/json') !== -1;
        let body = null;
        if (isJson) {
            try {
                body = await r.json();
            } catch (e) {}
        }
        const ra = parseInt(r.headers.get('retry-after') || '0', 10) || 0;
        return { ok: r.ok, status: r.status, body: body, retryAfter: ra, isJson: isJson };
    }

    function gateApplyServerBlock(body, retryAfterHeader) {
        let sec = 0;
        if (body && typeof body.retryAfterSec === 'number' && body.retryAfterSec > 0) {
            sec = body.retryAfterSec;
        } else if (retryAfterHeader > 0) {
            sec = retryAfterHeader;
        }
        if (sec > 0) {
            serverBlockUntil = Date.now() + sec * 1000;
        }
    }

    function gateClearServerBlock() {
        serverBlockUntil = 0;
    }

    function gateGetBlocking() {
        const now = Date.now();
        if (serverBlockUntil > now) {
            const ms = serverBlockUntil - now;
            return {
                kind: ms > 120000 ? 'locked' : 'cooldown',
                until: serverBlockUntil,
            };
        }
        return null;
    }

    function isLocalDevPreviewHost() {
        if (window.location.protocol === 'file:') {
            return true;
        }
        const h = window.location.hostname;
        return h === 'localhost' || h === '127.0.0.1';
    }

    function shouldFallbackToProductionApi() {
        return isLocalDevPreviewHost() && !API_BASE_FROM_META;
    }

    function accessStatusNeedsRetry(res) {
        if (res.fetchError) {
            return true;
        }
        if (!res.isJson) {
            return true;
        }
        if (!res.body || typeof res.body.ready !== 'boolean') {
            return true;
        }
        if (res.body.ready === false) {
            return true;
        }
        return false;
    }

    function gateFetchNeedsRetryForPost(res) {
        if (res.fetchError) {
            return true;
        }
        if (res.status === 404 || res.status === 502) {
            return true;
        }
        if (!res.isJson && res.status >= 400) {
            return true;
        }
        return false;
    }

    async function gateLoadSession() {
        try {
            var fpPromise = collectFingerprint();
            var res = await gateFetchJson('/access-status', { method: 'GET' }, API_BASE);
            var usedBase = API_BASE;
            if (shouldFallbackToProductionApi() && accessStatusNeedsRetry(res)) {
                res = await gateFetchJson('/access-status', { method: 'GET' }, GATE_PRODUCTION_API_BASE);
                usedBase = GATE_PRODUCTION_API_BASE;
            }
            if (res.status === 429) {
                // Legacy servers returned 429 when status checks were over cap.
                // Treat as ready so verify-access can still run; PoW challenge
                // will be issued on the next verify attempt if missing here.
                gateActiveApiBase = usedBase;
                await fpPromise;
                return { ready: true, unlocked: false };
            }
            if (!res.body || typeof res.body.ready !== 'boolean') {
                gateActiveApiBase = API_BASE;
                return { ready: false, unlocked: false };
            }
            gateActiveApiBase = usedBase;
            gateApiReady = !!res.body.ready;
            if (gateApiReady && res.body.blockedUntilSec > 0) {
                serverBlockUntil = Date.now() + res.body.blockedUntilSec * 1000;
            }
            if (res.body.challenge) {
                startPowSolver(res.body.challenge);
            }
            await fpPromise;
            return {
                ready: gateApiReady,
                unlocked: !!res.body.unlocked,
                employmentType: res.body.employmentType
                    ? normalizeEmploymentType(res.body.employmentType)
                    : null,
                profileSlug: res.body.profileSlug || null,
            };
        } catch (e) {
            gateActiveApiBase = API_BASE;
            return { ready: false, unlocked: false };
        }
    }

    async function gateVerifyCode(code) {
        var nonce = await waitForPowSolution(60000);
        var honeypotEl = document.getElementById('access-code-confirm');
        var payload = {
            code: code,
            challengeId: currentChallenge && currentChallenge.id != null
                ? String(currentChallenge.id)
                : null,
            nonce: nonce,
            fingerprint: clientFingerprint,
        };
        if (honeypotEl && honeypotEl.value) {
            payload.accessCodeConfirm = honeypotEl.value;
        }
        var verifyOpts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        };
        var res = await gateFetchJson('/verify-access', verifyOpts, gateActiveApiBase);
        if (
            shouldFallbackToProductionApi() &&
            gateActiveApiBase !== GATE_PRODUCTION_API_BASE &&
            gateFetchNeedsRetryForPost(res)
        ) {
            res = await gateFetchJson('/verify-access', verifyOpts, GATE_PRODUCTION_API_BASE);
        }
        if (res.body && res.body.challenge) {
            startPowSolver(res.body.challenge);
        }
        if (res.status === 503) {
            return {
                ok: false,
                unavailable: true,
                serviceReason: res.body && res.body.reason,
            };
        }
        if (res.status === 429) {
            gateApplyServerBlock(res.body, res.retryAfter);
            return { ok: false, throttled: true };
        }
        if (res.status === 200 && res.body && res.body.ok) {
            gateClearServerBlock();
            return {
                ok: true,
                employmentType: res.body.employmentType
                    ? normalizeEmploymentType(res.body.employmentType)
                    : EMPLOYMENT_FULL_TIME,
                profileSlug: res.body.profileSlug || null,
            };
        }
        if (res.status === 400 && res.body && res.body.error === 'challenge_failed') {
            return { ok: false, challengeFailed: true };
        }
        if (res.status === 401) {
            return { ok: false };
        }
        return { ok: false, unavailable: true };
    }

    function gateFormatRemaining(ms) {
        if (ms <= 0) {
            return 'a moment';
        }
        const sec = Math.ceil(ms / 1000);
        if (sec < 60) {
            return sec + (sec === 1 ? ' second' : ' seconds');
        }
        const min = Math.ceil(sec / 60);
        return min + (min === 1 ? ' minute' : ' minutes');
    }

    function gateEscapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function gateRenderMessage(el, opts) {
        if (!el) return;
        var title = opts && opts.title ? String(opts.title) : '';
        var detail = opts && opts.detail ? String(opts.detail) : '';
        if (!title && !detail) {
            el.innerHTML = '';
            el.setAttribute('hidden', '');
            el.className = 'access-gate-message';
            return;
        }
        var html = '';
        if (title) {
            html +=
                '<p class="access-gate-message-title">' + gateEscapeHtml(title) + '</p>';
        }
        if (detail) {
            html +=
                '<p class="access-gate-message-detail">' + gateEscapeHtml(detail) + '</p>';
        }
        el.innerHTML = html;
        el.removeAttribute('hidden');
        el.className = 'access-gate-message access-gate-message--' + (opts.kind || 'error');
    }

    function scheduleGateThrottleUiSync(syncFn, untilTs) {
        if (gateThrottleUiTimer) {
            clearTimeout(gateThrottleUiTimer);
            gateThrottleUiTimer = null;
        }
        const delay = Math.min(Math.max(0, untilTs - Date.now() + 150), 2147483647);
        gateThrottleUiTimer = setTimeout(function () {
            gateThrottleUiTimer = null;
            syncFn();
        }, delay);
    }

    function applyUnlockedDom(opts) {
        document.documentElement.classList.remove('access-locked');
        document.documentElement.classList.add('access-unlocked');
        document.body.style.overflow = '';
        dedupeHeroButtons();
        if (opts && opts.clearLoading) {
            document.documentElement.classList.remove('loading');
        }
    }

    const gateEl = document.getElementById('access-gate');
    let refreshGateReadyUi = null;

    function initGateForm() {
        const gate = gateEl;
        const form = document.getElementById('access-gate-form');
        const codeInput = document.getElementById('access-code-input');
        const msgEl = document.getElementById('access-gate-message');
        const hintEl = document.getElementById('access-gate-hint');
        const submitBtn = form ? form.querySelector('.access-gate-submit') : null;
        if (!form || !codeInput || !gate || !submitBtn) return;

        const focusBeforeGateEl = document.activeElement;
        const submitLabelEl = submitBtn.querySelector('.access-gate-submit-label');
        const submitTextTarget = submitLabelEl || submitBtn;
        const submitBtnDefaultText = submitTextTarget.textContent;
        const gateInner = form.closest('.access-gate-inner');
        if (gateInner && !gateInner.querySelector('.access-gate-progress')) {
            const bar = document.createElement('div');
            bar.className = 'access-gate-progress';
            bar.setAttribute('aria-hidden', 'true');
            gateInner.insertBefore(bar, gateInner.firstChild);
        }

        function clearGateThrottleCountdown() {
            if (gateThrottleCountdownId !== null) {
                clearInterval(gateThrottleCountdownId);
                gateThrottleCountdownId = null;
            }
        }

        function setFormVerifyBusy(busy) {
            form.setAttribute('aria-busy', busy ? 'true' : 'false');
            submitTextTarget.textContent = busy ? 'Checking…' : submitBtnDefaultText;
            gate.classList.toggle('access-gate--verifying', !!busy);
            if (busy) {
                setGateHint('Checking your code…');
            }
        }

        function getGateFocusableEls() {
            const nodes = gate.querySelectorAll(
                'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'
            );
            return Array.prototype.filter.call(nodes, function (el) {
                return el.tabIndex !== -1;
            });
        }

        function onGateTabTrap(e) {
            if (e.key !== 'Tab') return;
            const items = getGateFocusableEls();
            if (items.length === 0) return;
            const first = items[0];
            const last = items[items.length - 1];
            if (e.shiftKey) {
                if (document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                }
            } else if (document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }

        gate.addEventListener('keydown', onGateTabTrap);

        function getCode() {
            return codeInput.value;
        }

        function setGateHint(text) {
            if (!hintEl) return;
            if (text) {
                hintEl.textContent = text;
                hintEl.removeAttribute('hidden');
            } else {
                hintEl.textContent = '';
                hintEl.setAttribute('hidden', '');
            }
        }

        function clearGateMessage() {
            if (gate.dataset.gateThrottle === '1') {
                return;
            }
            gateRenderMessage(msgEl, null);
            codeInput.setAttribute('aria-invalid', 'false');
            gate.classList.remove('access-gate--error', 'access-gate--wait');
        }

        function showGateError(title, detail) {
            delete gate.dataset.gateThrottle;
            gateRenderMessage(msgEl, { kind: 'error', title: title, detail: detail || '' });
            codeInput.setAttribute('aria-invalid', 'true');
            gate.classList.add('access-gate--error');
            gate.classList.remove('access-gate--wait');
            void gate.offsetWidth;
            setTimeout(function () {
                gate.classList.remove('access-gate--error');
            }, 500);
        }

        function showGateWait(title, detail) {
            gateRenderMessage(msgEl, { kind: 'wait', title: title, detail: detail || '' });
            codeInput.setAttribute('aria-invalid', 'false');
            gate.classList.remove('access-gate--error');
            gate.classList.add('access-gate--wait');
        }

        codeInput.addEventListener('input', function () {
            clearGateMessage();
        });

        function syncGateThrottleUi() {
            if (gateThrottleUiTimer) {
                clearTimeout(gateThrottleUiTimer);
                gateThrottleUiTimer = null;
            }
            clearGateThrottleCountdown();
            const block = gateGetBlocking();
            gate.classList.remove('access-gate--locked', 'access-gate--cooldown');
            if (!block) {
                if (gate.dataset.gateThrottle === '1') {
                    gateRenderMessage(msgEl, null);
                    delete gate.dataset.gateThrottle;
                }
                gate.classList.remove('access-gate--wait');
                codeInput.disabled = false;
                submitBtn.disabled = false;
                setGateHint('');
                return;
            }
            gate.dataset.gateThrottle = '1';
            const msLeft = block.until - Date.now();
            const waitDetail = 'Try again in ' + gateFormatRemaining(msLeft) + '.';
            if (block.kind === 'locked') {
                gate.classList.add('access-gate--locked');
                showGateWait(
                    'Too many wrong tries',
                    'Wait a bit, then enter your code again. ' + waitDetail,
                );
                codeInput.disabled = true;
                submitBtn.disabled = true;
            } else {
                gate.classList.add('access-gate--cooldown');
                showGateWait(
                    'Wait a moment',
                    waitDetail,
                );
                codeInput.disabled = false;
                submitBtn.disabled = true;
            }
            setGateHint('');
            scheduleGateThrottleUiSync(syncGateThrottleUi, block.until);
            gateThrottleCountdownId = window.setInterval(function () {
                const b = gateGetBlocking();
                if (!b) {
                    clearGateThrottleCountdown();
                    syncGateThrottleUi();
                    return;
                }
                const left = b.until - Date.now();
                const tickDetail = 'Try again in ' + gateFormatRemaining(left) + '.';
                if (b.kind === 'locked') {
                    showGateWait(
                        'Too many wrong tries',
                        'Wait a bit, then enter your code again. ' + tickDetail,
                    );
                } else {
                    showGateWait('Wait a moment', tickDetail);
                }
            }, 1000);
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            clearGateMessage();
            if (gateGetBlocking()) {
                syncGateThrottleUi();
                return;
            }
            if (!gateApiReady) {
                showGateError(
                    'Can\u2019t load right now',
                    'Refresh the page or try again in a minute.',
                );
                return;
            }
            const code = normalizeGateCode(getCode());
            if (code.length < MIN_GATE_CODE_LEN) {
                showGateError(
                    'Enter your code',
                    'Check your email, or request access below.',
                );
                codeInput.focus();
                return;
            }
            submitBtn.disabled = true;
            setFormVerifyBusy(true);
            gateVerifyCode(code).then(async function (result) {
                setFormVerifyBusy(false);
                submitBtn.disabled = false;
                setGateHint('');
                if (result.unavailable) {
                    showGateError(
                        'Not working right now',
                        'Wait a minute and try again, or request access below.',
                    );
                    return;
                }
                if (result.challengeFailed) {
                    showGateError(
                        'Try again',
                        'Click Enter portal one more time.',
                    );
                    codeInput.focus();
                    return;
                }
                if (result.throttled || gateGetBlocking()) {
                    syncGateThrottleUi();
                    return;
                }
                if (!result.ok) {
                    showGateError('Incorrect code, try again');
                    codeInput.value = '';
                    codeInput.focus();
                    return;
                }
                if (gateThrottleUiTimer) {
                    clearTimeout(gateThrottleUiTimer);
                    gateThrottleUiTimer = null;
                }
                clearGateThrottleCountdown();
                gateClearServerBlock();
                gate.classList.remove('access-gate--locked', 'access-gate--cooldown');
                delete gate.dataset.gateThrottle;
                if (/^#access=/.test(window.location.hash)) {
                    history.replaceState(null, '', window.location.pathname + window.location.search);
                }
                applyUnlockedDom({ clearLoading: true });
                if (result.profileSlug) {
                    persistProfileSlug(result.profileSlug);
                    await hydrateSiteProfile(result.profileSlug, result.employmentType);
                } else {
                    applyEmploymentVariant(result.employmentType || EMPLOYMENT_FULL_TIME);
                }
                if (isDemoInviteAccessCode(code)) {
                    markDemoAccess();
                    scheduleDemoInvitePopup();
                    injectDemoAccessButton();
                }
                gate.classList.remove('access-gate--verifying');
                gate.classList.add('access-gate--success');
                const inner = form.closest('.access-gate-inner');
                if (inner) {
                    const block = document.createElement('div');
                    block.className = 'access-gate-success-block';
                    block.setAttribute('role', 'status');
                    block.setAttribute('aria-live', 'polite');
                    block.innerHTML =
                        '<div class="access-gate-success-check" aria-hidden="true">' +
                        '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>' +
                        '</div>' +
                        '<p class="access-gate-success-text">You\u2019re in</p>' +
                        '<p class="access-gate-success-sub">Opening the site</p>';
                    inner.appendChild(block);
                }

                // Give the success animation a beat to land before the gate
                // begins fading out, so the checkmark is actually perceptible.
                setTimeout(function () {
                    gate.classList.add('access-gate--exiting');
                }, 450);
                gate.addEventListener('transitionend', function onTe(ev) {
                    // Only react to the gate's own opacity transition (the
                    // exit fade), not the descendant fade-to-0.18 triggered
                    // by `access-gate--success`, which would fire first.
                    if (ev.target !== gate || ev.propertyName !== 'opacity') return;
                    gate.removeEventListener('transitionend', onTe);
                    gate.removeEventListener('keydown', onGateTabTrap);
                    gate.remove();
                    if (
                        focusBeforeGateEl &&
                        document.body.contains(focusBeforeGateEl) &&
                        typeof focusBeforeGateEl.focus === 'function'
                    ) {
                        focusBeforeGateEl.focus();
                    } else {
                        const next =
                            document.querySelector('main a[href], .navbar a[href], .navbar button') ||
                            document.querySelector('a[href], button');
                        if (next) next.focus();
                    }
                });
            })
                .catch(function () {
                    setFormVerifyBusy(false);
                    submitBtn.disabled = false;
                    setGateHint('');
                    showGateError(
                        'Connection problem',
                        'Check your internet and try again.',
                    );
                });
        });

        function refreshReadyState() {
            if (gateGetBlocking()) {
                syncGateThrottleUi();
                return;
            }
            if (!gateApiReady) {
                showGateError(
                    'Can\u2019t load right now',
                    'Refresh the page or try again in a minute.',
                );
                setGateHint('');
                return;
            }
            if (!gate.dataset.gateThrottle) {
                clearGateMessage();
            }
            setGateHint('');
        }

        refreshGateReadyUi = refreshReadyState;

        refreshReadyState();
        syncGateThrottleUi();
        if (!codeInput.disabled) {
            codeInput.focus();
        } else {
            submitBtn.focus();
        }
    }

    // ------------------------------------------------------------------
    // Request-access form & view switching
    // ------------------------------------------------------------------
    //
    // The gate hosts two views inside the same card: "code" (default) and
    // "request". Switching is done by toggling [data-gate-view] on
    // #access-gate; CSS hides the inactive view via [hidden] on each
    // <section data-view="...">. We keep both forms inside the gate so the
    // tab trap and focus management already implemented by initGateForm
    // continue to work — display:none rows just drop out of the tab order.
    //
    // The request form shares the same PoW challenge and fingerprint that
    // the gate's solver is already burning CPU on, so requesting access has
    // zero additional client-side overhead.

    var pageLoadTs = Date.now();

    function setGateView(view) {
        if (!gateEl) return;
        var current = gateEl.getAttribute('data-gate-view') || 'code';
        if (current === view) return;
        gateEl.setAttribute('data-gate-view', view);
        var sections = gateEl.querySelectorAll('.access-gate-view');
        for (var i = 0; i < sections.length; i++) {
            var s = sections[i];
            var match = s.getAttribute('data-view') === view;
            if (match) {
                s.removeAttribute('hidden');
            } else {
                s.setAttribute('hidden', '');
            }
        }
        // Focus the first focusable control in the active view so keyboard
        // users land somewhere predictable.
        var active = gateEl.querySelector('.access-gate-view[data-view="' + view + '"]');
        if (active) {
            var firstField = active.querySelector(
                'input:not([type="hidden"]):not([disabled]):not([tabindex="-1"]), textarea:not([disabled]):not([tabindex="-1"]), button:not([disabled]):not([tabindex="-1"])',
            );
            if (firstField) firstField.focus();
        }
    }

    function initRequestForm() {
        if (!gateEl) return;
        var form = document.getElementById('access-request-form');
        var nameEl = document.getElementById('access-request-name');
        var emailEl = document.getElementById('access-request-email');
        var referralEl = document.getElementById('access-request-referral');
        var hpEl = document.getElementById('access-request-website');
        var msgEl = document.getElementById('access-request-message');
        var successEl = document.getElementById('access-request-success');
        var submitBtn = form ? form.querySelector('.access-gate-submit') : null;
        if (!form || !nameEl || !emailEl || !referralEl || !msgEl || !successEl || !submitBtn) {
            return;
        }
        var submitLabelEl = submitBtn.querySelector('.access-gate-submit-label');
        var submitTextTarget = submitLabelEl || submitBtn;
        var submitDefaultText = submitTextTarget.textContent;

        // View-switching buttons (works from either view).
        var switchBtns = gateEl.querySelectorAll('[data-gate-action]');
        Array.prototype.forEach.call(switchBtns, function (btn) {
            btn.addEventListener('click', function () {
                var action = btn.getAttribute('data-gate-action');
                if (action === 'show-request') {
                    clearRequestError();
                    setGateView('request');
                } else if (action === 'show-code') {
                    // Returning to code view: also reset the success state
                    // so a second request later in the session starts fresh.
                    if (!successEl.hasAttribute('hidden')) {
                        successEl.setAttribute('hidden', '');
                        form.removeAttribute('hidden');
                    }
                    setGateView('code');
                }
            });
        });

        function clearRequestError() {
            gateRenderMessage(msgEl, null);
        }
        function showRequestError(title, detail) {
            gateRenderMessage(msgEl, {
                kind: 'error',
                title: title,
                detail: detail || '',
            });
        }
        function setBusy(busy) {
            form.setAttribute('aria-busy', busy ? 'true' : 'false');
            submitTextTarget.textContent = busy ? 'Sending…' : submitDefaultText;
            submitBtn.disabled = !!busy;
        }

        [nameEl, emailEl, referralEl].forEach(function (el) {
            el.addEventListener('input', clearRequestError);
        });

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            clearRequestError();

            if (!gateApiReady) {
                showRequestError(
                    'Can\u2019t send right now',
                    'Refresh the page or try again in a minute.',
                );
                return;
            }

            var name = (nameEl.value || '').trim();
            var emailVal = (emailEl.value || '').trim();
            var referral = (referralEl.value || '').trim();

            if (name.length < 2) {
                showRequestError('Add your name', 'Jonathan needs to know who you are.');
                nameEl.focus();
                return;
            }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailVal) || emailVal.length > 254) {
                showRequestError('Add your email', 'Your code will be sent here if approved.');
                emailEl.focus();
                return;
            }
            if (referral.length < 2) {
                showRequestError('Tell us how you found Jonathan', 'A quick note is all you need.');
                referralEl.focus();
                return;
            }

            setBusy(true);
            submitRequestAccess({
                name: name,
                email: emailVal,
                referral: referral,
                hp: hpEl ? hpEl.value : '',
            })
                .then(function (result) {
                    setBusy(false);
                    if (result.ok) {
                        form.setAttribute('hidden', '');
                        successEl.removeAttribute('hidden');
                        // Reset values so a stale name/email isn't sitting in
                        // the DOM if the user comes back later.
                        nameEl.value = '';
                        emailEl.value = '';
                        referralEl.value = '';
                        return;
                    }
                    if (result.rateLimited) {
                        showRequestError(
                            'Slow down',
                            result.retryAfterSec
                                ? 'Wait ' +
                                      gateFormatRemaining(result.retryAfterSec * 1000) +
                                      ' before trying again.'
                                : 'Wait a while before trying again.',
                        );
                        return;
                    }
                    if (result.unavailable) {
                        if (result.reason === 'email_not_configured') {
                            showRequestError(
                                'Form not available',
                                'Email Jonathan directly for now.',
                            );
                        } else if (result.reason === 'email_send_failed') {
                            showRequestError(
                                'Didn\u2019t go through',
                                'Try again in a few minutes.',
                            );
                        } else {
                            showRequestError(
                                'Not working right now',
                                'Wait a minute and try again.',
                            );
                        }
                        return;
                    }
                    if (result.invalid) {
                        if (
                            result.reason === 'dwell_too_short' ||
                            result.reason === 'challenge_failed'
                        ) {
                            showRequestError(
                                'Try again',
                                'Wait a moment, then hit Send request again.',
                            );
                        } else {
                            showRequestError(
                                'Check your info',
                                'Make sure your email looks right.',
                            );
                        }
                        return;
                    }
                    showRequestError(
                        'Something went wrong',
                        'Try again, or email Jonathan directly.',
                    );
                })
                .catch(function () {
                    setBusy(false);
                    showRequestError(
                        'No connection',
                        'Check your internet and try again.',
                    );
                });
        });
    }

    async function submitRequestAccess(input) {
        var nonce = await waitForPowSolution(60000);
        var payload = {
            name: input.name,
            email: input.email,
            referral: input.referral,
            challengeId:
                currentChallenge && currentChallenge.id != null
                    ? String(currentChallenge.id)
                    : null,
            challengeIssuedAt: pageLoadTs,
            nonce: nonce,
            fingerprint: clientFingerprint,
        };
        if (input.hp) {
            payload.accessRequestWebsite = input.hp;
        }
        var reqOpts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        };
        var res = await gateFetchJson('/request-access', reqOpts, gateActiveApiBase);
        if (
            shouldFallbackToProductionApi() &&
            gateActiveApiBase !== GATE_PRODUCTION_API_BASE &&
            gateFetchNeedsRetryForPost(res)
        ) {
            res = await gateFetchJson('/request-access', reqOpts, GATE_PRODUCTION_API_BASE);
        }
        if (res.body && res.body.challenge) {
            startPowSolver(res.body.challenge);
        }
        if (res.status === 200 && res.body && res.body.ok) {
            return { ok: true };
        }
        if (res.status === 429) {
            return {
                ok: false,
                rateLimited: true,
                retryAfterSec:
                    (res.body && res.body.retryAfterSec) || res.retryAfter || 0,
            };
        }
        if (res.status === 503) {
            return {
                ok: false,
                unavailable: true,
                reason: res.body && res.body.reason,
            };
        }
        if (res.status === 400) {
            return {
                ok: false,
                invalid: true,
                reason: res.body && (res.body.error || res.body.reason),
            };
        }
        return { ok: false };
    }

    (async function runBootstrap() {
        const session = await gateLoadSession();
        let stored = false;
        let employmentType = EMPLOYMENT_FULL_TIME;
        let profileSlug = null;
        if (session.ready) {
            stored = !!session.unlocked;
            if (session.employmentType) {
                employmentType = session.employmentType;
            }
            if (session.profileSlug) {
                profileSlug = session.profileSlug;
            }
        } else {
            try {
                stored = localStorage.getItem(STORAGE_KEY) === '1';
            } catch (e) {}
            if (stored) {
                employmentType = readStoredEmploymentType();
                profileSlug = readStoredProfileSlug();
            }
        }

        if (!stored && session.ready) {
            const hash = window.location.hash;
            const m = /^#access=([^&#]+)/.exec(hash);
            if (m) {
                const phrase = decodeURIComponent(m[1].replace(/\+/g, ' '));
                if (gateIsPlausibleGuess(phrase)) {
                    const r = await gateVerifyCode(normalizeGateCode(phrase));
                    if (r.ok) {
                        stored = true;
                        employmentType = r.employmentType || EMPLOYMENT_FULL_TIME;
                        profileSlug = r.profileSlug || null;
                        if (isDemoInviteAccessCode(phrase)) {
                            markDemoAccess();
                            scheduleDemoInvitePopup();
                            injectDemoAccessButton();
                        }
                    }
                }
                history.replaceState(null, '', window.location.pathname + window.location.search);
            }
        }

        const preloader = document.getElementById('preloader');

        if (stored) {
            if (profileSlug) {
                await hydrateSiteProfile(profileSlug, employmentType);
            } else {
                applyEmploymentVariant(employmentType);
            }
            applyUnlockedDom();
            if (hasDemoAccess()) {
                injectDemoAccessButton();
            }
            if (typeof window.__portfolioPreloaderStart === 'function') {
                window.__portfolioPreloaderStart();
                window.__portfolioPreloaderStart = undefined;
            }
            return;
        }

        document.documentElement.classList.add('access-locked');
        document.documentElement.classList.remove('access-unlocked');
        if (preloader) preloader.remove();
        document.documentElement.classList.remove('loading');
        document.body.style.overflow = 'hidden';
        window.__portfolioPreloaderStart = undefined;

        if (refreshGateReadyUi) {
            refreshGateReadyUi();
        }
    })();

    if (gateEl) {
        initGateForm();
        initRequestForm();
    }
})();

// ============================================
// PRELOADER
// ============================================
(function initPreloader() {
    const preloader = document.getElementById('preloader');
    if (!preloader) return;

    const MIN_DISPLAY = 600;
    const loadStart = performance.now();

    function startPreloaderFlow() {
        function afterLoad() {
            const elapsed = performance.now() - loadStart;
            const remaining = Math.max(0, MIN_DISPLAY - elapsed);

            setTimeout(function () {
                preloader.classList.add('hidden');
                document.documentElement.classList.remove('loading');

                preloader.addEventListener('transitionend', function () {
                    preloader.remove();
                }, { once: true });
            }, remaining);
        }

        if (document.readyState === 'complete') {
            afterLoad();
        } else {
            window.addEventListener('load', afterLoad, { once: true });
        }
    }

    // Do not start the preloader from the inline access-unlocked class alone:
    // localStorage can be out of sync with the server cookie, which would hide
    // the gate and show this overlay until /access-status returns. Bootstrap
    // calls __portfolioPreloaderStart only after confirming access.
    window.__portfolioPreloaderStart = startPreloaderFlow;
})();

// ============================================
// THEME TOGGLE
// ============================================
const themeModule = (function initTheme() {
    const toggle = document.querySelector('.theme-toggle');
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    const DARK_COLOR = '99, 102, 241';
    const LIGHT_COLOR = '79, 70, 229';

    function getTheme() {
        return document.documentElement.getAttribute('data-theme') || 'dark';
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        if (metaThemeColor) {
            metaThemeColor.setAttribute('content', theme === 'light' ? '#f8fafc' : '#0a0a1a');
        }
        if (toggle) {
            toggle.setAttribute('aria-label',
                theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'
            );
        }
    }

    function getParticleColor() {
        return getTheme() === 'light' ? LIGHT_COLOR : DARK_COLOR;
    }

    if (toggle) {
        toggle.addEventListener('click', function () {
            const next = getTheme() === 'dark' ? 'light' : 'dark';
            localStorage.setItem('theme', next);
            applyTheme(next);
        });
    }

    const systemPref = window.matchMedia('(prefers-color-scheme: light)');
    systemPref.addEventListener('change', function (e) {
        if (!localStorage.getItem('theme')) {
            applyTheme(e.matches ? 'light' : 'dark');
        }
    });

    applyTheme(getTheme());

    return { getParticleColor: getParticleColor };
})();

// ============================================
// CURRENT YEAR
// ============================================
document.getElementById('current-year').textContent = new Date().getFullYear();

// ============================================
// PARTICLE CANVAS BACKGROUND
// ============================================
(function initCanvas() {
    const canvas = document.getElementById('bg-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let particles = [];
    let animationId;
    let width, height;

    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }

    function createParticles() {
        var isMobile = width < 768;
        var divisor = isMobile ? 35000 : 15000;
        var maxCount = isMobile ? 30 : 150;
        var count = Math.min(Math.floor((width * height) / divisor), maxCount);
        var maxDist = isMobile ? 100 : 120;
        particles = [];
        for (let i = 0; i < count; i++) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.3,
                vy: (Math.random() - 0.5) * 0.3,
                radius: Math.random() * 1.5 + 0.5,
                opacity: Math.random() * 0.5 + 0.1,
            });
        }
        particles._maxDist = maxDist;
    }

    function draw() {
        ctx.clearRect(0, 0, width, height);
        const rgb = themeModule.getParticleColor();

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0) p.x = width;
            if (p.x > width) p.x = 0;
            if (p.y < 0) p.y = height;
            if (p.y > height) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${rgb}, ${p.opacity})`;
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const q = particles[j];
                const dx = p.x - q.x;
                const dy = p.y - q.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                var maxDist = particles._maxDist || 120;
                if (dist < maxDist) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(q.x, q.y);
                    ctx.strokeStyle = `rgba(${rgb}, ${0.08 * (1 - dist / maxDist)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        animationId = requestAnimationFrame(draw);
    }

    resize();
    createParticles();
    draw();

    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            resize();
            createParticles();
        }, 200);
    });

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (prefersReduced.matches) {
        cancelAnimationFrame(animationId);
        canvas.style.display = 'none';
    }
    prefersReduced.addEventListener('change', (e) => {
        if (e.matches) {
            cancelAnimationFrame(animationId);
            canvas.style.display = 'none';
        } else {
            canvas.style.display = '';
            draw();
        }
    });
})();

// ============================================
// NAVBAR: SCROLL EFFECT & ACTIVE SECTION
// ============================================
const navbar = document.querySelector('.navbar');
const sections = document.querySelectorAll('.section, .hero');
const navLinks = document.querySelectorAll('.nav-menu a[data-section]');

function updateNavbar() {
    const scrollY = window.scrollY;

    if (scrollY > 50) {
        navbar.classList.add('scrolled');
    } else {
        navbar.classList.remove('scrolled');
    }

    let currentSection = '';
    sections.forEach((section) => {
        const top = section.offsetTop - 150;
        if (scrollY >= top) {
            currentSection = section.getAttribute('id');
        }
    });

    navLinks.forEach((link) => {
        link.classList.remove('active');
        if (link.dataset.section === currentSection) {
            link.classList.add('active');
        }
    });
}

window.addEventListener('scroll', updateNavbar, { passive: true });
updateNavbar();

// ============================================
// MOBILE NAVIGATION
// ============================================
const navToggle = document.querySelector('.nav-toggle');
const navMenu = document.querySelector('.nav-menu');
let overlay = document.createElement('div');
overlay.className = 'nav-overlay';
document.body.appendChild(overlay);

function setMobileNav(open) {
    const isOpen = Boolean(open);
    navMenu.classList.toggle('active', isOpen);
    navToggle.classList.toggle('active', isOpen);
    navToggle.setAttribute('aria-expanded', String(isOpen));
    overlay.classList.toggle('active', isOpen);
    document.body.style.overflow = isOpen ? 'hidden' : '';
}

function toggleMobileNav() {
    const isOpen = !navMenu.classList.contains('active');
    setMobileNav(isOpen);
}

function closeMobileNav() {
    setMobileNav(false);
}

function syncMobileNavForViewport() {
    if (window.innerWidth > 768 && navMenu.classList.contains('active')) {
        closeMobileNav();
    }
}

function handleMobileNavKeydown(event) {
    if (event.key === 'Escape' && navMenu.classList.contains('active')) {
        closeMobileNav();
    }
}

if (navToggle && navMenu) {
    navToggle.setAttribute('aria-expanded', 'false');
    navToggle.addEventListener('click', toggleMobileNav);
    overlay.addEventListener('click', closeMobileNav);
    window.addEventListener('resize', syncMobileNavForViewport);
    document.addEventListener('keydown', handleMobileNavKeydown);
}

document.querySelectorAll('.nav-menu a').forEach((link) => {
    link.addEventListener('click', () => {
        if (navMenu.classList.contains('active')) {
            closeMobileNav();
        }
    });
});

// ============================================
// SMOOTH SCROLLING
// ============================================
function scrollToSection(selector) {
    const target = document.querySelector(selector);
    if (!target) return;

    const top = target.getBoundingClientRect().top + window.scrollY - 80;
    window.scrollTo({
        top: Math.max(0, top),
        behavior: 'smooth',
    });
}

document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        scrollToSection(this.getAttribute('href'));
    });
});

document.querySelectorAll('.stat[data-scroll-to]').forEach((stat) => {
    const handleActivate = () => scrollToSection(stat.dataset.scrollTo);

    stat.addEventListener('click', handleActivate);
    stat.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleActivate();
        }
    });
});

// ============================================
// TYPING EFFECT
// ============================================
(function initTyping() {
    const fullTimeEl = document.getElementById('typing-text');
    const contractEl = document.getElementById('typing-text-contract');
    const profileEl = document.getElementById('typing-text-profile');
    if (!fullTimeEl && !contractEl && !profileEl) return;

    const phrasesByType = {
        full_time: [
            'Enterprise Data Scientist',
            'Data & AI Architect',
            'ML Solutions Engineer',
            'Insurance Analytics Expert',
            'MSE, FLMI',
        ],
        contract: [
            'Contract Data Scientist',
            'Production ML Delivery',
            'Executive Dashboards',
            'Insurance & Reinsurance',
            'MSE, FLMI',
        ],
    };

    let activeType = 'full_time';
    let activeEl = fullTimeEl || contractEl;
    let phrases = phrasesByType.full_time;
    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let initialized = false;
    const typeSpeed = 60;
    const deleteSpeed = 35;
    const pauseEnd = 2000;
    const pauseStart = 500;
    let startTimer = null;

    function resolveTypingTarget(type) {
        activeType = type === 'contract' ? 'contract' : 'full_time';
        phrases = phrasesByType[activeType];
        activeEl =
            activeType === 'contract' && contractEl ? contractEl : fullTimeEl || contractEl;
    }

    function resetTypingState() {
        phraseIndex = 0;
        charIndex = 0;
        isDeleting = false;
        initialized = false;
        if (activeEl) {
            activeEl.textContent = '';
        }
    }

    function scheduleStart(delayMs) {
        if (startTimer) {
            clearTimeout(startTimer);
        }
        startTimer = setTimeout(type, delayMs);
    }

    document.addEventListener('portfolio:employment-type', function (ev) {
        if (document.documentElement.getAttribute('data-profile-mode') === 'tailored') {
            return;
        }
        const nextType =
            ev && ev.detail && ev.detail.type === 'contract' ? 'contract' : 'full_time';
        resolveTypingTarget(nextType);
        resetTypingState();
        scheduleStart(250);
    });

    document.addEventListener('portfolio:profile-typing', function (ev) {
        const customPhrases =
            ev && ev.detail && ev.detail.phrases && ev.detail.phrases.length
                ? ev.detail.phrases
                : null;
        if (!customPhrases || !profileEl) return;
        if (fullTimeEl) fullTimeEl.hidden = true;
        if (contractEl) contractEl.hidden = true;
        profileEl.hidden = false;
        activeEl = profileEl;
        phrases = customPhrases;
        phraseIndex = 0;
        charIndex = 0;
        isDeleting = false;
        initialized = false;
        scheduleStart(250);
    });

    resolveTypingTarget(
        document.documentElement.getAttribute('data-employment-type') || 'full_time',
    );

    function type() {
        if (!activeEl) return;
        if (!initialized) {
            initialized = true;
            activeEl.textContent = '';
        }

        const currentPhrase = phrases[phraseIndex];

        if (isDeleting) {
            charIndex--;
            activeEl.textContent = currentPhrase.substring(0, charIndex);
        } else {
            charIndex++;
            activeEl.textContent = currentPhrase.substring(0, charIndex);
        }

        let delay = isDeleting ? deleteSpeed : typeSpeed;

        if (!isDeleting && charIndex === currentPhrase.length) {
            delay = pauseEnd;
            isDeleting = true;
        } else if (isDeleting && charIndex === 0) {
            isDeleting = false;
            phraseIndex = (phraseIndex + 1) % phrases.length;
            delay = pauseStart;
        }

        startTimer = setTimeout(type, delay);
    }

    scheduleStart(1000);
})();

// ============================================
// ANIMATED COUNTERS
// ============================================
(function initCounters() {
    const counters = document.querySelectorAll('.stat-number');
    if (!counters.length) return;

    let triggered = false;

    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting && !triggered) {
                    triggered = true;
                    animateCounters();
                }
            });
        },
        { threshold: 0.5 }
    );

    const statsContainer = document.querySelector('.hero-stats');
    if (statsContainer) observer.observe(statsContainer);

    function animateCounters() {
        counters.forEach((counter) => {
            const target = parseInt(counter.dataset.target, 10);
            counter.textContent = '0';
            const duration = 1500;
            const startTime = performance.now();

            function update(currentTime) {
                const elapsed = currentTime - startTime;
                const progress = Math.min(elapsed / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                const value = Math.round(eased * target);
                counter.textContent = value;

                if (progress < 1) {
                    requestAnimationFrame(update);
                }
            }

            requestAnimationFrame(update);
        });
    }
})();

// ============================================
// SCROLL REVEAL ANIMATIONS
// ============================================
(function initReveal() {
    const reveals = document.querySelectorAll('.reveal');
    if (!reveals.length) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (prefersReduced.matches) {
        reveals.forEach((el) => el.classList.add('visible'));
        return;
    }

    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        },
        {
            threshold: 0.1,
            rootMargin: '0px 0px -40px 0px',
        }
    );

    reveals.forEach((el) => observer.observe(el));
})();
