// ============================================
// ACCESS GATE + PRELOADER BOOTSTRAP
// ============================================
(function initAccessGateAndPreloader() {
    const STORAGE_KEY = 'portfolio_unlocked';
    const API_BASE = '/api';

    let gateApiReady = false;
    let serverBlockUntil = 0;
    let gateThrottleUiTimer = null;

    function normalizePhrase(s) {
        return String(s).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
    }

    function gateIsPlausibleGuess(phrase) {
        const n = normalizePhrase(phrase);
        return n.length >= 6 && n.length <= 8;
    }

    async function gateFetchJson(path, options) {
        const opts = Object.assign({ method: 'GET', credentials: 'include' }, options);
        const r = await fetch(API_BASE + path, opts);
        const ct = r.headers.get('content-type') || '';
        const isJson = ct.indexOf('application/json') !== -1;
        let body = null;
        if (isJson) {
            try {
                body = await r.json();
            } catch (e) {}
        }
        const ra = parseInt(r.headers.get('retry-after') || '0', 10) || 0;
        return { ok: r.ok, status: r.status, body: body, retryAfter: ra };
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

    async function gateLoadSession() {
        try {
            const res = await gateFetchJson('/access-status', { method: 'GET' });
            if (!res.body || typeof res.body.ready !== 'boolean') {
                return { ready: false, unlocked: false };
            }
            gateApiReady = !!res.body.ready;
            if (gateApiReady && res.body.blockedUntilSec > 0) {
                serverBlockUntil = Date.now() + res.body.blockedUntilSec * 1000;
            }
            return {
                ready: gateApiReady,
                unlocked: !!res.body.unlocked,
            };
        } catch (e) {
            return { ready: false, unlocked: false };
        }
    }

    async function gateVerifyCode(code) {
        const res = await gateFetchJson('/verify-access', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code }),
        });
        if (res.status === 503) {
            return { ok: false, unavailable: true };
        }
        if (res.status === 429) {
            gateApplyServerBlock(res.body, res.retryAfter);
            return { ok: false, throttled: true };
        }
        if (res.status === 200 && res.body && res.body.ok) {
            gateClearServerBlock();
            return { ok: true };
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
        if (opts && opts.clearLoading) {
            document.documentElement.classList.remove('loading');
        }
    }

    const gateEl = document.getElementById('access-gate');

    function initGateForm() {
        const gate = gateEl;
        const form = document.getElementById('access-gate-form');
        const segs = Array.prototype.slice.call(document.querySelectorAll('.access-seg'));
        const errEl = document.getElementById('access-gate-error');
        const submitBtn = form ? form.querySelector('.access-gate-submit') : null;
        if (!form || !segs.length || !gate || !submitBtn) return;

        function getCode() {
            return segs
                .map(function (inp) {
                    return inp.value;
                })
                .join('');
        }

        function clearError() {
            if (gate.dataset.gateThrottle === '1') {
                return;
            }
            errEl.textContent = '';
            segs.forEach(function (el) {
                el.setAttribute('aria-invalid', 'false');
            });
            gate.classList.remove('access-gate--error');
        }

        function showError(msg) {
            delete gate.dataset.gateThrottle;
            errEl.textContent = msg;
            segs.forEach(function (el) {
                el.setAttribute('aria-invalid', 'true');
            });
            gate.classList.add('access-gate--error');
            void gate.offsetWidth;
            setTimeout(function () {
                gate.classList.remove('access-gate--error');
            }, 500);
        }

        function fillFromString(str) {
            const chars = normalizePhrase(str).slice(0, segs.length).split('');
            segs.forEach(function (el, i) {
                el.value = chars[i] || '';
            });
        }

        segs.forEach(function (input, idx) {
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Backspace' && !input.value && idx > 0) {
                    e.preventDefault();
                    segs[idx - 1].focus();
                    segs[idx - 1].value = '';
                }
                if (e.key === 'ArrowLeft' && idx > 0) {
                    e.preventDefault();
                    segs[idx - 1].focus();
                }
                if (e.key === 'ArrowRight' && idx < segs.length - 1) {
                    e.preventDefault();
                    segs[idx + 1].focus();
                }
            });

            input.addEventListener('input', function () {
                clearError();
                let v = input.value;
                if (v.length > 1) {
                    fillFromString(v);
                    const filled = normalizePhrase(v).length;
                    const next = Math.min(idx + Math.max(filled, 1), segs.length - 1);
                    segs[next].focus();
                    return;
                }
                v = normalizePhrase(v).slice(0, 1);
                input.value = v;
                if (v && idx < segs.length - 1) {
                    segs[idx + 1].focus();
                }
            });

            input.addEventListener('paste', function (e) {
                e.preventDefault();
                const text = (e.clipboardData || window.clipboardData).getData('text') || '';
                fillFromString(text);
                const len = Math.min(normalizePhrase(text).length, segs.length);
                const focusIdx = len === 0 ? 0 : Math.min(len - 1, segs.length - 1);
                segs[focusIdx].focus();
            });
        });

        function syncGateThrottleUi() {
            if (gateThrottleUiTimer) {
                clearTimeout(gateThrottleUiTimer);
                gateThrottleUiTimer = null;
            }
            const block = gateGetBlocking();
            gate.classList.remove('access-gate--locked', 'access-gate--cooldown');
            if (!block) {
                if (gate.dataset.gateThrottle === '1') {
                    errEl.textContent = '';
                    delete gate.dataset.gateThrottle;
                }
                segs.forEach(function (el) {
                    el.disabled = false;
                });
                submitBtn.disabled = false;
                return;
            }
            gate.dataset.gateThrottle = '1';
            const msLeft = block.until - Date.now();
            if (block.kind === 'locked') {
                gate.classList.add('access-gate--locked');
                errEl.textContent =
                    'Too many attempts. Try again in ' + gateFormatRemaining(msLeft) + '.';
                segs.forEach(function (el) {
                    el.disabled = true;
                });
                submitBtn.disabled = true;
            } else {
                gate.classList.add('access-gate--cooldown');
                errEl.textContent =
                    'Please wait ' + gateFormatRemaining(msLeft) + ' before trying again.';
                segs.forEach(function (el) {
                    el.disabled = false;
                });
                submitBtn.disabled = true;
            }
            scheduleGateThrottleUiSync(syncGateThrottleUi, block.until);
        }

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            clearError();
            if (gateGetBlocking()) {
                syncGateThrottleUi();
                return;
            }
            if (!gateApiReady) {
                showError(
                    'Access verification needs the live site. Use your deployed URL or run npx vercel dev from this project.'
                );
                return;
            }
            const code = normalizePhrase(getCode());
            if (code.length < 6) {
                showError('Enter the full access code (6–8 characters).');
                segs[0].focus();
                return;
            }
            if (code.length > 8) {
                showError('The phrase has too many characters.');
                return;
            }
            submitBtn.disabled = true;
            gateVerifyCode(code).then(function (result) {
                submitBtn.disabled = false;
                if (result.unavailable) {
                    showError('Verification is temporarily unavailable. Try again shortly.');
                    return;
                }
                if (result.throttled || gateGetBlocking()) {
                    syncGateThrottleUi();
                    return;
                }
                if (!result.ok) {
                    showError("That code doesn't match. Try again.");
                    return;
                }
                if (gateThrottleUiTimer) {
                    clearTimeout(gateThrottleUiTimer);
                    gateThrottleUiTimer = null;
                }
                gateClearServerBlock();
                gate.classList.remove('access-gate--locked', 'access-gate--cooldown');
                delete gate.dataset.gateThrottle;
                if (/^#access=/.test(window.location.hash)) {
                    history.replaceState(null, '', window.location.pathname + window.location.search);
                }
                applyUnlockedDom({ clearLoading: true });
                gate.classList.add('access-gate--success');
                const inner = form.closest('.access-gate-inner');
                const msg = document.createElement('p');
                msg.className = 'access-gate-success-msg';
                msg.textContent = 'Access granted';
                if (inner) inner.appendChild(msg);

                gate.classList.add('access-gate--exiting');
                gate.addEventListener('transitionend', function onTe(ev) {
                    if (ev.propertyName !== 'opacity') return;
                    gate.removeEventListener('transitionend', onTe);
                    gate.remove();
                });
            });
        });

        syncGateThrottleUi();
        if (!segs[0].disabled) {
            segs[0].focus();
        } else {
            submitBtn.focus();
        }
    }

    (async function runBootstrap() {
        const session = await gateLoadSession();
        let stored = false;
        if (session.ready) {
            stored = !!session.unlocked;
        } else {
            try {
                stored = localStorage.getItem(STORAGE_KEY) === '1';
            } catch (e) {}
        }

        if (!stored && session.ready) {
            const hash = window.location.hash;
            const m = /^#access=([^&#]+)/.exec(hash);
            if (m) {
                const phrase = decodeURIComponent(m[1].replace(/\+/g, ' '));
                if (gateIsPlausibleGuess(phrase)) {
                    const r = await gateVerifyCode(normalizePhrase(phrase));
                    if (r.ok) {
                        stored = true;
                    }
                }
                history.replaceState(null, '', window.location.pathname + window.location.search);
            }
        }

        const preloader = document.getElementById('preloader');

        if (stored) {
            applyUnlockedDom();
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

        if (gateEl) initGateForm();
    })();
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
        window.addEventListener('load', function () {
            const elapsed = performance.now() - loadStart;
            const remaining = Math.max(0, MIN_DISPLAY - elapsed);

            setTimeout(function () {
                preloader.classList.add('hidden');
                document.documentElement.classList.remove('loading');

                preloader.addEventListener('transitionend', function () {
                    preloader.remove();
                }, { once: true });
            }, remaining);
        });
    }

    if (document.documentElement.classList.contains('access-unlocked')) {
        startPreloaderFlow();
        return;
    }

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
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            const top = target.getBoundingClientRect().top + window.scrollY - 80;
            window.scrollTo({
                top: Math.max(0, top),
                behavior: 'smooth',
            });
        }
    });
});

// ============================================
// TYPING EFFECT
// ============================================
(function initTyping() {
    const el = document.getElementById('typing-text');
    if (!el) return;

    const phrases = [
        'Enterprise Data Scientist',
        'Data & AI Architect',
        'ML Solutions Engineer',
        'Insurance Analytics Expert',
        'MSE, FLMI',
    ];

    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    let initialized = false;
    const typeSpeed = 60;
    const deleteSpeed = 35;
    const pauseEnd = 2000;
    const pauseStart = 500;

    function type() {
        if (!initialized) {
            initialized = true;
            el.textContent = '';
        }

        const currentPhrase = phrases[phraseIndex];

        if (isDeleting) {
            charIndex--;
            el.textContent = currentPhrase.substring(0, charIndex);
        } else {
            charIndex++;
            el.textContent = currentPhrase.substring(0, charIndex);
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

        setTimeout(type, delay);
    }

    setTimeout(type, 1000);
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
