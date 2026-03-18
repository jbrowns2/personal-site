// ============================================
// PRELOADER
// ============================================
(function initPreloader() {
    const preloader = document.getElementById('preloader');
    if (!preloader) return;

    const MIN_DISPLAY = 600;
    const loadStart = performance.now();

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
        const count = Math.floor((width * height) / 15000);
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

                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(q.x, q.y);
                    ctx.strokeStyle = `rgba(${rgb}, ${0.08 * (1 - dist / 120)})`;
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

function toggleMobileNav() {
    const isOpen = navMenu.classList.toggle('active');
    navToggle.classList.toggle('active');
    navToggle.setAttribute('aria-expanded', isOpen);
    overlay.classList.toggle('active');
    document.body.style.overflow = isOpen ? 'hidden' : '';
}

navToggle.addEventListener('click', toggleMobileNav);
overlay.addEventListener('click', toggleMobileNav);

document.querySelectorAll('.nav-menu a').forEach((link) => {
    link.addEventListener('click', () => {
        if (navMenu.classList.contains('active')) {
            toggleMobileNav();
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
