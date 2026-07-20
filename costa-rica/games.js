(function () {
  'use strict';

  var REQUIRED_PROFILE = 'costa-rica';
  var PROFILE_SLUG_KEY = 'portfolio_profile_slug';
  var BEST_DAY_KEY = 'pura_vida_best_day';
  var API_BASE = '/api';

  var gateCheck = document.getElementById('gate-check');
  var app = document.getElementById('app');
  var lobby = document.getElementById('lobby');
  var stage = document.getElementById('stage');
  var canvas = document.getElementById('game-canvas');
  var ctx = canvas.getContext('2d');
  var memoryBoard = document.getElementById('memory-board');
  var overlay = document.getElementById('stage-overlay');
  var overlayTitle = document.getElementById('overlay-title');
  var overlayCopy = document.getElementById('overlay-copy');
  var overlayAction = document.getElementById('overlay-action');
  var stageTitle = document.getElementById('stage-title');
  var stageHud = document.getElementById('stage-hud');
  var stageHint = document.getElementById('stage-hint');
  var lifetimeScoreEl = document.getElementById('lifetime-score');
  var backLobby = document.getElementById('back-lobby');

  var activeGame = null;
  var rafId = 0;
  var bestDay = readBestDay();

  function readBestDay() {
    try {
      return Number(localStorage.getItem(BEST_DAY_KEY)) || 0;
    } catch (e) {
      return 0;
    }
  }

  function writeBestDay(score) {
    if (score <= bestDay) return;
    bestDay = score;
    try {
      localStorage.setItem(BEST_DAY_KEY, String(bestDay));
    } catch (e) {}
    renderBestDay();
  }

  function renderBestDay() {
    lifetimeScoreEl.textContent = 'Best day: ' + bestDay;
  }

  function storedProfileOk() {
    try {
      return sessionStorage.getItem(PROFILE_SLUG_KEY) === REQUIRED_PROFILE;
    } catch (e) {
      return false;
    }
  }

  async function ensureDecoyAccess() {
    try {
      var res = await fetch(API_BASE + '/access-status', {
        method: 'GET',
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        var body = await res.json();
        if (body && body.unlocked && body.profileSlug === REQUIRED_PROFILE) {
          try {
            sessionStorage.setItem(PROFILE_SLUG_KEY, REQUIRED_PROFILE);
          } catch (e) {}
          return true;
        }
        if (body && body.unlocked && body.profileSlug && body.profileSlug !== REQUIRED_PROFILE) {
          window.location.replace('/');
          return false;
        }
      }
    } catch (e) {}

    if (storedProfileOk()) {
      return true;
    }

    window.location.replace('/');
    return false;
  }

  function showOverlay(title, copy, actionLabel, onAction) {
    overlay.hidden = false;
    overlayTitle.textContent = title;
    overlayCopy.textContent = copy || '';
    overlayAction.textContent = actionLabel || 'Play';
    overlayAction.onclick = function () {
      overlay.hidden = true;
      if (typeof onAction === 'function') onAction();
    };
  }

  function stopLoop() {
    if (rafId) {
      cancelAnimationFrame(rafId);
      rafId = 0;
    }
    window.removeEventListener('keydown', onKeyDown);
    window.removeEventListener('keyup', onKeyUp);
    canvas.onpointerdown = null;
    canvas.onpointermove = null;
    canvas.onpointerup = null;
    canvas.onpointerleave = null;
  }

  function returnToLobby() {
    stopLoop();
    if (activeGame && typeof activeGame.destroy === 'function') {
      activeGame.destroy();
    }
    activeGame = null;
    memoryBoard.hidden = true;
    memoryBoard.innerHTML = '';
    canvas.hidden = false;
    overlay.hidden = true;
    stage.hidden = true;
    lobby.hidden = false;
    stageHud.textContent = 'Score 0';
    stageHint.textContent = '';
  }

  function openGame(name) {
    stopLoop();
    lobby.hidden = true;
    stage.hidden = false;
    memoryBoard.hidden = true;
    memoryBoard.innerHTML = '';
    canvas.hidden = false;
    overlay.hidden = true;

    if (name === 'sloth') {
      stageTitle.textContent = 'Sloth Crossing';
      stageHint.textContent = 'Arrow keys / WASD or drag to move. Grab mangoes. Avoid buses.';
      activeGame = createSlothGame();
    } else if (name === 'coffee') {
      stageTitle.textContent = 'Coffee Catch';
      stageHint.textContent = 'Move left/right to catch beans. Rocks ruin the brew.';
      activeGame = createCoffeeGame();
    } else {
      stageTitle.textContent = 'Jungle Memory';
      stageHint.textContent = 'Match the Costa Rica icons. Fewer flips = bragging rights.';
      canvas.hidden = true;
      memoryBoard.hidden = false;
      activeGame = createMemoryGame();
    }

    showOverlay(
      '¡Listo!',
      activeGame.intro,
      'Start',
      function () {
        activeGame.start();
      }
    );
  }

  var keys = Object.create(null);

  function onKeyDown(e) {
    keys[e.key] = true;
    if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', ' '].indexOf(e.key) !== -1) {
      e.preventDefault();
    }
  }

  function onKeyUp(e) {
    keys[e.key] = false;
  }

  function bindMovementKeys() {
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keyup', onKeyUp);
  }

  function fitCanvasBackingStore() {
    var rect = canvas.getBoundingClientRect();
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = Math.max(1, Math.floor(rect.width * dpr));
    var h = Math.max(1, Math.floor(rect.height * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    return { w: canvas.width, h: canvas.height, dpr: dpr };
  }

  function createSlothGame() {
    var score = 0;
    var lives = 3;
    var running = false;
    var sloth = { x: 0.5, y: 0.88, w: 0.08, h: 0.1 };
    var cars = [];
    var mangoes = [];
    var lastSpawn = 0;
    var lastMango = 0;
    var pointerX = null;
    var startTime = 0;

    function spawnCar(now) {
      cars.push({
        x: Math.random() > 0.5 ? -0.2 : 1.2,
        y: 0.28 + Math.random() * 0.42,
        w: 0.16,
        h: 0.07,
        vx: (Math.random() > 0.5 ? 1 : -1) * (0.00018 + Math.random() * 0.00022),
        color: Math.random() > 0.5 ? '#e85d4c' : '#f5c518',
        born: now,
      });
    }

    function spawnMango(now) {
      mangoes.push({
        x: 0.12 + Math.random() * 0.76,
        y: 0.18 + Math.random() * 0.55,
        r: 0.025,
        born: now,
      });
    }

    function updateHud() {
      stageHud.textContent = 'Mangoes ' + score + ' · Lives ' + lives;
    }

    function endGame(won) {
      running = false;
      stopLoop();
      writeBestDay(score);
      showOverlay(
        won ? 'Pura vida!' : 'Traffic won',
        won ? 'You collected ' + score + ' mangoes before nap time.' : 'The sloth needs a coconut break. Score: ' + score,
        'Try again',
        function () {
          openGame('sloth');
        }
      );
    }

    function tick(now) {
      if (!running) return;
      var size = fitCanvasBackingStore();
      var w = size.w;
      var h = size.h;

      if (now - lastSpawn > 900) {
        spawnCar(now);
        lastSpawn = now;
      }
      if (now - lastMango > 1400) {
        spawnMango(now);
        lastMango = now;
      }

      var move = 0;
      if (keys.ArrowLeft || keys.a || keys.A) move -= 1;
      if (keys.ArrowRight || keys.d || keys.D) move += 1;
      if (keys.ArrowUp || keys.w || keys.W) sloth.y -= 0.006;
      if (keys.ArrowDown || keys.s || keys.S) sloth.y += 0.006;
      if (pointerX != null) {
        var target = pointerX;
        move = target < sloth.x - 0.01 ? -1 : target > sloth.x + 0.01 ? 1 : 0;
        sloth.y += (0.72 - sloth.y) * 0.02;
      }
      sloth.x += move * 0.008;
      sloth.x = Math.max(0.05, Math.min(0.95, sloth.x));
      sloth.y = Math.max(0.12, Math.min(0.9, sloth.y));

      cars = cars.filter(function (car) {
        car.x += car.vx * (16);
        return car.x > -0.3 && car.x < 1.3;
      });
      mangoes = mangoes.filter(function (m) {
        return now - m.born < 7000;
      });

      for (var i = 0; i < cars.length; i++) {
        var c = cars[i];
        if (
          Math.abs(c.x - sloth.x) < (c.w + sloth.w) * 0.35 &&
          Math.abs(c.y - sloth.y) < (c.h + sloth.h) * 0.45
        ) {
          lives -= 1;
          cars.splice(i, 1);
          sloth.x = 0.5;
          sloth.y = 0.88;
          updateHud();
          if (lives <= 0) {
            endGame(false);
            return;
          }
          break;
        }
      }

      for (var j = mangoes.length - 1; j >= 0; j--) {
        var m = mangoes[j];
        var dx = m.x - sloth.x;
        var dy = m.y - sloth.y;
        if (dx * dx + dy * dy < 0.004) {
          mangoes.splice(j, 1);
          score += 1;
          updateHud();
          if (score >= 12) {
            endGame(true);
            return;
          }
        }
      }

      // Draw
      ctx.clearRect(0, 0, w, h);
      var sky = ctx.createLinearGradient(0, 0, 0, h);
      sky.addColorStop(0, '#7ed6e8');
      sky.addColorStop(0.55, '#3cbf6f');
      sky.addColorStop(1, '#1f7a4d');
      ctx.fillStyle = sky;
      ctx.fillRect(0, 0, w, h);

      ctx.fillStyle = '#4a5560';
      for (var lane = 0; lane < 3; lane++) {
        var ly = (0.32 + lane * 0.16) * h;
        ctx.fillRect(0, ly, w, 0.06 * h);
        ctx.strokeStyle = '#f5c518';
        ctx.setLineDash([12, 14]);
        ctx.beginPath();
        ctx.moveTo(0, ly + 0.03 * h);
        ctx.lineTo(w, ly + 0.03 * h);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      mangoes.forEach(function (m) {
        ctx.font = Math.floor(0.06 * h) + 'px serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('🥭', m.x * w, m.y * h);
      });

      cars.forEach(function (car) {
        ctx.fillStyle = car.color;
        roundRect(ctx, (car.x - car.w / 2) * w, (car.y - car.h / 2) * h, car.w * w, car.h * h, 10);
        ctx.fill();
        ctx.fillStyle = '#2a1f14';
        ctx.font = Math.floor(0.035 * h) + 'px Nunito, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('BUS', car.x * w, car.y * h);
      });

      ctx.font = Math.floor(0.09 * h) + 'px serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('🦥', sloth.x * w, sloth.y * h);

      if (now - startTime > 90000) {
        endGame(score >= 8);
        return;
      }

      rafId = requestAnimationFrame(tick);
    }

    function onPointer(e) {
      var rect = canvas.getBoundingClientRect();
      pointerX = (e.clientX - rect.left) / rect.width;
    }

    return {
      intro: 'Guide the sloth across San José traffic. Collect 12 mangoes before the siesta timer.',
      start: function () {
        running = true;
        score = 0;
        lives = 3;
        cars = [];
        mangoes = [];
        lastSpawn = 0;
        lastMango = 0;
        startTime = performance.now();
        updateHud();
        bindMovementKeys();
        canvas.onpointerdown = onPointer;
        canvas.onpointermove = function (e) {
          if (e.buttons) onPointer(e);
        };
        canvas.onpointerup = function () {
          pointerX = null;
        };
        canvas.onpointerleave = function () {
          pointerX = null;
        };
        rafId = requestAnimationFrame(tick);
      },
      destroy: function () {
        running = false;
      },
    };
  }

  function createCoffeeGame() {
    var score = 0;
    var misses = 0;
    var running = false;
    var basket = { x: 0.5, w: 0.16 };
    var drops = [];
    var lastDrop = 0;
    var pointerX = null;

    function updateHud() {
      stageHud.textContent = 'Beans ' + score + ' · Spills ' + misses + '/5';
    }

    function endGame() {
      running = false;
      stopLoop();
      writeBestDay(score);
      showOverlay(
        score >= 20 ? 'Barista legend' : 'Brew interrupted',
        'You caught ' + score + ' beans. The volcano remains unimpressed.',
        'Brew again',
        function () {
          openGame('coffee');
        }
      );
    }

    function tick(now) {
      if (!running) return;
      var size = fitCanvasBackingStore();
      var w = size.w;
      var h = size.h;

      if (now - lastDrop > 520) {
        drops.push({
          x: 0.1 + Math.random() * 0.8,
          y: -0.05,
          vy: 0.004 + Math.random() * 0.003,
          rock: Math.random() < 0.22,
        });
        lastDrop = now;
      }

      var move = 0;
      if (keys.ArrowLeft || keys.a || keys.A) move -= 1;
      if (keys.ArrowRight || keys.d || keys.D) move += 1;
      if (pointerX != null) {
        basket.x += (pointerX - basket.x) * 0.2;
      } else {
        basket.x += move * 0.012;
      }
      basket.x = Math.max(0.08, Math.min(0.92, basket.x));

      for (var i = drops.length - 1; i >= 0; i--) {
        var d = drops[i];
        d.y += d.vy;
        if (d.y > 0.9 && Math.abs(d.x - basket.x) < basket.w * 0.55) {
          if (d.rock) {
            misses += 1;
          } else {
            score += 1;
          }
          drops.splice(i, 1);
          updateHud();
          if (misses >= 5) {
            endGame();
            return;
          }
          continue;
        }
        if (d.y > 1.05) {
          if (!d.rock) misses += 1;
          drops.splice(i, 1);
          updateHud();
          if (misses >= 5) {
            endGame();
            return;
          }
        }
      }

      ctx.clearRect(0, 0, w, h);
      var bg = ctx.createLinearGradient(0, 0, 0, h);
      bg.addColorStop(0, '#1b3a4b');
      bg.addColorStop(0.45, '#0b6e8a');
      bg.addColorStop(1, '#5a3a1a');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, w, h);

      // volcano
      ctx.fillStyle = '#3a2a22';
      ctx.beginPath();
      ctx.moveTo(w * 0.2, h * 0.45);
      ctx.lineTo(w * 0.5, h * 0.12);
      ctx.lineTo(w * 0.8, h * 0.45);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = '#e85d4c';
      ctx.beginPath();
      ctx.arc(w * 0.5, h * 0.14, h * 0.04, 0, Math.PI * 2);
      ctx.fill();

      drops.forEach(function (d) {
        ctx.font = Math.floor(0.055 * h) + 'px serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(d.rock ? '🪨' : '☕', d.x * w, d.y * h);
      });

      ctx.fillStyle = '#8b5a2b';
      roundRect(ctx, (basket.x - basket.w / 2) * w, h * 0.88, basket.w * w, h * 0.07, 12);
      ctx.fill();
      ctx.fillStyle = '#fff6e8';
      ctx.font = Math.floor(0.035 * h) + 'px Nunito, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('BASKET', basket.x * w, h * 0.915);

      rafId = requestAnimationFrame(tick);
    }

    function onPointer(e) {
      var rect = canvas.getBoundingClientRect();
      pointerX = (e.clientX - rect.left) / rect.width;
    }

    return {
      intro: 'Catch coffee beans from the Arenal sky. Five spills and the café closes.',
      start: function () {
        running = true;
        score = 0;
        misses = 0;
        drops = [];
        lastDrop = 0;
        updateHud();
        bindMovementKeys();
        canvas.onpointerdown = onPointer;
        canvas.onpointermove = onPointer;
        canvas.onpointerup = function () {
          pointerX = null;
        };
        canvas.onpointerleave = function () {
          pointerX = null;
        };
        rafId = requestAnimationFrame(tick);
      },
      destroy: function () {
        running = false;
      },
    };
  }

  function createMemoryGame() {
    var icons = ['🦥', '🦜', '🌋', '🏄', '☕', '🍍', '🦎', '🌺'];
    var cards = [];
    var flipped = [];
    var matches = 0;
    var flips = 0;
    var locked = false;

    function updateHud() {
      stageHud.textContent = 'Matches ' + matches + '/8 · Flips ' + flips;
    }

    function shuffle(arr) {
      for (var i = arr.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var t = arr[i];
        arr[i] = arr[j];
        arr[j] = t;
      }
      return arr;
    }

    function finish() {
      var bonus = Math.max(0, 40 - flips);
      writeBestDay(bonus + matches * 2);
      showOverlay(
        'Rainforest complete',
        'Matched all pairs in ' + flips + ' flips. Tour guide tip jar: +' + bonus,
        'Shuffle again',
        function () {
          openGame('memory');
        }
      );
    }

    function render() {
      memoryBoard.innerHTML = '';
      cards.forEach(function (card, index) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'memory-card' + (card.faceUp || card.matched ? '' : ' is-face-down') + (card.matched ? ' is-matched' : '');
        btn.textContent = card.faceUp || card.matched ? card.icon : '🇨🇷';
        btn.disabled = card.matched || locked;
        btn.setAttribute('aria-label', card.faceUp || card.matched ? 'Card ' + card.icon : 'Hidden card');
        btn.addEventListener('click', function () {
          if (locked || card.faceUp || card.matched) return;
          card.faceUp = true;
          flipped.push(index);
          flips += 1;
          updateHud();
          render();
          if (flipped.length === 2) {
            locked = true;
            var a = cards[flipped[0]];
            var b = cards[flipped[1]];
            if (a.icon === b.icon) {
              a.matched = true;
              b.matched = true;
              matches += 1;
              flipped = [];
              locked = false;
              updateHud();
              render();
              if (matches >= 8) finish();
            } else {
              setTimeout(function () {
                a.faceUp = false;
                b.faceUp = false;
                flipped = [];
                locked = false;
                render();
              }, 650);
            }
          }
        });
        memoryBoard.appendChild(btn);
      });
    }

    return {
      intro: 'Flip cards and match every Costa Rica icon. Speed is optional; swagger is not.',
      start: function () {
        var deck = icons.concat(icons);
        shuffle(deck);
        cards = deck.map(function (icon) {
          return { icon: icon, faceUp: false, matched: false };
        });
        flipped = [];
        matches = 0;
        flips = 0;
        locked = false;
        updateHud();
        render();
      },
      destroy: function () {
        memoryBoard.innerHTML = '';
      },
    };
  }

  function roundRect(context, x, y, w, h, r) {
    var radius = Math.min(r, w / 2, h / 2);
    context.beginPath();
    context.moveTo(x + radius, y);
    context.arcTo(x + w, y, x + w, y + h, radius);
    context.arcTo(x + w, y + h, x, y + h, radius);
    context.arcTo(x, y + h, x, y, radius);
    context.arcTo(x, y, x + w, y, radius);
    context.closePath();
  }

  document.querySelectorAll('[data-game]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      openGame(btn.getAttribute('data-game'));
    });
  });

  backLobby.addEventListener('click', returnToLobby);

  renderBestDay();

  ensureDecoyAccess().then(function (ok) {
    if (!ok) return;
    gateCheck.hidden = true;
    app.hidden = false;
  });
})();
