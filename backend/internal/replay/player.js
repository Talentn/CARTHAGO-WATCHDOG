// The match replay: draws the recording of one match from above and lets a reviewer play,
// pause, scrub and jump to what was found. It is the only script of the dashboard (the
// match page) and of the community review page. Each serves it from its own origin; it
// loads nothing else and sends nothing anywhere, and the page's Content-Security-Policy
// allows exactly that.
(function () {
  "use strict";

  var root = document.getElementById("match-replay");
  if (!root) return;
  var canvas = root.querySelector("canvas");
  var ctx = canvas.getContext("2d");
  var playBtn = root.querySelector(".mr-play");
  var speedSel = root.querySelector(".mr-speed");
  var seek = root.querySelector(".mr-seek");
  var clockEl = root.querySelector(".mr-clock");
  var ticksEl = root.querySelector(".mr-ticks");
  var statusEl = root.querySelector(".mr-status");

  var css = getComputedStyle(document.documentElement);
  function token(name) { return css.getPropertyValue(name).trim(); }
  var col = {
    page: token("--page"), inset: token("--inset"), line: token("--line-2"), grid: token("--line"),
    text: token("--text"), text2: token("--text-2"), muted: token("--muted"),
    watch: token("--accent"), act: token("--act")
  };
  var mono = token("--mono") || "monospace";

  var rec = null;        // the recording
  var outline = null;    // the outline of the match's map, when the studio registered one
  var mapImg = null;     // its picture, once loaded
  var crossing = {};     // index of a shot whose line crosses a wall line -> true
  var t = Number(root.dataset.t) || 0;
  var focus = Number(root.dataset.focus);
  var playing = false;
  var speed = 1;
  var lastFrame = 0;
  var levels = {};       // slot -> "act" | "watch"
  var teamIndex = {};    // team -> 0, 1, ...
  var view = { w: 0, h: 0, k: 1, ox: 0, oy: 0 };
  // A player whose next known position is more than this far away in time is not drawn in
  // between: the game server stopped sending them (dead, left, not spawned).
  var GAP_STEPS = 8;
  var SHOT_MS = 400, KILL_MS = 1200, TRAIL_STEPS = 16;

  function clock(ms) {
    var s = Math.floor(ms / 1000), h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60;
    var two = function (n) { return (n < 10 ? "0" : "") + n; };
    return h > 0 ? h + ":" + two(m) + ":" + two(s % 60) : two(m) + ":" + two(s % 60);
  }

  function undelta(list) {
    for (var i = 1; i < list.length; i++) list[i] += list[i - 1];
  }

  // The index of the last sample at or before step f, or -1.
  function sampleAt(p, f) {
    var lo = 0, hi = p.t.length - 1, at = -1;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (p.t[mid] <= f) { at = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    return at;
  }

  // Where a player stands and looks at match time ms, or null when they are not in play.
  function pose(p, ms) {
    var f = ms / rec.step_ms;
    var i = sampleAt(p, f);
    if (i < 0) return null;
    var next = i + 1 < p.t.length ? i + 1 : -1;
    if (next < 0 || p.t[next] - p.t[i] > GAP_STEPS) {
      return f - p.t[i] <= GAP_STEPS ? { x: p.x[i], y: p.y[i], yaw: p.yaw[i] } : null;
    }
    var a = (f - p.t[i]) / (p.t[next] - p.t[i]);
    var turn = ((p.yaw[next] - p.yaw[i]) % 360 + 540) % 360 - 180;
    return { x: p.x[i] + (p.x[next] - p.x[i]) * a, y: p.y[i] + (p.y[next] - p.y[i]) * a, yaw: p.yaw[i] + turn * a };
  }

  function fit() {
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    view.w = w; view.h = h;
    if (!rec) return;
    var b = rec.bounds, pad = 40;
    var bw = Math.max(b[2] - b[0], 100), bh = Math.max(b[3] - b[1], 100);
    view.k = Math.min((w - 2 * pad) / bw, (h - 2 * pad) / bh);
    view.ox = (w - bw * view.k) / 2 - b[0] * view.k;
    view.oy = (h + bh * view.k) / 2 + b[1] * view.k;
  }
  function sx(x) { return view.ox + x * view.k; }
  function sy(y) { return view.oy - y * view.k; }

  function colourOf(p) {
    var level = levels[p.slot];
    return level === "act" ? col.act : level === "watch" ? col.watch : null;
  }

  function drawFrame() {
    var b = rec.bounds;
    // Ten metres between grid lines, or fifty when ten would be too tight to read.
    var cell = 1000;
    if (cell * view.k < 24) cell = 5000;
    ctx.lineWidth = 1;
    ctx.strokeStyle = col.grid;
    ctx.beginPath();
    for (var gx = Math.ceil(b[0] / cell) * cell; gx <= b[2]; gx += cell) {
      ctx.moveTo(Math.round(sx(gx)) + 0.5, sy(b[3])); ctx.lineTo(Math.round(sx(gx)) + 0.5, sy(b[1]));
    }
    for (var gy = Math.ceil(b[1] / cell) * cell; gy <= b[3]; gy += cell) {
      ctx.moveTo(sx(b[0]), Math.round(sy(gy)) + 0.5); ctx.lineTo(sx(b[2]), Math.round(sy(gy)) + 0.5);
    }
    ctx.stroke();
    if (outline) drawOutline();
    else {
      ctx.strokeStyle = col.line;
      ctx.strokeRect(Math.round(sx(b[0])) + 0.5, Math.round(sy(b[3])) + 0.5, Math.round((b[2] - b[0]) * view.k), Math.round((b[3] - b[1]) * view.k));
    }
    ctx.fillStyle = col.muted;
    ctx.font = "12px " + mono;
    ctx.textBaseline = "alphabetic";
    ctx.textAlign = "left";
    ctx.fillText("grid " + cell / 100 + " m", 12, view.h - 12);
  }

  // The map, under everything that moves: the studio's picture of it, or its wall lines.
  function drawOutline() {
    var r = outline.rect;
    if (mapImg) {
      ctx.globalAlpha = 0.7;
      ctx.drawImage(mapImg, sx(r[0]), sy(r[3]), (r[2] - r[0]) * view.k, (r[3] - r[1]) * view.k);
      ctx.globalAlpha = 1;
    }
    if (!outline.lines) return;
    ctx.strokeStyle = col.text2;
    ctx.lineWidth = 1.5;
    ctx.lineCap = "square";
    ctx.beginPath();
    for (var i = 0; i < outline.lines.length; i++) {
      var l = outline.lines[i];
      ctx.moveTo(sx(l[0]), sy(l[1])); ctx.lineTo(sx(l[2]), sy(l[3]));
    }
    ctx.stroke();
    ctx.lineCap = "butt";
  }

  function drawShots() {
    var shots = rec.shots;
    // Shots are in time order: find the first one still on screen.
    var lo = 0, hi = shots.length;
    while (lo < hi) {
      var mid = (lo + hi) >> 1;
      if (shots[mid][0] < t - KILL_MS) lo = mid + 1; else hi = mid;
    }
    for (var i = lo; i < shots.length && shots[i][0] <= t; i++) {
      var s = shots[i], age = t - s[0];
      var shooter = bySlot[s[1]], target = s[2] >= 0 ? bySlot[s[2]] : null;
      var from = shooter && pose(shooter, s[0]);
      if (!from) continue;
      var to = target && pose(target, s[0]);
      // A shot across a wall line stays longer and is dashed, so it reads without colour.
      var across = crossing[i] === true;
      if (across && to && age <= KILL_MS) {
        ctx.globalAlpha = 1 - age / KILL_MS * 0.6;
        ctx.strokeStyle = col.text;
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 4]);
        ctx.beginPath(); ctx.moveTo(sx(from.x), sy(from.y)); ctx.lineTo(sx(to.x), sy(to.y)); ctx.stroke();
        ctx.setLineDash([]);
      } else if (age <= SHOT_MS) {
        var ex, ey;
        if (to) { ex = sx(to.x); ey = sy(to.y); } else {
          var rad = from.yaw * Math.PI / 180, reach = 1500;
          ex = sx(from.x + Math.cos(rad) * reach); ey = sy(from.y + Math.sin(rad) * reach);
        }
        ctx.globalAlpha = (1 - age / SHOT_MS) * (s[3] ? 0.9 : 0.45);
        ctx.strokeStyle = col.text;
        ctx.lineWidth = s[3] ? 1.5 : 1;
        ctx.beginPath(); ctx.moveTo(sx(from.x), sy(from.y)); ctx.lineTo(ex, ey); ctx.stroke();
      }
      if (s[4] && to) {
        ctx.globalAlpha = 1 - age / KILL_MS;
        ctx.strokeStyle = col.text;
        ctx.lineWidth = 1.5;
        var kx = sx(to.x), ky = sy(to.y);
        ctx.beginPath(); ctx.moveTo(kx - 6, ky - 6); ctx.lineTo(kx + 6, ky + 6); ctx.moveTo(kx + 6, ky - 6); ctx.lineTo(kx - 6, ky + 6); ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
  }

  function drawPlayer(p) {
    var at = pose(p, t);
    if (!at) return;
    var x = sx(at.x), y = sy(at.y), marked = colourOf(p), ink = marked || col.text;
    var focused = p.slot === focus;

    var f = t / rec.step_ms, i = sampleAt(p, f);
    ctx.strokeStyle = ink;
    ctx.globalAlpha = focused ? 0.6 : 0.25;
    ctx.lineWidth = focused ? 1.5 : 1;
    ctx.beginPath(); ctx.moveTo(x, y);
    for (var j = i; j >= 0 && f - p.t[j] <= TRAIL_STEPS && (j === i || p.t[j + 1] - p.t[j] <= GAP_STEPS); j--) ctx.lineTo(sx(p.x[j]), sy(p.y[j]));
    ctx.stroke();
    ctx.globalAlpha = 1;

    // The view direction: +X is right and +Y is up, so the screen angle is the negative yaw.
    var rad = -at.yaw * Math.PI / 180;
    if (focused) {
      ctx.fillStyle = ink;
      ctx.globalAlpha = 0.14;
      ctx.beginPath(); ctx.moveTo(x, y); ctx.arc(x, y, 56, rad - 0.5, rad + 0.5); ctx.closePath(); ctx.fill();
      ctx.globalAlpha = 1;
    }
    ctx.strokeStyle = ink;
    ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + Math.cos(rad) * 16, y + Math.sin(rad) * 16); ctx.stroke();

    // Team one is a filled dot and team two a ring, so the teams read without colour.
    var hollow = teamIndex[p.team] === 1;
    ctx.beginPath(); ctx.arc(x, y, 5, 0, 2 * Math.PI);
    ctx.fillStyle = hollow ? col.inset : ink;
    ctx.fill();
    ctx.strokeStyle = ink; ctx.lineWidth = 1.5; ctx.stroke();
    if (focused) {
      ctx.beginPath(); ctx.arc(x, y, 10, 0, 2 * Math.PI);
      ctx.strokeStyle = col.text; ctx.lineWidth = 1; ctx.stroke();
    }
    ctx.fillStyle = marked || focused ? col.text : col.muted;
    ctx.font = "11px " + mono;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText(p.label, x + 12, y - 10);
  }

  var bySlot = {};

  function draw() {
    ctx.fillStyle = col.inset;
    ctx.fillRect(0, 0, view.w, view.h);
    if (!rec) return;
    drawFrame();
    drawShots();
    // Marked and highlighted players are drawn last, on top.
    var order = rec.players.slice().sort(function (a, b) {
      return (a.slot === focus) - (b.slot === focus) || !!levels[a.slot] - !!levels[b.slot];
    });
    order.forEach(drawPlayer);
    seek.value = String(Math.round(t));
    clockEl.textContent = clock(t) + " / " + clock(rec.duration_ms);
  }

  function setPlaying(on) {
    playing = on && !!rec;
    playBtn.textContent = playing ? "Pause" : "Play";
    if (playing) {
      if (t >= rec.duration_ms) t = 0;
      lastFrame = 0;
      window.requestAnimationFrame(frame);
    }
  }

  function frame(now) {
    if (!playing) return;
    if (lastFrame) t += Math.min(now - lastFrame, 250) * speed;
    lastFrame = now;
    if (t >= rec.duration_ms) { t = rec.duration_ms; setPlaying(false); }
    draw();
    if (playing) window.requestAnimationFrame(frame);
  }

  function seekTo(ms) {
    t = Math.max(0, Math.min(ms, rec ? rec.duration_ms : ms));
    draw();
  }

  function setFocus(slot) {
    focus = slot;
    document.querySelectorAll(".mr-follow").forEach(function (b) {
      var on = Number(b.dataset.slot) === focus;
      b.setAttribute("aria-pressed", on ? "true" : "false");
      b.textContent = on ? "Highlighted" : "Highlight";
    });
    draw();
  }

  // Every row of the findings table has a jump button; the timeline gets one tick per row.
  function wireMarks() {
    var rank = { act: 2, watch: 1 };
    document.querySelectorAll(".mr-jump").forEach(function (b) {
      var ms = Number(b.dataset.t), slot = Number(b.dataset.slot), level = b.dataset.level;
      if (slot >= 0 && rank[level] && (rank[level] > (rank[levels[slot]] || 0))) levels[slot] = level;
      var jump = function () {
        setPlaying(false);
        // Open a little before the moment, so pressing play shows what led to it.
        if (slot >= 0) setFocus(slot);
        seekTo(Math.max(0, ms - 2000));
        root.scrollIntoView({ block: "nearest" });
      };
      b.addEventListener("click", jump);
      var tick = document.createElement("button");
      tick.type = "button";
      tick.className = "mr-tick lvl-" + level + " kind-" + b.dataset.kind;
      tick.title = b.title;
      tick.setAttribute("aria-label", "Jump to " + b.title);
      tick.style.left = (rec.duration_ms > 0 ? ms / rec.duration_ms * 100 : 0) + "%";
      tick.addEventListener("click", jump);
      ticksEl.appendChild(tick);
    });
    document.querySelectorAll(".mr-follow").forEach(function (b) {
      b.addEventListener("click", function () {
        var slot = Number(b.dataset.slot);
        setFocus(slot === focus ? -1 : slot);
      });
    });
  }

  function start(data) {
    rec = data;
    if (outline) {
      // Show the whole map, not only where the players went.
      var r = outline.rect, b = rec.bounds;
      rec.bounds = [Math.min(b[0], r[0]), Math.min(b[1], r[1]), Math.max(b[2], r[2]), Math.max(b[3], r[3])];
      (outline.crossings || []).forEach(function (i) { crossing[i] = true; });
      if (outline.kind === "image" && outline.src) {
        var img = new Image();
        img.onload = function () { mapImg = img; draw(); };
        img.src = outline.src;
      }
    }
    rec.players.forEach(function (p) {
      undelta(p.t); undelta(p.x); undelta(p.y); undelta(p.yaw);
      p.label = p.name.length > 14 ? p.name.slice(0, 13) + "…" : p.name;
      bySlot[p.slot] = p;
      if (p.team && !(p.team in teamIndex)) teamIndex[p.team] = Object.keys(teamIndex).length;
    });
    wireMarks();
    fit();
    seek.max = String(rec.duration_ms);
    [seek, playBtn, speedSel].forEach(function (el) { el.disabled = false; });
    statusEl.textContent = rec.truncated ? "The match ran past the recording's size cap, so the replay stops early" : "";
    seek.addEventListener("input", function () { setPlaying(false); seekTo(Number(seek.value)); });
    playBtn.addEventListener("click", function () { setPlaying(!playing); });
    speedSel.addEventListener("change", function () { speed = Number(speedSel.value) || 1; });
    if (window.ResizeObserver) new ResizeObserver(function () { fit(); draw(); }).observe(canvas);
    else window.addEventListener("resize", function () { fit(); draw(); });
    setFocus(focus);
    seekTo(t);
  }

  fit();
  draw();
  statusEl.textContent = "Loading the recording";
  // The outline is optional: a match whose map has none, or an outline that fails to load,
  // plays as a match without one.
  var outlineLoaded = !root.dataset.outline ? Promise.resolve(null) :
    fetch(root.dataset.outline, { credentials: "same-origin" })
      .then(function (res) { return res.ok ? res.json() : null; })
      .catch(function () { return null; });
  Promise.all([fetch(root.dataset.src, { credentials: "same-origin" })
    .then(function (res) {
      if (!res.ok) throw new Error("status " + res.status);
      return res.json();
    }), outlineLoaded])
    .then(function (got) { outline = got[1]; start(got[0]); })
    .catch(function () { statusEl.textContent = "The recording could not be loaded. Reload the page to try again"; });
})();
