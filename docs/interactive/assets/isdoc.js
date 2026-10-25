/* isitsecure interactive docs — tiny animation engine.
   A .scene holds a <figure class="stage"> with an inline SVG and a
   .scene-steps list of .step captions. Step N (1-based) puts classes
   s1…sN on the .scene and data-step="N", so CSS can gate visibility with the
   .at-N / .until-N / .only-N / .lit-N utilities (see isdoc.css). Scenes
   autoplay while on screen, pause when scrolled away or when the reader takes
   the controls, and loop. Each step may fire a JS hook via data-on="fnName". */
(function () {
  "use strict";
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- theme toggle ---------- */
  const root = document.documentElement;
  try { const t = localStorage.getItem("isdoc-theme"); if (t) root.setAttribute("data-theme", t); } catch (e) {}
  function currentDark() {
    const t = root.getAttribute("data-theme");
    if (t) return t === "dark";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  document.querySelectorAll("[data-theme-toggle]").forEach(btn => {
    const paint = () => { btn.textContent = currentDark() ? "☀" : "☾"; btn.setAttribute("aria-label", currentDark() ? "Switch to light theme" : "Switch to dark theme"); };
    paint();
    btn.addEventListener("click", () => {
      const next = currentDark() ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("isdoc-theme", next); } catch (e) {}
      paint();
    });
  });

  /* ---------- code compare tabs ---------- */
  document.querySelectorAll(".code-compare").forEach(box => {
    const tabs = box.querySelectorAll(".tab"), panels = box.querySelectorAll("[role=tabpanel]");
    tabs.forEach((tab, i) => tab.addEventListener("click", () => {
      tabs.forEach((t, j) => t.setAttribute("aria-selected", String(i === j)));
      panels.forEach((p, j) => { p.hidden = i !== j; });
    }));
  });

  /* ---------- scenes ---------- */
  const ICONS = {
    play: '<svg viewBox="0 0 16 16"><path d="M4 2.5v11l9-5.5z"/></svg>',
    pause: '<svg viewBox="0 0 16 16"><rect x="3" y="2.5" width="3.5" height="11"/><rect x="9.5" y="2.5" width="3.5" height="11"/></svg>',
    prev: '<svg viewBox="0 0 16 16"><path d="M12 2.5v11l-7-5.5z"/><rect x="3" y="2.5" width="2" height="11"/></svg>',
    next: '<svg viewBox="0 0 16 16"><path d="M4 2.5v11l7-5.5z"/><rect x="11" y="2.5" width="2" height="11"/></svg>',
    restart: '<svg viewBox="0 0 16 16"><path d="M8 3a5 5 0 1 1-4.6 3H1.8A6.5 6.5 0 1 0 8 1.5V0L4.5 2.5 8 5z"/></svg>'
  };

  class Scene {
    constructor(el) {
      this.el = el;
      this.steps = Array.from(el.querySelectorAll(".scene-steps .step"));
      this.n = this.steps.length;
      this.i = 0;
      this.interval = parseInt(el.dataset.interval || "2600", 10);
      this.loop = el.dataset.loop !== "false";
      this.autoplay = el.dataset.autoplay !== "false" && !reduced;
      this.playing = false;
      this.timer = null;
      this.userStopped = false;
      el.style.setProperty("--interval", this.interval + "ms");
      el.tabIndex = 0;
      this.buildControls();
      this.go(0, true);
      this.observe();
      el.addEventListener("keydown", e => {
        if (e.key === "ArrowRight") { e.preventDefault(); this.manual(() => this.next(true)); }
        if (e.key === "ArrowLeft")  { e.preventDefault(); this.manual(() => this.prev()); }
        if (e.key === " ")          { e.preventDefault(); this.toggle(); }
      });
    }
    buildControls() {
      const c = document.createElement("div");
      c.className = "controls";
      c.innerHTML =
        `<button class="cbtn restart" title="Restart" aria-label="Restart">${ICONS.restart}</button>` +
        `<button class="cbtn prev" title="Previous step" aria-label="Previous step">${ICONS.prev}</button>` +
        `<button class="cbtn play" title="Play / pause" aria-label="Play">${ICONS.play}</button>` +
        `<button class="cbtn next" title="Next step" aria-label="Next step">${ICONS.next}</button>` +
        `<div class="dots" role="tablist"></div><span class="counter tnum"></span>`;
      this.el.appendChild(c);
      this.dots = c.querySelector(".dots");
      this.steps.forEach((_, k) => {
        const d = document.createElement("button");
        d.className = "dot"; d.title = "Step " + (k + 1); d.setAttribute("aria-label", "Go to step " + (k + 1));
        d.addEventListener("click", () => this.manual(() => this.go(k)));
        this.dots.appendChild(d);
      });
      this.counter = c.querySelector(".counter");
      this.playBtn = c.querySelector(".play");
      c.querySelector(".restart").addEventListener("click", () => { this.go(0); if (!this.playing) this.play(); });
      c.querySelector(".prev").addEventListener("click", () => this.manual(() => this.prev()));
      c.querySelector(".next").addEventListener("click", () => this.manual(() => this.next(true)));
      this.playBtn.addEventListener("click", () => this.toggle());
    }
    manual(fn) { this.userStopped = true; this.pause(); fn(); }
    go(k, silent) {
      this.i = Math.max(0, Math.min(this.n - 1, k));
      const cls = ["scene", "is-ready"];
      if (this.playing) cls.push("is-playing");
      for (let s = 1; s <= this.i + 1; s++) cls.push("s" + s);
      this.el.className = cls.join(" ");
      this.el.dataset.step = String(this.i + 1);
      this.steps.forEach((st, j) => st.classList.toggle("is-active", j === this.i));
      Array.from(this.dots.children).forEach((d, j) => {
        d.classList.toggle("done", j < this.i); d.classList.toggle("cur", j === this.i);
        d.setAttribute("aria-selected", String(j === this.i));
      });
      this.counter.textContent = (this.i + 1) + " / " + this.n;
      const hook = this.steps[this.i].dataset.on;
      if (hook && typeof window[hook] === "function") { try { window[hook](this, this.i + 1, this.el); } catch (e) { console.error(e); } }
      this.el.dispatchEvent(new CustomEvent("step", { detail: { index: this.i + 1, scene: this } }));
      if (this.playing) this.arm();
    }
    arm() {
      clearTimeout(this.timer);
      const last = this.i === this.n - 1;
      const wait = last ? this.interval * 1.6 : this.interval;
      this.timer = setTimeout(() => {
        if (!this.playing) return;
        if (last) { if (this.loop) this.go(0); else this.pause(); }
        else this.next();
      }, wait);
    }
    next(stopAtEnd) { if (this.i < this.n - 1) this.go(this.i + 1); else if (!stopAtEnd) this.go(0); }
    prev() { this.go(Math.max(0, this.i - 1)); }
    play() {
      this.playing = true; this.userStopped = false;
      this.el.classList.add("is-playing");
      this.playBtn.innerHTML = ICONS.pause; this.playBtn.setAttribute("aria-label", "Pause");
      // restart the fill bar on the current dot
      const cur = this.dots.querySelector(".cur"); if (cur) { cur.classList.remove("cur"); void cur.offsetWidth; cur.classList.add("cur"); }
      this.arm();
    }
    pause() {
      this.playing = false; clearTimeout(this.timer);
      this.el.classList.remove("is-playing");
      this.playBtn.innerHTML = ICONS.play; this.playBtn.setAttribute("aria-label", "Play");
    }
    toggle() { if (this.playing) { this.userStopped = true; this.pause(); } else this.play(); }
    observe() {
      if (!("IntersectionObserver" in window)) { if (this.autoplay) this.play(); return; }
      const io = new IntersectionObserver(entries => {
        entries.forEach(en => {
          if (en.isIntersecting) { if (this.autoplay && !this.userStopped && !this.playing) this.play(); }
          else if (this.playing) { this.pause(); }
        });
      }, { threshold: 0.35 });
      io.observe(this.el);
    }
  }

  const scenes = {};
  document.querySelectorAll("[data-scene]").forEach(el => { const s = new Scene(el); if (el.id) scenes[el.id] = s; });

  /* ---------- helpers for step hooks ---------- */
  const SVGNS = "http://www.w3.org/2000/svg";
  /** Animate a small dot along an SVG path. `path` is a <path> element or a
      "d" string. Returns the created element (removed after `hold` ms unless
      `keep`). Uses SMIL so it works inside any inline SVG. */
  function packet(svg, path, opts) {
    opts = opts || {};
    const d = typeof path === "string" ? path : path.getAttribute("d");
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("r", opts.r || 6);
    c.setAttribute("class", "packet " + (opts.cls || "f-accent"));
    if (opts.label) {
      const g = document.createElementNS(SVGNS, "g"); g.setAttribute("class", "packet");
      const t = document.createElementNS(SVGNS, "text");
      t.setAttribute("class", "mono"); t.setAttribute("text-anchor", "middle"); t.setAttribute("dy", "-10");
      t.textContent = opts.label; g.appendChild(c); g.appendChild(t);
      return motion(svg, g, d, opts);
    }
    return motion(svg, c, d, opts);
  }
  function motion(svg, node, d, opts) {
    const dur = reduced ? 1 : (opts.duration || 900);
    const am = document.createElementNS(SVGNS, "animateMotion");
    am.setAttribute("dur", dur + "ms"); am.setAttribute("fill", "freeze"); am.setAttribute("path", d);
    am.setAttribute("calcMode", "spline"); am.setAttribute("keySplines", "0.4 0 0.2 1"); am.setAttribute("keyTimes", "0;1");
    if (opts.delay) am.setAttribute("begin", opts.delay + "ms"); else am.setAttribute("begin", "0ms");
    node.appendChild(am);
    (opts.layer || svg).appendChild(node);
    if (!opts.keep) setTimeout(() => node.remove(), dur + (opts.delay || 0) + (opts.hold == null ? 300 : opts.hold));
    return node;
  }
  /** Remove all packets in an svg (call at the start of a step hook). */
  function clearPackets(svg) { svg.querySelectorAll(".packet").forEach(p => p.remove()); }
  /** Type text into an element, character by character. */
  function typeText(el, text, ms) {
    if (el._typing) clearInterval(el._typing);
    if (reduced) { el.textContent = text; return; }
    el.textContent = ""; let k = 0;
    el._typing = setInterval(() => { el.textContent = text.slice(0, ++k); if (k >= text.length) clearInterval(el._typing); }, ms || 28);
  }
  /** Count a number up in an element. */
  function count(el, to, ms, fmt) {
    const from = parseFloat(el.textContent) || 0; const t0 = performance.now(); const dur = reduced ? 1 : (ms || 800);
    fmt = fmt || (v => Math.round(v));
    function tick(t) { const p = Math.min(1, (t - t0) / dur); const e = 1 - Math.pow(1 - p, 3); el.textContent = fmt(from + (to - from) * e); if (p < 1) requestAnimationFrame(tick); }
    requestAnimationFrame(tick);
  }
  window.IsDoc = { scenes, packet, clearPackets, typeText, count, reduced };
})();
