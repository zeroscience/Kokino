// Kokino Forensic Toolkit website. The background is the application's own
// perspective grid (ui/js/lib.js drawTunnel); the download buttons ask
// GitHub for the latest release and fall back to the releases page.
"use strict";

const NS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs) => {
  const e = document.createElementNS(NS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
};

function drawTunnel(host) {
  const W = 2000, H = 1050, cx = 1000, cy = 525, bw = 430, bh = 170, cols = 15, rows = 6;
  const g = svg("g", { class: "tunnel-g", fill: "none", stroke: "var(--grid)", "stroke-width": 1, "vector-effect": "non-scaling-stroke" });
  const Zb = 10, step = 0.62;
  for (let i = 0; ; i++) {
    const z = Zb - i * step;
    const s = Zb / z, w = bw * s, hh = bh * s;
    g.append(svg("rect", { x: cx - w, y: cy - hh, width: 2 * w, height: 2 * hh, opacity: Math.min(1, 0.3 + i * 0.07) }));
    if (z <= step || (w > cx + 200 && hh > cy + 200)) break;
  }
  const ray = (x, y) => svg("line", { x1: x, y1: y, x2: cx + (x - cx) * 8, y2: cy + (y - cy) * 8 });
  for (let i = 0; i <= cols; i++) {
    const x = cx - bw + (i * 2 * bw) / cols;
    g.append(ray(x, cy - bh), ray(x, cy + bh));
  }
  for (let j = 1; j < rows; j++) {
    const y = cy - bh + (j * 2 * bh) / rows;
    g.append(ray(cx - bw, y), ray(cx + bw, y));
  }
  const back = svg("g", { opacity: 0.4 });
  for (let i = 1; i < cols; i++) { const x = cx - bw + (i * 2 * bw) / cols; back.append(svg("line", { x1: x, y1: cy - bh, x2: x, y2: cy + bh })); }
  for (let j = 1; j < rows; j++) { const y = cy - bh + (j * 2 * bh) / rows; back.append(svg("line", { x1: cx - bw, y1: y, x2: cx + bw, y2: y })); }
  g.append(back, svg("rect", { class: "scanline", x: cx - bw, y: cy - bh, width: 2 * bw, height: 1.5, fill: "var(--scan)", stroke: "none" }));
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "xMidYMid slice" });
  root.append(g);
  host.replaceChildren(root);
}

// ---------- theme: the system's, or the visitor's choice (kept in this browser)
const KEY = "kokino-site-theme";
function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else document.documentElement.dataset.theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}
let chosen = null;
try { chosen = localStorage.getItem(KEY); } catch (e) { /* private window */ }
applyTheme(chosen);

// ---------- downloads
const PACKAGES = {
  windows: [[/windows-x64\.msi$/, "Installer (.msi)"], [/windows-x64\.zip$/, ".zip"]],
  linux: [[/_amd64\.deb$/, ".deb"], [/linux-x86_64\.tar\.gz$/, ".tar.gz"]],
  macos: [[/macos-universal\.dmg$/, ".dmg"]],
};

function sizeOf(n) {
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
}

async function latest() {
  const r = await fetch("https://api.github.com/repos/zeroscience/Kokino/releases/latest", { headers: { Accept: "application/vnd.github+json" }, referrerPolicy: "no-referrer" });
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

function showRelease(rel) {
  const v = String(rel.tag_name || "").replace(/^v/, "");
  if (!/^[0-9][0-9A-Za-z.\-]*$/.test(v)) return;
  const pill = document.getElementById("version");
  pill.textContent = `Version ${v}, open source, Apache-2.0`;
  const intro = document.getElementById("dl-intro");
  const when = rel.published_at ? new Date(rel.published_at).toISOString().slice(0, 10) : "";
  intro.replaceChildren(`Kokino ${v}${when ? `, released ${when}` : ""}. Release notes and every file are on `, Object.assign(document.createElement("a"), { href: rel.html_url || "https://github.com/zeroscience/Kokino/releases/latest", rel: "noopener", textContent: "GitHub Releases" }), ".");
  const assets = Array.isArray(rel.assets) ? rel.assets : [];
  for (const box of document.querySelectorAll("[data-assets]")) {
    const links = [];
    for (const [re, label] of PACKAGES[box.dataset.assets] || []) {
      const a = assets.find((x) => re.test(x.name || ""));
      // Only links to GitHub's own download host.
      if (!a || !/^https:\/\/github\.com\/zeroscience\/Kokino\/releases\/download\//.test(a.browser_download_url || "")) continue;
      const el = document.createElement("a");
      el.className = links.length ? "btn" : "btn primary";
      el.href = a.browser_download_url;
      el.rel = "noopener";
      el.textContent = `${label} `;
      const small = document.createElement("small");
      small.textContent = sizeOf(a.size || 0);
      el.append(small);
      links.push(el);
    }
    if (links.length) box.replaceChildren(...links);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  drawTunnel(document.getElementById("ambient"));
  document.getElementById("theme").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem(KEY, next); } catch (e) { /* kept for this page only */ }
  });
  const nav = document.getElementById("nav");
  const menu = document.getElementById("menu");
  menu.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    menu.setAttribute("aria-expanded", String(open));
  });
  nav.addEventListener("click", (e) => {
    if (e.target.tagName === "A") { nav.classList.remove("open"); menu.setAttribute("aria-expanded", "false"); }
  });
  latest().then(showRelease).catch(() => { /* the releases page links stay */ });
});
