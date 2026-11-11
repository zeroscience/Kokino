// Shared helpers: API client, DOM builder, formatting, motion.

// The session lives in an HttpOnly cookie. Every request carries
// x-requested-with, which the server requires for state changes (CSRF).
// A 401 or a forced password change raises a "kokino:auth" event so the
// app can show the sign-in screen without losing the current route.
export async function api(path, opts = {}) {
  const res = await fetch("/api" + path, {
    method: opts.method || "GET",
    credentials: "same-origin",
    headers: { "x-requested-with": "kokino", ...(opts.body ? { "content-type": "application/json" } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = { error: text }; }
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    err.status = res.status;
    if (!opts.quiet && (res.status === 401 || (res.status === 403 && data.error === "password change required"))) {
      window.dispatchEvent(new CustomEvent("kokino:auth", { detail: { status: res.status, error: data.error } }));
    }
    throw err;
  }
  return data;
}

/** URL usable in <a href> for downloads; the session cookie authenticates it. */
export function apiUrl(path) {
  return "/api" + path;
}

/** h("div.card#id", {attrs/on*}, ...children) */
export function h(sel, attrs, ...kids) {
  if (attrs == null || typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs)) {
    if (attrs != null) kids.unshift(attrs);
    attrs = {};
  }
  const [, tag = "div", rest = ""] = sel.match(/^([a-z0-9]*)(.*)$/i);
  const el = document.createElement(tag || "div");
  for (const part of rest.match(/[.#][^.#]+/g) || []) {
    if (part[0] === ".") el.classList.add(part.slice(1));
    else el.id = part.slice(1);
  }
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k === "class") el.classList.add(...String(v).split(/\s+/).filter(Boolean));
    else if (k === "html") el.innerHTML = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}

export const $ = (s, root = document) => root.querySelector(s);

export function svg(tag, attrs = {}, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const k of kids.flat()) if (k) el.append(k);
  return el;
}

/**
 * Background: a perspective grid tunnel (an evidence room seen head-on).
 * Frames sit at evenly spaced world depths, so they spread out toward the
 * viewer; rails run from each division of the back wall out to the edges.
 * Colors come from --grid / --scan, so both themes work.
 */
export function drawTunnel(host) {
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
  host.replaceChildren(svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "xMidYMid slice" }, g));
}

export function bytes(n) {
  if (n == null) return "";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${n} B` : `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}

export const num = (n) => Number(n || 0).toLocaleString("en-US");

// ---------------------------------------------------------------- time zone
// Stored times are UTC. They are shown in the display zone: the examiner's
// own (the browser's) unless they pick UTC or another zone. Times stored as
// a device's local clock with no zone (FAT, EXIF) are shown as stored.
const TZ_KEY = "kokino.tz";
const browserZone = () => {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; } catch (e) { return "UTC"; }
};
let tzChoice = (() => { try { return localStorage.getItem(TZ_KEY) || "local"; } catch (e) { return "local"; } })();

// Date order: day first by default (as in North Macedonia and most of
// Europe); ISO or US order on request.
const DF_KEY = "kokino.datefmt";
export const DATE_FORMATS = { dmy: "dd-mm-yyyy", ymd: "yyyy-mm-dd", mdy: "mm/dd/yyyy" };
let dfChoice = (() => { try { const v = localStorage.getItem(DF_KEY); return DATE_FORMATS[v] ? v : "dmy"; } catch (e) { return "dmy"; } })();
export const dateFormat = () => dfChoice;
/** "dd-mm-yyyy" and so on, for placeholders and hints. */
export const datePattern = () => DATE_FORMATS[dfChoice];
export function setDateFormat(f) {
  dfChoice = DATE_FORMATS[f] ? f : "dmy";
  try { localStorage.setItem(DF_KEY, dfChoice); } catch (e) { /* kept for this tab only */ }
}
const fmtDate = (y, m, d) => (dfChoice === "ymd" ? `${y}-${m}-${d}` : dfChoice === "mdy" ? `${m}/${d}/${y}` : `${d}-${m}-${y}`);

/** "local", "UTC" or an IANA zone name. */
export const zoneChoice = () => tzChoice;
/** The zone times are shown in: an IANA name such as "Europe/Amsterdam", or "UTC". */
export const zone = () => (tzChoice === "local" ? browserZone() : tzChoice);
export const localZone = browserZone;
export function setZone(z) {
  tzChoice = z || "local";
  try { localStorage.setItem(TZ_KEY, tzChoice); } catch (e) { /* kept for this tab only */ }
}
const isUtc = (z) => z === "UTC" || z === "Etc/UTC" || z === "GMT";
/** Short name for headings: "UTC", or the zone's city ("Amsterdam"). */
export const zoneName = () => (isUtc(zone()) ? "UTC" : zone().split("/").pop().replace(/_/g, " "));
/** One sentence for page introductions. */
export const zoneSentence = () => (isUtc(zone()) ? "Times are UTC." : `Times are ${zoneName()} time (${zone()}); stored as UTC.`);

const fmts = new Map();
function partsIn(ms, z) {
  let f = fmts.get(z);
  if (!f) {
    f = new Intl.DateTimeFormat("en-GB", { timeZone: z, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    fmts.set(z, f);
  }
  const o = {};
  for (const p of f.formatToParts(ms)) o[p.type] = p.value;
  return o;
}
/** Minutes the zone is ahead of UTC at instant `ms`. */
function offsetMinutes(ms, z) {
  if (isUtc(z)) return 0;
  const p = partsIn(ms, z);
  const wall = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second);
  return Math.round((wall - Math.floor(ms / 1000) * 1000) / 60000);
}
/** "UTC+2", "UTC-3:30", or "UTC", for the display zone at instant `ms`. */
export function offsetLabel(ms, z = zone()) {
  const m = offsetMinutes(ms, z);
  if (!m) return "UTC";
  const a = Math.abs(m);
  return `UTC${m > 0 ? "+" : "-"}${Math.floor(a / 60)}${a % 60 ? ":" + String(a % 60).padStart(2, "0") : ""}`;
}

/**
 * A stored time for people, day first, in the display zone:
 * "2021-07-01T12:37:00.1234567Z" -> "01-07-2021 14:37:00.1234567" (Amsterdam).
 * EXIF's "2021:07:01 12:37:00" too. `len` keeps what the first `len`
 * characters of the ISO form would: 10 the date, 16 to the minute, 19 to the
 * second; without it, everything. Options: `raw` shows a device-local time
 * (FAT) as stored, `label` adds the UTC offset. Only times marked UTC ("Z" or
 * an offset) are converted. Anything else comes back as it is.
 */
export function ts(s, len, opt = {}) {
  if (!s) return "";
  const m = /^(\d{4})[-:](\d{2})[-:](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(\.\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/.exec(String(s).trim());
  if (!m) return s;
  let [, y, mo, d, hh, mi, ss = "00", frac = "", tz] = m;
  let label = "";
  if (hh != null && tz && !opt.raw) {
    const off = tz === "Z" ? 0 : (tz[0] === "-" ? -1 : 1) * (+tz.slice(1, 3) * 60 + +tz.slice(-2));
    const ms = Date.UTC(+y, +mo - 1, +d, +hh, +mi, +ss) - off * 60000;
    const z = zone();
    if (!isNaN(ms)) {
      if (!isUtc(z)) ({ year: y, month: mo, day: d, hour: hh, minute: mi, second: ss } = partsIn(ms, z));
      label = offsetLabel(ms, z);
    }
  }
  const time = hh == null ? "" : `${hh}:${mi}:${ss}${frac}`;
  const shown = len ? time.slice(0, Math.max(0, len - 11)) : time;
  return fmtDate(y, mo, d) + (shown ? " " + shown : "") + (opt.label && label && shown ? " " + label : "");
}

/** The UTC instant (ISO) where day "yyyy-mm-dd" starts in the display zone. */
export function dayStart(iso) {
  const [y, m, d] = iso.split("-").map(Number);
  const guess = Date.UTC(y, m - 1, d);
  const z = zone();
  let t = guess - offsetMinutes(guess, z) * 60000;
  t = guess - offsetMinutes(t, z) * 60000; // again, in case a DST change falls in between
  return new Date(t).toISOString();
}

/** A day typed in the chosen order (d.m.yyyy, or m/d/yyyy for US order), or ISO yyyy-mm-dd, to "yyyy-mm-dd"; "" if empty, null if not a date. */
export function parseDay(s) {
  const t = String(s || "").trim();
  if (!t) return "";
  const m = /^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{4})$/.exec(t);
  const [dd, mm] = m ? (dfChoice === "mdy" ? [m[2], m[1]] : [m[1], m[2]]) : [];
  const iso = m ? `${m[3]}-${mm.padStart(2, "0")}-${dd.padStart(2, "0")}` : (/^\d{4}-\d{2}-\d{2}$/.test(t) ? t : null);
  if (!iso) return null;
  const d = new Date(iso + "T00:00:00Z");
  return !isNaN(d) && d.toISOString().slice(0, 10) === iso ? iso : null;
}

export function hexOff(n, w = 12) {
  return Number(n).toString(16).toUpperCase().padStart(w, "0");
}

// Error log: every error shown as a toast is kept (newest first, at most
// 100, in this browser), so it can be read after the toast is gone.
const ERR_KEY = "kokino.errors";
let errs = (() => { try { return JSON.parse(localStorage.getItem(ERR_KEY) || "[]"); } catch (e) { return []; } })();
let errListeners = [];
const saveErrs = () => { try { localStorage.setItem(ERR_KEY, JSON.stringify(errs)); } catch (e) { /* kept for this tab */ } errListeners.forEach((f) => f()); };
/** Logged errors: [{ t: ISO time, msg, seen }], newest first. */
export const errorLog = () => errs;
export function onErrorLog(f) { errListeners.push(f); }
export function markErrorsSeen() { errs = errs.map((e) => ({ ...e, seen: true })); saveErrs(); }
export function clearErrorLog() { errs = []; saveErrs(); }
function logError(msg) {
  const text = String(msg);
  // The same message again within a second (a retry loop) is kept once.
  if (errs[0] && errs[0].msg === text && Date.now() - Date.parse(errs[0].t) < 1000) return;
  errs = [{ t: new Date().toISOString(), msg: text, seen: false }, ...errs].slice(0, 100);
  saveErrs();
}

export function toast(msg, bad = false) {
  if (bad) logError(msg);
  const t = h("div.toast" + (bad ? ".bad" : ""), msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => { t.style.transition = "opacity .4s, transform .4s"; t.style.opacity = 0; t.style.transform = "translateY(10px)"; }, 3800);
  setTimeout(() => t.remove(), 4300);
}

const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Critically-damped-ish spring from a to b, calling fn(v) each frame. */
export function spring(from, to, fn, { stiffness = 120, damping = 16, mass = 1 } = {}) {
  if (reduce) { fn(to); return; }
  let x = from, v = 0, last = performance.now();
  const step = (now) => {
    const dt = Math.min(0.032, (now - last) / 1000);
    last = now;
    const a = (-stiffness * (x - to) - damping * v) / mass;
    v += a * dt;
    x += v * dt;
    fn(x);
    if (Math.abs(v) > 0.001 || Math.abs(x - to) > 0.001) requestAnimationFrame(step);
    else fn(to);
  };
  requestAnimationFrame(step);
}

/** Animated integer counter. */
export function countUp(el, to, fmt = num) {
  if (reduce) { el.textContent = fmt(to); return; }
  const start = performance.now(), dur = 1100;
  const step = (now) => {
    const p = Math.min(1, (now - start) / dur);
    const e = 1 - Math.pow(1 - p, 4);
    el.textContent = fmt(Math.round(to * e));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

export function modal(content) {
  const m = document.getElementById("modal");
  m.replaceChildren(h("div.card", content));
  m.classList.add("open");
  m.onclick = (e) => { if (e.target === m) closeModal(); };
  return m;
}

export function closeModal() {
  const m = document.getElementById("modal");
  m.classList.remove("open");
  m.replaceChildren();
}

export function debounce(fn, ms = 250) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// Small stroke icons (24x24 grid), drawn here so the UI needs no icon font.
const ICONS = {
  folder: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z",
  file: "M6 3h8l4 4v14H6Z M14 3v4h4",
  exe: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2",
  doc: "M6 3h8l4 4v14H6Z M9 12h6 M9 16h6 M9 8h2",
  image: "M4 5h16v14H4Z M4 16l5-5 4 4 3-3 4 4 M15 9h.01",
  archive: "M4 7h16v13H4Z M3 4h18v3H3Z M10 11h4",
  db: "M5 6c0-1.7 3.1-3 7-3s7 1.3 7 3-3.1 3-7 3-7-1.3-7-3Z M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6 M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3",
  key: "M8 15a4 4 0 1 1 0-8 4 4 0 0 1 0 8Z M12 11h9 M18 11v3 M15 11v2",
  lens: "M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z M16 16l5 5",
  dot: "M12 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z",
  chev: "M9 6l6 6-6 6",
  cases: "M4 4h7v7H4Z M13 4h7v7h-7Z M4 13h7v7H4Z M13 13h7v7h-7Z",
  disk: "M3 6h18v12H3Z M7 14h.01 M11 14h6",
  chain: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1 M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  pie: "M12 3a9 9 0 1 0 9 9h-9Z M14 3.2A9 9 0 0 1 20.8 10H14Z",
  tree: "M4 5h6 M4 12h16 M4 19h10 M4 5v14",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M12 7v5l3 2",
  alert: "M12 3l10 18H2Z M12 10v4 M12 17h.01",
  hex: "M8 5l-5 7 5 7 M16 5l5 7-5 7 M13.5 4l-3 16",
  orphan: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z M10 11l4 4 M14 11l-4 4",
  up: "M12 19V5 M6 11l6-6 6 6",
  users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z M2 21a7 7 0 0 1 14 0 M17 3.5a4 4 0 0 1 0 7 M19 14a7 7 0 0 1 3 7",
  user: "M12 12a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9Z M4 21a8 8 0 0 1 16 0",
  lock: "M6 11h12v10H6Z M8.5 11V7.5a3.5 3.5 0 0 1 7 0V11 M12 15v2",
  logout: "M15 4h4v16h-4 M10 8l-4 4 4 4 M6 12h10",
  trash: "M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13 M10 11v6 M14 11v6",
  book: "M4 5a2 2 0 0 1 2-2h13v15H6a2 2 0 0 0-2 2Z M4 20a2 2 0 0 0 2 2h13v-4 M8 7h7 M8 11h5",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M12 11v6 M12 7.5h.01",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z M20 20l-4.2-4.2",
  monitor: "M3 4h18v12H3Z M8 20h8 M12 16v4",
  layers: "M12 3l9 5-9 5-9-5Z M3 13l9 5 9-5 M3 17l9 5 9-5",
  star: "M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.8l6.1-.9Z",
  mail: "M3 6h18v12H3Z M3 7l9 6 9-6",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M3 12h18 M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9 M12 3c-2.5 2.6-3.8 5.6-3.8 9s1.3 6.4 3.8 9",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6Z M9 12l2 2 4-4",
  download: "M12 4v11 M7 10l5 5 5-5 M5 20h14",
  hash: "M9 4l-2 16 M17 4l-2 16 M4 9h16 M3 15h16",
};

export function icon(name, size = 16) {
  const s = svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", class: "icn" });
  for (const d of (ICONS[name] || ICONS.dot).split(" M").map((p, i) => (i ? "M" + p : p))) s.append(svg("path", { d }));
  return s;
}

/** Icon for a file row, chosen by detected content category. */
export function fileIcon(r) {
  if (r.is_dir) return icon("folder");
  const m = { executable: "exe", document: "doc", image: "image", archive: "archive", database: "db", crypto: "key", forensic: "lens" };
  return icon(m[r.category] || "file");
}
