// Kokino Forensic Toolkit - byte map (in the spirit of binvis.io) and strings.
//
// The byte map lays the data along a Hilbert curve, so bytes that are close
// in the file stay close on screen and structure shows as shapes. Each cell
// is one slice of the data, colored by its byte classes or its entropy.

import { api, h, num, bytes, hexOff, debounce, modal, closeModal } from "./lib.js";

/** Hilbert curve: position d (0..n*n-1) to (x, y) on an n x n grid. */
function d2xy(n, d) {
  let x = 0, y = 0, t = d;
  for (let s = 1; s < n; s *= 2) {
    const rx = 1 & (t / 2), ry = 1 & (t ^ rx);
    if (ry === 0) {
      if (rx === 1) { x = s - 1 - x; y = s - 1 - y; }
      [x, y] = [y, x];
    }
    x += s * rx; y += s * ry; t = Math.floor(t / 4);
  }
  return [x, y];
}

// Byte classes as in binvis.io: 0x00 black, 0xFF white, low (control) green, text blue, high red.
const CLASS = { zero: [0, 0, 0], ff: [255, 255, 255], low: [77, 175, 74], text: [55, 126, 184], high: [228, 26, 28] };

/** Entropy 0..1 to a color: dark blue (repetitive) to magenta to bright pink (random or compressed). */
function entColor(e) {
  const f = (a, b) => Math.round(a + (b - a) * e);
  return e < 0.5 ? [f(10, 120), f(20, 40), f(60, 160)] : [f(-110, 255), f(60, 90), f(280, 180)].map((v) => Math.max(0, Math.min(255, v)));
}

const decode = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/**
 * Byte map widget. `url` returns { start, size, cells, used, per_cell, data }.
 * `onPick(offset)` gets the offset (relative to the data, plus `start`) of a clicked cell.
 */
export function byteMap(url, onPick, { size = 256 } = {}) {
  const canvas = h("canvas.bmap", { width: size, height: size });
  const info = h("div.muted.mono.bmap-info", "Hover a cell; click to open it.");
  let mode = "class";
  const seg = h("div.seg");
  const legend = h("div.bmap-legend");
  let m = null;
  const drawSeg = () => seg.replaceChildren(...[["class", "Byte class"], ["entropy", "Entropy"]].map(([k, l]) => h("button", { class: mode === k ? "on" : null, onclick: () => { mode = k; drawSeg(); draw(); } }, l)));
  const sw = (rgb, label) => h("span", h("i", { style: { background: `rgb(${rgb.join(",")})` } }), label);
  const draw = () => {
    if (!m) return;
    legend.replaceChildren(...(mode === "class"
      ? [sw(CLASS.zero, "0x00"), sw(CLASS.ff, "0xFF"), sw(CLASS.low, "low (control)"), sw(CLASS.text, "text"), sw(CLASS.high, "high (0x80+)")]
      : [sw(entColor(0), "low entropy"), sw(entColor(0.5), ""), sw(entColor(1), "high (compressed / encrypted)")]));
    const n = Math.sqrt(m.cells);
    const img = new ImageData(n, n);
    for (let i = 0; i < m.cells; i++) {
      const [x, y] = d2xy(n, i);
      const o = (y * n + x) * 4;
      if (i >= m.used) { img.data[o + 3] = 0; continue; }
      const c = m.d.subarray(i * 6, i * 6 + 6);
      let rgb;
      if (mode === "entropy") rgb = entColor(c[0] / 255);
      else {
        const t = c[1] + c[2] + c[3] + c[4] + c[5] || 1;
        rgb = [0, 1, 2].map((k) => (CLASS.zero[k] * c[1] + CLASS.ff[k] * c[2] + CLASS.text[k] * c[3] + CLASS.low[k] * c[4] + CLASS.high[k] * c[5]) / t);
      }
      img.data.set([rgb[0], rgb[1], rgb[2], 255], o);
    }
    const tmp = new OffscreenCanvas(n, n);
    tmp.getContext("2d").putImageData(img, 0, 0);
    const ctx = canvas.getContext("2d");
    ctx.imageSmoothingEnabled = false;
    ctx.clearRect(0, 0, size, size);
    ctx.drawImage(tmp, 0, 0, size, size);
  };
  // Cell under the pointer, from canvas pixels back along the curve.
  let xy2d = null;
  const cellAt = (e) => {
    if (!m) return null;
    const r = canvas.getBoundingClientRect();
    const n = Math.sqrt(m.cells);
    const x = Math.floor(((e.clientX - r.left) / r.width) * n), y = Math.floor(((e.clientY - r.top) / r.height) * n);
    if (x < 0 || y < 0 || x >= n || y >= n) return null;
    const i = xy2d[y * n + x];
    return i < m.used ? i : null;
  };
  canvas.addEventListener("mousemove", (e) => {
    const i = cellAt(e);
    if (i == null) return;
    const c = m.d.subarray(i * 6, i * 6 + 6);
    const pct = (v) => Math.round((v / 255) * 100) + "%";
    const off = i * m.per_cell;
    info.textContent = `${hexOff(m.start + off)} +${bytes(Math.min(m.per_cell, m.size - off))}  entropy ${((c[0] / 255) * 8).toFixed(2)}  00 ${pct(c[1])} FF ${pct(c[2])} text ${pct(c[3])} low ${pct(c[4])} high ${pct(c[5])}`;
  });
  canvas.addEventListener("click", (e) => { const i = cellAt(e); if (i != null && onPick) onPick(m.start + i * m.per_cell); });
  const note = h("div.muted", { style: { fontSize: "12px" } }, "Loading...");
  api(url).then((r) => {
    m = { ...r, d: decode(r.data) };
    const n = Math.sqrt(m.cells);
    xy2d = new Uint32Array(m.cells);
    for (let i = 0; i < m.cells; i++) { const [x, y] = d2xy(n, i); xy2d[y * n + x] = i; }
    note.textContent = `${num(m.used)} cells of ${bytes(m.per_cell)} along a Hilbert curve (each sampled from its first 4 KiB), starting top left. ${bytes(m.size)} in all.`;
    draw();
  }).catch((e) => { note.textContent = "Byte map not available: " + e.message; });
  drawSeg();
  return h("div.bmap-wrap", h("div.row.wrap", seg, legend), canvas, info, note);
}

/**
 * Strings panel. `url` is the strings endpoint (without a query);
 * `onPick(offset)` gets a string's offset in the data.
 */
export function stringsPanel(url, onPick) {
  const q = h("input", { placeholder: "Filter strings...", style: { flex: 1 } });
  const min = h("select", [4, 5, 6, 8, 10, 16].map((v) => h("option", { value: v, selected: v === 5 ? "" : null }, `min ${v}`)));
  let enc = "";
  const seg = h("div.seg");
  const drawSeg = () => seg.replaceChildren(...[["", "All"], ["8bit", "ASCII / UTF-8"], ["utf16le", "UTF-16"]].map(([k, l]) => h("button", { class: enc === k ? "on" : null, onclick: () => { enc = k; drawSeg(); load(); } }, l)));
  const count = h("span.muted");
  const tbody = h("tbody");
  const load = debounce(async () => {
    tbody.replaceChildren(h("tr", h("td", { colspan: 3 }, h("div.spin"))));
    try {
      const r = await api(`${url}?min=${min.value}&q=${encodeURIComponent(q.value.trim())}&enc=${enc === "8bit" ? "8bit" : enc}&limit=3000`);
      count.textContent = `${num(r.matches)} of ${num(r.total)} strings${r.matches > r.items.length ? `, first ${num(r.items.length)} shown` : ""}${r.scanned < r.size ? `; first ${bytes(r.scanned)} of ${bytes(r.size)} scanned` : ""}`;
      tbody.replaceChildren(...r.items.map((s) => h("tr", { onclick: onPick ? () => onPick(s.offset) : null, style: { cursor: onPick ? "pointer" : null } },
        h("td.mono.muted", { style: { whiteSpace: "nowrap" } }, hexOff(s.offset, 8)), h("td.muted", { style: { whiteSpace: "nowrap" } }, s.enc), h("td.mono.strtext", s.text))));
    } catch (e) { tbody.replaceChildren(); count.textContent = e.message; }
  }, 250);
  q.addEventListener("input", load);
  min.addEventListener("change", load);
  drawSeg();
  load();
  return h("div.stack", h("div.row.wrap", q, min, seg), count,
    h("div.scroll", { style: { maxHeight: "420px" } }, h("table.tbl.strtbl", h("thead", h("tr", h("th", "Offset"), h("th", "Encoding"), h("th", "Text"))), tbody)));
}

/** Byte map and strings of one file or carved file, in a modal with tabs. */
export function bytesDialog(title, base, onPick, start = "map") {
  let tab = start;
  const body = h("div");
  const seg = h("div.seg");
  const pick = (off) => { closeModal(); onPick(off); };
  const draw = () => {
    seg.replaceChildren(...[["map", "Byte map"], ["strings", "Strings"]].map(([k, l]) => h("button", { class: tab === k ? "on" : null, onclick: () => { tab = k; draw(); } }, l)));
    body.replaceChildren(tab === "map" ? byteMap(base + "/binmap", pick, { size: 384 }) : stringsPanel(base + "/strings", pick));
  };
  draw();
  modal([h("div.hd", h("h2", title), h("span.sp"), seg, h("button.ghost.sm", { onclick: closeModal }, "Close")), body]);
}
