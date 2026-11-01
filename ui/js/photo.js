// Pictures: the evidence-wide list of analyzed images and the photo
// forensics viewer (magnifier, error level, noise, level sweep, luminance
// gradient, bit planes, clone detection, thumbnail comparison, compression
// and hidden-data panels, region bookmarks).
//
// Pixel views are computed here in the browser on the bytes the server
// serves; everything stated as a finding comes from the server.

import { api, apiUrl, h, svg, icon, num, bytes, ts, toast } from "./lib.js";

let K; // helpers from app.js
export function photoInit(k) { K = k; }

const srcPath = (cid, eid, s) => s.kind === "carved" ? `/cases/${cid}/evidence/${eid}/carved/${s.id}` : `/cases/${cid}/evidence/${eid}/fs/${s.fi}/file/${s.idx}`;
const imageUrl = (cid, eid, s) => apiUrl(srcPath(cid, eid, s) + (s.kind === "carved" ? "/preview" : "/image"));
export const viewerHref = (cid, eid, s, region) => `#/c/${cid}/e/${eid}/photo?${s.kind === "carved" ? `carved=${s.id}` : `fi=${s.fi}&idx=${s.idx}`}${region ? `&region=${region.join(",")}` : ""}`;
const srcOfRow = (x) => (x.carved != null ? { kind: "carved", id: x.carved } : { kind: "file", fi: x.fi, idx: x.idx });

// ---------------------------------------------------------------- list

export async function photosTab(ctx) {
  const { cid, eid } = ctx;
  const base = `/cases/${cid}/evidence/${eid}/photos`;
  const { result: r, rules } = await api(base);
  const R = Object.fromEntries(rules.map((x) => [x.id, x]));
  const job = K.state.jobs.find((j) => j.evidence === eid && j.state === "running");
  const start = () => api(base, { method: "POST" }).then((j) => { toast("Analyzing pictures"); K.kickJobs(j); K.route(); }).catch((e) => toast(e.message, true));
  const flagged = r ? r.images.filter((i) => i.findings.some((f) => R[f.id] && R[f.id].flag)) : [];
  const intro = h("div.hd", h("div", h("h1", "Pictures"),
    h("div.muted", r
      ? `${num(r.images.length)} picture${r.images.length === 1 ? "" : "s"} (JPEG, PNG, BMP: live, deleted and carved), ${num(flagged.length)} with findings. Analyzed ${ts(r.scanned_at, 16)}.`
      : "Every JPEG, PNG and BMP in the evidence, checked for editing, re-saving and hidden data.")),
    h("span.sp"),
    r && K.canWrite() && !job ? h("button.sm", { onclick: start, title: "Analyze every picture again" }, "Analyze again") : null);
  if (!r) {
    return K.render(h("div.stack", intro, h("div.card.empty.stack",
      job ? [h("div.spin"), h("p", "Working..."), h("span", { "data-job-ev": eid }, K.jobPill(job))]
        : [h("p", "Kokino reads each picture's EXIF, compression tables and history, EXIF thumbnail, software traces, data after the end of the image and, for PNG and BMP, the least significant bits."),
          K.canWrite() ? h("button.primary", { onclick: start }, "Analyze pictures") : h("p.muted", "Ask an examiner on this case to run it.")])));
  }
  const counts = {};
  for (const i of r.images) for (const f of new Set(i.findings.map((f) => f.id))) counts[f] = (counts[f] || 0) + 1;
  const filters = [
    ["", `All (${num(r.images.length)})`],
    ["flagged", `Flagged (${num(flagged.length)})`],
    ...rules.filter((x) => counts[x.id]).map((x) => [x.id, `${x.title} (${num(counts[x.id])})`]),
    ["deleted", `Deleted (${num(r.images.filter((i) => i.deleted && i.source === "file").length)})`],
    ["carved", `Carved (${num(r.images.filter((i) => i.source === "carved").length)})`],
  ];
  let filter = filters.some((f) => f[0] === ctx.q.f) ? ctx.q.f : flagged.length ? "flagged" : "";
  let view = ctx.q.view === "table" ? "table" : "gallery";
  let q = "", limit = 300;
  const seg = h("div.seg.wrap"), viewSeg = h("div.seg"), out = h("div");
  const search = h("input", { placeholder: "Filter by name, camera, software...", style: { width: "260px" }, oninput: (e) => { q = e.target.value.toLowerCase(); limit = 300; draw(); } });
  const pills = (i) => i.findings.filter((f) => R[f.id] && R[f.id].flag).map((f) => h("span.pill.bad", { title: f.detail }, R[f.id].title));
  const open = (i) => { location.hash = viewerHref(cid, eid, srcOfRow(i)); };
  const draw = () => {
    seg.replaceChildren(...filters.map(([k, l]) => h("button", { class: filter === k ? "on" : null, onclick: () => { filter = k; limit = 300; draw(); } }, l)));
    viewSeg.replaceChildren(...[["gallery", "Gallery"], ["table", "Table"]].map(([k, l]) => h("button", { class: view === k ? "on" : null, onclick: () => { view = k; draw(); } }, l)));
    history.replaceState(null, "", `#/c/${cid}/e/${eid}/photos?view=${view}${filter ? `&f=${filter}` : ""}`);
    const list = r.images.filter((i) =>
      (!filter || (filter === "flagged" ? i.findings.some((f) => R[f.id] && R[f.id].flag) : filter === "deleted" ? i.deleted && i.source === "file" : filter === "carved" ? i.source === "carved" : i.findings.some((f) => f.id === filter)))
      && (!q || [i.name, i.path, i.make, i.model, i.software, i.taken].join(" ").toLowerCase().includes(q)));
    const shown = list.slice(0, limit);
    const more = list.length > limit ? h("button", { onclick: () => { limit += 300; draw(); } }, `Show more (${num(list.length - limit)} left)`) : null;
    if (!list.length) return out.replaceChildren(h("div.card.empty", "None."));
    if (view === "gallery") {
      out.replaceChildren(h("div.carved-grid", shown.map((i) => h("div.card.flat.carved-tile", { onclick: () => open(i), title: i.path },
        i.error && !i.width ? h("div.carved-icon", (i.format || "?").slice(0, 4)) : h("img", { src: imageUrl(cid, eid, srcOfRow(i)), loading: "lazy", alt: "" }),
        h("div.ell", { style: { color: i.deleted ? "var(--del)" : null } }, h("b", i.name)),
        h("div.muted.ell", [i.make, i.model].filter(Boolean).join(" ") || `${i.format} ${i.width}x${i.height}`),
        h("div.row.wrap", { style: { gap: "4px" } }, pills(i))))), ...(more ? [more] : []));
    } else {
      out.replaceChildren(h("div.scroll", { style: { maxHeight: "calc(100vh - 300px)" } }, h("table.tbl.sys",
        h("thead", h("tr", ["Picture", "Camera", "Taken (EXIF)", "Software", "Compression", "Double JPEG", "Thumbnail", "Findings"].map((c) => h("th", c)))),
        h("tbody", shown.map((i) => h("tr", { class: i.deleted ? "deleted" : null, onclick: () => open(i) },
          h("td.nm", h("b", i.name), h("div.muted.mono.ell", { title: i.path }, i.path), i.error ? h("div.muted", i.error) : null),
          h("td", [i.make, i.model].filter(Boolean).join(" ")), h("td.mono", ts(i.taken)),
          h("td.muted.ell", { title: i.software, style: { maxWidth: "200px" } }, i.software),
          h("td", i.quality != null ? `${i.tables} Q${i.quality}` : ""),
          h("td.num", i.double_score != null ? i.double_score.toFixed(3) : ""),
          h("td.num", i.thumb_diff != null ? (i.thumb_diff >= 9 ? "shape" : i.thumb_diff.toFixed(2)) : ""),
          h("td", h("div.row.wrap", { style: { gap: "4px" } }, pills(i)))))))), ...(more ? [more] : []));
    }
  };
  draw();
  K.render(h("div.stack", intro,
    h("div.row.wrap", seg, h("span.sp"), search, viewSeg),
    h("p.muted", { style: { fontSize: "12.5px" } }, "Findings point to where to look; each one says what it does and does not prove. Click a picture for the viewer: magnifier, error level, noise, level sweep, gradient, bit planes, clone detection and the thumbnail comparison."),
    out));
}

// ---------------------------------------------------------------- pixel views

const lum = (d, i) => 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];

function lumaPlane(img) {
  const { data: d, width: w, height: hh } = img;
  const y = new Float32Array(w * hh);
  for (let p = 0, i = 0; p < y.length; p++, i += 4) y[p] = lum(d, i);
  return y;
}

function gray(w, hh, f) {
  const out = new ImageData(w, hh);
  const o = out.data;
  for (let p = 0, i = 0; p < w * hh; p++, i += 4) { const v = f(p); o[i] = o[i + 1] = o[i + 2] = v; o[i + 3] = 255; }
  return out;
}

async function elaView(src, canvas, quality, amp) {
  const blob = await new Promise((res) => canvas.toBlob(res, "image/jpeg", quality / 100));
  const bmp = await createImageBitmap(blob);
  const c = new OffscreenCanvas(src.width, src.height);
  const x = c.getContext("2d");
  x.drawImage(bmp, 0, 0);
  const re = x.getImageData(0, 0, src.width, src.height).data;
  const out = new ImageData(src.width, src.height);
  const a = src.data, o = out.data;
  for (let i = 0; i < a.length; i += 4) {
    o[i] = Math.min(255, Math.abs(a[i] - re[i]) * amp);
    o[i + 1] = Math.min(255, Math.abs(a[i + 1] - re[i + 1]) * amp);
    o[i + 2] = Math.min(255, Math.abs(a[i + 2] - re[i + 2]) * amp);
    o[i + 3] = 255;
  }
  return out;
}

function noiseView(src, amp) {
  const w = src.width, hh = src.height, y = lumaPlane(src);
  const m = new Float32Array(9);
  return gray(w, hh, (p) => {
    const px = p % w, py = (p / w) | 0;
    if (px === 0 || py === 0 || px === w - 1 || py === hh - 1) return 0;
    let k = 0;
    for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) m[k++] = y[p + dy * w + dx];
    m.sort();
    return Math.min(255, Math.abs(y[p] - m[4]) * amp);
  });
}

function sweepView(src, level, width) {
  const y = lumaPlane(src), lo = level - width / 2;
  return gray(src.width, src.height, (p) => Math.max(0, Math.min(255, ((y[p] - lo) / Math.max(1, width)) * 255)));
}

function gradientView(src, amp) {
  const w = src.width, hh = src.height, y = lumaPlane(src);
  const out = new ImageData(w, hh), o = out.data;
  for (let py = 1; py < hh - 1; py++) for (let px = 1; px < w - 1; px++) {
    const p = py * w + px;
    const gx = (y[p - w + 1] + 2 * y[p + 1] + y[p + w + 1]) - (y[p - w - 1] + 2 * y[p - 1] + y[p + w - 1]);
    const gy = (y[p + w - 1] + 2 * y[p + w] + y[p + w + 1]) - (y[p - w - 1] + 2 * y[p - w] + y[p - w + 1]);
    const i = p * 4;
    o[i] = 128 + gx * amp / 8; o[i + 1] = 128 + gy * amp / 8; o[i + 2] = Math.min(255, Math.hypot(gx, gy) * amp / 4); o[i + 3] = 255;
  }
  return out;
}

function bitplaneView(src, channel, bit) {
  const d = src.data;
  return gray(src.width, src.height, (p) => {
    const i = p * 4;
    const v = channel === 3 ? Math.round(lum(d, i)) : d[i + channel];
    return ((v >> bit) & 1) * 255;
  });
}

/**
 * Copy-move detection: 8x8 blocks (on an image scaled to at most 640 px)
 * described by their 4x4 averages minus the mean, sorted, and compared
 * with their neighbors in sort order. A copied region produces many block
 * pairs with the same shift, so only shifts seen at least `minPairs` times
 * are kept. Flat blocks (sky, walls) are skipped below `minDetail`, and
 * edge-like blocks above `maxCoherence`. Calibration: of 33 unedited camera
 * photos, 31 gave no group and two gave 45 and 12 pairs, so with the
 * default of 30 one of them still shows a group; a 120x90 copy within a
 * picture gave 65 pairs.
 */
export async function findClones(src, opts) {
  const scale = Math.min(1, 640 / Math.max(src.width, src.height));
  const w = Math.max(16, Math.round(src.width * scale)), hh = Math.max(16, Math.round(src.height * scale));
  const c = new OffscreenCanvas(w, hh);
  const x = c.getContext("2d");
  const full = new OffscreenCanvas(src.width, src.height);
  full.getContext("2d").putImageData(src, 0, 0);
  x.imageSmoothingQuality = "high";
  x.drawImage(full, 0, 0, w, hh);
  const y = lumaPlane(x.getImageData(0, 0, w, hh));
  const B = 8, step = 2, blocks = [];
  for (let by = 0; by + B <= hh; by += step) {
    for (let bx = 0; bx + B <= w; bx += step) {
      const f = new Float32Array(16);
      let mean = 0;
      for (let j = 0; j < 4; j++) for (let i = 0; i < 4; i++) {
        let s = 0;
        for (let yy = 0; yy < 2; yy++) for (let xx = 0; xx < 2; xx++) s += y[(by + j * 2 + yy) * w + bx + i * 2 + xx];
        f[j * 4 + i] = s / 4; mean += s / 4;
      }
      mean /= 16;
      // Remove the best-fit plane, not just the mean: blocks on the same
      // smooth slope (sky, walls, skin) would otherwise match everywhere.
      let gx = 0, gy = 0;
      for (let j = 0; j < 4; j++) for (let i = 0; i < 4; i++) { gx += f[j * 4 + i] * (i - 1.5); gy += f[j * 4 + i] * (j - 1.5); }
      gx /= 20; gy /= 20;
      let sd = 0;
      for (let j = 0; j < 4; j++) for (let i = 0; i < 4; i++) { const k = j * 4 + i; f[k] -= mean + gx * (i - 1.5) + gy * (j - 1.5); sd += f[k] * f[k]; }
      sd = Math.sqrt(sd / 16);
      if (sd < opts.minDetail) continue;
      // Edge-like blocks (structure in one direction only) match themselves
      // anywhere along the edge; keep blocks with texture both ways.
      let xx = 0, yy2 = 0, xy = 0;
      for (let j = 0; j < 3; j++) for (let i = 0; i < 3; i++) {
        const k = j * 4 + i, dx = f[k + 1] - f[k], dy = f[k + 4] - f[k];
        xx += dx * dx; yy2 += dy * dy; xy += dx * dy;
      }
      const tr = xx + yy2, coh = tr > 0 ? Math.sqrt((xx - yy2) ** 2 + 4 * xy * xy) / tr : 1;
      if (coh > opts.maxCoherence) continue;
      blocks.push({ x: bx, y: by, f, key: Array.from(f, (v) => Math.round(v / opts.quant)) });
    }
    if (by % 64 === 0) await new Promise((r) => setTimeout(r));
  }
  blocks.sort((a, b) => { for (let k = 0; k < 16; k++) if (a.key[k] !== b.key[k]) return a.key[k] - b.key[k]; return 0; });
  const shifts = new Map();
  for (let i = 0; i < blocks.length; i++) {
    for (let j = i + 1; j < Math.min(blocks.length, i + 6); j++) {
      const a = blocks[i], b = blocks[j];
      const dx = b.x - a.x, dy = b.y - a.y;
      if (Math.hypot(dx, dy) < opts.minDist) continue;
      let dist = 0;
      for (let k = 0; k < 16; k++) dist += Math.abs(a.f[k] - b.f[k]);
      if (dist / 16 > opts.maxDiff) continue;
      // Canonical direction so A->B and B->A count together.
      const flip = dy < 0 || (dy === 0 && dx < 0);
      const key = flip ? `${-dx},${-dy}` : `${dx},${dy}`;
      if (!shifts.has(key)) shifts.set(key, []);
      shifts.get(key).push(flip ? [b, a] : [a, b]);
    }
  }
  // One copy yields a few neighboring shifts (resampling, blocks sliding
  // along straight edges): fold each shift into a bigger one within 6 px,
  // then drop groups under 15% of the largest (edge-on-edge coincidences).
  const ranked = [...shifts.entries()].map(([k, v]) => ({ d: k.split(",").map(Number), pairs: v })).sort((a, b) => b.pairs.length - a.pairs.length);
  const merged = [];
  for (const g of ranked) {
    const into = merged.find((m) => Math.abs(m.d[0] - g.d[0]) <= 6 && Math.abs(m.d[1] - g.d[1]) <= 6);
    if (into) into.pairs.push(...g.pairs); else merged.push({ d: g.d, pairs: [...g.pairs] });
  }
  merged.sort((a, b) => b.pairs.length - a.pairs.length);
  const top = merged.length ? merged[0].pairs.length : 0;
  const groups = merged.filter((g) => g.pairs.length >= Math.max(opts.minPairs, top * 0.15)).slice(0, 12);
  return { scale: w / src.width, groups: groups.map((g) => ({ shift: g.d.join(","), pairs: g.pairs.map(([a, b]) => [a.x, a.y, b.x, b.y]) })), blocks: blocks.length };
}

function autoContrast(img) {
  const d = img.data;
  let lo = 255, hi = 0;
  for (let i = 0; i < d.length; i += 4) { const v = lum(d, i); if (v < lo) lo = v; if (v > hi) hi = v; }
  const k = 255 / Math.max(1, hi - lo);
  for (let i = 0; i < d.length; i += 4) for (let c = 0; c < 3; c++) d[i + c] = (d[i + c] - lo) * k;
  return img;
}

function equalize(img) {
  const d = img.data, hist = new Uint32Array(256);
  for (let i = 0; i < d.length; i += 4) hist[Math.round(lum(d, i))]++;
  const cdf = new Float32Array(256);
  let acc = 0;
  for (let v = 0; v < 256; v++) { acc += hist[v]; cdf[v] = acc / (d.length / 4); }
  for (let i = 0; i < d.length; i += 4) {
    const v = Math.round(lum(d, i)), t = cdf[v] * 255, k = v ? t / v : 1;
    for (let c = 0; c < 3; c++) d[i + c] = Math.min(255, d[i + c] * k);
  }
  return img;
}

// ---------------------------------------------------------------- viewer

const VIEWS = [
  ["original", "Original"],
  ["ela", "Error level"],
  ["noise", "Noise"],
  ["sweep", "Level sweep"],
  ["gradient", "Gradient"],
  ["bits", "Bit planes"],
  ["clones", "Clones"],
];

const HELP = {
  original: "The picture as stored (EXIF rotation not applied, so pixel positions match the file).",
  ela: "Error level analysis: the picture is saved again as JPEG and the difference is shown. Areas pasted in or edited after the last save often stand out from the rest; edges and text always look brighter, so compare similar surfaces.",
  noise: "Noise analysis: the difference to a 3x3 median filter. Every camera leaves an even grain; regions with a different grain (smoother, sharper, or from another photo) can be inserted.",
  sweep: "Level sweep: stretches a narrow band of brightness. Move the level to look for edges that a copied or retouched area leaves at one brightness.",
  gradient: "Luminance gradient: direction (red, green) and strength (blue) of brightness changes. Lighting that does not fit, or edges that stop abruptly, show up here.",
  bits: "Bit planes: one bit of one channel as black and white. In natural pictures the lowest planes look like noise with faint structure; a uniform or blocky region in plane 0 can be hidden data (lossless pictures only; JPEG decoding changes these bits).",
  clones: "Clone detection: regions copied within the same picture (copy-move). Pairs of matching blocks with the same shift are drawn in one color. Repeated patterns (tiles, fences, sky) can match by nature.",
};

export async function photoViewer(ctx) {
  const { cid, eid, q } = ctx;
  const s = q.carved != null ? { kind: "carved", id: Number(q.carved) } : { kind: "file", fi: Number(q.fi || 0), idx: Number(q.idx) };
  K.render(h("div.card.empty", h("div.spin"), h("p", "Opening picture...")));
  const [{ report: rep, rules }, meta] = await Promise.all([
    api(srcPath(cid, eid, s) + "/photo"),
    s.kind === "file" ? api(srcPath(cid, eid, s)).then((f) => f.row) : api(`/cases/${cid}/evidence/${eid}/carved`).then((c) => c.result.files.find((f) => f.id === s.id)),
  ]);
  const R = Object.fromEntries(rules.map((x) => [x.id, x]));
  const name = s.kind === "file" ? meta.name : `Carved ${meta.label} #${meta.id}`;
  const where = s.kind === "file" ? meta.path : `${meta.region} at offset ${num(meta.offset)}`;
  const bmBase = s.kind === "file"
    ? { cid, eid, kind: "file", fi: s.fi, record: meta.record, idx: s.idx, title: meta.name, path: meta.path }
    : { cid, eid, kind: "carved", carved: s.id, title: name, path: where };
  const wholeKey = s.kind === "file" ? `file:${eid}:${s.fi}:${meta.record}` : `carved:${eid}:${meta.offset}`;

  // Pixels exactly as stored: no color management, no EXIF rotation.
  let src = null, err = null;
  try {
    const blob = await fetch(imageUrl(cid, eid, s), { credentials: "same-origin" }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.blob(); });
    const bmp = await createImageBitmap(blob, { colorSpaceConversion: "none", premultiplyAlpha: "none", imageOrientation: "none" });
    const c = new OffscreenCanvas(bmp.width, bmp.height);
    const x = c.getContext("2d", { willReadFrequently: true });
    x.drawImage(bmp, 0, 0);
    src = x.getImageData(0, 0, bmp.width, bmp.height);
  } catch (e) { err = e.message; }

  const stage = h("div.pv-stage");
  const view = h("canvas.pv-canvas");
  const over = h("canvas.pv-over");
  // The lens: a round window centered on the cursor showing the current
  // view enlarged relative to what is on screen (4x = four times the size
  // you see), drawn at the screen's pixel density so pixels stay sharp.
  const LENS = 280;
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  const lens = h("canvas.pv-lens", { width: Math.round(LENS * dpr), height: Math.round(LENS * dpr), style: { width: `${LENS}px`, height: `${LENS}px` } });
  const lensLabel = h("div.pv-lens-label");
  const layer = h("div.pv-layer", view);
  stage.append(layer, over, lens, lensLabel);
  const status = h("span.muted.pv-status");
  const params = h("div.row.wrap.pv-params");
  const help = h("p.muted.pv-help");
  const toolSeg = h("div.seg.wrap");
  let mode = VIEWS.some((v) => v[0] === q.view) ? q.view : "original";
  let tf = { s: 1, x: 0, y: 0 };
  let lensOn = false, lensZoom = 4, lensEnh = "none", marking = false, clones = null, lastMouse = null;
  const P = { ela: { q: 90, amp: 20 }, noise: { amp: 12 }, sweep: { level: 128, width: 24 }, gradient: { amp: 4 }, bits: { ch: 0, bit: 0 }, clones: { minDetail: 6, maxDiff: 2.5, minDist: 24, minPairs: 30, quant: 6, maxCoherence: 0.6 } };
  const ctxView = view.getContext("2d", { willReadFrequently: true });
  const regionParam = q.region ? q.region.split(",").map(Number) : null;

  const applyTf = () => { layer.style.transform = `translate(${tf.x}px,${tf.y}px) scale(${tf.s})`; drawOverlay(); };
  const fit = () => {
    if (!src) return;
    const r = stage.getBoundingClientRect();
    tf.s = Math.min((r.width - 16) / src.width, (r.height - 16) / src.height, 4);
    tf.x = (r.width - src.width * tf.s) / 2;
    tf.y = (r.height - src.height * tf.s) / 2;
    applyTf();
  };
  const toImage = (e) => {
    const r = stage.getBoundingClientRect();
    return [(e.clientX - r.left - tf.x) / tf.s, (e.clientY - r.top - tf.y) / tf.s];
  };

  const bms = () => (K.state.bm ? K.state.bm.list.filter((b) => b.region && b.evidence === eid && (s.kind === "file" ? b.kind === "file" && b.record === meta.record && b.fi === s.fi : b.kind === "carved" && b.carved === s.id)) : []);
  // Overlay: a screen-sized canvas over the picture, redrawn on every pan and
  // zoom, so outlines and labels keep the same on-screen size at any zoom.
  // `pending` is the rectangle being dragged with Mark region.
  const drawOverlay = (pending) => {
    if (!src) return;
    const r = stage.getBoundingClientRect();
    const W = Math.max(1, Math.round(r.width * dpr)), H = Math.max(1, Math.round(r.height * dpr));
    if (over.width !== W || over.height !== H) { over.width = W; over.height = H; }
    const o = over.getContext("2d");
    o.setTransform(1, 0, 0, 1, 0, 0);
    o.clearRect(0, 0, W, H);
    // Picture coordinates from here; a width divided by the zoom is constant on screen.
    o.setTransform(dpr * tf.s, 0, 0, dpr * tf.s, dpr * tf.x, dpr * tf.y);
    const lw = 1.5 / tf.s;
    if (mode === "clones" && clones) {
      const colors = ["#ff3b30", "#34c759", "#0a84ff", "#ffcc00", "#bf5af2", "#ff9f0a", "#5ac8fa", "#ff2d55", "#30d158", "#64d2ff", "#ffd60a", "#ac8e68"];
      clones.groups.forEach((g, gi) => {
        o.strokeStyle = o.fillStyle = colors[gi % colors.length];
        o.globalAlpha = 0.35;
        const k = 1 / clones.scale, B = 8 * k;
        for (const [ax, ay, bx, by] of g.pairs) { o.fillRect(ax * k, ay * k, B, B); o.fillRect(bx * k, by * k, B, B); }
        o.globalAlpha = 0.9; o.lineWidth = lw;
        const [ax, ay, bx, by] = g.pairs[Math.floor(g.pairs.length / 2)];
        o.beginPath(); o.moveTo(ax * k + B / 2, ay * k + B / 2); o.lineTo(bx * k + B / 2, by * k + B / 2); o.stroke();
      });
      o.globalAlpha = 1;
    }
    // A thin line with a faint dark edge, readable on light and dark pictures.
    const box = ([x, y, w, hh], color, dashed) => {
      o.setLineDash([]);
      o.strokeStyle = "rgba(0,0,0,.45)"; o.lineWidth = lw * 2.2; o.strokeRect(x, y, w, hh);
      o.strokeStyle = color; o.lineWidth = lw; o.setLineDash(dashed ? [5 / tf.s, 3 / tf.s] : []); o.strokeRect(x, y, w, hh);
      o.setLineDash([]);
    };
    const labels = [];
    for (const b of bms()) {
      box(b.region, "#ffd60a", true);
      labels.push([b.region, b.tags.join(", ") || "Bookmark"]);
    }
    if (regionParam) box(regionParam, "#ff453a", false);
    if (pending) box(pending, "#ffd60a", false);
    // Labels in screen pixels: a small tab just above the region's corner.
    o.setTransform(dpr, 0, 0, dpr, 0, 0);
    o.font = "11px system-ui, sans-serif";
    o.textBaseline = "middle";
    for (const [[x, y], text] of labels) {
      const sx = tf.x + x * tf.s, sy = tf.y + y * tf.s;
      const w = Math.ceil(o.measureText(text).width) + 8, th = 15;
      const ty = sy - th - 1 < 0 ? sy + 1 : sy - th - 1;
      o.fillStyle = "rgba(0,0,0,.62)"; o.fillRect(sx, ty, w, th);
      o.fillStyle = "#ffd60a"; o.fillText(text, sx + 4, ty + th / 2 + 0.5);
    }
  };

  let busy = 0;
  const compute = async () => {
    if (!src) return;
    const my = ++busy;
    status.textContent = "Computing...";
    await new Promise((r) => setTimeout(r, 20));
    let out;
    try {
      const base = document.createElement("canvas");
      if (mode === "ela") { base.width = src.width; base.height = src.height; base.getContext("2d").putImageData(src, 0, 0); out = await elaView(src, base, P.ela.q, P.ela.amp); }
      else if (mode === "noise") out = noiseView(src, P.noise.amp);
      else if (mode === "sweep") out = sweepView(src, P.sweep.level, P.sweep.width);
      else if (mode === "gradient") out = gradientView(src, P.gradient.amp);
      else if (mode === "bits") out = bitplaneView(src, P.bits.ch, P.bits.bit);
      else if (mode === "clones") {
        clones = await findClones(src, P.clones);
        out = new ImageData(new Uint8ClampedArray(src.data), src.width, src.height);
        for (let i = 0; i < out.data.length; i += 4) for (let c = 0; c < 3; c++) out.data[i + c] = out.data[i + c] * 0.55;
        status.textContent = clones.groups.length ? `${clones.groups.length} shift${clones.groups.length === 1 ? "" : "s"} with copied blocks (${num(clones.groups.reduce((a, g) => a + g.pairs.length, 0))} pairs, ${num(clones.blocks)} blocks compared)` : `No copied regions found (${num(clones.blocks)} blocks compared)`;
      } else out = src;
    } catch (e) { status.textContent = e.message; return; }
    if (my !== busy) return;
    view.width = src.width; view.height = src.height;
    ctxView.putImageData(out, 0, 0);
    if (mode !== "clones") status.textContent = `${src.width} x ${src.height} px`;
    drawOverlay();
  };

  const slider = (label, obj, key, min, max, stepv = 1) => {
    const v = h("span.mono", String(obj[key]));
    const inp = h("input", { type: "range", min, max, step: stepv, value: obj[key], oninput: (e) => { obj[key] = Number(e.target.value); v.textContent = e.target.value; }, onchange: compute });
    return h("label.row.pv-slider", h("span", label), inp, v);
  };
  const drawParams = () => {
    help.textContent = HELP[mode];
    const p = {
      ela: () => [slider("Quality", P.ela, "q", 50, 100), slider("Amplify", P.ela, "amp", 1, 60)],
      noise: () => [slider("Amplify", P.noise, "amp", 1, 40)],
      sweep: () => [slider("Level", P.sweep, "level", 0, 255), slider("Width", P.sweep, "width", 2, 128)],
      gradient: () => [slider("Amplify", P.gradient, "amp", 1, 16)],
      bits: () => [h("div.seg", ["Red", "Green", "Blue", "Luma"].map((n, i) => h("button", { class: P.bits.ch === i ? "on" : null, onclick: () => { P.bits.ch = i; drawParams(); compute(); } }, n))),
        h("div.seg", [0, 1, 2, 3, 4, 5, 6, 7].map((b) => h("button", { class: P.bits.bit === b ? "on" : null, onclick: () => { P.bits.bit = b; drawParams(); compute(); } }, String(b))))],
      clones: () => [slider("Min detail", P.clones, "minDetail", 1, 30), slider("Max difference", P.clones, "maxDiff", 0.5, 10, 0.5), slider("Min distance", P.clones, "minDist", 8, 120), slider("Min pairs", P.clones, "minPairs", 5, 120), slider("Max edge-likeness", P.clones, "maxCoherence", 0.2, 1, 0.05)],
    }[mode];
    params.replaceChildren(...(p ? p() : []));
  };
  const drawTools = () => toolSeg.replaceChildren(...VIEWS.map(([k, l]) => h("button", { class: mode === k ? "on" : null, onclick: () => { mode = k; drawTools(); drawParams(); compute(); history.replaceState(null, "", viewerHref(cid, eid, s, regionParam) + `&view=${k}`); } }, l)));

  // Pan, zoom, lens and region marking.
  let drag = null;
  stage.addEventListener("wheel", (e) => {
    e.preventDefault();
    // With the magnifier on, the wheel sets its strength; Shift+wheel still zooms the picture.
    if (lensOn && !e.shiftKey) {
      lensZoom = Math.max(1.5, Math.min(32, lensZoom * Math.exp(-e.deltaY * 0.002)));
      drawLens();
      drawLensAt(e);
      return;
    }
    const r = stage.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    const k = Math.exp(-e.deltaY * 0.0015), ns = Math.max(0.02, Math.min(32, tf.s * k));
    tf.x = mx - (mx - tf.x) * (ns / tf.s); tf.y = my - (my - tf.y) * (ns / tf.s); tf.s = ns;
    applyTf(); drawOverlay();
  }, { passive: false });
  stage.addEventListener("dblclick", fit);
  stage.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    drag = marking ? { mark: toImage(e), cur: toImage(e) } : { x: e.clientX, y: e.clientY, tx: tf.x, ty: tf.y };
  });
  const up = () => {
    if (!stage.isConnected) { window.removeEventListener("mouseup", up); return; }
    if (!drag) return;
    const d = drag; drag = null;
    if (d.mark && src) {
      const [x0, y0] = d.mark, [x1, y1] = d.cur;
      const rx = Math.max(0, Math.round(Math.min(x0, x1))), ry = Math.max(0, Math.round(Math.min(y0, y1)));
      const rw = Math.min(src.width - rx, Math.round(Math.abs(x1 - x0))), rh = Math.min(src.height - ry, Math.round(Math.abs(y1 - y0)));
      drawOverlay();
      if (rw < 4 || rh < 4) return;
      const region = [rx, ry, rw, rh];
      const vname = VIEWS.find((v) => v[0] === mode)[1];
      K.bookmarkDialog({ ...bmBase, key: `region:${wholeKey}:${region.join(",")}`, region, view: vname, title: `${bmBase.title}, region ${rx},${ry} ${rw}x${rh}`, detail: `${vname} view` }, () => drawOverlay());
      setMarking(false);
    }
  };
  window.addEventListener("mouseup", up);
  stage.addEventListener("mousemove", (e) => {
    if (drag && drag.mark) {
      drag.cur = toImage(e);
      const [x0, y0] = drag.mark, [x1, y1] = drag.cur;
      drawOverlay([Math.min(x0, x1), Math.min(y0, y1), Math.abs(x1 - x0), Math.abs(y1 - y0)]);
    } else if (drag) {
      tf.x = drag.tx + e.clientX - drag.x; tf.y = drag.ty + e.clientY - drag.y; applyTf();
    }
    if (lensOn) drawLensAt(e);
  });
  stage.addEventListener("mouseleave", () => { lens.style.display = "none"; lensLabel.style.display = "none"; lastMouse = null; });

  function drawLensAt(e) {
    if (!src || !e) return;
    lastMouse = { clientX: e.clientX, clientY: e.clientY };
    const r = stage.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const [ix, iy] = toImage(e);
    const W = lens.width;
    // Image pixels covered by the lens: what LENS screen pixels show, divided by the strength.
    const span = LENS / (tf.s * lensZoom);
    const lx = lens.getContext("2d");
    lx.fillStyle = "#111";
    lx.fillRect(0, 0, W, W);
    // Smooth only while still shrinking the picture; enlarged pixels stay square.
    lx.imageSmoothingEnabled = W / span < 1;
    lx.imageSmoothingQuality = "high";
    const sx = ix - span / 2, sy = iy - span / 2;
    // Clip the source to the picture so the edges line up when near them.
    const cx0 = Math.max(0, sx), cy0 = Math.max(0, sy), cx1 = Math.min(src.width, sx + span), cy1 = Math.min(src.height, sy + span);
    if (cx1 > cx0 && cy1 > cy0) {
      const k = W / span;
      lx.drawImage(view, cx0, cy0, cx1 - cx0, cy1 - cy0, (cx0 - sx) * k, (cy0 - sy) * k, (cx1 - cx0) * k, (cy1 - cy0) * k);
      if (lensEnh !== "none") {
        const img = lx.getImageData(0, 0, W, W);
        lx.putImageData(lensEnh === "contrast" ? autoContrast(img) : equalize(img), 0, 0);
      }
    }
    // Center mark: the exact pixel under the cursor.
    const px = Math.max(2, W / span);
    lx.strokeStyle = "rgba(255,255,255,.85)";
    lx.lineWidth = Math.max(1, dpr);
    lx.strokeRect(W / 2 - px / 2, W / 2 - px / 2, px, px);
    lens.style.left = `${mx - LENS / 2}px`;
    lens.style.top = `${my - LENS / 2}px`;
    lens.style.display = "block";
    const inside = ix >= 0 && iy >= 0 && ix < src.width && iy < src.height;
    lensLabel.textContent = `${(Math.round(lensZoom * 10) / 10)}x${inside ? `  ${Math.floor(ix)}, ${Math.floor(iy)}` : ""}`;
    lensLabel.style.left = `${mx - LENS / 2}px`;
    lensLabel.style.top = `${my + LENS / 2 + 6}px`;
    lensLabel.style.display = "block";
  }

  // Marking and the magnifier exclude each other: the lens would sit over the spot being dragged.
  const setMarking = (on) => {
    marking = on;
    markBtn.classList.toggle("on", on);
    stage.classList.toggle("marking", on);
    if (on && lensOn) { lensOn = false; lens.style.display = "none"; lensLabel.style.display = "none"; drawLens(); }
  };
  const markBtn = h("button.sm", { title: "Drag a rectangle on the picture to bookmark that region (turns the magnifier off)", onclick: () => setMarking(!marking) }, icon("star", 14), "Mark region");
  const lensSeg = h("div.seg");
  function drawLens() {
    stage.classList.toggle("lensing", lensOn);
    lensSeg.replaceChildren(
    h("button", { class: lensOn ? "on" : null, onclick: () => { lensOn = !lensOn; if (!lensOn) { lens.style.display = "none"; lensLabel.style.display = "none"; } else if (marking) setMarking(false); drawLens(); }, title: "Magnifier over the current view. Mouse wheel: strength. Shift+wheel: zoom the picture." }, icon("lens", 14), "Magnifier"),
    ...(lensOn ? [[2, "2x"], [4, "4x"], [8, "8x"], [16, "16x"]].map(([z, l]) => h("button", { class: Math.abs(lensZoom - z) < 0.01 ? "on" : null, onclick: () => { lensZoom = z; drawLens(); } }, l)) : []),
    ...(lensOn ? [["none", "Plain"], ["contrast", "Contrast"], ["equalize", "Equalize"]].map(([k, l]) => h("button", { class: lensEnh === k ? "on" : null, onclick: () => { lensEnh = k; drawLens(); } }, l)) : []));
  }
  drawLens();

  const exportHref = s.kind === "file" ? apiUrl(srcPath(cid, eid, s) + "/export") : apiUrl(srcPath(cid, eid, s) + "/export");
  const head = h("div.hd",
    h("div", { style: { minWidth: 0 } }, h("h1.ell", { style: { color: (s.kind === "file" && meta.deleted) ? "var(--del)" : null } }, name), h("div.muted.mono.ell", where)),
    h("span.sp"),
    s.kind === "file" && meta.deleted ? h("span.pill.bad", "Deleted") : s.kind === "carved" ? h("span.pill.info", "Carved") : null,
    K.bmButton({ ...bmBase, key: wholeKey }),
    h("button.sm", { title: "Byte map and printable strings of the file", onclick: () => K.bytesDialog(name, srcPath(cid, eid, s), (off) => (s.kind === "file" ? K.fileDrawer({ cid, eid, fi: s.fi }, s.idx, off) : location.hash = `#/c/${cid}/e/${eid}/hex?off=${meta.offset + off}`)) }, "Bytes and strings"),
    K.canWrite() ? h("a.btn.sm", { href: exportHref }, "Export (hashed + audited)") : null,
    h("a.btn.sm", { href: `#/c/${cid}/e/${eid}/photos` }, "All pictures"));

  const side = h("div.pv-side", sidePanel(rep, R, src));
  K.render(h("div.stack",
    head,
    h("div.pv",
      h("div.pv-main",
        h("div.row.wrap", toolSeg, h("span.sp"), lensSeg, markBtn),
        params, help,
        err ? h("div.card.empty", h("p", `The browser could not decode this picture: ${err}`), h("p.muted", "The findings on the right come from Kokino's own parser and still apply.")) : stage,
        h("div.row", status, h("span.sp"), h("span.muted", { style: { fontSize: "12px" } }, "Wheel to zoom (with the magnifier on: its strength; Shift+wheel zooms), drag to pan, double-click to fit."))),
      side)));
  if (src) {
    view.width = src.width; view.height = src.height;
    drawTools(); drawParams(); fit(); await compute();
    if (regionParam) {
      const r = stage.getBoundingClientRect();
      const [x, y, w, hh] = regionParam;
      tf.s = Math.min(8, (r.width * 0.6) / Math.max(w, 1), (r.height * 0.6) / Math.max(hh, 1));
      tf.x = r.width / 2 - (x + w / 2) * tf.s; tf.y = r.height / 2 - (y + hh / 2) * tf.s;
      applyTf(); drawOverlay();
    }
    K.loadBookmarks(cid).then(drawOverlay).catch(() => {});
  } else drawTools();
}

// ---------------------------------------------------------------- side panel

function kv(rows) {
  return h("div.kv", rows.filter((r) => r && r[1] != null && r[1] !== "").map(([k, v]) => [h("span", k), typeof v === "string" || typeof v === "number" ? h("span.mono.wrap", String(v)) : v]));
}

function qtable(t, title) {
  if (!t) return null;
  return h("div", h("div.muted", { style: { fontSize: "12px" } }, title), h("table.qt", [0, 1, 2, 3, 4, 5, 6, 7].map((r) => h("tr", t.slice(r * 8, r * 8 + 8).map((v) => h("td", String(v)))))));
}

function bars(values, labelFn) {
  const W = 300, H = 90, max = Math.max(1, ...values);
  const bw = W / values.length;
  return svg("svg", { viewBox: `0 0 ${W} ${H + 14}`, class: "pv-chart" },
    ...values.map((v, i) => svg("rect", { x: i * bw + 1, y: H - (v / max) * H, width: Math.max(1, bw - 2), height: (v / max) * H, fill: "var(--accent)" }, svg("title", {}, labelFn(i, v)))),
    svg("text", { x: 0, y: H + 12, "font-size": 10, fill: "currentColor" }, labelFn(0, values[0]).split(":")[0]),
    svg("text", { x: W, y: H + 12, "font-size": 10, fill: "currentColor", "text-anchor": "end" }, labelFn(values.length - 1, values[values.length - 1]).split(":")[0]));
}

function lsbChart(prefix) {
  const W = 300, H = 80;
  const pts = prefix.map(([s, p]) => `${(s * W).toFixed(1)},${(H - p * H).toFixed(1)}`).join(" ");
  return svg("svg", { viewBox: `0 0 ${W} ${H + 14}`, class: "pv-chart" },
    svg("line", { x1: 0, x2: W, y1: H * 0.01, y2: H * 0.01, stroke: "var(--bad)", "stroke-dasharray": "4 3" }),
    svg("polyline", { points: pts, fill: "none", stroke: "var(--accent)", "stroke-width": 2 }),
    svg("text", { x: 0, y: H + 12, "font-size": 10, fill: "currentColor" }, "0%"),
    svg("text", { x: W, y: H + 12, "font-size": 10, fill: "currentColor", "text-anchor": "end" }, "100% of pixel data"));
}

/** EXIF thumbnail, the picture at the same size, and their difference. */
function thumbCompare(dataUrl, src, t) {
  const box = h("div.row.wrap.pv-thumbs");
  const img = new Image();
  img.onload = () => {
    const w = img.width, hh = img.height;
    const a = h("canvas", { width: w, height: hh }), b = h("canvas", { width: w, height: hh }), d = h("canvas", { width: w, height: hh });
    a.getContext("2d").drawImage(img, 0, 0);
    if (src) {
      const full = document.createElement("canvas");
      full.width = src.width; full.height = src.height; full.getContext("2d").putImageData(src, 0, 0);
      // Fit the picture into the thumbnail like the camera did (letterboxed).
      const k = Math.min(w / src.width, hh / src.height), dw = src.width * k, dh = src.height * k;
      const bx = b.getContext("2d");
      bx.fillStyle = "#000"; bx.fillRect(0, 0, w, hh);
      bx.imageSmoothingQuality = "high";
      bx.drawImage(full, (w - dw) / 2, (hh - dh) / 2, dw, dh);
      const p = a.getContext("2d").getImageData(0, 0, w, hh).data, q = bx.getImageData(0, 0, w, hh).data;
      const out = new ImageData(w, hh);
      for (let i = 0; i < p.length; i += 4) { const v = Math.min(255, Math.abs(lum(p, i) - lum(q, i)) * 4); out.data[i] = v; out.data[i + 1] = v * 0.5; out.data[i + 2] = 0; out.data[i + 3] = 255; }
      d.getContext("2d").putImageData(out, 0, 0);
    }
    box.replaceChildren(h("div", a, h("div.muted", "EXIF thumbnail")), src ? h("div", b, h("div.muted", "Picture now")) : null, src ? h("div", d, h("div.muted", "Difference x4")) : null);
  };
  img.src = dataUrl;
  return h("div.stack", box, t ? kv([
    ["Shape", `thumbnail ${t.thumb_aspect} / picture ${t.image_aspect}${t.aspect_differs ? " (different)" : ""}`],
    ["Largest difference", `${t.max_cell} in cell ${t.cell[0] + 1},${t.cell[1] + 1} of 6x6 (mean ${t.mean_diff})`],
  ]) : null);
}

function section(title, ...body) {
  const kids = body.flat().filter(Boolean);
  return kids.length ? h("div.card.flat.stack", h("h3", title), ...kids) : null;
}

function sidePanel(r, R, src) {
  const x = r.exif, j = r.jpeg, ras = r.raster;
  const findings = r.findings.length
    ? r.findings.map((f) => {
      const rule = R[f.id] || { title: f.id, explanation: "", caveat: "", flag: false };
      return h("div.card.flat.ind" + (rule.flag ? ".hot" : ""), h("b", rule.title), h("div.mono", { style: { fontSize: "12.5px", margin: "4px 0" } }, f.detail),
        h("p", { style: { margin: "4px 0" } }, rule.explanation), h("div.cav", rule.caveat));
    })
    : [h("p.muted", "No findings. This does not prove the picture is original: see the views on the left and the limits in the wiki.")];
  const dj = r.double;
  return h("div.stack",
    section("Findings", findings),
    section("Picture", kv([
      ["Format", `${r.format}${j ? `, ${j.mode}` : ""}${j && j.subsampling ? `, ${j.subsampling}` : ""}${ras ? `, ${ras.color} ${ras.bit_depth}-bit${ras.interlaced ? ", interlaced" : ""}` : ""}`],
      ["Size", `${r.width} x ${r.height} px, ${bytes(r.size)}`],
    ])),
    x ? section("Camera and dates (EXIF)", kv([
      ["Make", x.make], ["Model", x.model], ["Serial", x.serial], ["Lens", x.lens], ["Software", x.software], ["Artist", x.artist],
      ["Taken", ts(x.original)], ["Digitized", ts(x.digitized)], ["Changed", ts(x.datetime)], ["Time offset", x.offset_time],
      ["Orientation", x.orientation ? String(x.orientation) : ""],
      ["GPS", x.gps ? `${x.gps.lat.toFixed(6)}, ${x.gps.lon.toFixed(6)}${x.gps.alt != null ? `, ${x.gps.alt.toFixed(0)} m` : ""}${x.gps.time ? ` (${ts(x.gps.time)} UTC)` : ""}` : ""],
      ["Thumbnail", x.thumb_len ? `${bytes(x.thumb_len)}` : "none"],
    ]), h("p.muted", { style: { fontSize: "12px" } }, "EXIF dates are the camera clock's local time as stored.")) : null,
    r.software.length ? section("Software traces", h("ul", r.software.map((s) => h("li.mono", s)))) : null,
    r.thumbnail_data ? section("EXIF thumbnail", thumbCompare(r.thumbnail_data, src, r.thumbnail)) : null,
    j ? section("Compression",
      kv([
        ["Tables", j.tables ? `${j.tables.kind === "standard" ? "standard IJG (libjpeg) tables" : "custom tables"}, quality ${j.tables.exact ? "" : "about "}${j.tables.quality}` : "none"],
        ["Fingerprint", j.tables ? j.tables.fingerprint : ""],
        ["Restart interval", j.restart ? String(j.restart) : ""],
        ["Double JPEG", dj ? (dj.score == null ? "not enough data to judge" : `score ${dj.score.toFixed(3)}${dj.detected ? " (re-saved)" : ""} over ${dj.positions} positions`) : ""],
      ]),
      dj && dj.score != null ? h("div", h("div.muted", { style: { fontSize: "12px" } }, `Histogram of coefficient ${dj.example_position} (step ${dj.example_step}): a smooth decay is normal; regular peaks and gaps mean a second compression.`), bars(dj.example, (i, v) => `${i + 1}: ${num(v)}`)) : null,
      h("div.row.wrap", { style: { gap: "16px" } }, qtable(j.luma, "Luminance table"), qtable(j.chroma, "Chrominance table"))) : null,
    section("Hidden data",
      r.trailing ? kv([["After the end", `${num(r.trailing.len)} bytes at offset ${num(r.trailing.offset)}: ${r.trailing.kind}${r.trailing.benign ? " (known, normal)" : ""}`]]) : h("p.muted", "Nothing after the end of the image."),
      r.lsb ? h("div", kv([["LSB test", r.lsb.detected ? `${r.lsb.from_end ? "last" : "first"} ${Math.round(r.lsb.embedded_share * 100)}% of the pixel data looks embedded` : "no sign of LSB embedding"], ["Ones in plane 0", r.lsb.ones.toFixed(3)]]),
        h("div.muted", { style: { fontSize: "12px" } }, "Chi-square p-value over a growing share of the pixel data (dashed: 0.99)."), lsbChart(r.lsb.prefix)) : null,
      ras && ras.text.length ? kv(ras.text.map(([k, v]) => [k, v])) : null),
    j ? h("details.card.flat", h("summary", "JPEG segments"), h("div.mono", { style: { fontSize: "12px" } }, j.segments.map((s) => h("div", s))), j.comments.length ? kv(j.comments.map((c) => ["Comment", c])) : null) : null,
    ras ? h("details.card.flat", h("summary", "PNG / BMP structure"), h("div.mono", { style: { fontSize: "12px" } }, ras.chunks.join(", ")), ras.note ? h("p.muted", ras.note) : null) : null,
    r.notes.length ? section("Not checked", h("ul", r.notes.map((n) => h("li.muted", n)))) : null);
}
