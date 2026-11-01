// Virtualized hex viewer and overlay editor for the whole evidence image.
//
// Never scrolls a giant DOM: it renders only the rows that fit and moves a
// byte offset on wheel, keys and the slider, so a multi-terabyte image works
// the same as a floppy. Edits are posted as overlay patches stored in the
// case; the evidence file is never written.

import { api, h, hexOff, toast, apiUrl, ts } from "./lib.js";

const ROW = 16;
const CHUNK = 64 * 1024;

export class HexView {
  constructor({ cid, eid, size, onSelect }) {
    this.cid = cid; this.eid = eid; this.size = size; this.onSelect = onSelect;
    this.top = 0; this.rows = 24; this.sel = null; this.anchor = null;
    this.cache = new Map(); this.patches = new Map(); this.hits = new Set();
    this.editing = false; this.nibble = null;
    this.el = h("div.hex", { tabindex: 0 });
    this.slider = h("input.slider", { type: "range", min: 0, max: 1000, value: 0 });
    this.slider.addEventListener("input", () => this.go(Math.floor((this.slider.value / 1000) * Math.max(0, this.size - this.rows * ROW)), false));
    this.el.addEventListener("wheel", (e) => { e.preventDefault(); this.scrollRows(Math.sign(e.deltaY) * Math.max(1, Math.round(Math.abs(e.deltaY) / 22))); }, { passive: false });
    this.el.addEventListener("keydown", (e) => this.key(e));
    this.el.addEventListener("mousedown", (e) => {
      const off = e.target.dataset && e.target.dataset.o;
      if (off == null) return;
      this.el.focus();
      this.select(Number(off), e.shiftKey);
    });
    window.addEventListener("resize", () => this.el.isConnected && this.fit());
  }

  fit() {
    const avail = Math.max(240, window.innerHeight - this.el.getBoundingClientRect().top - 90);
    const rows = Math.max(8, Math.floor(avail / 22));
    if (rows !== this.rows) { this.rows = rows; this.render(); }
  }

  async loadPatches() {
    const list = await api(`/cases/${this.cid}/evidence/${this.eid}/patches`);
    this.patches = new Map(list.map((p) => [p.offset, p]));
    this.render();
    return list;
  }

  async chunk(i) {
    if (this.cache.has(i)) return this.cache.get(i);
    const p = api(`/cases/${this.cid}/evidence/${this.eid}/hex?offset=${i * CHUNK}&len=${CHUNK}`).then((r) => {
      const b = new Uint8Array(r.data.length / 2);
      for (let k = 0; k < b.length; k++) b[k] = parseInt(r.data.substr(k * 2, 2), 16);
      return b;
    });
    this.cache.set(i, p);
    if (this.cache.size > 64) this.cache.delete(this.cache.keys().next().value);
    return p;
  }

  async bytesAt(off, len) {
    const out = new Uint8Array(Math.max(0, Math.min(len, this.size - off)));
    let got = 0;
    while (got < out.length) {
      const o = off + got, ci = Math.floor(o / CHUNK), c = await this.chunk(ci);
      const within = o - ci * CHUNK, n = Math.min(c.length - within, out.length - got);
      if (n <= 0) break;
      out.set(c.subarray(within, within + n), got);
      got += n;
    }
    return out;
  }

  scrollRows(n) { this.go(this.top + n * ROW, false); }

  go(off, select = true) {
    off = Math.max(0, Math.min(Number(off) || 0, Math.max(0, this.size - 1)));
    const top = Math.floor(off / ROW) * ROW;
    const maxTop = Math.max(0, Math.ceil(this.size / ROW) * ROW - this.rows * ROW);
    if (select) {
      this.top = Math.min(Math.max(0, top - ROW * 4), maxTop);
      this.select(off, false);
    } else {
      this.top = Math.min(top, maxTop);
      this.render();
    }
    this.slider.value = maxTop ? Math.round((this.top / maxTop) * 1000) : 0;
  }

  select(off, extend) {
    if (extend && this.anchor != null) this.sel = off;
    else { this.anchor = off; this.sel = off; }
    this.nibble = null;
    if (this.sel < this.top) this.top = Math.floor(this.sel / ROW) * ROW;
    if (this.sel >= this.top + this.rows * ROW) this.top = Math.floor(this.sel / ROW) * ROW - (this.rows - 1) * ROW;
    this.render();
    this.inspect();
  }

  range() {
    if (this.sel == null) return null;
    const a = Math.min(this.anchor, this.sel), b = Math.max(this.anchor, this.sel);
    return [a, b];
  }

  async inspect() {
    if (this.sel == null || !this.onSelect) return;
    const b = await this.bytesAt(this.sel, 16);
    for (let i = 0; i < b.length; i++) { const p = this.patches.get(this.sel + i); if (p) b[i] = p.value; }
    this.onSelect(this.sel, b, this.range());
  }

  key(e) {
    const k = e.key;
    if (this.editing && this.sel != null && /^[0-9a-fA-F]$/.test(k)) {
      e.preventDefault();
      if (this.nibble == null) { this.nibble = parseInt(k, 16); this.render(); return; }
      const value = (this.nibble << 4) | parseInt(k, 16);
      const at = this.sel;
      this.nibble = null;
      this.patch(at, value).then(() => this.select(Math.min(at + 1, this.size - 1), false));
      return;
    }
    const moves = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: ROW, ArrowUp: -ROW, PageDown: ROW * this.rows, PageUp: -ROW * this.rows };
    if (k in moves) {
      e.preventDefault();
      if (this.sel == null) { this.scrollRows(Math.sign(moves[k]) * (Math.abs(moves[k]) >= ROW ? Math.abs(moves[k]) / ROW : 1)); return; }
      this.select(Math.max(0, Math.min(this.size - 1, this.sel + moves[k])), e.shiftKey);
    } else if (k === "Home") { e.preventDefault(); this.go(0); }
    else if (k === "End") { e.preventDefault(); this.go(this.size - 1); }
    else if (k === "Escape") { this.nibble = null; this.render(); }
  }

  async patch(offset, value) {
    try {
      const list = await api(`/cases/${this.cid}/evidence/${this.eid}/patches`, { method: "POST", body: { offset, value } });
      this.patches = new Map(list.map((p) => [p.offset, p]));
      this.onPatches && this.onPatches(list);
    } catch (err) { toast(err.message, true); }
  }

  async render() {
    const start = this.top, len = this.rows * ROW;
    const data = await this.bytesAt(start, len);
    if (start !== this.top) return; // a newer render is on the way
    const [ra, rb] = this.range() || [-1, -1];
    const frag = document.createDocumentFragment();
    for (let r = 0; r < this.rows; r++) {
      const base = start + r * ROW;
      if (base >= this.size) break;
      const hx = h("span.hx"), as = h("span.as");
      for (let i = 0; i < ROW; i++) {
        const o = base + i, idx = r * ROW + i;
        if (o >= this.size || idx >= data.length) { hx.append(h("span", " ")); as.append(h("span", " ")); continue; }
        const p = this.patches.get(o);
        const v = p ? p.value : data[idx];
        let cls = v === 0 ? "z" : "";
        if (p) cls += " pt";
        if (o === this.sel) cls += " sel";
        else if (o >= ra && o <= rb) cls += " rng";
        if (this.hits.has(o)) cls += " hit";
        const txt = o === this.sel && this.nibble != null ? this.nibble.toString(16).toUpperCase() + "_" : v.toString(16).toUpperCase().padStart(2, "0");
        hx.append(h("span", { class: cls, "data-o": o, title: p ? `overlay: was ${p.original.toString(16).padStart(2, "0")}` : null }, txt));
        as.append(h("span", { class: cls, "data-o": o }, v >= 32 && v < 127 ? String.fromCharCode(v) : "."));
      }
      frag.append(h("div.hr", h("span.off", hexOff(base)), hx, as));
    }
    this.el.replaceChildren(frag);
    this.el.classList.toggle("editing", this.editing);
  }
}

/** Data inspector for the bytes at the selection. */
export function inspector(off, b, range) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const has = (n) => b.length >= n;
  const ft = (lo, hi) => {
    const ticks = BigInt(hi) * 4294967296n + BigInt(lo);
    if (ticks === 0n) return "";
    const ms = Number(ticks / 10000n) - 11644473600000;
    if (ms < -1e13 || ms > 1e13) return "";
    const d = new Date(ms);
    return isNaN(d) ? "" : ts(d.toISOString());
  };
  const unix = (s) => (s > 0 && s < 4102444800 ? ts(new Date(s * 1000).toISOString()) : "");
  const rows = [
    ["Offset", `${off} (0x${off.toString(16).toUpperCase()})`],
    range && range[1] > range[0] ? ["Selection", `${range[1] - range[0] + 1} bytes`] : null,
    ["Sector", `${Math.floor(off / 512)} (+${off % 512})`],
    ["int8 / uint8", has(1) ? `${dv.getInt8(0)} / ${dv.getUint8(0)}` : ""],
    ["int16 LE", has(2) ? dv.getInt16(0, true) : ""],
    ["uint16 LE / BE", has(2) ? `${dv.getUint16(0, true)} / ${dv.getUint16(0, false)}` : ""],
    ["int32 LE", has(4) ? dv.getInt32(0, true) : ""],
    ["uint32 LE / BE", has(4) ? `${dv.getUint32(0, true)} / ${dv.getUint32(0, false)}` : ""],
    ["uint64 LE", has(8) ? dv.getBigUint64(0, true).toString() : ""],
    ["FILETIME", has(8) ? ft(dv.getUint32(0, true), dv.getUint32(4, true)) : ""],
    ["Unix time 32", has(4) ? unix(dv.getUint32(0, true)) : ""],
    ["ASCII", Array.from(b).map((v) => (v >= 32 && v < 127 ? String.fromCharCode(v) : ".")).join("")],
    ["UTF-16LE", has(2) ? (() => { let s = ""; for (let i = 0; i + 1 < b.length; i += 2) { const c = dv.getUint16(i, true); s += c >= 32 && c < 0xd800 ? String.fromCharCode(c) : "."; } return s; })() : ""],
  ].filter(Boolean);
  return h("div.kv", rows.map(([k, v]) => [h("span", k), h("code", String(v))]));
}

export function carveLink(cid, eid, a, b, patched) {
  return apiUrl(`/cases/${cid}/evidence/${eid}/carve?offset=${a}&len=${b - a + 1}&patched=${patched ? "true" : "false"}`);
}
