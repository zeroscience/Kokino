// Kokino Forensic Toolkit - browser GUI.

import { api, apiUrl, drawTunnel, h, svg, $, bytes, num, errorLog, onErrorLog, markErrorsSeen, clearErrorLog, ts, parseDay, dayStart, datePattern, dateFormat, setDateFormat, DATE_FORMATS, zone, zoneName, zoneSentence, zoneChoice, setZone, localZone, offsetLabel, hexOff, toast, spring, countUp, modal, closeModal, debounce, fileIcon, icon } from "./lib.js";
import { HexView, inspector, carveLink } from "./hex.js";
import { authOpen, closeAuth, loginScreen, passwordScreen, setupScreen } from "./auth.js";
import { aboutPage, wikiPage } from "./help.js";
import { photoInit, photosTab, photoViewer, viewerHref } from "./photo.js";
import { byteMap, stringsPanel, bytesDialog } from "./binview.js";

const view = $("#view");
const state = { info: null, me: null, jobs: [], route: null, caseCache: {}, write: false, polling: false };

const isAdmin = () => state.me && state.me.role === "admin";
const canCreate = () => state.me && state.me.role !== "reviewer";
/** Write access to the case currently open. */
const canWrite = () => state.write;

// ---------------------------------------------------------------- theme
const THEME_KEY = "kokino.theme";
// Swatches are bg, panel, accent. Steel light is the default; orange and lilac use the sharp, classic style.
const THEMES = [
  { id: "light", label: "Steel light", sw: ["#eef2f5", "#ffffff", "#3f6e93"] },
  { id: "orange", label: "Orange", sw: ["#0a0a0a", "#d95a1b", "#ff7a1a"], sharp: true },
  { id: "dark", label: "Steel dark", sw: ["#0b0e11", "#141a20", "#c5d9e8"] },
  { id: "lilac", label: "Lilac (classic)", sw: ["#f5f3f9", "#ffffff", "#7a5bc2"], sharp: true },
];
function applyTheme(t) {
  const th = THEMES.find((x) => x.id === t) || THEMES[0];
  document.documentElement.dataset.theme = th.id;
  document.documentElement.classList.toggle("sharp", !!th.sharp);
  try { localStorage.setItem(THEME_KEY, th.id); } catch (e) {}
}
try { applyTheme(localStorage.getItem(THEME_KEY) || "light"); } catch (e) { applyTheme("light"); }
drawTunnel($("#ambient"));
$("#theme").onclick = (e) => {
  e.stopPropagation();
  const menu = $("#theme-menu");
  const cur = document.documentElement.dataset.theme;
  menu.replaceChildren(...THEMES.map((th) => h("button", { class: th.id === cur ? "on" : null, onclick: () => { applyTheme(th.id); menu.classList.remove("open"); } },
    h("span.swatch", th.sw.map((c) => h("i", { style: { background: c } }))), th.label)));
  menu.classList.toggle("open");
};
document.addEventListener("pointerdown", (e) => { if (!e.target.closest(".themes")) $("#theme-menu").classList.remove("open"); });

// Error log: a red button with the number of errors not yet read.
function drawErrButton() {
  const b = $("#errlog");
  const unseen = errorLog().filter((e) => !e.seen).length;
  b.hidden = errorLog().length === 0;
  b.classList.toggle("new", unseen > 0);
  b.replaceChildren(icon("alert", 14), h("span", unseen ? `${unseen} error${unseen === 1 ? "" : "s"}` : "Errors"));
}
onErrorLog(drawErrButton);
drawErrButton();
$("#errlog").onclick = () => {
  const list = h("div.stack.errlist");
  const fill = () => list.replaceChildren(...(errorLog().length
    ? errorLog().map((e) => h("div.err-item",
        h("div.row", h("span.mono.muted", ts(e.t, 19, { label: true })), h("span.sp"),
          h("button.ghost.sm", { title: "Copy this message", onclick: async () => { try { await navigator.clipboard.writeText(`${e.t} ${e.msg}`); toast("Copied"); } catch (x) { toast("Copy not allowed here: select the text instead"); } } }, "Copy")),
        h("div.err-msg", e.msg)))
    : [h("p.muted", "No errors.")]));
  fill();
  markErrorsSeen();
  modal([
    h("div.hd", h("h2", "Errors"), h("span.sp"),
      h("button.sm", { onclick: () => { clearErrorLog(); fill(); } }, "Clear"),
      h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("p.muted", { style: { margin: "0 0 8px", fontSize: "12.5px" } }, "Errors shown in this browser, newest first (the last 100). Server-side details are in the server console; every case action is in the case audit log."),
    h("div.err-scroll", list),
  ]);
};

// Time zone for showing times: this computer's by default; UTC or any other on request.
const tzButton = () => {
  const b = $("#tz");
  b.textContent = zoneName();
  b.title = `Times are shown in ${zone()} (${offsetLabel(Date.now())} now). Click to change.`;
};
tzButton();
$("#tz").onclick = () => {
  const now = Date.now();
  const all = typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : [];
  const opt = (value, label) => h("option", { value, selected: zoneChoice() === value ? "" : null }, label);
  const sel = h("select", { style: { width: "100%" } },
    opt("local", `This computer's zone: ${localZone()} (${offsetLabel(now, localZone())} now)`),
    opt("UTC", "UTC"),
    all.filter((z) => z !== "UTC").map((z) => opt(z, `${z.replace(/_/g, " ")} (${offsetLabel(now, z)} now)`)));
  const fmt = h("select", { style: { width: "100%" } }, Object.entries(DATE_FORMATS).map(([k, p]) => h("option", { value: k, selected: dateFormat() === k ? "" : null }, `${p}${k === "dmy" ? " (day first)" : k === "ymd" ? " (ISO 8601)" : " (US)"}`)));
  const save = h("button.primary", "Save");
  save.onclick = () => { setZone(sel.value); setDateFormat(fmt.value); closeModal(); tzButton(); toast(`Times are shown in ${zone()}, dates as ${datePattern()}`); route(); };
  modal([
    h("div.hd", h("h2", "Time zone and date format"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("div.stack",
      h("label", "Show times in", sel),
      h("label", "Date format", fmt),
      h("p.muted", { style: { margin: 0, fontSize: "12.5px" } }, "Kokino stores every time as UTC and converts it for display, with summer time applied for each date. FAT and EXIF times are the device's own clock with no zone recorded, so they are shown as stored. Reports state the zone they use. This choice is kept in this browser."),
      h("div.row", save, h("button", { onclick: closeModal }, "Cancel"))),
  ]);
};

// ---------------------------------------------------------------- routing
function parse() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [path, qs = ""] = raw.split("?");
  const parts = path.split("/").filter(Boolean);
  return { parts, q: Object.fromEntries(new URLSearchParams(qs)) };
}

export function go(path) { location.hash = "#" + path; }

window.addEventListener("hashchange", route);

async function route() {
  const { parts, q } = parse();
  closeDrawer();
  state.route = { parts, q };
  try {
    if (!state.me) return;
    if (parts[0] === "c" && parts[1] && parts[2] === "e" && parts[3]) await workspace(parts[1], parts[3], parts[4] || "summary", q);
    else if (parts[0] === "c" && parts[1]) await caseView(parts[1], parts[2] || "evidence");
    else if (parts[0] === "users" && isAdmin()) await usersView();
    else if (parts[0] === "system-audit" && isAdmin()) await systemAuditView();
    else if (parts[0] === "hashsets" && isAdmin()) await hashsetsView();
    else if (parts[0] === "deleted-cases" && isAdmin()) await deletedCasesView();
    else if (parts[0] === "wiki") helpView("wiki", "Wiki", wikiPage(parts[1]));
    else if (parts[0] === "about") helpView("about", "About", aboutPage(state.info));
    else await home();
  } catch (err) {
    if (err.status === 401) return;
    view.replaceChildren(h("div.card", h("h2", err.status === 404 ? "Not available" : "Something went wrong"), h("p.muted", err.status === 404 ? "This case does not exist or is not assigned to you." : err.message)));
  }
}

function setNav(items) {
  const nav = $("#nav");
  const top = nav.scrollTop;
  nav.replaceChildren(...items.map((it) => (it.sec
    ? h("div.sec", { title: it.sec }, it.sec)
    : h("a", { href: "#" + it.href, title: it.label, class: [it.on ? "on" : "", it.sub ? "sub" : "", it.open ? "open" : ""].join(" ") }, h("span.ico", it.icon ? icon(it.icon) : ""), h("span.lbl", it.label), it.n != null ? h("span.n", it.n) : null))));
  nav.scrollTop = top;
  const on = nav.querySelector("a.on");
  if (on && (on.offsetTop < nav.scrollTop || on.offsetTop > nav.scrollTop + nav.clientHeight - 40)) on.scrollIntoView({ block: "center" });
}

/** Links shown on every page: cases, and administration for admins. */
function globalNav(active) {
  const items = [{ sec: "Workspace" }, { href: "/", label: "Cases", icon: "cases", on: active === "cases" }];
  if (isAdmin()) items.push({ href: "/users", label: "Users", icon: "users", on: active === "users" }, { href: "/hashsets", label: "Hash sets", icon: "hash", on: active === "hashsets" }, { href: "/deleted-cases", label: "Deleted cases", icon: "trash", on: active === "deleted-cases" }, { href: "/system-audit", label: "System audit", icon: "shield", on: active === "system-audit" });
  return items;
}

/** Help links, shown at the bottom of every menu. */
function helpNav(active) {
  return [{ sec: "Help" }, { href: "/wiki", label: "Wiki", icon: "book", on: active === "wiki" }, { href: "/about", label: "About", icon: "info", on: active === "about" }];
}

/** Wiki and About. Opened from inside a case, the case's menu stays and the
 * breadcrumbs lead back to the page you were on. */
function helpView(active, label, page) {
  const back = state.lastCase;
  if (back) {
    setCrumbs([{ label: back.c.info.name, href: back.route }, { label: "Help" }, { label }]);
    caseNav(back.c, null, back.eid, active);
  } else {
    setCrumbs([{ label: "Help" }, { label }]);
    setNav([...globalNav(null), ...helpNav(active)]);
  }
  render(page);
}

function setCrumbs(items) {
  const c = $("#crumbs");
  c.replaceChildren(...items.flatMap((it, i) => [i ? h("span.sep", "/") : null, it.href ? h("a", { href: "#" + it.href }, it.label) : h("b", it.label)]).filter(Boolean));
}

// Optional sections pass null; replaceChildren would print it as text.
function render(...nodes) { view.replaceChildren(...nodes.filter((n) => n != null && n !== false)); view.scrollTop = 0; }

// ---------------------------------------------------------------- jobs
// Jobs started from this window are watched until they end, so a job that
// starts and finishes between two polls (small images take a second or two)
// still refreshes the page.
const watchedJobs = new Set();

/** Poll now (after starting a job) instead of waiting for the next tick. */
function kickJobs(job) {
  if (job && job.id) watchedJobs.add(job.id);
  clearTimeout(state.pollTimer);
  pollJobs();
}

async function pollJobs() {
  if (!state.me) { state.polling = false; return; }
  clearTimeout(state.pollTimer);
  let next = 4000;
  try {
    const jobs = await api("/jobs");
    const before = new Map(state.jobs.map((j) => [j.id, j.state]));
    state.jobs = jobs;
    const running = jobs.filter((j) => j.state === "running");
    // Pills are updated in place, so their bar and pulse run on instead of restarting each poll.
    // Hash set imports show on their own page, not here. Pills already shown are
    // updated where they are: moving or replacing them restarts their animations.
    const top = $("#jobs");
    const keep = running.filter((j) => j.kind !== "hashset").slice(0, 2);
    const ids = keep.map((j) => j.id).join(",");
    if ([...top.children].map((c) => c.dataset.id).join(",") === ids) keep.forEach((j, i) => updatePill(top.children[i], j));
    else top.replaceChildren(...keep.map(jobPill));
    // Live progress wherever the page shows a job for an evidence item.
    for (const el of document.querySelectorAll("[data-job-ev]")) {
      const j = running.find((x) => x.evidence === el.dataset.jobEv);
      if (!j) continue;
      const old = el.firstElementChild;
      if (old && old.dataset.id === j.id) updatePill(old, j);
      else el.replaceChildren(jobPill(j));
    }
    let refresh = false;
    for (const j of jobs) {
      const was = before.get(j.id);
      const ended = j.state !== "running" && (was === "running" || watchedJobs.has(j.id));
      if (!ended) continue;
      watchedJobs.delete(j.id);
      delete state.caseCache[j.case];
      toast(j.state === "done" ? ({ index: "Text index ready", carve: "Carving complete", photos: "Picture analysis complete", hashes: "Hash analysis complete", hashset: "Hash set imported" }[j.kind] || "Analysis complete") : `Job ${j.state}: ${j.error || ""}`, j.state !== "done");
      const r = state.route;
      if (r && (r.parts[1] === j.case || (!j.case && r.parts[0] === "hashsets"))) refresh = true;
    }
    if (refresh) route();
    next = running.length || watchedJobs.size ? 600 : 2500;
  } catch (e) { /* retry later */ }
  state.pollTimer = setTimeout(pollJobs, next);
}

function jobPill(j) {
  return updatePill(h("div.job", { "data-id": j.id }, h("span.dot.pulse", { style: { color: "var(--accent)" } }), h("span.job-stage"), h("div.bar", h("i.flow")), h("span.muted.job-pct")), j);
}

/** New stage, bar width and percentage on an existing pill. */
function updatePill(el, j) {
  const pct = j.total ? Math.min(100, (j.done / j.total) * 100) : 0;
  el.title = j.stage;
  el.querySelector(".job-stage").textContent = j.stage.length > 34 ? j.stage.slice(0, 33) + "..." : j.stage;
  el.querySelector(".bar i").style.width = pct.toFixed(1) + "%";
  el.querySelector(".job-pct").textContent = pct.toFixed(0) + "%";
  return el;
}

// ---------------------------------------------------------------- home
function homeNav(active) {
  state.lastCase = null; // left the case
  setNav([...globalNav(active), ...helpNav(null)]);
}

const initials = (u) => (u.display_name || u.username).split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?";
const rolePill = (r) => h("span.pill.role-" + r, r);

async function home() {
  setCrumbs([{ label: "Cases" }]);
  homeNav("cases");
  const cases = await api("/cases");
  const name = h("input", { placeholder: "e.g. 2026-041 Laptop seizure" });
  const desc = h("input", { placeholder: "Optional" });
  const create = async (e) => {
    e.preventDefault();
    try {
      const c = await api("/cases", { method: "POST", body: { name: name.value, description: desc.value } });
      toast("Case created");
      go("/c/" + c.id);
    } catch (err) { toast(err.message, true); }
  };
  render(
    h("div.hero",
      h("h1", "Every finding, ", h("em", "traceable to the byte.")),
      h("p", "Open an image, and Kokino walks every NTFS MFT record, FAT/exFAT directory entry, ext2/3/4 inode, HFS+/APFS catalog record and ISO 9660/UDF directory record, live and deleted, compares $SI against $FN timestamps, checks signatures and scores the evidence for anti-forensic activity, with an explanation behind every number."),
    ),
    h("div.grid.g3",
      canCreate()
        ? h("form.card.stack", { onsubmit: create, style: { gridColumn: "span 1" } },
            h("h2", "New case"),
            h("label", "Case name", name),
            h("label", "Description", desc),
            h("p.muted", { style: { margin: 0, fontSize: "12.5px" } }, `You become the lead examiner. ${isAdmin() ? "Assign others under Members." : "An admin can assign others."}`),
            h("button.primary", { type: "submit" }, "Create case"),
          )
        : h("div.card.stack", { style: { gridColumn: "span 1" } }, h("h2", "Reviewer access"), h("p.muted", "You can open and review the cases assigned to you. Evidence, analysis and exports stay read-only.")),
      h("div.stack", { style: { gridColumn: "span 2" } },
        h("div.hd", h("h3", isAdmin() ? "All cases" : "Your cases"), h("span.sp"), h("span.muted", state.root || "")),
        cases.length
          ? h("div.grid.g2.stagger", cases.map((c, i) => h("div.card.case-card", { style: { "--i": i }, onclick: () => go("/c/" + c.info.id) },
              h("h2", c.info.name),
              h("div.muted", `${c.info.examiner}, ${ts(c.info.created, 16, { label: true })}`),
              h("div.row", { style: { marginTop: "10px" } }, h("span.pill", `${c.evidence_count} evidence`), c.access === "reviewer" ? h("span.pill.role-reviewer", "read-only") : null, c.info.description ? h("span.muted", c.info.description) : null))))
          : h("div.card.empty", canCreate() ? "No cases yet. Create one to begin." : "No cases are assigned to you yet."),
      ),
    ),
  );
}

// ---------------------------------------------------------------- case
async function getCase(cid) {
  const c = await api("/cases/" + cid);
  state.caseCache[cid] = c;
  state.write = c.access === "admin" || c.access === "examiner";
  return c;
}

function caseNav(c, active, eid, helpActive = null) {
  // Remembered for the Help pages (not when drawn for them).
  if (!helpActive) state.lastCase = { c, eid, route: location.hash.slice(1) || `/c/${c.info.id}` };
  const items = [
    ...globalNav(null),
    { sec: c.info.name },
    { href: `/c/${c.info.id}`, label: "Evidence", icon: "disk", on: active === "evidence", n: c.evidence.length },
    { href: `/c/${c.info.id}/members`, label: "Members", icon: "users", on: active === "members", n: Object.keys(c.info.members || {}).length },
    { href: `/c/${c.info.id}/bookmarks`, label: "Bookmarks", icon: "star", on: active === "bookmarks", n: state.bm && state.bm.cid === c.info.id ? state.bm.list.length : null },
    { href: `/c/${c.info.id}/audit`, label: "Audit log", icon: "chain", on: active === "audit" },
  ];
  // Only the evidence being worked on expands; the rest stay one line each.
  if (c.evidence.length) items.push({ sec: "Evidence items" });
  for (const e of c.evidence) {
    const base = `/c/${c.info.id}/e/${e.record.id}`;
    const open = eid === e.record.id;
    items.push({ href: base + "/summary", label: e.record.name, icon: "chev", open });
    if (!open) continue;
    const on = (t) => active === t;
    items.push(
      { href: base + "/summary", label: "Summary", icon: "pie", on: on("summary"), sub: true },
      { href: base + "/explorer", label: "Explorer", icon: "tree", on: on("explorer"), sub: true },
      { href: base + "/timeline", label: "Timeline", icon: "clock", on: on("timeline"), sub: true },
      { href: base + "/system", label: "System summary", icon: "monitor", on: on("system"), sub: true },
      { href: base + "/search", label: "Search", icon: "search", on: on("search"), sub: true },
      { href: base + "/carved", label: "Carved files", icon: "layers", on: on("carved"), sub: true },
      { href: base + "/photos", label: "Pictures", icon: "image", on: on("photos") || on("photo"), sub: true },
      { href: base + "/web", label: "Web activity", icon: "globe", on: on("web"), sub: true },
      { href: base + "/hashes", label: "Hash analysis", icon: "hash", on: on("hashes"), sub: true },
      { href: base + "/indicators", label: "Anti-forensics", icon: "alert", on: on("indicators"), sub: true },
      { href: base + "/hex", label: "Hex", icon: "hex", on: on("hex"), sub: true },
    );
  }
  setNav([...items, ...helpNav(helpActive)]);
}

async function caseView(cid, tab) {
  await loadBookmarks(cid).catch(() => {});
  const c = await getCase(cid);
  caseNav(c, tab);
  setCrumbs([{ label: "Cases", href: "/" }, { label: c.info.name }]);
  if (tab === "audit") return auditView(c);
  if (tab === "bookmarks") return bookmarksView(c);
  if (tab === "members") return membersView(c);
  const jobFor = (eid) => state.jobs.find((j) => j.evidence === eid && j.state === "running") || c.jobs.find((j) => j.evidence === eid && j.state === "running");
  render(
    h("div.hd", h("div", h("h1", c.info.name), h("div.muted", `Lead examiner ${c.info.examiner}, created ${ts(c.info.created, 19, { label: true })}, ${c.info.id}`)), h("span.sp"),
      canWrite() ? h("button", { onclick: () => editCase(c) }, "Edit case") : null,
      isAdmin() ? h("button.danger", { onclick: () => deleteCase(c) }, "Delete case") : null,
      canWrite() ? h("button.primary", { onclick: () => addEvidence(cid) }, "+ Add evidence") : h("span.readonly-note", icon("lock", 14), "Read-only access")),
    c.info.description ? h("p.muted", c.info.description) : null,
    c.audit && !c.audit.ok ? h("div.card.flat.alert-bad", h("b", "Audit log integrity check FAILED"), h("p", `The hash chain breaks at entry ${c.audit.broken_at}: entries from there on were altered, removed, reordered or written out of order. Earlier entries verify. Preserve the case folder as it is and investigate before relying on this case.`), h("a.btn.sm", { href: `#/c/${cid}/audit` }, "Open audit log")) : null,
    c.evidence.length
      ? h("div.grid.stagger", c.evidence.map((e, i) => evidenceCard(cid, e, jobFor(e.record.id), i)))
      : h("div.card.empty", h("p", "No evidence yet."), canWrite() ? h("button.primary", { onclick: () => addEvidence(cid) }, "Add a disk image") : null),
  );
}

/** What the imaging tool wrote into an E01: case details, dates, geometry, unreadable sectors. */
function acquisitionBlock(a) {
  const m = a.acquisition || {};
  const order = ["case_number", "evidence_number", "examiner", "description", "notes", "acquired", "system_date", "acquisition_software", "acquisition_os", "model", "serial_number", "device_label"];
  const keys = [...order.filter((k) => m[k]), ...Object.keys(m).filter((k) => !order.includes(k))];
  const label = (k) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
  const errs = a.read_errors || [];
  const errSectors = errs.reduce((n, r) => n + r[1], 0);
  const body = h("div.kv", { style: { marginTop: "10px" } },
    keys.map((k) => [h("span", label(k)), h("span", k === "acquired" || k === "system_date" ? ts(m[k]) : m[k])]),
    h("span", "Media"), h("span", `${a.media_type || "unknown"}, ${num(a.bytes_per_sector)} bytes/sector, ${num(a.chunk_count)} chunks (${num(a.compressed_chunks)} compressed)`),
    h("span", "Segments"), h("span", `${a.segments.length} file${a.segments.length === 1 ? "" : "s"}`),
    h("span", "Unreadable sectors"), errs.length
      ? h("span", h("span.pill.bad", h("span.dot"), `${num(errSectors)} sectors in ${errs.length} range(s)`), " ", h("span.muted", errs.slice(0, 6).map((r) => `${r[0]}+${r[1]}`).join(", ") + (errs.length > 6 ? ", ..." : "")))
      : h("span.muted", "none recorded by the imager"),
  );
  const det = h("details.acq", h("summary", "Acquisition details recorded in the image", m.case_number ? h("span.muted", { style: { marginLeft: "6px" } }, `- case ${m.case_number}`) : null, errs.length ? h("span.pill.bad", { style: { marginLeft: "8px" } }, "read errors") : null), body);
  return det;
}

function evidenceCard(cid, e, job, i) {
  const r = e.record;
  const hs = r.hashes;
  const verified = e.verified === true ? h("span.pill.ok", h("span.dot"), "matches acquisition hash") : e.verified === false ? h("span.pill.bad", h("span.dot"), "hash MISMATCH") : hs ? h("span.pill", "no acquisition hash supplied") : null;
  return h("div.card", { style: { "--i": i } },
    h("div.hd",
      h("div", h("h2", r.name), h("code.muted", r.path)),
      h("span.sp"),
      job ? h("span", { "data-job-ev": r.id }, jobPill(job)) : e.analyzed ? h("span.pill.ok", h("span.dot"), "Analyzed") : h("span.pill.warn", "Not analyzed"),
    ),
    h("div.kv",
      h("span", "Format / size"), h("span", `${r.format}, ${bytes(r.size)} (${num(r.size)} bytes)`),
      h("span", "MD5"), h("code", hs ? hs.md5 : "pending"),
      h("span", "SHA-1"), h("code", hs ? hs.sha1 : "pending"),
      h("span", "SHA-256"), h("code", hs ? hs.sha256 : "pending"),
      h("span", "Integrity"), h("span", verified || h("span.muted", "hashing...")),
      r.embedded ? [h("span", "Stored in image"), h("span", e.embedded_verified === true ? h("span.pill.ok", h("span.dot"), "matches the hash the imager recorded") : e.embedded_verified === false ? h("span.pill.bad", h("span.dot"), "does NOT match the hash the imager recorded") : h("span.muted", "checking..."))] : null,
      r.notes ? [h("span", "Notes"), h("span", r.notes)] : null,
    ),
    r.acquisition ? acquisitionBlock(r.acquisition) : null,
    h("div.row", { style: { marginTop: "14px" } },
      h("button.primary", { disabled: !e.analyzed, onclick: () => go(`/c/${cid}/e/${r.id}/summary`) }, "Open workspace"),
      canWrite() ? h("button", { disabled: !!job, onclick: () => reingest(cid, r.id, false) }, "Re-analyze") : null,
      canWrite() ? h("button", { disabled: !!job, onclick: () => reingest(cid, r.id, true) }, "Re-hash + analyze") : null,
      e.analyzed ? h("a.btn", { href: apiUrl(`/cases/${cid}/evidence/${r.id}/report`), target: "_blank", rel: "noopener" }, "HTML report") : null,
    ),
  );
}

async function reingest(cid, eid, rehash) {
  try {
    kickJobs(await api(`/cases/${cid}/evidence/${eid}/ingest?rehash=${rehash}`, { method: "POST" }));
    toast("Job started");
    setTimeout(route, 300);
  } catch (err) { toast(err.message, true); }
}

/** Name and description (write access); the lead examiner too for admins. Changes go to the audit log. */
async function editCase(c) {
  const name = h("input", { value: c.info.name, style: { width: "100%" } });
  const desc = h("textarea", { rows: 3, style: { width: "100%" } }, c.info.description);
  let lead = null;
  if (isAdmin()) {
    const users = await api("/users").catch(() => []);
    const leads = users.filter((u) => u.role !== "reviewer" && !u.disabled).map((u) => u.username);
    if (!leads.includes(c.info.examiner)) leads.unshift(c.info.examiner);
    lead = h("select", leads.map((u) => h("option", { value: u, selected: u === c.info.examiner ? "" : null }, u)));
  }
  const save = h("button.primary", "Save");
  save.onclick = async () => {
    save.disabled = true;
    try {
      const body = { name: name.value, description: desc.value };
      if (lead) body.examiner = lead.value;
      await api(`/cases/${c.info.id}`, { method: "PATCH", body });
      closeModal();
      delete state.caseCache[c.info.id];
      toast("Case updated");
      route();
    } catch (e) { toast(e.message, true); save.disabled = false; }
  };
  modal([
    h("div.hd", h("h2", "Edit case"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("div.stack",
      h("label", "Case name", name),
      h("label", "Description", desc),
      lead ? h("label", "Lead examiner", lead) : h("p.muted", { style: { margin: 0, fontSize: "12.5px" } }, `Lead examiner: ${c.info.examiner}. An admin can change it.`),
      h("p.muted", { style: { margin: 0, fontSize: "12.5px" } }, `The case id (${c.info.id}) and folder stay the same. Each change is recorded in the case audit log with its old and new value.`),
      h("div.row", save, h("button", { onclick: closeModal }, "Cancel"))),
  ]);
  name.focus();
}

/** Admins only: moves the case folder to the deleted-cases folder after typed confirmation. */
function deleteCase(c) {
  const input = h("input", { placeholder: c.info.name, style: { width: "100%" } });
  const go_ = h("button.danger", { disabled: true }, "Delete case");
  input.addEventListener("input", () => { go_.disabled = input.value.trim() !== c.info.name; });
  go_.onclick = async () => {
    go_.disabled = true;
    try {
      const r = await api(`/cases/${c.info.id}`, { method: "DELETE", body: { confirm: input.value.trim() } });
      closeModal();
      delete state.caseCache[c.info.id];
      state.bm = null;
      toast(`Case deleted. Its folder was moved to ${r.moved_to}`);
      go("/");
    } catch (e) { toast(e.message, true); go_.disabled = false; }
  };
  modal([
    h("div.hd", h("h2", "Delete case"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("div.stack",
      h("p", "This removes ", h("b", c.info.name), ` (${c.evidence.length} evidence item${c.evidence.length === 1 ? "" : "s"}) from Kokino for everyone.`),
      h("ul.impact",
        h("li", "The evidence image files are not touched."),
        h("li", "The case folder, with its analysis, search index, carving results, bookmarks, exports and audit log, is moved to the deleted-cases folder (", h("code", ".kokino/deleted"), " in the cases directory). An administrator can restore it from Deleted cases."),
        h("li", "The deletion is recorded in the system audit log with each evidence item's SHA-256.")),
      h("label", "Type the case name to confirm", input),
      h("div.row", go_, h("button", { onclick: closeModal }, "Cancel"))),
  ]);
  setTimeout(() => input.focus(), 50);
}

function addEvidence(cid) {
  const path = h("input", { placeholder: "Full path to .E01 / .dd / .raw / .img / .001 / .vhd / .vhdx / .vmdk" });
  const name = h("input", { placeholder: "Defaults to file name" });
  const notes = h("textarea", { rows: 2, placeholder: "Acquisition notes, chain of custody reference..." });
  const md5 = h("input.mono", { placeholder: "optional" });
  const sha1 = h("input.mono", { placeholder: "optional" });
  const sha256 = h("input.mono", { placeholder: "optional" });
  const picker = h("div.picker");
  const where = h("code.muted");
  const browse = async (p) => {
    try {
      const r = await api("/browse?path=" + encodeURIComponent(p || ""));
      where.textContent = r.path || "Choose a location";
      picker.replaceChildren(
        ...(r.path ? [h("div", { onclick: () => browse(r.parent || "") }, icon("up"), "..")] : []),
        ...r.entries.map((e) => h("div", { onclick: () => (e.is_dir ? browse(e.path) : ((path.value = e.path), toast("Selected " + e.name))) }, e.is_dir ? icon("folder") : icon("disk"), h("span", e.name), h("span.sp"), e.is_dir ? null : h("span.muted", bytes(e.size)))),
      );
    } catch (err) { toast(err.message, true); }
  };
  browse("");
  const submit = async () => {
    try {
      const added = await api(`/cases/${cid}/evidence`, { method: "POST", body: { path: path.value, name: name.value, notes: notes.value, expected_md5: md5.value, expected_sha1: sha1.value, expected_sha256: sha256.value } });
      kickJobs(added.job);
      closeModal();
      toast("Evidence added. Hashing and analysis started.");
      route();
    } catch (err) { toast(err.message, true); }
  };
  modal([
    h("div.hd", h("h2", "Add evidence"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("p.muted", "The image is opened read-only. For E01, pick the first segment; the others are found automatically and the hash the imager stored is checked too. Kokino hashes the media (MD5, SHA-1, SHA-256), compares against the acquisition hash if you supply one, and records every step in the case audit log."),
    h("div.stack",
      h("label", "Image path", path),
      h("div", where, picker),
      h("div.grid.g2", h("label", "Display name", name), h("label", "Acquisition MD5", md5)),
      h("div.grid.g2", h("label", "Acquisition SHA-1", sha1), h("label", "Acquisition SHA-256", sha256)),
      h("label", "Notes", notes),
      h("div.row", h("span.sp"), h("button.primary", { onclick: submit }, "Add and analyze")),
    ),
  ]);
}

async function auditView(c) {
  setCrumbs([{ label: "Cases", href: "/" }, { label: c.info.name, href: "/c/" + c.info.id }, { label: "Audit log" }]);
  const a = await api(`/cases/${c.info.id}/audit`);
  render(
    h("div.hd", h("h1", "Audit log"), h("span.sp"), a.verify.ok ? h("span.pill.ok", h("span.dot"), `hash chain intact, ${a.verify.entries} entries`) : h("span.pill.bad", h("span.dot"), `chain broken at entry ${a.verify.broken_at}`)),
    h("p.muted", "Append-only. Each entry embeds the SHA-256 of the previous one, so any edit, deletion or reordering is detectable. Head: ", h("code", a.verify.head)),
    h("div.scroll", h("table.tbl", h("thead", h("tr", h("th", "#"), h("th", `Time (${zoneName()})`), h("th", "User"), h("th", "Action"), h("th", "Detail"))),
      h("tbody", a.entries.slice().reverse().map((e) => h("tr", h("td.num", e.seq), h("td", ts(e.time)), h("td", e.examiner), h("td", h("b", e.action)), h("td.mono", { title: JSON.stringify(e.detail, null, 1) }, JSON.stringify(e.detail))))))),
  );
}

// ---------------------------------------------------------------- workspace
async function workspace(cid, eid, tab, q) {
  const c = state.caseCache[cid] && state.caseCache[cid].evidence.some((e) => e.record.id === eid) ? state.caseCache[cid] : await getCase(cid);
  const ev = c.evidence.find((e) => e.record.id === eid);
  if (!ev) throw new Error("evidence not found");
  await loadBookmarks(cid).catch(() => {});
  caseNav(c, tab, eid);
  setCrumbs([{ label: "Cases", href: "/" }, { label: c.info.name, href: "/c/" + cid }, { label: ev.record.name, href: `/c/${cid}/e/${eid}/summary` }, { label: { web: "Web activity", photos: "Pictures", photo: "Picture", hashes: "Hash analysis" }[tab] || tab[0].toUpperCase() + tab.slice(1) }]);
  if (!ev.analyzed) {
    // The job list may predate this ingest (started in another tab or by
    // another examiner): ask the server before deciding.
    const running = () => state.jobs.find((j) => j.evidence === eid && j.state === "running");
    if (!running()) state.jobs = await api("/jobs").catch(() => state.jobs);
    const job = running();
    if (job) {
      kickJobs(job);
      return render(h("div.card.empty", h("div.spin"), h("p", "Analysis in progress..."), h("span", { "data-job-ev": eid }, jobPill(job))));
    }
    const fresh = await getCase(cid);
    if (fresh.evidence.some((e) => e.record.id === eid && e.analyzed)) return workspace(cid, eid, tab, q);
    const failed = state.jobs.find((j) => j.evidence === eid && j.kind === "ingest" && j.state !== "done");
    return render(h("div.card.empty", h("p", "This evidence has not been analyzed."), failed && failed.error ? h("p.muted", failed.error) : null, h("a.btn", { href: `#/c/${cid}` }, "Back to the case")));
  }
  const s = await api(`/cases/${cid}/evidence/${eid}/summary`);
  const fi = Math.min(Number(q.fi || 0), Math.max(0, s.filesystems.length - 1));
  const ctx = { cid, eid, fi, s, ev, q, fs: s.filesystems[fi] };
  if (tab === "hex") return hexTab(ctx);
  // Search also covers disk space outside parsed volumes, so it works without a parsed file system.
  if (tab === "search") return searchTab(ctx);
  // Carving covers disk space outside parsed volumes too.
  if (tab === "carved") return carvedTab(ctx);
  // Pictures include carved ones, so they work without a parsed file system.
  photoInit({ state, render, kickJobs, route, canWrite, jobPill, bmButton, bookmarkDialog, loadBookmarks, fileDrawer, bytesDialog });
  if (tab === "photos") return photosTab(ctx);
  if (tab === "photo") return photoViewer(ctx);
  if (tab === "hashes") return hashesTab(ctx);
  if (!ctx.fs) {
    return render(h("div.card.stack", h("h2", "No supported filesystem found"), h("p.muted", "Kokino parses NTFS, FAT12/16/32, exFAT, ext2/3/4, ISO 9660, UDF, HFS+ and APFS. Detected volumes:"), volumeMap(s), ...s.errors.map((e) => h("p", e)), h("a.btn", { href: `#/c/${cid}/e/${eid}/hex` }, "Open in hex")));
  }
  if (tab === "explorer") return explorerTab(ctx);
  if (tab === "timeline") return timelineTab(ctx);
  if (tab === "indicators") return indicatorsTab(ctx);
  if (tab === "web") return webTab(ctx);
  if (tab === "system") return systemTab(ctx);
  return summaryTab(ctx);
}

function fsPicker(ctx, tab) {
  if (ctx.s.filesystems.length < 2) return null;
  return h("div.seg", ctx.s.filesystems.map((f, i) => h("button", { class: i === ctx.fi ? "on" : null, onclick: () => go(`/c/${ctx.cid}/e/${ctx.eid}/${tab}?fi=${i}`) }, `Vol ${f.volume.index} ${f.info.label || ""}`)));
}

/** FAT12/16/32 and exFAT: one timestamp set, no MFT, no named streams. */
const isFat = (label) => /fat/i.test(label || "");
const isExt = (label) => /^ext/i.test(label || "");
const isOptical = (label) => /iso 9660|udf/i.test(label || "");
const isMac = (label) => /hfs|apfs/i.test(label || "");
const isNtfs = (label) => !isFat(label) && !isExt(label) && !isOptical(label) && !isMac(label);
/** FAT12/16/32 store the device's local time with no zone: shown as stored, never converted. exFAT stores a UTC offset. */
const deviceClock = (label) => isFat(label) && label !== "exFAT";
const fsClock = (ctx) => ({ raw: !!(ctx.fs && deviceClock(ctx.fs.volume.fs_label)) });

const FS_COLORS = { ntfs: "linear-gradient(135deg,var(--accent),var(--accent2))", fat32: "#6f8aa3", ex_fat: "#6f8aa3", bit_locker: "#9a8fb8", ext: "#6fc28f", unknown: "color-mix(in srgb,var(--muted) 45%,var(--bg2))" };

function volumeMap(s) {
  const total = s.image_size || 1;
  return h("div.volmap", s.volumes.map((v, i) => h("div", { style: { "--i": i, color: v.kind === "unallocated" ? "var(--muted)" : v.supported ? "var(--accent-ink)" : null, flex: `${Math.max(v.length / total, 0.02)}`, background: v.kind === "unallocated" ? "repeating-linear-gradient(45deg,var(--bg2) 0 6px,color-mix(in srgb,var(--muted) 22%,var(--bg2)) 6px 12px)" : v.supported ? FS_COLORS.ntfs : FS_COLORS[v.fs] || FS_COLORS.unknown }, title: `${v.description}, ${v.fs_label}, offset ${v.start}, ${bytes(v.length)}` }, v.length / total > 0.08 ? `${v.kind === "unallocated" ? "Unallocated" : v.fs_label} ${bytes(v.length)}` : "")));
}

function gauge(likelihood, band) {
  const R = 78, C = Math.PI * R;
  const arc = svg("path", { d: `M ${100 - R} 100 A ${R} ${R} 0 0 1 ${100 + R} 100`, fill: "none", stroke: "url(#gg)", "stroke-width": 14, "stroke-linecap": "round", "stroke-dasharray": C, "stroke-dashoffset": C });
  const knob = svg("circle", { r: 7, cx: 100 - R, cy: 100, fill: "var(--text)" });
  const el = svg("svg", { viewBox: "0 0 200 112", width: 240 },
    svg("defs", {}, svg("linearGradient", { id: "gg" }, svg("stop", { offset: "0", "stop-color": "#6fc28f" }), svg("stop", { offset: ".5", "stop-color": "#e0a458" }), svg("stop", { offset: "1", "stop-color": "#e5484d" }))),
    svg("path", { d: `M ${100 - R} 100 A ${R} ${R} 0 0 1 ${100 + R} 100`, fill: "none", stroke: "var(--line2)", "stroke-width": 14, "stroke-linecap": "round" }),
    arc, knob);
  const val = h("b", "0%");
  spring(0, likelihood, (v) => {
    const vv = Math.max(0, Math.min(1, v));
    arc.setAttribute("stroke-dashoffset", C * (1 - vv));
    const a = Math.PI * (1 - vv);
    knob.setAttribute("cx", 100 + R * Math.cos(a));
    knob.setAttribute("cy", 100 - R * Math.sin(a));
    val.textContent = Math.round(vv * 100) + "%";
  }, { stiffness: 60, damping: 11 });
  return h("div.gauge", el, h("div.lbl", val, h("span", band)));
}

function histogram(ctx) {
  const days = ctx.fs.stats.histogram;
  if (!days.length) return h("div.muted", "No timestamps in range.");
  const W = 1000, H = 170, P = 4;
  const t0 = Date.parse(days[0].day), t1 = Date.parse(days[days.length - 1].day) || t0 + 1;
  const span = Math.max(1, t1 - t0);
  const max = Math.max(...days.map((d) => d.created + d.modified));
  const x = (d) => P + ((Date.parse(d.day) - t0) / span) * (W - 2 * P);
  const y = (v) => H - 18 - (Math.sqrt(v) / Math.sqrt(max)) * (H - 30);
  const pts = days.map((d) => [x(d), y(d.created + d.modified)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = line + ` L ${pts[pts.length - 1][0]} ${H - 18} L ${pts[0][0]} ${H - 18} Z`;
  const tip = svg("g", { opacity: 0 }, svg("line", { y1: 0, y2: H - 18, stroke: "var(--muted)", "stroke-dasharray": "3 3" }), svg("text", { y: 12, fill: "var(--text)", "font-size": 12 }));
  const el = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" },
    svg("defs", {}, svg("linearGradient", { id: "ha", x1: 0, y1: 0, x2: 0, y2: 1 }, svg("stop", { offset: 0, "stop-color": "var(--accent)", "stop-opacity": ".45" }), svg("stop", { offset: 1, "stop-color": "var(--accent2)", "stop-opacity": "0" }))),
    svg("path", { class: "area", d: area, fill: "url(#ha)" }),
    svg("path", { class: "line", d: line, fill: "none", stroke: "var(--accent2)", "stroke-width": 1.6, "vector-effect": "non-scaling-stroke" }),
    svg("text", { x: P, y: H - 2, fill: "var(--muted)", "font-size": 11 }, document.createTextNode(ts(days[0].day))),
    svg("text", { x: W - P, y: H - 2, fill: "var(--muted)", "font-size": 11, "text-anchor": "end" }, document.createTextNode(ts(days[days.length - 1].day))),
    tip);
  let cur = null;
  el.addEventListener("mousemove", (e) => {
    const r = el.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    let best = days[0], bd = Infinity;
    for (const d of days) { const dd = Math.abs(x(d) - px); if (dd < bd) { bd = dd; best = d; } }
    cur = best;
    tip.setAttribute("opacity", 1);
    tip.setAttribute("transform", `translate(${x(best)},0)`);
    const t = tip.querySelector("text");
    t.textContent = `${ts(best.day)}: ${best.created} created, ${best.modified} modified`;
    t.setAttribute("text-anchor", x(best) > W * 0.7 ? "end" : "start");
    t.setAttribute("x", x(best) > W * 0.7 ? -6 : 6);
  });
  el.addEventListener("mouseleave", () => tip.setAttribute("opacity", 0));
  el.addEventListener("click", () => cur && go(`/c/${ctx.cid}/e/${ctx.eid}/timeline?fi=${ctx.fi}&from=${cur.day}&to=${cur.day}`));
  el.style.cursor = "pointer";
  return el;
}

function tile(k, v, s, cls = "") {
  const vEl = h("div.v", "0");
  setTimeout(() => countUp(vEl, v), 60);
  return h("div.card.tile" + cls, h("div.k", k), vEl, s ? h("div.s", s) : null);
}

function summaryTab(ctx) {
  const { fs, s, ev } = ctx;
  const st = fs.stats;
  const hs = ev.record.hashes || {};
  const integrity = ev.verified === true ? h("span.pill.ok", h("span.dot"), "verified against acquisition hash") : ev.verified === false ? h("span.pill.bad", h("span.dot"), "HASH MISMATCH") : h("span.pill", "no acquisition hash");
  const maxCat = Math.max(1, ...st.by_category.map((c) => c[1]));
  const maxExt = Math.max(1, ...st.top_ext.map((c) => c[1]));
  render(h("div.stack",
    h("div.hd", h("div", h("h1", ev.record.name), h("div.muted", `${fs.volume.fs_label} "${fs.info.label}", ${isOptical(fs.volume.fs_label) ? `${fs.info.version}, created ${ts(fs.info.serial, 19)}, sector` : isExt(fs.volume.fs_label) || isMac(fs.volume.fs_label) ? `${fs.info.version}, UUID ${fs.info.serial}, block` : `serial ${fs.info.serial}, ${isFat(fs.volume.fs_label) ? "" : `NTFS ${fs.info.version}, `}cluster`} ${fs.info.cluster_size} B, analyzed ${ts(s.analyzed_at, 19, { label: true })} by Kokino ${s.tool_version}`)), h("span.sp"), fsPicker(ctx, "summary"),
      h("a.btn", { href: apiUrl(`/cases/${ctx.cid}/evidence/${ctx.eid}/report`), target: "_blank", rel: "noopener" }, "HTML report")),
    h("div.card.flat", h("div.hd", h("h3", "Disk layout"), h("span.sp"), h("span.muted", `${s.image_format}, ${bytes(s.image_size)}`)), volumeMap(s)),
    h("div.grid.g4.stagger",
      tile("Files", st.files, bytes(st.bytes)),
      tile("Directories", st.dirs),
      tile("Deleted files", st.deleted_files, bytes(st.deleted_bytes) + " recoverable metadata", ".del"),
      tile("Orphans / ADS", st.orphans + st.ads, `${num(st.orphans)} orphaned, ${num(st.ads)} alternate streams`),
    ),
    h("div.grid.g3",
      h("div.card", { style: { gridColumn: "span 1" } }, h("h3", "Anti-forensics likelihood"), gauge(fs.score.likelihood, fs.score.band),
        fs.score.drivers.length ? h("ul.impact", fs.score.drivers.map((d) => h("li", d))) : h("p.muted", "No indicators triggered."),
        h("a.btn.sm", { href: `#/c/${ctx.cid}/e/${ctx.eid}/indicators?fi=${ctx.fi}` }, "See the evidence behind the score")),
      h("div.card", { style: { gridColumn: "span 2" } }, h("h3", "Impact summary"), h("ul.impact.stagger", st.impact.map((l, i) => h("li", { style: { "--i": i } }, l))),
        st.users.length ? h("div.row.wrap", h("span.muted", "User profiles:"), st.users.map((u) => h("span.pill.info", u))) : null),
    ),
    h("div.card", h("div.hd", h("h3", isNtfs(fs.volume.fs_label) ? "Activity ($SI created + modified per day)" : "Activity (created + modified per day)"), h("span.sp"), h("span.muted", "click a day to open the timeline")), histogram(ctx)),
    h("div.grid.g2",
      h("div.card.bars", h("h3", { style: { marginBottom: "10px" } }, "Content by signature"), st.by_category.length ? st.by_category.map(([k, v], i) => h("div.b", h("span", k), h("div.t", h("i", { style: { width: (v / maxCat) * 100 + "%", "--i": i } })), h("span.n", num(v)))) : h("p.muted", "No recognised signatures.")),
      h("div.card.bars", h("h3", { style: { marginBottom: "10px" } }, "Top extensions"), st.top_ext.map(([k, v], i) => h("div.b", h("span.mono", "." + k), h("div.t", h("i", { style: { width: (v / maxExt) * 100 + "%", "--i": i } })), h("span.n", num(v))))),
    ),
    h("div.card", h("h3", "Evidence integrity"), h("div.kv", { style: { marginTop: "10px" } },
      h("span", "Status"), integrity, h("span", "MD5"), h("code", hs.md5 || ""), h("span", "SHA-1"), h("code", hs.sha1 || ""), h("span", "SHA-256"), h("code", hs.sha256 || ""),
      h("span", "Hashed"), h("span", ts(ev.record.hashed_at || "")), h("span", "Path"), h("code", ev.record.path))),
    fs.unreadable.length ? h("div.card", h("h3", `Unreadable MFT records (${fs.unreadable.length})`), h("p.muted", "Valid record slots Kokino could not parse. Inspect them in the hex view."),
      h("div.kv", fs.unreadable.slice(0, 50).map((u) => [h("span", "Record " + u.record), h("code", u.reason)]))) : null,
    s.errors.length ? h("div.card", h("h3", "Limitations"), h("ul", s.errors.map((e) => h("li", e)))) : null,
  ));
}

// ---------------------------------------------------------------- explorer
function fileRow(ctx, r, i, onclick) {
  return h("tr", { class: r.deleted ? "deleted" : null, onclick: onclick || (() => fileDrawer(ctx, r.idx)) },
    h("td.nm", { title: r.path }, r.flags.length ? h("span.flag", { title: r.flags.join(", ") }) : null, h("span.ico", fileIcon(r)), r.name, hashPill(r.hash)),
    h("td.num", r.is_dir ? (r.children ? num(r.children) + " items" : "") : bytes(r.size)),
    h("td", ts(r.modified, 19, fsClock(ctx))),
    h("td", r.sig_label ? h("span", { style: { color: r.mismatch ? "var(--bad)" : null } }, r.sig_label + (r.mismatch ? " (mismatch)" : "")) : h("span.muted", r.ext ? "." + r.ext : "")),
    r.name_only ? h("td.num.muted", { title: `No MFT record holds this name; recovered from ${r.name_only}` }, "name only") : h("td.num.mono", r.record),
  );
}

/** Badge for a file in a hash set: known bad (flagged) or known good. */
function hashPill(kind) {
  if (kind === "notable") return h("span.pill.bad.hp", { title: "In a known-bad hash set" }, "Known bad");
  if (kind === "known") return h("span.pill.hp", { title: "In a known-good hash set (e.g. NSRL)" }, "Known");
  return null;
}

const fileHead = () => h("thead", h("tr", h("th", "Name"), h("th", { style: { textAlign: "right" } }, "Size"), h("th", "Modified"), h("th", "Signature"), h("th", { style: { textAlign: "right" } }, "Record #")));

async function explorerTab(ctx) {
  const base = `/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}`;
  const tree = h("div.card.flat.tree");
  const tbody = h("tbody");
  const title = h("b", "/");
  const count = h("span.muted");
  const search = h("input", { placeholder: "Search all paths...", style: { flex: 1 } });
  let filter = ctx.q.filter || "";
  const seg = h("div.seg");
  const filters = [["", "All"], ["files", "Files"], ["deleted", "Deleted"], ["flagged", "Flagged"], ["mismatch", "Mismatch"], ["ads", "ADS"], ["notable", "Known bad"]];
  const drawSeg = () => seg.replaceChildren(...filters.map(([k, l]) => h("button", { class: filter === k ? "on" : null, onclick: () => { filter = k; drawSeg(); listSearch(); } }, l)));
  // Hide files in known-good hash sets (NSRL...). Remembered while the GUI is open.
  const hideBox = h("input", { type: "checkbox", checked: state.hideKnown ? "" : null });
  const hideLbl = h("label.row.muted", { style: { gap: "6px", fontSize: "12.5px", whiteSpace: "nowrap" }, title: "Leave out files found in a known-good hash set. Run Hash analysis first." }, hideBox, "Hide known good");
  let curDir = null;
  hideBox.addEventListener("change", () => { state.hideKnown = hideBox.checked; if (search.value.trim() || filter) listSearch(); else if (curDir) showDir(curDir[0], curDir[1]); });
  drawSeg();
  let selNode = null;

  const showDir = async (dir, label) => {
    const r = await api(`${base}/children?dir=${dir}`);
    curDir = [dir, label];
    const items = state.hideKnown ? r.items.filter((x) => x.hash !== "known") : r.items;
    title.textContent = label;
    count.textContent = `${items.length} items${items.length < r.items.length ? ` (${r.items.length - items.length} known good hidden)` : ""}`;
    tbody.replaceChildren(...items.map((it, i) => fileRow(ctx, it, i, it.is_dir ? () => expandTo(it) : null)));
    return r;
  };

  const node = (it, depth = 0) => {
    const tw = h("span.tw", it.children ? icon("chev", 12) : "");
    const kids = h("div");
    const n = h("div.n", { class: it.deleted ? "deleted" : null }, tw, h("span.ico", icon(it.virtual ? "orphan" : "folder")), it.name || "/");
    let open = false;
    n.onclick = async (e) => {
      e.stopPropagation();
      if (selNode) selNode.classList.remove("on");
      selNode = n; n.classList.add("on");
      const r = await showDir(it.virtual ? "orphans" : it.record, it.path || "/");
      if (!it.children && !it.virtual) return;
      open = !open || e.detail === -1;
      tw.classList.toggle("open", open);
      if (open) kids.replaceChildren(h("div.kids", r.items.filter((x) => x.is_dir).map((x) => node(x, depth + 1))));
      else kids.replaceChildren();
    };
    n._open = () => { if (!open) n.onclick({ stopPropagation() {}, detail: -1 }); };
    return h("div", n, kids);
  };

  const expandTo = async (it) => {
    await showDir(it.record, it.path);
    if (selNode) selNode.classList.remove("on");
  };

  const listSearch = debounce(async () => {
    const q = search.value.trim();
    if (!q && !filter) return showDir(5, "/");
    const r = await api(`${base}/files?q=${encodeURIComponent(q)}&filter=${filter}&limit=1000${state.hideKnown ? "&hide_known=true" : ""}`);
    title.textContent = q ? `Search "${q}"` : filters.find((f) => f[0] === filter)[1];
    count.textContent = `${num(r.total)} matches${r.total > r.items.length ? `, first ${r.items.length} shown` : ""}`;
    tbody.replaceChildren(...r.items.map((it, i) => fileRow(ctx, it, i)));
  }, 280);
  search.addEventListener("input", listSearch);

  const root = await api(`${base}/children?dir=`);
  const rootNode = node({ record: 5, name: "/", path: "/", children: root.items.length });
  tree.append(rootNode);
  if (root.orphans) tree.append(node({ virtual: true, name: "$OrphanFiles", path: "$OrphanFiles", children: root.orphans }));
  render(h("div.stack",
    h("div.hd", h("h1", "Explorer"), h("span.sp"), fsPicker(ctx, "explorer")),
    h("div.explorer",
      tree,
      h("div.listpane",
        h("div.row.wrap", search, seg, hideLbl),
        h("div.row", title, count),
        h("div.scroll", h("table.tbl", fileHead(), tbody)),
      ),
    ),
  ));
  rootNode.firstChild._open();
  if (filter) listSearch();
}

// ---------------------------------------------------------------- file drawer
function closeDrawer() { const d = $("#drawer"); d.classList.remove("open"); d.setAttribute("aria-hidden", "true"); $("#drawer-bm").replaceChildren(); }

// The drawer closes from its pinned button, Esc, or any press outside it
// (overlays like the modal and toasts do not count as outside).
$("#drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("#drawer").classList.contains("open") && !$("#modal").classList.contains("open")) closeDrawer();
});
document.addEventListener("pointerdown", (e) => {
  const d = $("#drawer");
  if (!d.classList.contains("open") || d.contains(e.target)) return;
  if (e.target.closest("#modal, #auth, #toasts")) return;
  closeDrawer();
});

async function fileDrawer(ctx, idx, startOffset) {
  const d = $("#drawer");
  const body = d.querySelector(".drawer-body");
  body.replaceChildren(h("div.spin"));
  d.classList.add("open");
  d.setAttribute("aria-hidden", "false");
  const base = `/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/file/${idx}`;
  const f = await api(base);
  const r = f.row;
  const fat = isFat(f.fs);
  const mac = isMac(f.fs);
  // Inode-based file systems share the inode labels.
  const ext = isExt(f.fs) || mac;
  const optical = isOptical(f.fs);
  const ntfs = isNtfs(f.fs);
  const u = f.unix;
  const nameOnly = f.name_only;
  const names = fat ? ["created", "modified", "accessed"] : ["created", "modified", "accessed", "mft_modified"];
  const labels = { created: "Born (B)", modified: optical ? "Recorded / modified (M)" : "Modified (M)", accessed: fat ? "Accessed (A, date only)" : "Accessed (A)", mft_modified: ext ? "Inode changed (C)" : optical ? "Attributes changed (C)" : "MFT changed (C)" };
  const tsTable = h("table.ts", h("tr", h("th", ""), h("th", fat ? "Directory entry" : ext ? "Inode" : optical ? "Directory record" : "$STANDARD_INFORMATION"), ntfs ? h("th", "$FILE_NAME") : null),
    names.map((n, i) => {
      if (!ntfs) return h("tr", h("td.muted", labels[n]), h("td.mono", ts((f.si && f.si[n]) || "", undefined, { raw: deviceClock(f.fs) })));
      const a = f.si && f.si[n], b = f.fn && f.fn[n];
      const ra = f.si && f.si.raw[i], rb = f.fn && f.fn.raw[i];
      const back = n === "created" && ra && rb && ra + 10000000 < rb;
      const whole = ra && ra % 10000000 === 0 && rb && rb % 10000000 !== 0;
      return h("tr", h("td.muted", labels[n]), h("td.mono", { class: back ? "bad" : whole ? "diff" : null, title: back ? "$SI earlier than $FN: possible timestomping" : whole ? "whole-second $SI" : null }, ts(a || "")), h("td.mono", ts(b || "")));
    }),
    u && u.deleted ? h("tr", h("td.muted", "Deleted (D)"), h("td.mono", { style: { color: "var(--del)" } }, ts(u.deleted))) : null);
  const hexBox = h("pre.mono", { style: { margin: 0, whiteSpace: "pre", overflow: "auto", maxHeight: "320px", fontSize: "12px" } });
  let page = startOffset ? Math.floor(startOffset / 4096) : 0;
  let stream = "";
  const pageInfo = h("span.muted");
  // Byte map and strings: loaded when opened. Picking one shows that part in Content.
  const showAt = (off) => { stream = ""; page = Math.floor(off / 4096); loadHex(); hexBox.scrollIntoView({ block: "center", behavior: "smooth" }); };
  const lazy = (label, make) => {
    const d = h("details.card.flat.lazy", h("summary", h("h3", label)));
    d.addEventListener("toggle", () => { if (d.open && d.children.length === 1) d.append(make()); });
    return d;
  };
  const loadHex = async () => {
    if (r.is_dir) { hexBox.textContent = "(directory)"; return; }
    try {
      const b = await api(`${base}/bytes?offset=${page * 4096}&len=4096&stream=${encodeURIComponent(stream)}`);
      const bytesArr = b.data.match(/../g) || [];
      let out = "";
      for (let i = 0; i < bytesArr.length; i += 16) {
        const row = bytesArr.slice(i, i + 16);
        const asc = row.map((x) => { const v = parseInt(x, 16); return v >= 32 && v < 127 ? String.fromCharCode(v) : "."; }).join("");
        out += hexOff(page * 4096 + i, 8) + "  " + row.join(" ").toUpperCase().padEnd(48) + "  " + asc + "\n";
      }
      hexBox.textContent = out || "(empty)";
      pageInfo.textContent = `${num(page * 4096)} to ${num(page * 4096 + bytesArr.length)} of ${num(b.size)}`;
    } catch (err) { hexBox.textContent = "Cannot read content: " + err.message; }
  };
  const ent = r.entropy;
  const cursor = h("i", { style: { left: "0%" } });
  setTimeout(() => (cursor.style.left = ((ent || 0) / 8) * 100 + "%"), 80);
  const jump = (off) => { closeDrawer(); go(`/c/${ctx.cid}/e/${ctx.eid}/hex?off=${off}`); };
  $("#drawer-bm").replaceChildren(bmButton({ cid: ctx.cid, eid: ctx.eid, kind: "file", key: `file:${ctx.eid}:${ctx.fi}:${r.record}`, fi: ctx.fi, record: r.record, idx, title: r.name, path: r.path }));
  body.replaceChildren(
    h("div.stack",
      h("div", h("h2", { style: { color: r.deleted ? "var(--del)" : null, wordBreak: "break-all" } }, h("span.ico", fileIcon(r)), r.name), h("code.muted", r.path)),
      h("div.row.wrap",
        r.deleted ? h("span.pill.bad", "Deleted") : h("span.pill.ok", "Allocated"),
        r.orphan ? h("span.pill.warn", "Orphan") : null,
        r.is_dir ? h("span.pill", "Directory") : null,
        f.resident ? h("span.pill.info", ext ? "Stored in the inode" : "Resident in MFT") : null,
        u && u.journal_seq != null ? h("span.pill.info", { title: "ext3/ext4 clear a deleted file's block map; this content was read through an older copy of its inode kept in the file-system journal" }, `Recovered from the journal (transaction ${u.journal_seq})`) : null,
        nameOnly ? h("span.pill.warn", { title: "No MFT record holds this name any more. It was found in a folder index ($I30) or the NTFS log ($LogFile), with its $FILE_NAME times and size, but without content." }, `Name only, from ${nameOnly.source}`) : null,
        fat && r.deleted && !r.is_dir ? h("span.pill.warn", { title: "The FAT chain is cleared on delete, so the clusters after the first are assumed to follow it" }, "Recovered as contiguous") : null,
        f.attribute_names.map((a) => h("span.pill", a)),
      ),
      f.attribute_names.includes("Encrypted") && !r.is_dir ? h("div.card.flat.ind", h("b", "Encrypted with EFS"), h("p", { style: { margin: "6px 0 0" } }, "Windows encrypted this file (Encrypting File System). The content, hashes, strings and search text here are of the ciphertext as stored on disk, not of the original file."),
        h("div.cav", "Decrypting needs the user's EFS certificate and private key (from their profile or an exported .pfx). File names, sizes and timestamps are not encrypted.")) : null,
      f.indicators.length ? h("div.stack", f.indicators.map((i) => h("div.card.flat.ind.hot", h("b", i.title), h("p", { style: { margin: "6px 0 0" } }, i.explanation), h("div.cav", i.caveat)))) : null,
      f.hashes && f.hashes.sets.some((s) => s.kind === "notable") ? h("div.card.flat.ind.hot", h("b", "In a known-bad hash set"), h("p", { style: { margin: "6px 0 0" } }, f.hashes.sets.filter((s) => s.kind === "notable").map((s) => `${s.name} (${ALGO[s.algo]})`).join(", ")),
        h("div.cav", "A hash match means identical content, not how the file got here or whether anyone opened it.")) : null,
      h("div.card.flat", h("h3", fat ? (f.fs === "exFAT" ? `Timestamps (${zoneName()}, from the stored UTC offset, 10 ms precision)` : "Timestamps (the device's local clock as stored, 2 s precision)") : mac ? `Timestamps (${zoneName()}, stored in UTC; APFS to the nanosecond, HFS+ to the second)` : ext ? `Timestamps (${zoneName()}, stored in UTC; ext4 to the nanosecond, ext2/ext3 to the second)` : optical ? `Timestamps (${zoneName()}, recorded as local time with its UTC offset, 1 s precision; born, accessed and changed only with Rock Ridge)` : `Timestamps (${zoneName()}, 100 ns precision)`), tsTable),
      h("div.card.flat", h("h3", "Identity"), h("div.kv", { style: { marginTop: "8px" } },
        fat || optical ? [h("span", "Entry id / parent"), h("span.mono", { title: "Assigned by Kokino in directory order; this file system has no record numbers" }, `${r.record} / ${f.parent}`)]
          : ext ? [h("span", "Inode / entry id"), h("span.mono", { title: "Entry ids are assigned by Kokino; hard links share one inode" }, `${u ? u.inode : ""} / ${r.record}`)]
          : nameOnly ? [h("span", "Former MFT record / seq"), h("span.mono", nameOnly.mft_record != null ? `${nameOnly.mft_record} / ${nameOnly.mft_seq}` : "not known"), h("span", "Parent record / seq"), h("span.mono", `${f.parent} / ${f.parent_seq}`)]
          : [h("span", "MFT record / seq"), h("span.mono", `${r.record} / ${r.seq}`), h("span", "Parent record / seq"), h("span.mono", `${f.parent} / ${f.parent_seq}`)],
        u ? [h("span", "Mode"), h("span.mono", `${u.mode_string} (${u.mode.padStart(6, "0")})`), h("span", "Owner uid / gid"), h("span.mono", `${u.uid} / ${u.gid}`)] : null,
        u && u.link_target != null ? [h("span", "Link target"), h("span.mono", { style: { wordBreak: "break-all" } }, u.link_target)] : null,
        ext || optical ? null : [h("span", "8.3 name"), h("span.mono", f.dos_name || "")],
        h("span", "Logical / allocated"), h("span", `${num(r.size)} / ${num(f.alloc_size)} bytes`),
        h("span", "Signature"), h("span", { style: { color: r.mismatch ? "var(--bad)" : null } }, r.sig_label ? `${r.sig_label}${r.mismatch ? ", does not match ." + r.ext : ""}` : "unknown"),
        h("span", "Entropy"), ent != null ? h("div", h("div.entropy", cursor), h("span.muted", `${ent.toFixed(3)} bits/byte`)) : h("span.muted", "n/a"),
        f.uniform != null ? [h("span", "Sampled content"), h("span", { style: { color: "var(--warn)" } }, `every sampled byte is 0x${f.uniform.toString(16).padStart(2, "0")}`)] : null,
        fat ? null : [h("span", "Hard links"), h("span", f.hard_links)],
        ntfs ? [h("span", "USN"), h("span.mono", f.usn ?? "")] : null,
        f.record_image_offset != null ? [h("span", fat ? "Directory entry at" : ext ? "Inode at" : optical ? "Directory record at" : nameOnly ? (nameOnly.source === "$LogFile" ? "Log record at" : "Index entry at") : "MFT record at"), h("a.mono", { href: "#", onclick: (e) => { e.preventDefault(); jump(f.record_image_offset); } }, `image offset ${num(f.record_image_offset)} -> hex`)] : null,
        u && u.journal_seq != null ? [h("span", "Inode copy in journal"), h("a.mono", { href: "#", onclick: (e) => { e.preventDefault(); jump(u.inode_image_offset); } }, `image offset ${num(u.inode_image_offset)} -> hex`)] : null,
        f.data_image_offset != null ? [h("span", ext ? "First data block" : optical ? "First data sector" : "First data cluster"), h("a.mono", { href: "#", onclick: (e) => { e.preventDefault(); jump(f.data_image_offset); } }, `image offset ${num(f.data_image_offset)} -> hex`)] : null,
        f.error ? [h("span", "Parser note"), h("span", { style: { color: "var(--warn)" } }, f.error)] : null,
      )),
      f.streams.length > 1 ? h("div.card.flat", h("h3", "Data streams"), h("table.ts", h("tr", h("th", "Name"), h("th", "Size"), h("th", "")),
        f.streams.map((s) => h("tr", h("td.mono", s.name || "(unnamed $DATA)"), h("td", bytes(s.size)), h("td", h("button.sm", { onclick: () => { stream = s.name; page = 0; loadHex(); } }, "View"), " ", canWrite() ? h("a.btn.sm", { href: apiUrl(`${base}/export?stream=${encodeURIComponent(s.name)}`) }, "Export") : null))))) : null,
      f.journal && f.journal.length ? h("div.card.flat", h("h3", "Change journal"), h("p.muted", { style: { margin: "4px 0 8px" } }, "What the NTFS change journal recorded for this file, newest first."),
        h("table.ts", f.journal.map((c) => h("tr", h("td.mono", ts(c.t, 19)), h("td", h("b", c.what)), h("td.mono", { style: { wordBreak: "break-all" } }, c.old_path ? `${c.old_path} -> ${c.path}` : c.path))))) : null,
      nameOnly && !r.is_dir ? h("div.card.flat", h("h3", "Content"), h("p.muted", { style: { margin: 0 } }, "None: only the name, times and size survive. Carving may still find the content in free space.")) : null,
      !r.is_dir && !nameOnly ? h("div.card.flat",
        h("div.hd", h("h3", "Content"), h("span.sp"), pageInfo,
          h("button.sm", { onclick: () => { if (page > 0) { page--; loadHex(); } } }, "Prev"),
          h("button.sm", { onclick: () => { page++; loadHex(); } }, "Next"),
          ["jpeg", "png", "bmp"].includes(r.sig) ? h("a.btn.sm", { href: viewerHref(ctx.cid, ctx.eid, { kind: "file", fi: ctx.fi, idx }), onclick: closeDrawer }, icon("image", 14), "Analyze picture") : null,
          canWrite() ? h("a.btn.sm.primary", { href: apiUrl(`${base}/export`) }, "Export (hashed + audited)") : null),
        r.deleted ? h("p.muted", { style: { marginTop: 0 } }, "Deleted file: clusters may have been reused, so content may belong to another file.") : null,
        hexBox) : null,
      f.hashes ? h("div.card.flat", h("h3", "Hashes"), h("div.kv", { style: { marginTop: "8px" } },
        f.hashes.error ? [h("span", "Not hashed"), h("span", { style: { color: "var(--warn)" } }, f.hashes.error)]
          : [h("span", "MD5"), h("span.mono.sel", f.hashes.md5), h("span", "SHA-1"), h("span.mono.sel", f.hashes.sha1), h("span", "SHA-256"), h("span.mono.sel", { style: { wordBreak: "break-all" } }, f.hashes.sha256)],
        h("span", "Hash sets"), f.hashes.sets.length ? h("div.row.wrap", f.hashes.sets.map((s) => h("span.pill", { class: s.kind === "notable" ? "bad" : null, title: `${s.kind === "notable" ? "Known bad" : "Known good"}, matched by ${ALGO[s.algo]}` }, s.name))) : h("span.muted", "no match"),
        h("span", "Hashed"), h("span.muted", ts(f.hashes.hashed_at, 19)))) : null,
      !r.is_dir && !nameOnly && r.size > 0 ? lazy("Byte map", () => byteMap(`${base}/binmap`, showAt)) : null,
      !r.is_dir && !nameOnly && r.size > 0 ? lazy("Strings", () => stringsPanel(`${base}/strings`, showAt)) : null,
      f.events.length ? h("div.card.flat", h("h3", "Timeline events"), h("table.ts", f.events.map((e) => h("tr", h("td.mono", ts(e.t, undefined, { raw: deviceClock(f.fs) })), h("td", macb(e.macb)), h("td", h("span.src." + e.src, ext && e.src === "SI" ? "INODE" : e.src)))))) : null,
    ),
  );
  if (!nameOnly) loadHex();
}

function macb(s) { return h("span.macb", [...s].map((c) => (c === "." ? "." : h("b", c)))); }

// ---------------------------------------------------------------- timeline
async function timelineTab(ctx) {
  const base = `/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/timeline`;
  const q = h("input", { placeholder: "Filter by path...", value: ctx.q.q || "", style: { flex: 1 } });
  // Days as dd.mm.yyyy, whatever the computer's locale (a date picker would follow it).
  const raw = fsClock(ctx).raw;
  const day = (v, ph) => h("input", { placeholder: ph, title: `Day as ${datePattern()} (${raw ? "device clock" : zoneName()})`, value: ts(v, 10), style: { width: "118px" } });
  const from = day(ctx.q.from, `from ${datePattern()}`);
  const to = day(ctx.q.to, `to ${datePattern()}`);
  let only = ctx.q.only || "";
  const seg = h("div.seg");
  const ntfs = !ctx.fs || isNtfs(ctx.fs.volume.fs_label);
  const opts = [["", "All"], ...(ntfs ? [["si", "$SI"], ["fn", "$FN"]] : []), ["web", "Web"], ["windows", ntfs ? "Windows" : "System"], ["deleted", "Deleted"], ["flagged", "Flagged"]];
  const drawSeg = () => seg.replaceChildren(...opts.map(([k, l]) => h("button", { class: only === k ? "on" : null, onclick: () => { only = k; drawSeg(); reload(); } }, l)));
  drawSeg();
  const tbody = h("tbody");
  const count = h("span.muted");
  const more = h("button", "Load more");
  let offset = 0, total = 0;
  const load = async (append) => {
    const [f, t] = [parseDay(from.value), parseDay(to.value)];
    from.classList.toggle("bad", f === null);
    to.classList.toggle("bad", t === null);
    if (f === null || t === null) {
      count.textContent = `Type days as ${datePattern()}, for example ${ts("2026-10-30")}.`;
      return;
    }
    // A day runs midnight to midnight in the display zone; FAT times are compared as stored.
    const next = (iso) => new Date(Date.parse(iso + "T00:00:00Z") + 86400000).toISOString().slice(0, 10);
    const params = new URLSearchParams({ q: q.value, from: f && !raw ? dayStart(f) : f, to: t && !raw ? dayStart(next(t)) : t, only, offset, limit: 400 });
    const r = await api(`${base}?${params}`);
    total = r.total;
    const WIN = { EXEC: "Program run", OPEN: "File or folder opened", USB: "USB device", INST: "Program installed", NET: "Network", EVT: "Event", USN: "File change (change journal)" };
    const rows = r.items.map((e) => {
      const art = e.web || e.windows;
      const click = e.web ? () => webDetail(e.src === "DL" ? "Download" : e.src === "SEARCH" ? "Search" : "Page visit", [[`Time (${zoneName()})`, ts(e.t)], ["What", e.path], ["Where", e.detail]])
        : e.windows ? () => webDetail(WIN[e.src] || e.src, [[`Time (${zoneName()})`, ts(e.t)], ["What", e.path], ["Detail", e.detail], ["More", h("a", { href: `#/c/${ctx.cid}/e/${ctx.eid}/system?fi=${ctx.fi}&sec=${{ EXEC: "exec", OPEN: "files", USB: "devices", NET: "devices", INST: "software", USN: "journal" }[e.src] || "events"}`, onclick: closeModal }, "Open in the System summary")]])
        : () => fileDrawer(ctx, e.idx);
      return h("tr", { class: e.deleted ? "deleted" : null, onclick: click },
        h("td.mono", ts(e.t, undefined, art ? {} : fsClock(ctx))), h("td", art ? h("span.muted", e.macb) : macb(e.macb)), h("td", h("span.src." + e.src, { title: WIN[e.src] || (e.src === "DEL" ? "Inode deleted (dtime)" : null) }, !ntfs && e.src === "SI" ? "INODE" : e.src)),
        h("td.nm", { title: art ? `${e.path}
${e.detail}` : e.path }, e.flags.length ? h("span.flag", { title: e.flags.join(", ") }) : null, e.path, art ? h("div.muted.ell", e.detail) : null),
        h("td.num", e.is_dir || (art && !e.size) ? "" : bytes(e.size)));
    });
    if (append) tbody.append(...rows); else tbody.replaceChildren(...rows);
    offset += r.items.length;
    count.textContent = `${num(total)} events`;
    more.style.display = offset < total ? "" : "none";
  };
  const reload = debounce(() => { offset = 0; load(false); }, 250);
  q.addEventListener("input", reload);
  from.addEventListener("change", reload);
  to.addEventListener("change", reload);
  more.onclick = () => load(true);
  render(h("div.stack",
    h("div.hd", h("h1", "Timeline"), h("span.sp"), fsPicker(ctx, "timeline")),
    h("p.muted", ntfs ? "MACB events from $STANDARD_INFORMATION and $FILE_NAME, interleaved with browser visits (VISIT), downloads (DL) and searches (SEARCH). $FN times are set by the kernel and are much harder to forge, so compare the two sources when something looks off."
      : isExt(ctx.fs && ctx.fs.volume.fs_label) ? "MACB events from each inode (M modified, A accessed, C inode changed, B born; born times exist on ext4 only), deletion times (DEL), interleaved with browser visits (VISIT), downloads (DL) and searches (SEARCH). touch can set M and A to anything, but not C: the kernel sets C to the time of the change."
      : "MACB events from the directory entries, interleaved with browser visits (VISIT), downloads (DL) and searches (SEARCH)."),
    h("div.row.wrap", q, h("label", "From", from), h("label", "To", to), seg, count),
    h("div.scroll", { style: { maxHeight: "calc(100vh - 290px)" } }, h("table.tbl", h("thead", h("tr", h("th", { title: raw ? "FAT stores the device's local clock with no zone: times are shown as stored" : null }, raw ? "Time (device clock)" : `Time (${zoneName()})`), h("th", "MACB"), h("th", "Src"), h("th", "Path"), h("th", { style: { textAlign: "right" } }, "Size"))), tbody)),
    h("div.row", h("span.sp"), more),
  ));
  load(false);
}

// ---------------------------------------------------------------- web activity
const srcName = (s) => s ? `${s.browser}: ${s.user || "unknown user"} / ${s.profile || "?"}` : "";

function webDetail(title, rows, target) {
  modal([
    h("div.hd", h("h2", title), h("span.sp"), target ? bmButton(target) : null, h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("div.kv", rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => [h("span", k), typeof v === "string" ? h("span.mono.wrap", v) : v])),
  ]);
}

// ---------------------------------------------------------------- bookmarks and tags
async function loadBookmarks(cid, force) {
  if (!force && state.bm && state.bm.cid === cid) return state.bm;
  const r = await api(`/cases/${cid}/bookmarks`);
  state.bm = { cid, list: r.bookmarks, tags: r.tags, suggested: r.suggested };
  return state.bm;
}
const bmOf = (key) => (state.bm ? state.bm.list.find((b) => b.key === key) : null);
const tagChip = (t, on, onclick) => h("button.chip", { class: on ? "on" : null, style: { "--h": tagHue(t) }, onclick, type: "button" }, t);
function tagHue(t) {
  let x = 0;
  for (const c of t.toLowerCase()) x = (x * 31 + c.charCodeAt(0)) % 360;
  return x;
}

/** Star button for an item; target = {cid, eid, kind, key, ...snapshot}. */
function bmButton(t) {
  const b = h("button.sm.bm");
  const draw = () => {
    const ex = bmOf(t.key);
    b.replaceChildren(icon("star", 14), ex ? (ex.tags.length ? ex.tags.join(", ") : "Bookmarked") : "Bookmark");
    b.classList.toggle("on", !!ex);
    b.title = ex ? `Bookmarked by ${ex.created_by}${ex.note ? ": " + ex.note : ""}` : "Bookmark and tag this item";
  };
  b.onclick = (e) => { e.stopPropagation(); bookmarkDialog(t, draw); };
  loadBookmarks(t.cid).then(draw).catch(() => {});
  draw();
  return b;
}

async function bookmarkDialog(t, done) {
  const bm = await loadBookmarks(t.cid);
  const ex = bmOf(t.key);
  const tags = new Set(ex ? ex.tags : []);
  const chips = h("div.row.wrap.chips");
  const known = () => [...new Set([...bm.suggested, ...Object.keys(bm.tags), ...tags])];
  const drawChips = () => chips.replaceChildren(...known().map((x) => tagChip(x, tags.has(x), () => { tags.has(x) ? tags.delete(x) : tags.add(x); drawChips(); })));
  const add = h("input", { placeholder: "New tag, then Enter", maxlength: 40, style: { width: "220px" } });
  add.addEventListener("keydown", (e) => { if (e.key === "Enter" && add.value.trim()) { tags.add(add.value.trim()); add.value = ""; drawChips(); } });
  const note = h("textarea", { rows: 4, maxlength: 4000, placeholder: "Note (why this matters)", style: { width: "100%" } });
  note.value = ex ? ex.note : "";
  const finish = async () => {
    await loadBookmarks(t.cid, true);
    const n = document.querySelector('#nav a[href$="/bookmarks"] .n');
    if (n) n.textContent = state.bm.list.length;
    closeModal();
    if (done) done();
    if (state.route && state.route.parts[2] === "bookmarks") route();
  };
  const save = async () => {
    try {
      const body = { evidence: t.eid, kind: t.kind, key: t.key, fi: t.fi, record: t.record, idx: t.idx, offset: t.offset, len: t.len, carved: t.carved, region: t.region, view: t.view || "", title: t.title || "", detail: t.detail || "", path: t.path || "", time: t.time || "", tags: [...tags], note: note.value };
      if (ex) await api(`/cases/${t.cid}/bookmarks/${ex.id}`, { method: "PUT", body: { tags: [...tags], note: note.value } });
      else await api(`/cases/${t.cid}/bookmarks`, { method: "POST", body });
      toast(ex ? "Bookmark updated" : "Bookmarked");
      await finish();
    } catch (e) { toast(e.message, true); }
  };
  const remove = async () => {
    try { await api(`/cases/${t.cid}/bookmarks/${ex.id}`, { method: "DELETE" }); toast("Bookmark removed"); await finish(); } catch (e) { toast(e.message, true); }
  };
  drawChips();
  modal([
    h("div.hd", h("h2", ex ? "Edit bookmark" : "Bookmark"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("div.stack",
      h("div", h("b", t.title || t.key), t.path ? h("div.muted.mono.wrap", t.path) : null),
      h("div", h("h3", "Tags"), chips, h("div.row", { style: { marginTop: "8px" } }, add)),
      h("div", h("h3", "Note"), note),
      ex ? h("p.muted", { style: { fontSize: "12.5px" } }, `Bookmarked by ${ex.created_by} on ${ts(ex.created_at, 16)}${ex.updated_by !== ex.created_by || ex.updated_at !== ex.created_at ? `, last changed by ${ex.updated_by}` : ""}.`) : h("p.muted", { style: { fontSize: "12.5px" } }, t.kind === "file" ? "The file's MD5 and SHA-256 are computed from the evidence and stored with the bookmark." : "Bookmarks and changes to them are recorded in the case audit log."),
      h("div.row", h("button.primary", { onclick: save }, ex ? "Save" : "Bookmark"), ex ? h("button", { onclick: remove }, "Remove bookmark") : null)),
  ]);
  setTimeout(() => (ex ? note : add).focus(), 50);
}

const BM_KINDS = { file: "File", event: "Event", carved: "Carved file", hit: "Search hit", offset: "Byte range", web: "Web history" };

async function bookmarksView(c) {
  const cid = c.info.id;
  setCrumbs([{ label: "Cases", href: "/" }, { label: c.info.name, href: "/c/" + cid }, { label: "Bookmarks" }]);
  const bm = await loadBookmarks(cid, true);
  let tag = state.route.q.tag || "", q = "";
  const evName = (eid) => (c.evidence.find((e) => e.record.id === eid) || { record: { name: eid } }).record.name;
  const chips = h("div.row.wrap.chips");
  const out = h("div");
  const report = h("a.btn.sm.ghost", { target: "_blank", style: { whiteSpace: "nowrap" } }, icon("book", 14), "Quick list");
  const caseReport = canWrite() ? h("button.sm.primary", { style: { whiteSpace: "nowrap" }, onclick: () => caseReportDialog(c, bm, tag) }, icon("book", 14), "Case report") : null;
  const reports = h("div");
  reportsCard(cid, reports);
  const open = async (b) => {
    if (b.region && b.kind === "carved") { location.hash = viewerHref(cid, b.evidence, { kind: "carved", id: b.carved }, b.region); return; }
    if (b.region && b.kind === "file") {
      try { const r = await api(`/cases/${cid}/evidence/${b.evidence}/fs/${b.fi}/by-record/${b.record}`); location.hash = viewerHref(cid, b.evidence, { kind: "file", fi: b.fi, idx: r.idx }, b.region); } catch (e) { toast(e.message, true); }
      return;
    }
    if (b.kind === "file") {
      try { const r = await api(`/cases/${cid}/evidence/${b.evidence}/fs/${b.fi}/by-record/${b.record}`); fileDrawer({ cid, eid: b.evidence, fi: b.fi }, r.idx); } catch (e) { toast(e.message, true); }
    } else if (b.kind === "carved") go(`/c/${cid}/e/${b.evidence}/carved?view=table&id=${b.carved}`);
    else if ((b.kind === "hit" || b.kind === "offset") && b.offset != null) go(`/c/${cid}/e/${b.evidence}/hex?off=${b.offset}`);
    else webDetail(b.title, [["Kind", BM_KINDS[b.kind] || b.kind], [`Time (${zoneName()})`, ts(b.time)], ["Where", b.path], ["Detail", b.detail], ["Note", b.note],
      ["", h("a", { href: `#/c/${cid}/e/${b.evidence}/${b.kind === "web" ? "web" : `system?fi=${b.fi || 0}&sec=events`}`, onclick: closeModal }, b.kind === "web" ? "Open Web activity" : "Open the event list")]]);
  };
  const draw = () => {
    chips.replaceChildren(tagChip(`All (${bm.list.length})`, !tag, () => { tag = ""; draw(); }), ...Object.entries(bm.tags).map(([t, n]) => tagChip(`${t} (${n})`, tag === t, () => { tag = t; draw(); })));
    report.href = apiUrl(`/cases/${cid}/bookmarks/report${tag ? `?tag=${encodeURIComponent(tag)}` : ""}`);
    report.title = tag ? `One-page HTML list of items tagged ${tag}` : "One-page HTML list of every bookmarked item";
    const list = bm.list.filter((b) => (!tag || b.tags.includes(tag)) && (!q || [b.title, b.path, b.detail, b.note, b.tags.join(" ")].join(" ").toLowerCase().includes(q)));
    out.replaceChildren(list.length
      ? h("div.scroll", { style: { maxHeight: "calc(100vh - 290px)" } }, h("table.tbl.sys", h("thead", h("tr", ["Item", "Kind", "Evidence", "Tags", "Note", "Bookmarked"].map((x) => h("th", x)))),
        h("tbody", list.slice().reverse().map((b) => h("tr", { class: b.deleted ? "deleted" : null, onclick: () => open(b) },
          h("td.nm", h("b", b.title), h("div.muted.mono.ell", { title: b.path }, b.path), b.region ? h("div.muted", `Region ${b.region[0]},${b.region[1]} ${b.region[2]}x${b.region[3]} px${b.view ? ` (${b.view} view)` : ""}`) : null, b.sha256 ? h("div.muted.mono", { title: `MD5 ${b.md5}` }, `SHA-256 ${b.sha256.slice(0, 16)}...`) : null),
          h("td", h("span.pill", b.region ? "Picture region" : BM_KINDS[b.kind] || b.kind)), h("td", evName(b.evidence)),
          h("td", h("div.row.wrap.chips", b.tags.map((t) => tagChip(t, true, (e) => { e.stopPropagation(); tag = t; draw(); })))),
          h("td.muted", { style: { maxWidth: "280px" } }, b.note),
          h("td", h("div", b.created_by), h("div.muted", ts(b.created_at, 16)), h("button.sm.ghost", { onclick: (e) => { e.stopPropagation(); bookmarkDialog({ cid, eid: b.evidence, kind: b.kind, key: b.key, title: b.title, path: b.path }); } }, "Edit")))))))
      : h("div.card.empty", bm.list.length ? "No bookmarks match." : "No bookmarks yet. Use the Bookmark button on a file, event, carved file, search hit or hex selection."));
  };
  const filter = h("input", { placeholder: "Filter bookmarks...", style: { flex: 1 } });
  filter.addEventListener("input", debounce(() => { q = filter.value.toLowerCase(); draw(); }, 150));
  draw();
  render(h("div.stack",
    h("div.hd", h("div", h("h1", "Bookmarks"), h("div.muted", "Tagged items of this case, with your notes. Every change is recorded in the case audit log.")), h("span.sp"), report, caseReport),
    h("div.row.wrap", chips, filter),
    out, reports));
}

/** Case reports made so far, from the audit log, each file checked against its recorded SHA-256. */
async function reportsCard(cid, host) {
  let list = [];
  try { list = await api(`/cases/${cid}/reports`); } catch { return; }
  if (!list.length) return host.replaceChildren();
  const fileLink = (f) => h("div.row", { style: { gap: "8px" } },
    f.present
      ? h("a", f.name.endsWith(".html") ? { href: apiUrl(`/cases/${cid}/reports/${f.name}`), target: "_blank" } : { href: apiUrl(`/cases/${cid}/reports/${f.name}`), download: f.name }, f.format === "HTML" ? "HTML (print to PDF)" : "Word")
      : h("span.muted", `${f.format}: file missing`),
    f.present ? h("span.pill", { class: f.intact ? "ok" : "bad", title: f.intact ? "The file still has the SHA-256 recorded when it was made" : "The file changed after it was made" }, f.intact ? "intact" : "CHANGED") : null,
    h("span.muted.mono", { title: `SHA-256 ${f.sha256}` }, `SHA-256 ${f.sha256.slice(0, 16)}...`));
  host.replaceChildren(h("div.card.stack",
    h("h3", "Case reports"),
    h("div.scroll", h("table.tbl", h("thead", h("tr", ["Report", "Made", "Scope", "Exhibits", "Files"].map((x) => h("th", x)))),
      h("tbody", list.map((r) => h("tr",
        h("td", h("b", r.title || "Forensic examination report"), h("div.muted.mono", r.report), r.reference ? h("div.muted", r.reference) : null),
        h("td", h("div", r.by), h("div.muted", ts(r.time, 16))),
        h("td", r.tag ? `Tagged ${r.tag}` : "All bookmarks"),
        h("td", String(r.exhibits)),
        h("td", r.files.map(fileLink))))))),
    h("p.muted", { style: { fontSize: "12.5px", margin: 0 } }, "Reports are kept in the case exports folder. Their SHA-256 is in the case audit log, so a copy handed over can be checked against it.")));
}

/** Options for the court-ready case report, then generate it. */
function caseReportDialog(c, bm, tag) {
  const cid = c.info.id;
  const title = h("input", { placeholder: "Forensic examination report", maxlength: 200 });
  const reference = h("input", { placeholder: "Your reference or lab number (optional)", maxlength: 120 });
  const requested = h("input", { placeholder: "Who asked for the examination (optional)", maxlength: 200 });
  const scope = h("select", h("option", { value: "" }, `All bookmarks (${bm.list.length})`),
    Object.entries(bm.tags).map(([t, n]) => h("option", { value: t, selected: t === tag ? "" : null }, `Tagged ${t} (${n})`)));
  const summary = h("textarea", { rows: 6, maxlength: 20000, placeholder: "Summary of findings, in your words (optional). Blank lines start new paragraphs." });
  const full = h("input", { type: "checkbox" });
  const utc = h("input", { type: "checkbox", checked: zoneName() === "UTC" ? "" : null });
  const go = h("button.primary", "Generate report");
  const body = h("div.stack",
    h("p.muted", { style: { margin: 0 } }, "Every bookmarked item becomes a numbered exhibit with its location, hashes, findings and your note. Kokino reads each exhibit from the evidence again and checks its hash, and adds the evidence and its verification, the chain of custody from the audit log, methods, limitations and a sign-off block."),
    h("label", "Title", title), h("div.row.wrap", { style: { gap: "12px" } }, h("label", { style: { flex: 1 } }, "Reference", reference), h("label", { style: { flex: 1 } }, "Requested by", requested)),
    h("label", "Exhibits", scope), h("label", "Summary", summary),
    h("label.row", { style: { gap: "8px" } }, full, "Append the full audit log (every entry, including searches)"),
    h("label.row", { style: { gap: "8px" } }, utc, "Times in UTC (otherwise the local time of the computer running Kokino, with each UTC offset)"),
    h("div.row", go, h("button.ghost", { onclick: closeModal }, "Cancel")));
  go.onclick = async () => {
    go.disabled = true;
    go.textContent = "Reading exhibits from the evidence...";
    try {
      const r = await api(`/cases/${cid}/report`, { method: "POST", body: { title: title.value, reference: reference.value, requested_by: requested.value, summary: summary.value, tag: scope.value, full_audit: full.checked, utc: utc.checked } });
      const url = (n) => apiUrl(`/cases/${cid}/reports/${n}`);
      body.replaceChildren(
        h("p", h("b", `Report ${r.report}`), ` with ${r.exhibits} exhibit${r.exhibits === 1 ? "" : "s"} is saved in the case exports folder.`),
        ...r.files.map((f) => h("div.stack", { style: { gap: "2px" } },
          h("a.btn", f.format === "HTML" ? { href: url(f.name), target: "_blank" } : { href: url(f.name), download: f.name }, icon(f.format === "HTML" ? "book" : "download", 14), f.format === "HTML" ? "Open HTML (print it to save a PDF)" : "Download Word (.docx)"),
          h("span.muted.mono", { style: { fontSize: "11.5px", wordBreak: "break-all" } }, `${f.name}  SHA-256 ${f.sha256}`))),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Both SHA-256 values are recorded in the case audit log."),
        h("div.row", h("button", { onclick: () => { closeModal(); route(); } }, "Done")));
    } catch (e) {
      toast(e.message, true);
      go.disabled = false;
      go.textContent = "Generate report";
    }
  };
  modal([h("div.hd", h("h2", "Case report"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Cancel")), body]);
  setTimeout(() => title.focus(), 50);
}

// ---------------------------------------------------------------- full-text search
const SEARCH_HELP = {
  keyword: ["Whole words; all must appear. Use \"quoted phrases\", OR, NOT and a trailing * for prefixes. Punctuation is ignored, so alice@example.com and C:\\Users work as typed. To find text inside a longer string (raw database records often glue fields together), use Regex."],
  regex: ["Regular expression (Rust syntax), matched inside each extracted string. Case-insensitive unless ticked. Example: ", h("code", "pass(word)?\\s*[:=]\\s*\\S+")],
  preset: ["Ready-made patterns. Card numbers and IBANs are only reported when their checksum is valid."],
};

async function searchTab(ctx) {
  const { cid, eid } = ctx;
  const base = `/cases/${cid}/evidence/${eid}`;
  const idx = await api(`${base}/textindex`);
  const job = state.jobs.find((j) => j.evidence === eid && j.state === "running");
  const build = () => api(`${base}/textindex`, { method: "POST" }).then((j) => { toast("Building the text index"); kickJobs(j); route(); }).catch((e) => toast(e.message, true));
  const st = idx.stats;
  const intro = h("div.hd", h("div", h("h1", "Search"),
    h("div.muted", st
      ? `Indexed ${num(st.streams)} file streams (${num(st.deleted_streams)} deleted, ${bytes(st.file_bytes)}), text inside ${num(st.documents)} document${st.documents === 1 ? "" : "s"}, ${bytes(st.unalloc_bytes)} of unallocated clusters and ${bytes(st.disk_bytes)} outside parsed volumes. Built ${ts(st.built_at, 16)}.`
      : "Full-text search over files, deleted files and unallocated space.")),
    h("span.sp"),
    st && canWrite() && !job ? h("button.sm", { onclick: build, title: "Rebuild the index from the image" }, "Rebuild index") : null);
  if (!st) {
    if (idx.outdated) intro.append(h("p.muted", { style: { flexBasis: "100%" } }, "The existing index was made by an older Kokino version and does not include text inside documents. Rebuild it to search them."));
    return render(h("div.stack", intro, h("div.card.empty.stack",
      job ? [h("div.spin"), h("p", "Building the text index..."), h("span", { "data-job-ev": eid }, jobPill(job))]
        : [h("p", "This evidence has no text index yet. Building it reads every file stream, deleted files where their records survive, all free clusters and the space outside partitions, and extracts UTF-8 and UTF-16 text."),
          canWrite() ? h("button.primary", { onclick: build }, "Build text index") : h("p.muted", "Ask an examiner on this case to build it.")])));
  }

  let mode = ["keyword", "regex", "preset"].includes(ctx.q.mode) ? ctx.q.mode : "keyword";
  let scope = ["all", "files", "deleted", "unallocated"].includes(ctx.q.scope) ? ctx.q.scope : "all";
  const input = h("input", { placeholder: "Search text...", value: mode === "preset" ? "" : ctx.q.q || "", style: { flex: 1 } });
  const presetSel = h("select", idx.presets.map((p) => h("option", { value: p.id, title: p.pattern, selected: mode === "preset" && ctx.q.q === p.id ? "" : null }, p.label)));
  const caseBox = h("input", { type: "checkbox", checked: ctx.q.case === "true" ? "" : null });
  const caseLbl = h("label.row.muted", { style: { gap: "6px", fontSize: "12.5px" } }, caseBox, "Case-sensitive");
  const help = h("div.muted", { style: { fontSize: "12.5px" } });
  const modeSeg = h("div.seg");
  const scopeSeg = h("div.seg");
  let lastRun = false;
  const drawForm = () => {
    modeSeg.replaceChildren(...[["keyword", "Keywords"], ["regex", "Regex"], ["preset", "Presets"]].map(([k, l]) => h("button", { class: mode === k ? "on" : null, onclick: () => { mode = k; drawForm(); } }, l)));
    scopeSeg.replaceChildren(...[["all", "All"], ["files", "Live files"], ["deleted", "Deleted files"], ["unallocated", "Unallocated"]].map(([k, l]) => h("button", { class: scope === k ? "on" : null, onclick: () => { scope = k; drawForm(); if (lastRun) run(); } }, l)));
    input.style.display = mode === "preset" ? "none" : "";
    presetSel.style.display = mode === "preset" ? "" : "none";
    caseLbl.style.display = mode === "regex" ? "" : "none";
    input.placeholder = mode === "regex" ? "Regular expression..." : "Words, \"phrases\", OR, NOT, prefix*";
    help.replaceChildren(...SEARCH_HELP[mode]);
  };
  const searchBtn = h("button.primary", { onclick: () => run() }, icon("search", 15), "Search");
  input.addEventListener("keydown", (e) => e.key === "Enter" && run());

  const out = h("div.stack");
  const where = (x) => {
    if (x.source === "file") return h("div", { style: { minWidth: 0 } }, h("b.ell", { title: x.path }, x.path || "(file)"),
      x.part ? h("div.muted.ell", { title: x.part }, `inside ${x.part}`) : null, x.stream ? h("div.muted", `stream :${x.stream}`) : null);
    if (x.source === "carved") return h("div", h("b", `Carved file #${x.carved}`), x.part ? h("div.muted.ell", { title: x.part }, `inside ${x.part}`) : null);
    if (x.fi == null) return h("span.muted", x.source === "raw" ? "Volume not parsed (raw)" : "Outside any partition");
    const v = ctx.s.filesystems[x.fi];
    return h("span.muted", `Free clusters, volume ${v ? v.volume.index : x.fi}`);
  };
  const srcPill = (x) => x.source === "file"
    ? (x.deleted ? h("span.pill.bad", "Deleted") : h("span.pill.ok", "File"))
    : x.source === "raw" ? h("span.pill", "Raw") : x.source === "carved" ? h("span.pill.info", "Carved") : h("span.pill.warn", "Unallocated");
  const run = async () => {
    const q = mode === "preset" ? presetSel.value : input.value.trim();
    if (!q) return input.focus();
    lastRun = true;
    const params = new URLSearchParams({ q, mode, scope });
    if (mode === "regex" && caseBox.checked) params.set("case", "true");
    history.replaceState(null, "", `#/c/${cid}/e/${eid}/search?${params}`);
    out.replaceChildren(h("div.card.empty", h("div.spin")));
    try {
      const r = await api(`${base}/textsearch?${params}`);
      const rows = r.hits.map((x) => h("tr", { class: x.deleted ? "deleted" : null, onclick: () => (x.carved != null ? go(`/c/${cid}/e/${eid}/carved?view=table&id=${x.carved}`) : x.file != null && x.fi != null ? fileDrawer({ ...ctx, fi: x.fi }, x.file) : x.image_offset != null && go(`/c/${cid}/e/${eid}/hex?off=${x.image_offset}`)) },
        h("td", srcPill(x)),
        h("td.nm", where(x)),
        h("td.ctx", h("span.muted", x.before), h("mark", x.matched), h("span.muted", x.after)),
        h("td", x.part ? h("span.src", { title: "Text decoded from inside the file (ZIP, Office, PDF...)" }, "Decoded") : x.enc === "utf16" ? h("span.src", "UTF-16") : null,
          bmButton({ cid, eid, kind: "hit", key: `hit:${eid}:${x.image_offset != null ? x.image_offset : `c${x.carved}:${x.part}:${x.offset}`}`, offset: x.image_offset, len: x.matched.length,
            title: `"${x.matched}"`, detail: `${x.before}${x.matched}${x.after}`, path: x.path || (x.carved != null ? `carved file #${x.carved}${x.part ? " / " + x.part : ""}` : x.source) })),
        h("td.num.mono", x.image_offset != null
          ? h("a", { href: `#/c/${cid}/e/${eid}/hex?off=${x.image_offset}`, title: "Open this byte in the hex view", onclick: (e) => e.stopPropagation() }, num(x.image_offset))
          : h("span.muted", { title: x.part ? "Decoded from compressed content, so it has no single place in the image. Open the file to view or export it." : "This stream's layout could not be mapped to the image" }, "-"))));
      out.replaceChildren(
        h("div.row.muted", `${num(r.hits.length)} hit${r.hits.length === 1 ? "" : "s"}${r.truncated ? " (more exist: narrow the search or the scope)" : ""} in ${num(r.elapsed_ms)} ms`, h("span.sp"), h("span", { style: { fontSize: "12px" } }, "Searches are recorded in the case audit log.")),
        r.hits.length
          ? h("div.scroll", { style: { maxHeight: "calc(100vh - 330px)" } }, h("table.tbl.hits", h("thead", h("tr", h("th", "Source"), h("th", "Location"), h("th", "Match"), h("th", ""), h("th", { style: { textAlign: "right" } }, "Image offset"))), h("tbody", rows)))
          : h("div.card.empty", "No matches."));
    } catch (e) {
      out.replaceChildren(h("div.card.empty", h("p.bad-text", e.message)));
    }
  };
  drawForm();
  const notes = st.document_notes && st.document_notes.length
    ? h("details.card.flat", h("summary.muted", `${num(st.document_notes.length)} document item${st.document_notes.length === 1 ? "" : "s"} could not be decoded (encrypted, unsupported or over a size limit)`),
      h("ul.muted", { style: { fontSize: "12.5px", margin: "8px 0 0" } }, st.document_notes.map((n) => h("li", n))))
    : null;
  render(h("div.stack", intro, notes,
    h("div.card.flat.stack",
      h("div.row.wrap", modeSeg, scopeSeg, h("span.sp"), caseLbl),
      h("div.row", input, presetSel, searchBtn),
      help),
    out));
  if (ctx.q.q) run(); else input.focus();
}

// ---------------------------------------------------------------- Windows system summary
const SYS_SECTIONS = [["overview", "Overview"], ["exec", "Programs run"], ["files", "Files and folders"], ["folders", "Folders (ShellBags)"], ["journal", "Change journal"], ["srum", "Network use (SRUM)"], ["devices", "USB and networks"], ["logons", "Accounts and logons"], ["events", "Events"], ["software", "Software and autostart"], ["sources", "Sources"]];
// The Windows artifacts API sends raw FILETIMEs (100 ns since 1601); minute
// precision survives the conversion to a JavaScript number.
const ftIso = (t) => (t ? new Date(t / 10000 - 11644473600000).toISOString().replace(/\.\d+Z$/, "Z") : "");
const t16 = (t) => (t ? ts(ftIso(t), 16) : "");

const LINUX_SECTIONS = [["overview", "Overview"], ["exec", "Commands"], ["logons", "Accounts and logons"], ["events", "Events"], ["software", "Packages and persistence"], ["devices", "USB and networks"], ["sources", "Sources"]];

// System summary of a Linux (ext) volume.
function linuxSystem(ctx, r) {
  const L = r.linux;
  const intro = h("div.hd", h("div", h("h1", "System summary"), h("div.muted", "Accounts, logons, shell histories, logs, the journal, packages and persistence of this Linux volume. " + zoneSentence())), h("span.sp"), fsPicker(ctx, "system"));
  const fileOf = (i) => (i == null ? "" : r.files[i] || "");
  const open = (i) => (i != null ? fileDrawer(ctx, i) : null);
  let section = LINUX_SECTIONS.some(([k]) => k === ctx.q.sec) ? ctx.q.sec : "overview";
  const seg = h("div.seg.wrap");
  const body = h("div.stack");
  const drawSeg = () => seg.replaceChildren(...LINUX_SECTIONS.map(([k, l]) => h("button", { class: section === k ? "on" : null, onclick: () => { section = k; history.replaceState(null, "", `#/c/${ctx.cid}/e/${ctx.eid}/system?fi=${ctx.fi}&sec=${k}`); drawSeg(); draw(); } }, l)));
  const table = (cols, rows, empty = "None found.") => rows.length
    ? h("div.scroll", { style: { maxHeight: "calc(100vh - 300px)" } }, h("table.tbl.sys", h("thead", h("tr", cols.map((c) => h("th", c)))), h("tbody", rows)))
    : h("div.card.empty", empty);
  const filterBox = (ph, on) => { const i = h("input", { placeholder: ph, style: { flex: 1 } }); i.addEventListener("input", debounce(() => on(i.value.toLowerCase()), 150)); return i; };
  const card = (title, ...kids) => h("div.card.flat.stack", h("h3", title), ...kids);
  const kv = (rows) => h("div.kv", rows.filter(([, v]) => v).map(([k, v]) => [h("span", k), h("span", v)]));
  const flagPill = (f) => (f ? h("span.pill.bad", { style: { marginLeft: "6px" } }, f) : null);
  const users = () => table(["Account", "uid", "Shell", "Password", "Groups", "Last logon", "Logons", "Failed", "Home"],
    L.users.map((u) => h("tr", { class: u.note ? "flagged" : null }, h("td", h("b", u.name), u.admin ? h("span.pill.warn", { style: { marginLeft: "6px" }, title: "uid 0, or member of sudo, wheel or admin" }, "admin") : null, u.gecos ? h("div.muted", u.gecos) : null, u.note ? h("div.bad-text", u.note) : null),
      h("td.num", u.uid), h("td.mono", { class: u.login_shell ? null : "muted" }, u.shell), h("td", { class: u.password.startsWith("none") ? "bad-text" : null }, u.password), h("td.muted", u.groups.join(", ")),
      h("td.mono", t16(u.last_logon), u.last_from ? h("div.muted", u.last_from) : null), h("td.num", u.logons ? num(u.logons) : ""), h("td.num", { class: u.failed ? "bad-text" : null }, u.failed ? num(u.failed) : ""), h("td.muted", u.home))));
  const sections = {
    overview: () => {
      const c = L.computer;
      const flagged = L.commands.filter((x) => x.flag);
      const odd = L.persistence.filter((p) => p.unusual);
      const failed = L.logons.filter((x) => x.kind === "failed").length;
      const notes = L.users.filter((u) => u.note);
      return [
        h("div.grid.g4",
          tile("Commands recorded", L.commands.length, `${num(flagged.length)} notable`, flagged.length ? ".bad" : ""),
          tile("Logons", L.logons.filter((x) => x.kind === "logon").length, `${num(failed)} failed`),
          tile("Persistence entries", L.persistence.length, `${num(odd.length)} stand out`, odd.length ? ".bad" : ""),
          tile("Packages", L.packages.length, L.usb.length ? `${L.usb.length} USB device(s) seen` : "")),
        h("div.grid.g2",
          card("Computer", kv([["Host name", c.hostname], ["Distribution", c.os], ["Time zone", c.time_zone], ["Machine id", c.machine_id], ["File system created", t16(c.fs_created)],
            ["Last mounted", [c.last_mounted, t16(c.last_mount_time)].filter(Boolean).join(" at ")], ["Last boot", t16(c.last_boot)], ["Last shutdown", t16(c.last_shutdown)], ["Kernels in /boot", c.kernels.join(", ")]])),
          card("Highlights", flagged.length || odd.length || notes.length
            ? h("ul.impact", [
              ...notes.map((u) => h("li", "Account ", h("b", u.name), `: ${u.note}`)),
              ...flagged.slice(0, 12).map((x) => h("li", h("b.bad-text", x.flag), ` (${x.user}, ${x.shell}): `, h("code", x.command))),
              ...odd.slice(0, 12).map((p) => h("li", `${p.kind}: `, h("code", p.command), ` (${p.reason})`)),
            ])
            : h("p.muted", "Nothing that stands out. Review the sections for context."))),
        card("Accounts", users()),
      ];
    },
    exec: () => {
      const shells = ["", ...new Set(L.commands.map((x) => x.shell))];
      let sh = "", q = "", only = false;
      const out = h("div");
      const fill = () => out.replaceChildren(table([`Time (${zoneName()})`, "Command", "Shell", "User", "Line"],
        L.commands.filter((x) => (!sh || x.shell === sh) && (!only || x.flag) && (!q || (x.command + " " + x.user).toLowerCase().includes(q))).slice(0, 5000).map((x) =>
          h("tr", { class: x.deleted ? "deleted" : x.flag ? "flagged" : null, onclick: () => open(x.file), title: fileOf(x.file) },
            h("td.mono", x.time ? t16(x.time) : h("span.muted", "no time")), h("td.nm.mono", x.command, flagPill(x.flag)), h("td", h("span.pill", x.shell)), h("td", x.user), h("td.num", x.line || "")))));
      const s2 = h("div.seg");
      const drawS = () => s2.replaceChildren(...shells.map((k) => h("button", { class: sh === k ? "on" : null, onclick: () => { sh = k; drawS(); fill(); } }, k || "All")),
        h("button", { class: only ? "on" : null, onclick: () => { only = !only; drawS(); fill(); } }, "Notable only"));
      drawS();
      fill();
      return [h("div.row.wrap", s2, filterBox("Filter commands...", (v) => { q = v; fill(); })),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Shell histories are written when a shell exits, so the newest commands of a session that is still open or was killed may be missing. bash records times only when HISTTIMEFORMAT was set; zsh and fish always do. sudo commands come from the auth log or journal, apt commands from apt's history log."), out];
    },
    logons: () => [
      card("Logons, failures, reboots", table([`Time (${zoneName()})`, "What", "Account", "From", "Terminal", "Ended", "Source"],
        L.logons.slice().reverse().slice(0, 5000).map((x) => h("tr", { onclick: () => open(x.file), title: fileOf(x.file) }, h("td.mono", t16(x.time)),
          h("td", h("span.pill" + (x.kind === "failed" ? ".bad" : x.kind === "logon" ? ".ok" : ""), x.kind), x.how ? h("span.muted", ` ${x.how}`) : null), h("td", h("b", x.user)), h("td.mono", x.from), h("td.mono", x.tty), h("td.mono", t16(x.end)), h("td.muted", x.source))),
        "No logon records (wtmp, btmp, auth log and journal may be missing or emptied).")),
      card("Accounts (passwd, shadow, group, lastlog)", users()),
    ],
    events: () => {
      const cats = ["", ...new Set(L.events.map((e) => e.category))];
      let cat = "", q = "";
      const out = h("div");
      const fill = () => out.replaceChildren(table([`Time (${zoneName()})`, "Category", "What happened", "Program", "User", "IP"],
        L.events.filter((e) => (!cat || e.category === cat) && (!q || (e.summary + " " + e.message + " " + e.user + " " + e.ip).toLowerCase().includes(q))).slice().reverse().slice(0, 3000).map((e) =>
          h("tr", { onclick: () => webDetail(e.category, [[`Time (${zoneName()})`, ts(ftIso(e.time))], ["Summary", e.summary], ["Message", e.message], ["Program", e.program], ["Host", e.host], ["Source", `${e.source}: ${fileOf(e.file)}`], ...(e.year_guessed ? [["Note", "classic syslog line: year inferred, time converted from the image's time zone"]] : [])],
            { cid: ctx.cid, eid: ctx.eid, kind: "event", key: `levent:${ctx.eid}:${ctx.fi}:${e.file}:${e.time}`, fi: ctx.fi, title: e.category, detail: e.summary, path: fileOf(e.file), time: ftIso(e.time) }) },
            h("td.mono", t16(e.time), e.year_guessed ? h("span.muted", { title: "year inferred" }, " *") : null),
            h("td", h("span.pill" + (/Failed/.test(e.category) ? ".bad" : e.category === "Account" || e.category === "Sudo" ? ".warn" : ""), e.category)),
            h("td.nm", e.summary), h("td.muted", e.program), h("td", e.user), h("td.mono", e.ip)))));
      const s2 = h("div.seg.wrap");
      const drawC = () => s2.replaceChildren(...cats.map((k) => h("button", { class: cat === k ? "on" : null, onclick: () => { cat = k; drawC(); fill(); } }, k || "All")));
      drawC();
      fill();
      return [h("div.row.wrap", s2, filterBox("Filter events...", (v) => { q = v; fill(); })), out,
        card("Log files", table(["Log", "Entries", "Oldest", "Newest", "Notable", "State"],
          L.logs.map((x) => h("tr", { onclick: () => open(x.file), title: x.path }, h("td.nm", h("b", x.kind), h("div.muted", x.path)), h("td.num", num(x.lines)), h("td.mono", t16(x.first)), h("td.mono", t16(x.last)), h("td.num", num(x.events)),
            h("td", x.deleted ? h("span.pill.bad", "deleted") : null, x.note ? h("span.muted", ` ${x.note}`) : null)))))];
    },
    software: () => [
      card("Persistence and privileges", table(["Kind", "Command or entry", "Name", "User", "Where", "File changed"],
        L.persistence.map((p) => h("tr", { class: p.unusual ? "flagged" : p.deleted ? "deleted" : null, onclick: () => open(p.file) }, h("td", h("b", p.kind), p.unusual ? h("div.bad-text", p.reason) : null),
          h("td.nm.mono", p.command), h("td", p.name), h("td", p.user), h("td.muted", p.location), h("td.mono", t16(p.written)))))),
      card("Installed packages", table(["Name", "Version", "Manager", "Installed", "By", "Description"],
        L.packages.map((p) => h("tr", h("td", h("b", p.name)), h("td.mono", p.version), h("td", p.manager), h("td.mono", t16(p.installed)), h("td", p.by), h("td.muted", p.description))))),
    ],
    devices: () => [
      card("USB devices seen by the kernel", table(["Device", "Serial number", "Vendor:product id", "First seen", "Last seen"],
        L.usb.map((u) => h("tr", h("td", h("b", u.name)), h("td.mono", u.serial), h("td.mono", u.revision), h("td.mono", t16(u.first_connected)), h("td.mono", t16(u.last_connected)))))),
      card("Networks and hosts", table(["Name", "Kind", "Detail", "Last connected"],
        L.networks.map((n) => h("tr", h("td.nm", h("b", n.name)), h("td", n.kind), h("td.muted.mono", [n.description, n.category, n.dns_suffix].filter(Boolean).join(" ")), h("td.mono", t16(n.last_connected)))))),
      card("Addresses", table(["Address", "Gateway", "DHCP server", "Domain", "Interface or file"],
        L.interfaces.map((i) => h("tr", h("td.mono", i.ip), h("td.mono", i.gateway), h("td.mono", i.dhcp_server), h("td", i.domain), h("td.muted.mono", i.guid))))),
    ],
    sources: () => [table(["Artifact file", "Kind", "State"],
      L.sources.map((x) => h("tr", { class: x.deleted ? "deleted" : null, onclick: () => open(x.file) }, h("td.nm", x.path), h("td", x.kind),
        h("td", x.error ? h("span.bad-text", x.error) : x.note ? h("span.muted", x.note) : h("span.pill.ok", "read"), x.deleted ? h("span.pill.bad", { style: { marginLeft: "6px" } }, "deleted") : null))))],
  };
  const draw = () => body.replaceChildren(...sections[section]());
  drawSeg();
  draw();
  render(h("div.stack", intro, seg, body));
}

async function systemTab(ctx) {
  const r = await api(`/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/windows`);
  // What this page reads depends on the volume: Windows files on NTFS,
  // Linux files on ext, either (usually neither) on a FAT or exFAT drive.
  const what = isMac(r.fs) ? "macOS system artifacts (property lists, unified logs, KnowledgeC, quarantine events) are not read yet; the files themselves are in the Explorer."
    : isExt(r.fs) ? "Accounts, logons, shell histories, logs, the journal, packages and persistence of this Linux volume."
    : isFat(r.fs) || isOptical(r.fs) ? "Windows or Linux system files found on this volume (a removable drive or disc usually has none)."
    : "Registry, event logs, Prefetch, shortcuts, Jump Lists, ShellBags and the change journal of this Windows volume.";
  const intro = h("div.hd", h("div", h("h1", "System summary"), h("div.muted", what + " " + zoneSentence())), h("span.sp"), fsPicker(ctx, "system"));
  if (isExt(r.fs) && r.schema < 5) {
    return render(h("div.stack", intro, h("div.card.empty", h("p", "This evidence was analyzed before Kokino read Linux system files."),
      canWrite() ? h("button.primary", { onclick: () => reingest(ctx.cid, ctx.eid, false) }, "Re-analyze now") : h("p.muted", "Ask an examiner on this case to re-analyze it."))));
  }
  if (r.schema < 3) {
    return render(h("div.stack", intro, h("div.card.empty", h("p", "This evidence was analyzed by an earlier Kokino version, before Windows artifacts were read."),
      canWrite() ? h("button.primary", { onclick: () => reingest(ctx.cid, ctx.eid, false) }, "Re-analyze now") : h("p.muted", "Ask an examiner on this case to re-analyze it."))));
  }
  if (r.linux && r.linux.sources && r.linux.sources.length) return linuxSystem(ctx, r);
  const w = r.windows;
  if (!w.sources.length && !r.journal) {
    return render(h("div.stack", intro, h("div.card.empty", isExt(r.fs) ? "No Linux system files (passwd, logs, shell histories, package databases) on this volume." : "No Windows registry hives, event logs, Prefetch files, shortcuts or Jump Lists on this volume.")));
  }
  const fileOf = (i) => (i == null ? "" : r.files[i] || "");
  const open = (i) => (i != null ? fileDrawer(ctx, i) : null);
  let section = SYS_SECTIONS.some(([k]) => k === ctx.q.sec) ? ctx.q.sec : "overview";
  const seg = h("div.seg.wrap");
  const body = h("div.stack");
  const drawSeg = () => seg.replaceChildren(...SYS_SECTIONS.map(([k, l]) => h("button", { class: section === k ? "on" : null, onclick: () => { section = k; history.replaceState(null, "", `#/c/${ctx.cid}/e/${ctx.eid}/system?fi=${ctx.fi}&sec=${k}`); drawSeg(); draw(); } }, l)));
  const table = (cols, rows, empty = "None found.") => rows.length
    ? h("div.scroll", { style: { maxHeight: "calc(100vh - 300px)" } }, h("table.tbl.sys", h("thead", h("tr", cols.map((c) => h("th", c)))), h("tbody", rows)))
    : h("div.card.empty", empty);
  const filterBox = (ph, on) => { const i = h("input", { placeholder: ph, style: { flex: 1 } }); i.addEventListener("input", debounce(() => on(i.value.toLowerCase()), 150)); return i; };
  const card = (title, ...kids) => h("div.card.flat.stack", h("h3", title), ...kids);
  const toolPill = (x) => (x.tool ? h("span.pill.bad", { title: "Known wiping or anti-forensic tool" }, "anti-forensic tool") : null);

  const sections = {
    overview: () => {
      const c = w.computer;
      const kv = (rows) => h("div.kv", rows.filter(([, v]) => v).map(([k, v]) => [h("span", k), h("span", v)]));
      const bias = c.active_bias_minutes == null ? "" : ` (UTC${c.active_bias_minutes <= 0 ? "+" : "-"}${Math.abs(c.active_bias_minutes) / 60})`;
      const cleared = w.events.filter((e) => e.category === "Log cleared");
      const ran = new Set(w.execution.filter((x) => x.source !== "ShimCache").map((x) => x.program.toLowerCase().split(/[\\/]/).pop()));
      const failed = w.events.filter((e) => e.event_id === 4625).length;
      return [
        h("div.grid.g4",
          tile("Programs run", ran.size, `${num(w.execution.filter((x) => x.tool).length)} record(s) of anti-forensic tools`),
          tile("Files and folders opened", w.access.length, `${num(w.access.filter((a) => a.drive_type === "removable").length)} on removable drives`),
          tile("USB storage devices", w.usb.length, w.usb[0] ? `last: ${w.usb[0].name || w.usb[0].product}` : ""),
          tile("Notable events", w.events.length, cleared.length ? `${cleared.length} log clearing(s)` : `${num(failed)} failed logon(s)`, cleared.length ? ".bad" : "")),
        h("div.grid.g2",
          card("Computer", kv([["Name", c.name], ["Windows", [c.os, c.version].filter(Boolean).join(" ")], ["Edition", c.edition], ["Build", c.build], ["Installed", t16(c.install_time)],
            ["Registered owner", [c.owner, c.organization].filter(Boolean).join(", ")], ["Time zone", c.time_zone + bias], ["Last shutdown", t16(c.last_shutdown)], ["Control set", c.control_set]])),
          card("Highlights", cleared.length || w.execution.some((x) => x.tool) || w.autoruns.some((a) => a.unusual)
            ? h("ul.impact", [
              ...cleared.map((e) => h("li", h("b.bad-text", e.summary), ` at ${t16(e.time)}`)),
              ...[...new Set(w.execution.filter((x) => x.tool && x.source !== "ShimCache").map((x) => `${x.program.split(/[\\/]/).pop().toLowerCase()} (${x.source})`))].map((t) => h("li", "Anti-forensic tool ran: ", h("b", t))),
              ...w.autoruns.filter((a) => a.unusual).map((a) => h("li", `Autostart from a user-writable or unusual location: `, h("code", a.command))),
              failed ? h("li", `${failed} failed logon(s)`) : null,
            ])
            : h("p.muted", "Nothing that stands out. Review the sections for context."))),
        r.journal ? card("Change journal ($UsnJrnl)", journalSummary()) : null,
        card("Accounts", usersTable()),
      ];
    },
    folders: () => {
      let q = "";
      const out = h("div");
      const fill = () => out.replaceChildren(table([`Last opened (${zoneName()})`, "Folder", "Kind", "User", "Folder times when opened (local)", "MFT record", "Source"],
        w.shellbags.filter((b) => !q || (b.path + " " + b.user).toLowerCase().includes(q)).map((b) =>
          h("tr", { class: b.deleted ? "deleted" : null, onclick: () => open(b.on_volume != null ? b.on_volume : b.file), title: b.on_volume != null ? fileOf(b.on_volume) : fileOf(b.file) },
            h("td.mono", t16(b.opened)), h("td.nm", h("b", b.path), b.written && b.written !== b.opened ? h("div.muted", `subfolder list changed ${t16(b.written)}`) : null),
            h("td", h("span.pill" + (b.kind === "network" || b.path.startsWith("\\\\") ? ".info" : b.kind === "drive" ? ".warn" : ""), b.kind), b.on_volume != null ? h("span.pill.ok", { style: { marginLeft: "4px" }, title: "The same folder (MFT record, sequence number and name) is on this volume" }, "on this volume") : null),
            h("td", b.user),
            h("td.muted", b.created ? `created ${ts(ftIso(b.created), 16, { raw: true })}` : "", b.modified ? h("div", `modified ${ts(ftIso(b.modified), 16, { raw: true })}`) : null),
            h("td.mono", b.mft ? `${b.mft[0]} / ${b.mft[1]}` : ""), h("td.muted", b.source)))));
      fill();
      return [filterBox("Filter by folder or user...", (v) => { q = v; fill(); }),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Explorer keeps the view settings of every folder a user opened, in UsrClass.dat (Windows 7 and later) or NTUSER.DAT, and keeps them after the folder, the USB stick or the network share is gone. A time is shown when the folder was the most recently opened one in its parent. The folder's own times are as they were when it was opened, in the computer's local time; the MFT record ties a folder to this or another NTFS volume."), out];
    },
    srum: () => {
      const s = w.srum;
      // SRUM names many programs "!!<file>!<date>!<hex>!..." instead of a path.
      const progName = (p) => (p.startsWith("!!") ? p.slice(2).split("!")[0] : p.split("\\").pop());
      if (!s) return [h("div.card.empty", "No SRUM database (Windows\\System32\\sru\\SRUDB.dat) on this volume.")];
      const kv = (rows) => h("div.kv", rows.filter(([, v]) => v).map(([k, v]) => [h("span", k), h("span", v)]));
      let q = "", pick = null;
      const out = h("div");
      const detail = h("div.stack");
      const loadRows = async (a) => {
        pick = a;
        const p = new URLSearchParams({ app: a.app, user: a.user, limit: 1000 });
        const [net, use] = await Promise.all([api(`/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/srum?${p}`), api(`/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/srum?kind=usage&${p}`)]);
        detail.replaceChildren(
          card(`${progName(a.app)}, hour by hour`, h("p.muted", { style: { margin: 0 } }, a.app + (a.user ? `, user ${a.user}` : "")),
            net.items.length ? table([`Hour ending (${zoneName()})`, "Sent", "Received", "Network", "Interface"], net.items.map((x) => h("tr", h("td.mono", t16(x.t)), h("td.num", { class: x.sent >= 104857600 ? "bad-text" : null }, bytes(x.sent)), h("td.num", bytes(x.received)), h("td", x.profile), h("td", x.interface)))) : null,
            net.total > net.items.length ? h("p.muted", `newest ${num(net.items.length)} of ${num(net.total)} hours`) : null,
            use.items.length ? table([`Hour ending (${zoneName()})`, "Disk read", "Disk written", "CPU cycles (foreground)", "CPU cycles (background)"], use.items.map((x) => h("tr", h("td.mono", t16(x.t)), h("td.num", bytes(x.read)), h("td.num", bytes(x.written)), h("td.num", num(x.foreground)), h("td.num", num(x.background))))) : null));
        detail.scrollIntoView({ block: "start", behavior: "smooth" });
      };
      const fill = () => out.replaceChildren(table(["Program", "User", "Sent", "Received", "Disk read", "Disk written", "First", "Last"],
        s.apps.filter((a) => !q || (a.app + " " + a.user).toLowerCase().includes(q)).map((a) =>
          h("tr", { class: pick === a ? "sel" : null, onclick: () => { loadRows(a); fill(); } },
            h("td.nm", h("b", progName(a.app)), h("div.muted", a.app)), h("td", a.user),
            h("td.num", { class: a.sent >= 1073741824 ? "bad-text" : null }, bytes(a.sent)), h("td.num", bytes(a.received)), h("td.num", bytes(a.read)), h("td.num", bytes(a.written)),
            h("td.mono", t16(a.first)), h("td.mono", t16(a.last))))));
      fill();
      return [
        card("SRUM (System Resource Usage Monitor)", kv([["Covers", s.first ? `${t16(s.first)} to ${t16(s.last)}` : "no records"], ["Programs", num(s.apps.length)],
          ["Hourly records", r.srum_rows ? `${num(r.srum_rows.network)} network, ${num(r.srum_rows.usage)} resource use${s.dropped ? ` (the oldest ${num(s.dropped)} not kept)` : ""}` : ""], ["Database", fileOf(s.file)]]),
          s.dirty ? h("p", { style: { color: "var(--warn)", margin: 0 } }, "Not cleanly closed: the newest hours may be only in its transaction logs (SRU*.log), which are not read.") : null,
          s.error ? h("p.bad-text", s.error) : null),
        filterBox("Filter by program or user...", (v) => { q = v; fill(); }),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Windows writes, about once an hour, how many bytes each program sent and received over which network and how much it read and wrote to disk, per user, and keeps about 30 to 60 days. A program that sent gigabytes is worth a look (cloud sync and copy tools such as rclone are a common way to take data out). Click a program for its hours. Times are when Windows wrote the record, at the end of the hour it covers."),
        out, detail,
        s.connections.length ? card("Network connections", table([`Connected (${zoneName()})`, "For", "Network", "Interface"], s.connections.slice().reverse().map((c) => h("tr", h("td.mono", t16(c.start)), h("td", `${Math.floor(c.seconds / 3600)} h ${Math.floor(c.seconds % 3600 / 60)} min`), h("td", c.profile), h("td", c.interface))))) : null,
      ];
    },
    journal: () => {
      const kinds = [["", "All"], ["created", "Created"], ["deleted", "Deleted"], ["renamed", "Renamed"], ["changed", "Other changes"]];
      let kind = "", q = "", order = "", shown = 0, total = 0;
      const out = h("tbody");
      const status = h("div.muted");
      const more = h("button", { onclick: () => load(false) }, "Show more");
      const load = async (reset) => {
        if (reset) { out.replaceChildren(); shown = 0; }
        const p = new URLSearchParams({ q, kind, order, offset: shown, limit: 500 });
        const res = await api(`/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/journal?${p}`);
        total = res.total;
        for (const c of res.items) {
          out.append(h("tr", { class: c.what.includes("deleted") ? "deleted" : null, onclick: () => (c.file != null ? open(c.file) : webDetail(c.path, [[`Time (${zoneName()})`, ts(c.t)], ["First record", c.first ? ts(c.first) : ""], ["What", c.what], ["Earlier name", c.old_path], ["MFT record / seq", `${c.record} / ${c.seq}`], ["USN", String(c.usn)]])), title: c.file_path || "" },
            h("td.mono", ts(c.t, 19)), h("td.nm", h("b", c.path), c.old_path ? h("div.muted", `was ${c.old_path}`) : null),
            h("td", h("span.pill" + (c.what.includes("deleted") ? ".bad" : c.what.includes("created") ? ".ok" : c.what.includes("renamed") ? ".warn" : ""), c.what)),
            h("td.mono", `${c.record} / ${c.seq}`), h("td", c.file != null ? h("span.pill.info", { title: c.file_path }, "on this volume") : null)));
        }
        shown += res.items.length;
        status.textContent = `${num(shown)} of ${num(total)} change(s)`;
        more.style.display = shown < total ? "" : "none";
      };
      const s2 = h("div.seg");
      const drawK = () => s2.replaceChildren(...kinds.map(([k, l]) => h("button", { class: kind === k ? "on" : null, onclick: () => { kind = k; drawK(); load(true); } }, l)));
      const ord = h("select", { onchange: () => { order = ord.value; load(true); } }, h("option", { value: "" }, "Newest first"), h("option", { value: "asc" }, "Oldest first"));
      drawK();
      load(true);
      return [r.journal ? card("Change journal ($UsnJrnl)", journalSummary()) : h("div.card.empty", "No change journal on this volume."),
        h("div.row.wrap", s2, filterBox("Filter by path or earlier name...", (v) => { q = v; load(true); }), ord),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Windows writes a record to the NTFS change journal for every change to a file. Records of one round of changes (from opening the file to closing it) are combined here into one line. Paths use folders as they are now, or as the journal last named them when the folder is gone; [folder N-S] is a folder neither knows. Click a change to open the file, when it is still on the volume."),
        h("table.tbl.sys", h("thead", h("tr", [`Time (${zoneName()})`, "File", "What happened", "Record / seq", ""].map((c) => h("th", c)))), out),
        h("div.row", status, more)];
    },
    exec: () => {
      const srcs = ["", "Prefetch", "UserAssist", "BAM", "DAM", "Amcache", "ShimCache", "Event 4688"];
      let src = "", q = "";
      const out = h("div");
      const fill = () => out.replaceChildren(table([`Last run (${zoneName()})`, "Program", "Source", "Runs", "User", "Detail"],
        w.execution.filter((x) => (!src || x.source === src) && (!q || (x.program + " " + x.detail + " " + x.sha1).toLowerCase().includes(q))).map((x) =>
          h("tr", { class: x.deleted ? "deleted" : null, onclick: () => open(x.file), title: fileOf(x.file) },
            h("td.mono", t16(x.times[0])), h("td.nm", h("b", x.program), toolPill(x), x.sha1 ? h("div.muted.mono", `SHA-1 ${x.sha1}`) : null, x.times.length > 1 ? h("div.muted", `earlier: ${x.times.slice(1).map(t16).join(", ")}`) : null),
            h("td", h("span.pill", x.source)), h("td.num", x.count == null ? "" : num(x.count)), h("td", x.user), h("td.muted", x.detail)))));
      const s2 = h("div.seg");
      const drawS = () => s2.replaceChildren(...srcs.map((k) => h("button", { class: src === k ? "on" : null, onclick: () => { src = k; drawS(); fill(); } }, k || "All")));
      drawS();
      fill();
      return [h("div.row.wrap", s2, filterBox("Filter by program, detail or hash...", (v) => { q = v; fill(); })),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Prefetch and UserAssist prove a program ran (with counts and times). BAM and DAM keep the last run of each program per user for about a week. Amcache records when a program was first seen. ShimCache lists programs Windows checked for compatibility; on Windows 10 and later an entry alone does not prove it ran."), out];
    },
    files: () => {
      let q = "";
      const out = h("div");
      const fill = () => out.replaceChildren(table([`Last used (${zoneName()})`, "Path or text", "Source", "User", "Volume", "Count", "Machine"],
        w.access.filter((a) => !q || (a.path + " " + a.volume_label + " " + a.source).toLowerCase().includes(q)).map((a) =>
          h("tr", { class: a.deleted ? "deleted" : null, onclick: () => open(a.file), title: fileOf(a.file) },
            h("td.mono", t16(a.time)), h("td.nm", h("b", a.path), a.first && a.first !== a.time ? h("div.muted", `first opened ${t16(a.first)}`) : null),
            h("td", h("span.pill", a.source), a.pinned ? h("span.pill.info", { style: { marginLeft: "4px" } }, "pinned") : null), h("td", a.user),
            h("td", a.drive_type ? h("span.pill" + (a.drive_type === "removable" ? ".warn" : a.drive_type === "network" ? ".info" : ""), a.drive_type) : null, h("div.muted", [a.volume_label, a.volume_serial].filter(Boolean).join(" "))),
            h("td.num", a.count == null ? "" : num(a.count)), h("td.muted", [a.machine, a.mac].filter(Boolean).join(" "))))));
      fill();
      return [filterBox("Filter by path, volume or source...", (v) => { q = v; fill(); }),
        h("p.muted", { style: { fontSize: "12.5px" } }, "Shortcuts (LNK) and Jump Lists keep the target's volume label and serial number, which ties a file to a specific USB stick or network share. RecentDocs, typed paths, Run box entries and Explorer searches come from each user's NTUSER.DAT; only the newest entry of each list has a time."), out];
    },
    devices: () => [
      card("USB storage devices", table(["Device", "Serial number", "Drive", "First connected", "Last connected", "Last removed"],
        w.usb.map((u) => h("tr", h("td.nm", h("b", u.name || `${u.vendor} ${u.product}`), h("div.muted", [u.vendor, u.product, u.revision].filter(Boolean).join(" "))), h("td.mono", u.serial), h("td", u.drive_letter),
          h("td.mono", t16(u.first_connected)), h("td.mono", t16(u.last_connected || u.key_written)), h("td.mono", t16(u.last_removed)))))),
      card("Networks", table(["Name", "Kind", "Category", "First connected", "Last connected", "Gateway MAC"],
        w.networks.map((n) => h("tr", h("td.nm", h("b", n.name), n.dns_suffix ? h("div.muted", n.dns_suffix) : null), h("td", n.kind), h("td", n.category), h("td.mono", t16(n.created)), h("td.mono", t16(n.last_connected)), h("td.mono", n.gateway_mac))))),
      card("Network interfaces", table(["Address", "Gateway", "DHCP server", "Domain", "Interface"],
        w.interfaces.map((i) => h("tr", h("td.mono", i.ip), h("td.mono", i.gateway), h("td.mono", i.dhcp_server), h("td", i.domain), h("td.muted.mono", i.guid))))),
    ],
    logons: () => {
      const per = {};
      for (const e of w.events) {
        if (![4624, 4625, 21, 1149].includes(e.event_id) || !e.user) continue;
        const k = e.user.split("\\").pop().toLowerCase(); // "LAB-PC\alice" and "alice" are one account
        const p = (per[k] = per[k] || { user: e.user.split("\\").pop(), ok: 0, failed: 0, rdp: 0, last: 0, ips: new Set(), types: new Set() });
        if (e.event_id === 4625) p.failed++; else if (e.event_id === 4624) p.ok++; else p.rdp++;
        if (e.event_id !== 4625) p.last = Math.max(p.last, e.time);
        if (e.ip) p.ips.add(e.ip);
        const lt = (e.data.find(([k]) => k === "LogonType") || [])[1];
        if (lt) p.types.add(lt);
      }
      const LT = { 2: "interactive", 3: "network", 7: "unlock", 10: "remote desktop", 11: "cached" };
      return [
        card("Logons by account (from the event logs)", table(["Account", "Successful", "Failed", "Remote desktop", "Last logon", "Logon types", "From"],
          Object.values(per).sort((a, b) => b.last - a.last).map((p) => h("tr", h("td", h("b", p.user)), h("td.num", num(p.ok)), h("td.num", { class: p.failed ? "bad-text" : null }, num(p.failed)), h("td.num", num(p.rdp)), h("td.mono", t16(p.last)),
            h("td", [...p.types].map((t) => LT[t] || `type ${t}`).join(", ")), h("td.mono", [...p.ips].join(", ")))), "No logon events (the Security log may be missing or cleared).")),
        card("Accounts (SAM and profiles)", usersTable()),
      ];
    },
    events: () => {
      const cats = ["", ...new Set(w.events.map((e) => e.category))];
      let cat = "", q = "";
      const out = h("div");
      const fill = () => {
        const list = w.events.filter((e) => (!cat || e.category === cat) && (!q || (e.summary + " " + e.title + " " + e.user + " " + e.ip).toLowerCase().includes(q)));
        out.replaceChildren(table([`Time (${zoneName()})`, "Category", "Event", "What happened", "User", "IP"],
          list.slice().reverse().slice(0, 3000).map((e) => h("tr", { onclick: () => webDetail(`${e.title} (event ${e.event_id})`, [[`Time (${zoneName()})`, ts(ftIso(e.time))], ["Log", e.channel], ["Record", String(e.record_id)], ["Computer", e.computer], ["Summary", e.summary], ...e.data, ["Log file", fileOf(e.file)]],
            { cid: ctx.cid, eid: ctx.eid, kind: "event", key: `event:${ctx.eid}:${ctx.fi}:${e.channel}:${e.record_id}`, fi: ctx.fi, title: `${e.title} (event ${e.event_id})`, detail: e.summary, path: `${e.channel}, record ${e.record_id}`, time: ftIso(e.time) }) },
            h("td.mono", t16(e.time)), h("td", h("span.pill" + (e.category === "Log cleared" || e.category === "Failed logon" ? ".bad" : e.category === "Account" || e.category === "Service" ? ".warn" : ""), e.category)),
            h("td", h("b", e.title), h("div.muted", `${e.channel.replace("Microsoft-Windows-", "")} ${e.event_id}`)), h("td.nm", e.summary), h("td", e.user), h("td.mono", e.ip)))));
      };
      const s2 = h("div.seg.wrap");
      const drawC = () => s2.replaceChildren(...cats.map((k) => h("button", { class: cat === k ? "on" : null, onclick: () => { cat = k; drawC(); fill(); } }, k || "All")));
      drawC();
      fill();
      return [h("div.row.wrap", s2, filterBox("Filter events...", (v) => { q = v; fill(); })), out,
        card("Event logs", table(["Log", "Records", "Oldest", "Newest", "Notable", "State"],
          w.logs.map((l) => h("tr", { onclick: () => open(l.file), title: l.path }, h("td.nm", h("b", l.channel), h("div.muted", l.path)), h("td.num", num(l.info.records)), h("td.mono", t16(l.info.oldest)), h("td.mono", t16(l.info.newest)), h("td.num", num(l.notable)),
            h("td", l.deleted ? h("span.pill.bad", "deleted") : null, l.info.dirty ? h("span.pill.warn", "not closed cleanly") : null, l.info.full ? h("span.pill", "full") : null, l.info.errors ? h("span.pill.warn", `${l.info.errors} unreadable records`) : null, l.error ? h("span.bad-text", l.error) : null))))),
        card("Event IDs in all logs", table(["Log", "Event ID", "Count"], w.event_counts.slice(0, 200).map(([c, id, n]) => h("tr", h("td", c), h("td.num", id), h("td.num", num(n)))))),
      ];
    },
    software: () => [
      card("Autostart entries", table(["Name", "Command", "Kind", "Where", "Changed"],
        w.autoruns.map((a) => h("tr", { class: a.unusual ? "flagged" : null }, h("td", h("b", a.name), a.unusual ? h("span.pill.warn", { style: { marginLeft: "6px" }, title: "Runs from a user-writable or unusual location" }, "unusual location") : null),
          h("td.nm.mono", a.command), h("td", a.kind, a.user ? h("div.muted", a.user) : null), h("td.muted", a.location), h("td.mono", t16(a.written)))))),
      card("Installed programs", table(["Name", "Version", "Publisher", "Installed", "Location"],
        w.programs.map((p) => h("tr", h("td", h("b", p.name), p.wow64 ? h("span.muted", " (32-bit)") : null), h("td", p.version), h("td", p.publisher), h("td.mono", t16(p.install_date || p.key_written)), h("td.muted", p.location))))),
    ],
    sources: () => [table(["Artifact file", "Kind", "State"],
      w.sources.map((s) => h("tr", { class: s.deleted ? "deleted" : null, onclick: () => open(s.file) }, h("td.nm", s.path), h("td", s.kind),
        h("td", s.error ? h("span.bad-text", s.error) : s.note ? h("span.muted", s.note) : h("span.pill.ok", "read"), s.deleted ? h("span.pill.bad", { style: { marginLeft: "6px" } }, "deleted") : null)))),
    ],
  };
  function journalSummary() {
    const j = r.journal;
    const kv = (rows) => h("div.kv", rows.filter(([, v]) => v).map(([k, v]) => [h("span", k), h("span", v)]));
    return h("div.stack", kv([["Covers", j.first ? `${t16(j.first)} to ${t16(j.last)}` : "no records"], ["Records", num(j.records)],
      ["Changes", `${num(j.changes + j.dropped)}: ${num(j.created_files)} created, ${num(j.deleted_files)} deleted, ${num(j.renamed_files)} renamed${j.dropped ? ` (the oldest ${num(j.dropped)} not kept)` : ""}`],
      ["Journal created", t16(j.created)], ["Size", `${bytes(j.size)} (${bytes(j.stored)} stored; older records aged out)`], ["Maximum size", j.max ? bytes(j.max.max_size) : ""], ["File", j.path]]),
      j.error ? h("p.bad-text", j.error) : null);
  }
  function usersTable() {
    return table(["Account", "RID", "Created", "Last logon", "Logons", "Password set", "Profile"],
      w.users.map((u) => h("tr", h("td", h("b", u.name), u.disabled ? h("span.pill", { style: { marginLeft: "6px" } }, "disabled") : null, h("div.muted.mono", u.sid)), h("td.num", u.rid ?? ""),
        h("td.mono", t16(u.created)), h("td.mono", t16(u.last_logon)), h("td.num", u.logon_count ? num(u.logon_count) : ""), h("td.mono", t16(u.password_set)), h("td.muted", u.profile))));
  }
  const draw = () => body.replaceChildren(...sections[section]());
  drawSeg();
  draw();
  // Analyzed before 1.2.8: the newer Windows artifacts are missing, not absent.
  const stale = isNtfs(r.fs) && r.schema < 6
    ? h("div.card.flat.stack", h("p", { style: { margin: 0, color: "var(--warn)" } }, "This evidence was analyzed by an earlier Kokino version, before the change journal, ShellBags, BAM/DAM, SRUM and the names of deleted files from folder indexes and $LogFile were read. Those parts are empty until it is analyzed again."),
      canWrite() ? h("div", h("button.primary", { onclick: () => reingest(ctx.cid, ctx.eid, false) }, "Re-analyze now")) : h("p.muted", { style: { margin: 0 } }, "Ask an examiner on this case to re-analyze it."))
    : null;
  render(h("div.stack", intro, stale, seg, body));
}

// ---------------------------------------------------------------- carved files
const PICTURES = ["jpeg", "png", "gif", "bmp", "webp"];

async function carvedTab(ctx) {
  const { cid, eid } = ctx;
  const base = `/cases/${cid}/evidence/${eid}/carved`;
  const { result: r } = await api(base);
  const job = state.jobs.find((j) => j.evidence === eid && j.state === "running");
  const start = () => api(base, { method: "POST" }).then((j) => { toast("Carving unallocated space"); kickJobs(j); route(); }).catch((e) => toast(e.message, true));
  const intro = h("div.hd", h("div", h("h1", "Carved files"),
    h("div.muted", r
      ? `${num(r.files.length)} file${r.files.length === 1 ? "" : "s"} recovered by content from ${bytes(r.scanned_bytes)} of unallocated space. Carved ${ts(r.carved_at, 16)}.`
      : "Files recovered from unallocated space by their content.")),
    h("span.sp"),
    r && canWrite() && !job ? h("button.sm", { onclick: start, title: "Carve again and update the text index" }, "Carve again") : null);
  if (!r) {
    return render(h("div.stack", intro, h("div.card.empty.stack",
      job ? [h("div.spin"), h("p", "Carving..."), h("span", { "data-job-ev": eid }, jobPill(job))]
        : [h("p", "Carving looks at every free cluster, the space outside partitions and unparsed volumes for files by their content: JPEG, PNG, GIF, BMP, PDF, Word/Excel/PowerPoint (both formats), ZIP, SQLite, executables, GZIP, 7-Zip, WAV, AVI, WebP, MP4 and event log chunks."),
          canWrite() ? h("button.primary", { onclick: start }, "Carve unallocated space") : h("p.muted", "Ask an examiner on this case to run it.")])));
  }
  const kinds = {};
  for (const f of r.files) kinds[f.kind] = (kinds[f.kind] || 0) + 1;
  let kind = ctx.q.kind && kinds[ctx.q.kind] ? ctx.q.kind : "";
  let view = ctx.q.view === "table" ? "table" : r.files.some((f) => PICTURES.includes(f.kind)) ? "gallery" : "table";
  const seg = h("div.seg.wrap");
  const viewSeg = h("div.seg");
  const out = h("div");
  const label = (f) => h("span", h("b", f.label), f.complete ? null : h("span.pill.warn", { style: { marginLeft: "6px" }, title: "The end of the file was not found: it may be cut off or overwritten" }, "incomplete"));
  const detail = (f) => webDetail(`Carved file #${f.id}: ${f.label}`, [
    ["Type", `${f.label} (.${f.ext})`],
    ["Offset in image", h("span", h("a", { href: `#/c/${cid}/e/${eid}/hex?off=${f.offset}`, onclick: closeModal }, num(f.offset)), h("span.muted", ` (0x${f.offset.toString(16)})`))],
    ["Length", `${num(f.len)} bytes`],
    ["Found in", f.region],
    ["Complete", f.complete ? "yes, the format's end was found" : "no, cut off or partly overwritten"],
    ["Detail", f.detail],
    ["Note", [f.note, f.beyond_region ? "Runs past the end of its free region: the tail may belong to another file, or the original was fragmented." : ""].filter(Boolean).join(" ")],
    ["MD5", f.md5],
    ["SHA-256", f.sha256],
    ["", h("div.row", PICTURES.includes(f.kind) ? h("img.carved-big", { src: apiUrl(`${base}/${f.id}/preview`), alt: "" }) : null)],
    ["", h("div.row.wrap", ["jpeg", "png", "bmp"].includes(f.kind) ? h("a.btn", { href: viewerHref(cid, eid, { kind: "carved", id: f.id }), onclick: closeModal }, icon("image", 14), "Analyze picture") : null,
      h("button", { onclick: () => bytesDialog(`Carved ${f.label} #${f.id}`, `/cases/${cid}/evidence/${eid}/carved/${f.id}`, (off) => go(`/c/${cid}/e/${eid}/hex?off=${f.offset + off}`)) }, icon("hex", 14), "Byte map and strings"))],
    ["", canWrite() ? h("a.btn.primary", { href: apiUrl(`${base}/${f.id}/export`) }, "Export (hashed + audited)") : h("span.muted", "Read-only access: export not available")],
  ], { cid, eid, kind: "carved", key: `carved:${eid}:${f.offset}`, carved: f.id, title: `Carved ${f.label} #${f.id}`, path: `${f.region} at offset ${f.offset}` });
  const draw = () => {
    seg.replaceChildren(...[["", `All (${num(r.files.length)})`], ...Object.entries(kinds).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, `${k} (${num(n)})`])].map(([k, l]) =>
      h("button", { class: kind === k ? "on" : null, onclick: () => { kind = k; draw(); } }, l)));
    viewSeg.replaceChildren(...[["gallery", "Gallery"], ["table", "Table"]].map(([k, l]) => h("button", { class: view === k ? "on" : null, onclick: () => { view = k; draw(); } }, l)));
    history.replaceState(null, "", `#/c/${cid}/e/${eid}/carved?view=${view}${kind ? `&kind=${kind}` : ""}`);
    const list = r.files.filter((f) => !kind || f.kind === kind);
    if (view === "gallery") {
      out.replaceChildren(list.length ? h("div.carved-grid", list.map((f) => h("div.card.flat.carved-tile", { onclick: () => detail(f), title: `${f.label} at offset ${f.offset}` },
        PICTURES.includes(f.kind) ? h("img", { src: apiUrl(`${base}/${f.id}/preview`), loading: "lazy", alt: "" }) : h("div.carved-icon", f.kind.split("-")[0].toUpperCase().slice(0, 6)),
        h("div.ell", h("b", f.kind)), h("div.muted.ell", `${bytes(f.len)}${f.detail ? ", " + f.detail : ""}`), f.complete ? null : h("span.pill.warn", "incomplete")))) : h("div.card.empty", "None."));
    } else {
      out.replaceChildren(list.length ? h("div.scroll", { style: { maxHeight: "calc(100vh - 290px)" } }, h("table.tbl.sys", h("thead", h("tr", ["Offset", "Type", "Size", "Detail", "Found in", "Note", "SHA-256"].map((c) => h("th", c)))),
        h("tbody", list.map((f) => h("tr", { onclick: () => detail(f) },
          h("td.mono", h("a", { href: `#/c/${cid}/e/${eid}/hex?off=${f.offset}`, onclick: (e) => e.stopPropagation() }, num(f.offset))), h("td", label(f)), h("td.num", bytes(f.len)), h("td", f.detail), h("td.muted", f.region),
          h("td.muted", [f.note, f.beyond_region ? "runs into allocated space" : ""].filter(Boolean).join("; ")), h("td.mono.muted", { title: f.sha256 }, f.sha256.slice(0, 16))))))) : h("div.card.empty", "None."));
    }
  };
  draw();
  render(h("div.stack", intro,
    h("div.row.wrap", seg, h("span.sp"), viewSeg),
    h("p.muted", { style: { fontSize: "12.5px" } }, "Each file is found by its header and ends where its own structure says, so only whole files are listed; broken or cut-off ones are marked incomplete. Nothing is copied until you export, and every export is hashed and written to the audit log."),
    out));
  if (ctx.q.id != null) { const f = r.files.find((x) => String(x.id) === String(ctx.q.id)); if (f) detail(f); }
}

async function webTab(ctx) {
  const base = `/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/web`;
  const head = await api(`${base}?kind=visits&limit=1`);
  const intro = h("div.hd", h("h1", "Web activity"), h("span.sp"), fsPicker(ctx, "web"));
  if (head.schema < 2) {
    return render(h("div.stack", intro, h("div.card.empty", h("p", "This evidence was analyzed by an earlier Kokino version, before browser history extraction existed."),
      canWrite() ? h("button.primary", { onclick: () => reingest(ctx.cid, ctx.eid, false) }, "Re-analyze now") : h("p.muted", "Ask an examiner on this case to re-analyze it."))));
  }
  if (!head.sources.length) {
    return render(h("div.stack", intro, h("div.card.empty", "No Chrome, Edge, Brave, Opera, Vivaldi or Firefox history databases on this volume.")));
  }
  const sources = head.sources;
  const webTarget = (what, title, where, t) => ({ cid: ctx.cid, eid: ctx.eid, kind: "web", fi: ctx.fi, key: `web:${ctx.eid}:${ctx.fi}:${what}:${t}:${String(where).slice(0, 200)}`, title: `${what}: ${title}`, path: where, time: t || "" });
  let kind = ["visits", "downloads", "searches"].includes(ctx.q.kind) ? ctx.q.kind : "visits";
  let src = ctx.q.src != null && ctx.q.src !== "" ? Number(ctx.q.src) : null;
  let offset = 0;

  const cards = h("div.grid.g3.stagger");
  const drawCards = () => cards.replaceChildren(...sources.map((s, i) => {
    const empty = !s.error && s.visits === 0 && s.urls === 0;
    return h("div.card.web-src", { class: src === i ? "on" : null, style: { "--i": i }, title: s.path, onclick: () => { src = src === i ? null : i; drawCards(); reload(); } },
      h("div.row", h("span.bbadge", s.browser.slice(0, 2)), h("div", { style: { minWidth: 0 } }, h("b", s.browser), h("div.muted.ell", `${s.user || "unknown user"} / ${s.profile || "?"}`)), h("span.sp"),
        s.deleted ? h("span.pill.bad", "deleted DB") : null, empty ? h("span.pill.warn", "empty") : null, s.wal ? h("span.pill.info", { title: "Changes still in the -wal file were applied" }, "WAL") : null),
      s.error
        ? h("p.bad-text", s.error)
        : h("div.web-stats", [["visits", s.visits], ["downloads", s.downloads], ["searches", s.searches], ["URLs", s.urls]].map(([l, n]) => h("div", h("b", num(n)), h("small", l)))),
      !s.error && s.oldest_iso ? h("div.muted", { style: { fontSize: "12px" } }, `${ts(s.oldest_iso, 16)}  to  ${ts(s.newest_iso, 16)}`) : null,
      empty ? h("div.cav", "History is empty: cleared, or the profile was never used. Compare with the profile's other files.") : null,
    );
  }));
  drawCards();

  const seg = h("div.seg");
  const drawSeg = () => seg.replaceChildren(...[["visits", "Visits"], ["downloads", "Downloads"], ["searches", "Searches"]].map(([k, l]) => h("button", { class: kind === k ? "on" : null, onclick: () => { kind = k; drawSeg(); reload(); } }, `${l} (${num(head.counts[k])})`)));
  drawSeg();
  const q = h("input", { placeholder: "Filter by URL, title, file or search term...", value: ctx.q.q || "", style: { flex: 1 } });
  const thead = h("thead");
  const tbody = h("tbody");
  const count = h("span.muted");
  const more = h("button", "Load more");
  const who = (i) => h("span.muted", { title: srcName(sources[i]) }, sources[i] ? sources[i].browser : "");
  const COLS = { visits: [`Time (${zoneName()})`, "Browser", "Page", "How", "Visits"], downloads: [`Started (${zoneName()})`, "Browser", "File", "From", "Size", "State"], searches: [`Time (${zoneName()})`, "Browser", "Engine", "Search term", "Source"] };
  const row = (x) => {
    if (kind === "downloads") {
      const file = (x.target || "").split(/[\\/]/).pop() || "(no target path)";
      return h("tr", { onclick: () => webDetail("Download", [[`Started (${zoneName()})`, ts(x.start_iso)], [`Finished (${zoneName()})`, ts(x.end_iso)], ["Browser", srcName(sources[x.src])], ["Saved to", x.target], ["Source URL", x.url], ["Referrer", x.referrer], ["Size", `${num(x.received)} of ${num(x.total)} bytes`], ["State", x.state], ["Danger", x.danger], ["MIME type", x.mime], ["Opened", x.opened ? "yes" : ""]], webTarget("Download", x.target || x.url, x.url, x.start_iso)) },
        h("td.mono", ts(x.start_iso, 19)), h("td", who(x.src)), h("td.nm", { title: x.target }, h("b", file), h("div.muted.ell", x.target)), h("td.nm.muted", { title: x.url }, x.url),
        h("td.num", x.received >= 0 ? bytes(x.received) : ""), h("td", h("span.pill" + (x.state === "complete" ? ".ok" : x.state.startsWith("interrupted") || x.state === "cancelled" ? ".warn" : ""), x.state), x.danger ? h("span.pill.bad", { style: { marginLeft: "6px" } }, x.danger) : null));
    }
    if (kind === "searches") {
      return h("tr", { onclick: () => webDetail("Search", [[`Time (${zoneName()})`, ts(x.t_iso)], ["Browser", srcName(sources[x.src])], ["Engine", x.engine], ["Term", x.term], ["Recorded in", x.how === "url" ? "a visited search URL" : "the browser's keyword table"], ["URL", x.url]], webTarget("Search", `"${x.term}"`, `${x.engine}: ${x.url || ""}`, x.t_iso)) },
        h("td.mono", ts(x.t_iso, 19)), h("td", who(x.src)), h("td", x.engine), h("td", h("b", x.term)), h("td.muted", x.how === "url" ? "visited URL" : "keyword table"));
    }
    return h("tr", { class: x.url_only ? "faint" : null, onclick: () => webDetail("Page visit", [[`Time (${zoneName()})`, ts(x.t_iso)], ["Browser", srcName(sources[x.src])], ["URL", x.url], ["Title", x.title], ["How", x.how], ["Typed", x.typed ? "yes, the user typed or pasted it" : ""], ["Times visited", String(x.visit_count)], ["Time on page", x.duration_ms ? `${(x.duration_ms / 1000).toFixed(1)} s` : ""], ["Note", x.url_only ? "Only the URL table remembers this page: its visit rows were expired or deleted, so the time is the last recorded visit." : ""]], webTarget("Page visit", x.title || x.url, x.url, x.t_iso)) },
      h("td.mono", ts(x.t_iso, 19)), h("td", who(x.src)),
      h("td.nm", { title: x.url }, x.title ? h("b", x.title) : null, h("div.muted.ell", x.url)),
      h("td", x.typed ? h("span.pill.info", x.how) : x.url_only ? h("span.pill.warn", "URL table only") : h("span.muted", x.how)), h("td.num", x.visit_count));
  };
  const load = async (append) => {
    const params = new URLSearchParams({ kind, q: q.value, offset, limit: 300 });
    if (src != null) params.set("src", src);
    const r = await api(`${base}?${params}`);
    thead.replaceChildren(h("tr", COLS[kind].map((c, i) => h("th", { style: (kind === "downloads" && i === 4) || (kind === "visits" && i === 4) ? { textAlign: "right" } : null }, c))));
    const rows = r.items.map(row);
    if (append) tbody.append(...rows); else tbody.replaceChildren(...rows);
    offset += r.items.length;
    count.textContent = `${num(r.total)} ${kind}${src != null ? " in " + srcName(sources[src]) : ""}`;
    more.style.display = offset < r.total ? "" : "none";
    history.replaceState(null, "", `#/c/${ctx.cid}/e/${ctx.eid}/web?fi=${ctx.fi}&kind=${kind}${src != null ? "&src=" + src : ""}${q.value ? "&q=" + encodeURIComponent(q.value) : ""}`);
  };
  const reload = debounce(() => { offset = 0; load(false); }, 200);
  q.addEventListener("input", reload);
  more.onclick = () => load(true);
  render(h("div.stack",
    intro,
    h("p.muted", "History read from each browser profile's database, including changes still in its -wal file. Click a profile to filter by it. " + zoneSentence() + " Pages marked \"URL table only\" lost their visit rows: expired by the browser or deleted selectively."),
    cards,
    h("div.row.wrap", seg, q, count),
    h("div.scroll", { style: { maxHeight: "calc(100vh - 260px)" } }, h("table.tbl.web", thead, tbody)),
    h("div.row", h("span.sp"), more),
  ));
  load(false);
}

// ---------------------------------------------------------------- indicators
function indicatorsTab(ctx) {
  const { fs } = ctx;
  const all = fs.indicators;
  render(h("div.stack",
    h("div.hd", h("h1", "Anti-forensics"), h("span.sp"), fsPicker(ctx, "indicators")),
    h("div.grid.g3",
      h("div.card", gauge(fs.score.likelihood, fs.score.band)),
      h("div.card", { style: { gridColumn: "span 2" } }, h("h3", "How this score works"),
        h("p", "Each indicator is a transparent rule with a weight (how suspicious one strong occurrence is) and a saturation constant k. Its strength is ", h("code", "weight x (1 - e^(-count / k))"), ". Indicators are combined with a noisy-OR: ", h("code", "1 - product(1 - strength)"), "."),
        h("p.muted", "It is a triage aid that tells you where to look. It is not a finding. Every indicator lists its caveats and the exact files behind it.")),
    ),
    all.length ? h("div.grid.g2.stagger", all.map((i, n) => indicatorCard(ctx, i, n))) : h("div.card.empty", "No anti-forensics indicators triggered on this volume."),
  ));
}

function indicatorCard(ctx, ind, n) {
  const list = h("div");
  let open = false;
  const toggle = async () => {
    open = !open;
    if (!open) return list.replaceChildren();
    const r = await api(`/cases/${ctx.cid}/evidence/${ctx.eid}/fs/${ctx.fi}/indicator/${ind.id}`);
    list.replaceChildren(h("div.scroll", { style: { maxHeight: "320px", marginTop: "10px" } }, h("table.tbl", fileHead(), h("tbody", r.items.map((it, i) => fileRow(ctx, it, i))))));
  };
  return h("div.card.ind", { class: ind.strength > 0.3 ? "hot" : "warm", style: { "--i": n } },
    h("div.row", h("span.pill", ind.category), h("span.sp"), h("b", num(ind.count)), h("span.muted", "hits")),
    h("h2", { style: { marginTop: "10px" } }, ind.title),
    h("div.str", h("i", { style: { width: (ind.strength * 100).toFixed(1) + "%" } })),
    h("div.row.muted", { style: { fontSize: "12px" } }, `strength ${ind.strength.toFixed(2)}`, h("span.sp"), `weight ${ind.weight.toFixed(2)}, k ${ind.k}`),
    h("p", ind.explanation),
    h("div.cav", "Caveat: " + ind.caveat),
    h("div.row", { style: { marginTop: "12px" } }, h("button.sm", { onclick: toggle }, "Show files")),
    list,
  );
}

// ---------------------------------------------------------------- hex
async function hexTab(ctx) {
  const { cid, eid, s } = ctx;
  const insp = h("div.inspect.muted", "Click a byte to inspect it.");
  const hv = new HexView({ cid, eid, size: s.image_size, onSelect: (off, b, range) => { insp.replaceChildren(inspector(off, b, range)); history.replaceState(null, "", `#/c/${cid}/e/${eid}/hex?off=${off}`); } });
  const goto = h("input.mono", { placeholder: "Offset (dec, 0x hex, or s:sector)", style: { width: "260px" } });
  const doGo = () => {
    const v = goto.value.trim();
    let off = v.startsWith("s:") ? Number(v.slice(2)) * 512 : v.toLowerCase().startsWith("0x") ? parseInt(v, 16) : Number(v);
    if (!isNaN(off)) hv.go(off);
  };
  goto.addEventListener("keydown", (e) => e.key === "Enter" && doGo());
  const sq = h("input", { placeholder: "Search text or hex bytes", style: { width: "240px" } });
  let mode = "text";
  const modeSeg = h("div.seg");
  const drawMode = () => modeSeg.replaceChildren(...["text", "hex"].map((m) => h("button", { class: mode === m ? "on" : null, onclick: () => { mode = m; drawMode(); } }, m)));
  drawMode();
  const hitsBox = h("div.stack");
  let next = 0;
  const runSearch = async (cont) => {
    if (!cont) { next = 0; hv.hits.clear(); hitsBox.replaceChildren(h("div.spin")); }
    const r = await api(`/cases/${cid}/evidence/${eid}/search?q=${encodeURIComponent(sq.value)}&mode=${mode}&from=${next}`).catch((e) => (toast(e.message, true), null));
    if (!r) return;
    if (!cont) hitsBox.replaceChildren();
    const pat = mode === "hex" ? sq.value.replace(/[^0-9a-f]/gi, "").length / 2 : sq.value.length;
    for (const hit of r.hits) {
      const len = hit.enc === "utf16le" ? pat * 2 : pat;
      for (let k = 0; k < len; k++) hv.hits.add(hit.offset + k);
      hitsBox.append(h("a.mono", { href: "#", onclick: (e) => { e.preventDefault(); hv.go(hit.offset); } }, `${hexOff(hit.offset)}  ${hit.enc}`));
    }
    next = r.next;
    if (next != null) hitsBox.append(h("button.sm", { onclick: (e) => { e.target.remove(); runSearch(true); } }, `Continue from ${bytes(next)} (${((next / r.size) * 100).toFixed(1)}%)`));
    else if (!hitsBox.childElementCount) hitsBox.append(h("span.muted", "No hits."));
    hv.render();
  };
  sq.addEventListener("keydown", (e) => e.key === "Enter" && runSearch(false));
  const editBtn = h("button", "Edit overlay: off");
  const banner = h("div.editbanner", { style: { display: "none" } }, "Overlay editing: type hex digits to change the selected byte. Changes are stored in the case and audit-logged; the evidence file is never written.");
  editBtn.onclick = () => { hv.editing = !hv.editing; editBtn.textContent = "Edit overlay: " + (hv.editing ? "ON" : "off"); editBtn.classList.toggle("primary", hv.editing); banner.style.display = hv.editing ? "" : "none"; hv.el.focus(); hv.render(); };
  const patchList = h("div.stack");
  const drawPatches = (list) => patchList.replaceChildren(
    h("div.row", h("h3", `Overlay (${list.length})`), h("span.sp"), list.length && canWrite() ? h("button.sm", { onclick: async () => { const l = await api(`/cases/${cid}/evidence/${eid}/patches`, { method: "DELETE" }); hv.patches = new Map(); drawPatches(l); hv.render(); } }, "Revert all") : null),
    ...list.slice(0, 200).map((p) => h("div.row.mono", { style: { fontSize: "12px" } }, h("a", { href: "#", onclick: (e) => { e.preventDefault(); hv.go(p.offset); } }, hexOff(p.offset)), `${p.original.toString(16).padStart(2, "0")} -> ${p.value.toString(16).padStart(2, "0")}`, h("span.sp"),
      canWrite() && h("button.sm.ghost", { onclick: async () => { const l = await api(`/cases/${cid}/evidence/${eid}/patches?offset=${p.offset}`, { method: "DELETE" }); hv.patches = new Map(l.map((x) => [x.offset, x])); drawPatches(l); hv.render(); } }, "revert"))));
  hv.onPatches = drawPatches;
  const exportSel = (patched) => {
    const r = hv.range();
    if (!r) return toast("Select a byte range first (click, then shift+click).", true);
    location.href = carveLink(cid, eid, r[0], r[1], patched);
  };
  render(h("div.stack",
    h("div.hd", h("h1", "Hex"), h("span.muted", `${s.image_format}, ${num(s.image_size)} bytes`)),
    h("div.hexbar", goto, h("button", { onclick: doGo }, "Go"),
      h("div.seg", s.volumes.map((v) => h("button", { title: v.description, onclick: () => hv.go(v.start) }, `Vol ${v.index}`))),
      h("button", { title: "Byte map of the whole image", onclick: () => modal([h("div.hd", h("h2", "Byte map of the image"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
        byteMap(`/cases/${cid}/evidence/${eid}/binmap?cells=16384`, (off) => { closeModal(); hv.go(off); }, { size: 512 })]) }, "Byte map"),
      h("span.sp"), sq, modeSeg, h("button", { onclick: () => runSearch(false) }, "Search"), canWrite() ? editBtn : h("span.readonly-note", icon("lock", 14), "Read-only")),
    banner,
    h("div.hexwrap",
      h("div.card.flat", hv.el, h("div", { style: { marginTop: "10px" } }, hv.slider)),
      h("div.stack",
        h("div.card.flat", h("h3", "Inspector"), insp),
        h("div.card.flat", h("h3", "Selection"), h("div.row.wrap", { style: { marginTop: "8px" } },
          canWrite() ? h("button.sm", { onclick: () => exportSel(false) }, "Export raw") : null, canWrite() ? h("button.sm", { onclick: () => exportSel(true) }, "Export with overlay") : null,
          h("button.sm", { onclick: () => { const r = hv.range() || (hv.sel != null ? [hv.sel, hv.sel] : null); if (!r) return toast("Click a byte or select a range first.", true); const len = r[1] - r[0] + 1; bookmarkDialog({ cid, eid, kind: "offset", key: `offset:${eid}:${r[0]}:${len}`, offset: r[0], len, title: `${num(len)} byte${len === 1 ? "" : "s"} at ${hexOff(r[0])}`, path: `image offset ${num(r[0])}` }); } }, icon("star", 14), "Bookmark"))),
        h("div.card.flat", patchList),
        h("div.card.flat", h("h3", "Search hits"), hitsBox),
      ),
    ),
  ));
  drawPatches(await hv.loadPatches());
  hv.fit();
  hv.go(Number(ctx.q.off || 0), ctx.q.off != null);
  hv.el.focus();
}

// ---------------------------------------------------------------- members
async function membersView(c) {
  setCrumbs([{ label: "Cases", href: "/" }, { label: c.info.name, href: "/c/" + c.info.id }, { label: "Members" }]);
  const admin = isAdmin();
  const users = admin ? await api("/users") : [];
  const byName = new Map(users.map((u) => [u.username, u]));
  const members = { ...(c.info.members || {}) };
  const list = h("div.stack");
  const addBox = h("div.row.wrap");
  const save = h("button.primary", { disabled: true }, "Save changes");
  const dirty = () => { save.disabled = false; };
  const draw = () => {
    const names = Object.keys(members).sort();
    list.replaceChildren(...(names.length ? names.map((n, i) => {
      const u = byName.get(n) || { username: n, display_name: n };
      const access = members[n];
      const sel = h("select", { onchange: (e) => { members[n] = e.target.value; dirty(); } },
        ...["examiner", "reviewer"].map((a) => h("option", { value: a, selected: a === access, disabled: a === "examiner" && u.role === "reviewer" }, a)));
      return h("div.row.card.flat", { style: { "--i": i, padding: "10px 14px" } },
        h("span.avatar.sm", initials(u)),
        h("div", h("b", u.display_name), h("div.muted", { style: { fontSize: "12px" } }, u.username, n === c.info.examiner ? ", lead examiner" : "", u.disabled ? ", disabled" : "")),
        h("span.sp"),
        admin ? sel : h("span.pill.role-" + access, access),
        admin ? h("button.sm.ghost", { onclick: () => { delete members[n]; dirty(); draw(); } }, "Remove") : null);
    }) : [h("div.card.empty", "No members. Only admins can open this case.")]));
    if (!admin) return;
    const candidates = users.filter((u) => !members[u.username] && !u.disabled && u.role !== "admin");
    const who = h("select", ...candidates.map((u) => h("option", { value: u.username }, `${u.display_name} (${u.username}, ${u.role})`)));
    const acc = h("select", h("option", { value: "examiner" }, "examiner"), h("option", { value: "reviewer" }, "reviewer"));
    addBox.replaceChildren(...(candidates.length ? [who, acc, h("button", { onclick: () => {
      const u = byName.get(who.value);
      members[who.value] = u && u.role === "reviewer" ? "reviewer" : acc.value;
      dirty(); draw();
    } }, "Add member")] : [h("span.muted", "Every active examiner and reviewer is already a member. Admins always have access.")]));
  };
  save.onclick = async () => {
    try {
      const r = await api(`/cases/${c.info.id}/members`, { method: "PUT", body: { members } });
      Object.keys(members).forEach((k) => delete members[k]);
      Object.assign(members, r);
      save.disabled = true;
      toast("Members saved and recorded in the audit log");
      const fresh = await getCase(c.info.id);
      caseNav(fresh, "members");
    } catch (err) { toast(err.message, true); }
  };
  draw();
  render(h("div.stack",
    h("div.hd", h("h1", "Members"), h("span.sp"), admin ? save : null),
    h("p.muted", "Examiners work the case: evidence, analysis, overlay edits and exports. Reviewers can open everything read-only. Admins can open every case without being listed. Changes are recorded in the case audit log."),
    list,
    admin ? h("div.card.flat", h("h3", "Add a member"), h("div", { style: { marginTop: "10px" } }, addBox)) : null,
  ));
}

// ---------------------------------------------------------------- users
function tempPassword() {
  const abc = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => abc[x % abc.length]).join("").replace(/(.{4})(?!$)/g, "$1-");
}

function showSecret(title, who, pw) {
  modal([
    h("div.hd", h("h2", title), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
    h("p.muted", `Give this temporary password to ${who} over a separate channel. They must choose their own password when they sign in. It is not shown again.`),
    h("div.secret", pw),
    h("div.row", { style: { marginTop: "14px" } }, h("span.sp"), h("button.primary", { onclick: async () => { try { await navigator.clipboard.writeText(pw); toast("Copied"); } catch (e) { toast("Copy failed; select the text instead", true); } } }, "Copy")),
  ]);
}

async function usersView() {
  setCrumbs([{ label: "Administration" }, { label: "Users" }]);
  homeNav("users");
  const [users, retired] = await Promise.all([api("/users"), api("/users/retired").catch(() => [])]);
  const patch = async (u, body, msg) => {
    try { await api(`/users/${encodeURIComponent(u.username)}`, { method: "PATCH", body }); toast(msg); route(); } catch (err) { toast(err.message, true); route(); }
  };
  const rows = users.map((u, i) => h("tr", { class: u.disabled ? "off" : null, style: { "--i": i } },
    h("td", h("div.row", h("span.avatar.sm", initials(u)), h("div", h("b", u.display_name), h("div.muted.mono", u.username)))),
    h("td", h("select", { disabled: u.username === state.me.username, onchange: (e) => patch(u, { role: e.target.value }, `${u.username} is now ${e.target.value}`) },
      ...["admin", "examiner", "reviewer"].map((r) => h("option", { value: r, selected: r === u.role }, r)))),
    h("td", u.disabled ? h("span.pill.bad", "disabled") : u.must_change_password ? h("span.pill.warn", "password pending") : h("span.pill.ok", h("span.dot"), "active")),
    h("td.muted", u.last_login ? ts(u.last_login, 19) : "never"),
    h("td", h("div.row",
      h("button.sm", { onclick: async () => {
        const pw = tempPassword();
        try { await api(`/users/${encodeURIComponent(u.username)}`, { method: "PATCH", body: { password: pw } }); showSecret("Password reset", u.display_name, pw); route(); } catch (err) { toast(err.message, true); }
      } }, "Reset password"),
      u.username === state.me.username ? null : h("button.sm.ghost", { onclick: () => patch(u, { disabled: !u.disabled }, u.disabled ? `${u.username} enabled` : `${u.username} disabled and signed out`) }, u.disabled ? "Enable" : "Disable"),
      u.username === state.me.username ? null : h("button.sm.ghost.danger", { onclick: () => deleteUserDialog(u) }, "Delete"),
    )),
  ));
  const uname = h("input", { placeholder: "e.g. jdoe", autocapitalize: "off", spellcheck: "false" });
  const dname = h("input", { placeholder: "e.g. Jane Doe" });
  const role = h("select", ...["examiner", "reviewer", "admin"].map((r) => h("option", { value: r }, r)));
  const create = async (e) => {
    e.preventDefault();
    const pw = tempPassword();
    try {
      const u = await api("/users", { method: "POST", body: { username: uname.value, display_name: dname.value, role: role.value, password: pw } });
      showSecret("Account created", u.display_name, pw);
      route();
    } catch (err) { toast(err.message, true); }
  };
  render(h("div.stack",
    h("div.hd", h("h1", "Users"), h("span.sp"), h("span.muted", `${users.filter((u) => !u.disabled).length} active`)),
    h("div.grid.g3",
      h("form.card.stack", { onsubmit: create },
        h("h2", "New account"),
        h("label", "Username", uname),
        h("label", "Display name", dname),
        h("label", "Role", role),
        h("p.muted", { style: { margin: 0, fontSize: "12.5px" } }, "Kokino generates a temporary password. The user replaces it at first sign-in."),
        h("button.primary", { type: "submit" }, "Create account")),
      h("div.card.flat", { style: { gridColumn: "span 2" } },
        h("div.scroll", h("table.tbl", h("thead", h("tr", h("th", "User"), h("th", "Role"), h("th", "Status"), h("th", `Last sign-in (${zoneName()})`), h("th", ""))), h("tbody.stagger", rows))),
        h("p.muted", { style: { fontSize: "12.5px", marginTop: "12px" } }, "Admin: accounts, case assignments, every case. Examiner: creates and works assigned cases. Reviewer: read-only on assigned cases. Locked out? Run `kokino user reset <name>` on the server. When someone leaves, Disable keeps everything as it is; Delete removes the account (see the wiki).")),
    ),
    retired.length ? h("details.card.flat",
      h("summary", `Deleted accounts (${retired.length})`),
      h("p.muted", { style: { fontSize: "12.5px" } }, "These usernames stay reserved: audit logs and bookmarks name them, so they can never be given to someone else. Nothing else about the accounts is kept."),
      h("div.scroll", h("table.tbl", h("thead", h("tr", ["Username", "Role", `Created (${zoneName()})`, `Deleted (${zoneName()})`, "Deleted by"].map((x) => h("th", x)))),
        h("tbody", retired.map((r) => h("tr", h("td.mono", r.username), h("td", r.role), h("td.muted", ts(r.created, 19)), h("td.muted", ts(r.deleted, 19)), h("td", r.deleted_by))))))) : null,
  ));
}

/** Delete an account: shows what it did, then asks for the username. */
async function deleteUserDialog(u) {
  let usage = [];
  try { usage = (await api(`/users/${encodeURIComponent(u.username)}/usage`)).usage; } catch (e) { return toast(e.message, true); }
  const confirm = h("input", { placeholder: u.username, autocapitalize: "off", spellcheck: "false", autocomplete: "off" });
  const del = h("button.danger", { disabled: true }, "Delete account");
  confirm.addEventListener("input", () => { del.disabled = confirm.value.trim().toLowerCase() !== u.username; });
  del.onclick = async () => {
    try {
      const d = await api(`/users/${encodeURIComponent(u.username)}`, { method: "DELETE", body: { confirm: confirm.value } });
      closeModal();
      toast(`${d.username} deleted${d.purged ? "" : ", username reserved"}${d.cases.length ? `, removed from ${d.cases.length} case(s)` : ""}`);
      route();
    } catch (e) { toast(e.message, true); }
  };
  modal([
    h("div.hd", h("h2", `Delete ${u.display_name}?`), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Cancel")),
    h("div.stack",
      usage.length
        ? [h("p", h("b", `${u.username} was used:`)), h("ul", usage.map((x) => h("li", x))),
          h("p", "Deleting removes the password and display name and signs the account out. The username stays reserved, so the records above keep naming one person, and it can never be created again.")]
        : [h("p", `${u.username} was never used: no sign-in, no audit entries, no bookmarks. The account is removed completely.`)],
      h("p.muted", { style: { fontSize: "12.5px" } }, "It is also removed from every case it was assigned to (written to each case's audit log). The deletion is recorded in the system audit log. To keep the account for later, use Disable instead."),
      h("label", "Type the username to confirm", confirm),
      h("div.row", del, h("button.ghost", { onclick: closeModal }, "Cancel"))),
  ]);
  setTimeout(() => confirm.focus(), 50);
}

// ---------------------------------------------------------------- hash sets
const KIND_LABEL = { known: "Known good", notable: "Known bad" };
const ALGO = { md5: "MD5", sha1: "SHA-1", sha256: "SHA-256" };

/** Admins: case folders in .kokino/deleted, with Restore. */
async function deletedCasesView() {
  setCrumbs([{ label: "Administration" }, { label: "Deleted cases" }]);
  homeNav("deleted-cases");
  const list = await api("/system/deleted-cases");
  const restore = (d) => {
    const go_ = h("button.primary", "Restore case");
    go_.onclick = async () => {
      go_.disabled = true;
      try {
        const r = await api(`/system/deleted-cases/${encodeURIComponent(d.folder)}/restore`, { method: "POST" });
        closeModal();
        toast(`${d.info.name} restored`);
        go("/c/" + r.id);
      } catch (e) { toast(e.message, true); go_.disabled = false; }
    };
    modal([
      h("div.hd", h("h2", "Restore case"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Close")),
      h("div.stack",
        h("p", h("b", d.info.name), ` (${d.evidence} evidence item${d.evidence === 1 ? "" : "s"}) goes back into the cases directory as it was, with its analysis, bookmarks, exports, members and audit log.`),
        h("ul.impact",
          h("li", "Its members see it again; nothing in it is changed."),
          h("li", "The restore is recorded in the case audit log and the system audit log."),
          h("li", "Evidence images are read from the paths recorded when they were added.")),
        h("div.row", go_, h("button", { onclick: closeModal }, "Cancel"))),
    ]);
  };
  render(h("div.stack",
    h("div.hd", h("div", h("h1", "Deleted cases"), h("div.muted", "Cases removed with Delete case. Their folders are kept in ", h("code", ".kokino/deleted"), " in the cases directory, never wiped, until an administrator removes them from disk."))),
    list.length ? h("div.card", h("div.scroll", h("table.tbl",
      h("thead", h("tr", ["Case", "Lead examiner", "Evidence", "Deleted", ""].map((x) => h("th", x)))),
      h("tbody", list.map((d) => h("tr",
        h("td", h("b", d.info.name), h("div.muted", { style: { fontSize: "12px" } }, `Created ${ts(d.info.created, 16)}, id `, h("span.mono", d.info.id)), d.info.description ? h("div.muted", d.info.description) : null),
        h("td", d.info.examiner),
        h("td.num", num(d.evidence)),
        h("td", { style: { whiteSpace: "nowrap" } }, d.deleted_at ? h("span.mono", ts(d.deleted_at, 16)) : h("span.muted", "unknown"), d.deleted_by ? h("div.muted", `by ${d.deleted_by}`) : null),
        h("td", d.id_in_use
          ? h("span.muted", { title: `A case with id ${d.info.id} is in the cases directory now` }, "id in use")
          : h("button.sm", { onclick: () => restore(d) }, "Restore")))))))) 
      : h("div.card.empty", "No deleted cases."),
  ));
}

async function hashsetsView() {
  setCrumbs([{ label: "Administration" }, { label: "Hash sets" }]);
  homeNav("hashsets");
  const sets = await api("/hashsets");
  const running = state.jobs.filter((j) => j.kind === "hashset" && j.state === "running");
  const toggle = async (s) => {
    try { await api(`/system/hashsets/${s.id}`, { method: "PATCH", body: { enabled: !s.enabled } }); toast(`${s.name} ${s.enabled ? "disabled" : "enabled"}`); route(); } catch (e) { toast(e.message, true); }
  };
  const del = (s) => {
    const confirm = h("input", { placeholder: s.name, autocomplete: "off" });
    const go = h("button.danger", { disabled: true }, "Delete hash set");
    confirm.addEventListener("input", () => { go.disabled = confirm.value.trim() !== s.name; });
    go.onclick = async () => { try { await api(`/system/hashsets/${s.id}`, { method: "DELETE" }); closeModal(); toast(`${s.name} deleted`); route(); } catch (e) { toast(e.message, true); } };
    modal([h("div.hd", h("h2", `Delete ${s.name}?`), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Cancel")),
      h("div.stack", h("p", "Its database is removed. Hash analyses already made keep their results and name the set; they change only when an examiner checks again. To stop using a set but keep it, disable it instead."),
        h("label", "Type the name to confirm", confirm), h("div.row", go, h("button.ghost", { onclick: closeModal }, "Cancel")))]);
    setTimeout(() => confirm.focus(), 50);
  };
  render(h("div.stack",
    h("div.hd", h("div", h("h1", "Hash sets"), h("div.muted", "Lists of file hashes shared by every case. Files in a known-good set (such as the NIST NSRL) can be hidden; files in a known-bad set are flagged. Examiners run Hash analysis on an evidence item to compare its files.")),
      h("span.sp"), h("button.primary", { style: { whiteSpace: "nowrap" }, onclick: importHashsetDialog }, icon("download", 14), "Import hash set")),
    running.length ? h("div.card.row", h("span", "Importing"), ...running.map((j) => h("span", { "data-job-ev": "" }, jobPill(j)))) : null,
    sets.length ? h("div.card", h("div.scroll", h("table.tbl",
      h("thead", h("tr", ["Name", "Kind", "Hashes", "Source", "Imported", ""].map((x) => h("th", x)))),
      h("tbody", sets.map((s) => h("tr", { class: s.enabled ? null : "muted" },
        h("td", h("b", s.name), s.description ? h("div.muted", s.description) : null, h("div.muted.mono", s.id)),
        h("td", h("span.pill", { class: s.kind === "notable" ? "bad" : "ok" }, KIND_LABEL[s.kind]), s.enabled ? null : h("div.muted", "disabled")),
        h("td.num", h("div", num(s.md5 + s.sha1 + s.sha256)), h("div.muted", [s.md5 ? `${num(s.md5)} MD5` : "", s.sha1 ? `${num(s.sha1)} SHA-1` : "", s.sha256 ? `${num(s.sha256)} SHA-256` : ""].filter(Boolean).join(", "))),
        h("td", h("div", s.source), h("div.muted", `${s.format}, ${bytes(s.source_bytes)}`), h("div.muted.mono", { title: `SHA-256 of the source file: ${s.source_sha256}` }, `SHA-256 ${s.source_sha256.slice(0, 16)}...`), s.source_verified ? h("span.pill.ok", { title: "The source file's SHA-256 equals the value its publisher listed (NIST signatures.txt)" }, h("span.dot"), s.source_verified) : null),
        h("td", h("div", s.imported_by), h("div.muted", ts(s.imported_at, 16))),
        h("td", h("div.row", h("button.sm.ghost", { onclick: () => toggle(s) }, s.enabled ? "Disable" : "Enable"), h("button.sm.ghost.danger", { onclick: () => del(s) }, "Delete")))))))))
      : h("div.card.empty.stack", h("p", "No hash sets yet."), h("p.muted", "Import the NIST NSRL (RDS v3 .db or .sql file, or NSRLFile.txt from RDS 2.x) as known good, and your lab's lists of known-bad files (one hash per line, md5sum or sha256sum output, or CSV) as known bad.")),
    h("p.muted", { style: { fontSize: "12.5px" } }, "Imports, changes and deletions are recorded in the system audit log with the SHA-256 of the source file. Each hash analysis records which sets it used, so a report can name the exact list version. On the server console: kokino hashset list / import / delete."),
  ));
}

/** Import a hash set from a file on the server. */
function importHashsetDialog() {
  const path = h("input", { placeholder: "Full path on the server, e.g. D:\\NSRL\\RDS_2024.12.1_modern_minimal.db" });
  const name = h("input", { placeholder: "e.g. NSRL RDS 2024.12 modern", maxlength: 80 });
  const kind = h("select", h("option", { value: "known" }, "Known good: hide matching files (e.g. NSRL)"), h("option", { value: "notable" }, "Known bad: flag matching files"));
  const desc = h("input", { placeholder: "Optional: where it came from, version", maxlength: 500 });
  const picker = h("div.picker");
  const where = h("code.muted");
  const browse = async (p) => {
    try {
      const r = await api("/browse?path=" + encodeURIComponent(p || ""));
      where.textContent = r.path || "Choose a location";
      picker.replaceChildren(
        ...(r.path ? [h("div", { onclick: () => browse(r.parent || "") }, icon("up"), "..")] : []),
        ...r.entries.map((e) => h("div", { onclick: () => (e.is_dir ? browse(e.path) : ((path.value = e.path), name.value || (name.value = e.name.replace(/\.[^.]+$/, "")), toast("Selected " + e.name))) }, e.is_dir ? icon("folder") : icon("hash"), h("span", e.name), h("span.sp"), e.is_dir ? null : h("span.muted", bytes(e.size)))),
      );
    } catch (err) { toast(err.message, true); }
  };
  browse("");
  const go = h("button.primary", "Import");
  go.onclick = async () => {
    try {
      const job = await api("/system/hashsets", { method: "POST", body: { path: path.value, name: name.value, kind: kind.value, description: desc.value } });
      closeModal();
      toast("Importing the hash set; large sets such as the NSRL take a while");
      kickJobs(job);
      route();
    } catch (e) { toast(e.message, true); }
  };
  modal([h("div.hd", h("h2", "Import hash set"), h("span.sp"), h("button.ghost.sm", { onclick: closeModal }, "Cancel")),
    h("div.stack",
      h("p.muted", { style: { margin: 0 } }, "Accepted: NSRL RDS v3 (.db SQLite, or .sql full and delta releases), NSRL RDS 2.x NSRLFile.txt, CSV with MD5 / SHA-1 / SHA-256 columns, and plain lists (one hash per line; md5sum and sha256sum output work). Unzip downloads first. The file is copied into Kokino's own format, so it can be moved afterwards."),
      h("label", "File", path), where, picker,
      h("div.row.wrap", { style: { gap: "12px" } }, h("label", { style: { flex: 1 } }, "Name", name), h("label", { style: { flex: 1 } }, "Kind", kind)),
      h("label", "Description", desc),
      h("div.row", go, h("button.ghost", { onclick: closeModal }, "Cancel")))]);
}

/** Hash analysis of one evidence item: every file hashed and compared with the hash sets. */
async function hashesTab(ctx) {
  const { cid, eid } = ctx;
  const base = `/cases/${cid}/evidence/${eid}/hashes`;
  let show = ["notable", "known", "unmatched", "unreadable"].includes(ctx.q.show) ? ctx.q.show : "notable";
  let r = await api(`${base}?show=${show}&limit=500`);
  const job = state.jobs.find((j) => j.evidence === eid && j.state === "running");
  const start = (rehash) => api(`${base}${rehash ? "?rehash=true" : ""}`, { method: "POST" }).then((j) => { toast(rehash ? "Hashing every file again" : "Checking the hash sets"); kickJobs(j); route(); }).catch((e) => toast(e.message, true));
  const intro = h("div.hd", h("div", h("h1", "Hash analysis"), h("div.muted", "MD5, SHA-1 and SHA-256 of every file, compared with the hash sets: known good (hide the noise) and known bad (flag what matters).")), h("span.sp"));
  const setsNote = r.sets.length ? null : h("p.muted", isAdmin() ? h("span", "There are no hash sets yet. ", h("a", { href: "#/hashsets" }, "Import one"), ", such as the NSRL.") : "There are no hash sets yet; an admin imports them under Hash sets.");
  if (!r.summary) {
    return render(h("div.stack", intro, h("div.card.empty.stack",
      job ? [h("div.spin"), h("p", "Working..."), h("span", { "data-job-ev": eid }, jobPill(job))]
        : [h("p", "This evidence has no hash analysis yet. It reads every file (live, and deleted where the content is still there) and hashes it."), setsNote,
          canWrite() ? h("button.primary", { onclick: () => start(false) }, "Run hash analysis") : h("p.muted", "Ask an examiner on this case to run it.")])));
  }
  const s = r.summary;
  if (canWrite() && !job) intro.append(h("button.sm", { style: { whiteSpace: "nowrap" }, onclick: () => start(false), title: "Look the stored hashes up in the current hash sets" }, "Check again"), h("button.sm.ghost", { style: { whiteSpace: "nowrap" }, onclick: () => start(true), title: "Read and hash every file again" }, "Rehash files"));
  const tbody = h("tbody");
  const count = h("span.muted");
  const filter = h("input", { placeholder: "Filter by path or hash...", style: { flex: 1 } });
  const seg = h("div.seg");
  const opts = [["notable", `Known bad (${num(s.notable)})`], ["known", `Known good (${num(s.known)})`], ["unmatched", "Not in any set"], ["unreadable", `Not readable (${num(s.unreadable)})`]];
  const drawSeg = () => seg.replaceChildren(...opts.map(([k, l]) => h("button", { class: show === k ? "on" : null, onclick: () => { show = k; drawSeg(); load(); } }, l)));
  const draw = () => {
    count.textContent = `${num(r.total)} file${r.total === 1 ? "" : "s"}${r.total > r.items.length ? `, first ${r.items.length} shown` : ""}`;
    tbody.replaceChildren(...r.items.map((x) => h("tr", { class: x.deleted ? "deleted" : null, onclick: () => fileDrawer({ cid, eid, fi: x.fi }, x.idx) },
      h("td.nm", { title: x.path }, h("b", x.name), h("div.muted.mono.ell", x.path)),
      h("td.num", bytes(x.size)),
      h("td", x.error ? h("span", { style: { color: "var(--warn)" } }, x.error) : h("span.mono.muted", { title: `MD5 ${x.md5}\nSHA-1 ${x.sha1}\nSHA-256 ${x.sha256}` }, x.sha256.slice(0, 20) + "...")),
      h("td", h("div.row.wrap", x.sets.map((z) => h("span.pill", { class: z.kind === "notable" ? "bad" : null, title: `matched by ${ALGO[z.algo]}` }, z.name)))),
      h("td", { onclick: (e) => e.stopPropagation() }, bmButton({ cid, eid, kind: "file", key: `file:${eid}:${x.fi}:${x.record}`, fi: x.fi, record: x.record, idx: x.idx, title: x.name, path: x.path })))));
  };
  const load = debounce(async () => {
    r = await api(`${base}?show=${show}&q=${encodeURIComponent(filter.value.trim())}&limit=500`);
    draw();
  }, 200);
  filter.addEventListener("input", load);
  drawSeg();
  draw();
  render(h("div.stack", intro,
    job ? h("div.card.row", h("span", { "data-job-ev": eid }, jobPill(job))) : null,
    s.outdated ? h("div.card.flat.ind.hot", h("b", "The hash sets changed since this analysis"), h("p", { style: { margin: "6px 0 0" } }, canWrite() ? "Use Check again to compare the stored hashes with the current sets. Files are not read again." : "An examiner on this case can check again.")) : null,
    h("div.statgrid",
      stat("Files hashed", num(s.files), bytes(s.bytes)),
      stat("Known bad", num(s.notable), "in a known-bad set", s.notable ? "bad" : null),
      stat("Known good", num(s.known), "can be hidden in Explorer"),
      stat("Not readable", num(s.unreadable), "content not recoverable")),
    h("div.card.flat", h("div.muted", { style: { fontSize: "12.5px" } }, `Hashed ${ts(s.hashed_at, 16)}, compared ${ts(s.matched_at, 16)} with: `, s.sets.length ? s.sets.map((x, i) => [i ? ", " : "", h("b", x.name), ` (${KIND_LABEL[x.kind].toLowerCase()})`]) : "no hash sets", ".")),
    setsNote,
    h("div.row.wrap", seg, filter),
    count,
    h("div.scroll", { style: { maxHeight: "calc(100vh - 360px)" } }, h("table.tbl", h("thead", h("tr", ["File", "Size", "SHA-256", "Hash sets", ""].map((x) => h("th", x)))), tbody)),
    h("p.muted", { style: { fontSize: "12.5px" } }, "A match means the content is identical to a file in that list. For deleted files the content is what is in their clusters now, which may belong to another file. Small, common files (empty templates, icons) can appear in both kinds of list."),
  ));
}

function stat(label, value, sub, tone) {
  return h("div.card.flat.stat", h("div.muted", label), h("div.big", { style: { color: tone === "bad" ? "var(--bad)" : null } }, value), sub ? h("div.muted", { style: { fontSize: "12px" } }, sub) : null);
}

async function systemAuditView() {
  setCrumbs([{ label: "Administration" }, { label: "System audit" }]);
  homeNav("system-audit");
  const a = await api("/system/audit");
  const bad = new Set(["auth.fail", "auth.locked"]);
  render(
    h("div.hd", h("h1", "System audit"), h("span.sp"), a.verify.ok ? h("span.pill.ok", h("span.dot"), `hash chain intact, ${a.verify.entries} entries`) : h("span.pill.bad", h("span.dot"), `chain broken at entry ${a.verify.broken_at}`)),
    h("p.muted", "Sign-ins, failed attempts, account changes and case assignments. Hash-chained like the case audit logs. Head: ", h("code", a.verify.head)),
    h("div.scroll", h("table.tbl", h("thead", h("tr", h("th", "#"), h("th", `Time (${zoneName()})`), h("th", "User"), h("th", "Action"), h("th", "Detail"))),
      h("tbody", a.entries.slice().reverse().map((e) => h("tr", h("td.num", e.seq), h("td", ts(e.time)), h("td", e.examiner), h("td", bad.has(e.action) ? h("b", { style: { color: "var(--bad)" } }, e.action) : h("b", e.action)), h("td.mono", { title: JSON.stringify(e.detail, null, 1) }, JSON.stringify(e.detail))))))),
  );
}

// ---------------------------------------------------------------- boot
window.addEventListener("unhandledrejection", (e) => { console.error(e.reason); toast(String(e.reason && e.reason.message || e.reason), true); });
window.addEventListener("error", (e) => toast(e.message, true));

/** Reload when the server now serves different GUI files than this page has. */
async function reloadIfUpgraded() {
  try {
    const info = await api("/info", { quiet: true });
    if (state.info && info.build && state.info.build && info.build !== state.info.build) {
      location.reload();
      return true;
    }
  } catch (e) {}
  return false;
}

async function signedIn() {
  if (await reloadIfUpgraded()) return;
  const me = await api("/auth/me", { quiet: true });
  state.me = me.user;
  state.root = me.cases_root;
  state.caseCache = {};
  state.bm = null;
  drawMe();
  closeAuth();
  if (!state.polling) { state.polling = true; pollJobs(); }
  route();
}

/** Drops everything the previous user could see; the route stays in the URL. */
function signedOut(notice) {
  state.me = null;
  state.write = false;
  state.caseCache = {};
  state.bm = null;
  state.jobs = [];
  closeDrawer();
  closeModal();
  for (const id of ["#me", "#nav", "#crumbs", "#jobs", "#view"]) $(id).replaceChildren();
  loginScreen(state.info, signedIn, notice);
}

function drawMe() {
  const u = state.me;
  $("#me").replaceChildren(...[
    h("span.avatar", initials(u)),
    h("div.who", h("b", { title: u.username }, u.display_name), h("small", u.role)),
    isAdmin() ? h("button.ghost", { title: "Manage users", "aria-label": "Manage users", onclick: () => go("/users") }, icon("users", 15)) : null,
    h("button.ghost", { title: "Change password", "aria-label": "Change password", onclick: () => passwordScreen(state.info, () => { closeAuth(); toast("Password changed"); }, false) }, icon("lock", 15)),
    h("button.ghost", { title: "Sign out", "aria-label": "Sign out", onclick: async () => { await api("/auth/logout", { method: "POST", quiet: true }).catch(() => {}); signedOut("You are signed out."); } }, icon("logout", 15)),
  ].filter(Boolean));
}

window.addEventListener("kokino:auth", async (e) => {
  if (authOpen()) return;
  // A 401 often means the server restarted, possibly as a newer build.
  if (await reloadIfUpgraded()) return;
  if (e.detail.status === 403) passwordScreen(state.info, signedIn, true);
  else signedOut("Your session ended. Sign in again to continue where you left off.");
});

(async () => {
  try {
    state.info = await api("/info", { quiet: true });
    $("#ver").textContent = "v" + state.info.version;
    const sep = () => h("span.foot-sep", "|");
    $("#foot").replaceChildren(
      h("span", `Kokino FTK ${state.info.version}`), sep(),
      h("a", { href: "#/wiki/license" }, "Apache-2.0 License"), sep(),
      h("a", { href: "#/wiki/privacy" }, "Privacy"), sep(),
      h("a", { href: "https://www.zeroscience.mk", target: "_blank", rel: "noopener noreferrer" }, "Zero Science Lab"));
  } catch (e) {
    view.replaceChildren(h("div.card", h("h2", "Not connected"), h("p.muted", "Cannot reach the Kokino server. Start it with `kokino serve` and open the link it prints.")));
    return;
  }
  if (state.info.setup_required) {
    const m = location.hash.match(/setup=([0-9a-f]+)/);
    if (m) history.replaceState(null, "", location.pathname + "#/");
    return setupScreen(state.info, m ? m[1] : "", signedIn);
  }
  if (/setup=/.test(location.hash)) history.replaceState(null, "", location.pathname + "#/");
  try {
    const me = await api("/auth/me", { quiet: true });
    if (me.user.must_change_password) return passwordScreen(state.info, signedIn, true);
    signedIn();
  } catch (e) {
    loginScreen(state.info, signedIn);
  }
})();
