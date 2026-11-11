//! Case report: the bookmarked items of a case as numbered exhibits, with
//! the evidence and its hashes, a chain of custody taken from the case
//! audit log, methods, limitations and a sign-off block.
//!
//! One document model is rendered to self-contained HTML (printed to PDF
//! from the browser) and to Word (.docx, written here without libraries).
//! Each exhibit's content is read from the evidence again and its hash
//! compared with the one taken when it was bookmarked. Both files are saved
//! in the case exports folder and their SHA-256 is written to the audit
//! log, so a report handed over can be checked against the case later.

use crate::state::{AppState, Loaded};
use kokino_core::audit::AuditEntry;
use kokino_core::bookmarks::Bookmark;
use kokino_core::case::{Case, EvidenceRecord};
use kokino_core::hashing::{hash_reader, sha256_hex, Hashes};
use kokino_core::time::{filetime_to_iso, human_as_stored, human_full, now_iso};
use kokino_analysis::photo::{self, Rgb};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ReportOptions {
    pub title: String,
    pub reference: String,
    pub requested_by: String,
    /// The examiner's summary of findings; blank lines separate paragraphs.
    pub summary: String,
    /// Only bookmarks with this tag; every bookmark when empty.
    pub tag: String,
    /// Append every audit log entry, not only the chain of custody.
    pub full_audit: bool,
    /// Times in UTC instead of the local time of the computer making the report.
    pub utc: bool,
}

/// How the report states its times, for the contents line and Methods.
fn zone_note(utc: bool) -> &'static str {
    if utc {
        "All times are UTC."
    } else {
        "Times are the local time of the computer that made this report, each with its UTC offset (summer time applied for each date)."
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportFile {
    pub name: String,
    pub format: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Generated {
    pub report: String,
    pub time: String,
    pub exhibits: usize,
    pub files: Vec<ReportFile>,
}

/// Exhibit content larger than this is not read again for the report.
const MAX_RECHECK: u64 = 1 << 30;
/// Byte ranges up to this size get a SHA-256 in the report.
const MAX_RANGE_HASH: u64 = 64 << 20;
const DEFAULT_TITLE: &str = "Forensic examination report";

/// Builds the report, saves the HTML and Word files in the case exports
/// folder and records them (with their SHA-256) in the case audit log.
pub fn generate(st: &AppState, cid: &str, username: &str, display_name: &str, o: &ReportOptions) -> anyhow::Result<Generated> {
    kokino_core::time::with_utc(o.utc, || generate_in_zone(st, cid, username, display_name, o))
}

fn generate_in_zone(st: &AppState, cid: &str, username: &str, display_name: &str, o: &ReportOptions) -> anyhow::Result<Generated> {
    let case = st.case(cid)?;
    let now = now_iso();
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let (doc, exhibits) = build(st, &case, username, display_name, o, &id, &now)?;
    let stamp: String = now.chars().filter(|c| c.is_ascii_digit()).take(14).collect();
    let base = format!("report-{}-{}-{}", &stamp[..8], &stamp[8..14], id);
    let dir = case.dir.join("exports");
    std::fs::create_dir_all(&dir)?;
    let mut files = vec![];
    for (ext, format, data) in [("html", "HTML", render_html(&doc).into_bytes()), ("docx", "Word", render_docx(&doc, &now)?)] {
        let name = format!("{}.{}", base, ext);
        std::fs::write(dir.join(&name), &data)?;
        files.push(ReportFile { name, format: format.into(), bytes: data.len() as u64, sha256: sha256_hex(&data) });
    }
    case.audit.append(
        username,
        "report.case",
        json!({"report": id, "title": doc.title, "reference": o.reference.trim(), "tag": o.tag.trim(), "exhibits": exhibits, "full_audit": o.full_audit, "files": files}),
    )?;
    Ok(Generated { report: id, time: now, exhibits, files })
}

/// Reports generated for a case, from its audit log (newest first), each
/// file checked against the SHA-256 recorded when it was made.
pub fn list(case: &Case) -> anyhow::Result<Vec<Value>> {
    let mut out = vec![];
    for e in case.audit.entries()?.into_iter().filter(|e| e.action == "report.case").rev() {
        let d = &e.detail;
        let files: Vec<Value> = d["files"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|f| {
                        let name = f["name"].as_str().unwrap_or("");
                        let now = file_path(case, name).ok().and_then(|p| std::fs::read(p).ok()).map(|b| sha256_hex(&b));
                        json!({"name": name, "format": f["format"], "bytes": f["bytes"], "sha256": f["sha256"], "present": now.is_some(), "intact": now.as_deref() == f["sha256"].as_str()})
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.push(json!({"report": d["report"], "time": e.time, "by": e.examiner, "title": d["title"], "reference": d["reference"], "tag": d["tag"], "exhibits": d["exhibits"], "files": files}));
    }
    Ok(out)
}

/// A saved report file. Only names this module generates are accepted.
pub fn file_path(case: &Case, name: &str) -> anyhow::Result<PathBuf> {
    let ok = name.len() <= 64
        && name.starts_with("report-")
        && (name.ends_with(".html") || name.ends_with(".docx"))
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && name.matches('.').count() == 1;
    if !ok {
        anyhow::bail!("not a report file name");
    }
    Ok(case.dir.join("exports").join(name))
}

// ---------------------------------------------------------------- document model

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Normal,
    Muted,
    Good,
    Bad,
}

#[derive(Clone)]
struct Run {
    t: String,
    b: bool,
    mono: bool,
    tone: Tone,
}

impl Run {
    fn b(mut self) -> Self {
        self.b = true;
        self
    }
    fn tone(mut self, t: Tone) -> Self {
        self.tone = t;
        self
    }
}

fn t(s: impl Into<String>) -> Run {
    Run { t: s.into(), b: false, mono: false, tone: Tone::Normal }
}
fn bold(s: impl Into<String>) -> Run {
    t(s).b()
}
fn mono(s: impl Into<String>) -> Run {
    Run { mono: true, ..t(s) }
}
fn muted(s: impl Into<String>) -> Run {
    t(s).tone(Tone::Muted)
}

type Para = Vec<Run>;

enum Block {
    Title { title: String, sub: String },
    H1(String),
    H2(String),
    P(Para),
    Small(Para),
    /// Two-column key / value table.
    Kv(Vec<(String, Vec<Para>)>),
    Table { head: Vec<String>, widths: Vec<u32>, rows: Vec<Vec<Vec<Para>>> },
    Bullets(Vec<Para>),
    Pre(String),
    Img { png: Vec<u8>, w: u32, h: u32, pixelated: bool, caption: String },
    Break,
    /// Signature lines, one per label.
    Sign(Vec<String>),
}

struct Doc {
    id: String,
    title: String,
    case_name: String,
    author: String,
    blocks: Vec<Block>,
}

fn kv(k: &str, v: Vec<Para>) -> (String, Vec<Para>) {
    (k.to_string(), v)
}
fn kv1(k: &str, v: Para) -> (String, Vec<Para>) {
    (k.to_string(), vec![v])
}

// ---------------------------------------------------------------- content

/// Outcome of reading an exhibit's content again for the report.
#[derive(Clone, PartialEq)]
enum Check {
    Match,
    Differs,
    /// A hash computed now (nothing earlier to compare with).
    Computed,
    NotChecked(String),
}

impl Check {
    fn label(&self) -> Run {
        match self {
            Check::Match => t("matches").tone(Tone::Good),
            Check::Differs => t("DIFFERS").tone(Tone::Bad),
            Check::Computed => muted("hashed now"),
            Check::NotChecked(_) => muted("not checked"),
        }
    }
}

struct Ctx<'a> {
    st: &'a AppState,
    case: &'a Case,
    names: HashMap<String, String>,
    loaded: HashMap<String, Result<Arc<Loaded>, String>>,
    photos: HashMap<String, Option<photo::PhotoScan>>,
    /// Caveats of the findings shown, by finding title.
    caveats: BTreeMap<String, String>,
    figures: usize,
}

impl Ctx<'_> {
    fn load(&mut self, eid: &str) -> Result<Arc<Loaded>, String> {
        let cid = self.case.info.id.clone();
        let st = self.st;
        self.loaded.entry(eid.to_string()).or_insert_with(|| st.loaded(&cid, eid).map_err(|e| format!("{:#}", e))).clone()
    }
    fn photos(&mut self, eid: &str) -> Option<&photo::PhotoScan> {
        let case = self.case;
        self.photos.entry(eid.to_string()).or_insert_with(|| crate::jobs::load_photos(case, eid)).as_ref()
    }
    fn name(&self, eid: &str) -> String {
        self.names.get(eid).cloned().unwrap_or_else(|| eid.to_string())
    }
}

/// Day first, to the second (dd-mm-yyyy hh:mm:ss UTC).
fn when(s: &str) -> String {
    kokino_core::time::human(s)
}

fn size(n: u64) -> String {
    let digits = n.to_string();
    let mut g = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            g.push(',');
        }
        g.push(c);
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = "";
    for x in units {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        u = x;
    }
    if u.is_empty() {
        format!("{} bytes", g)
    } else {
        format!("{} bytes ({:.1} {})", g, v, u)
    }
}

fn hash_paras(h: &Hashes) -> Vec<Para> {
    let mut v = vec![];
    for (k, x) in [("MD5", &h.md5), ("SHA-1", &h.sha1), ("SHA-256", &h.sha256)] {
        if !x.is_empty() {
            v.push(vec![muted(format!("{} ", k)), mono(x.clone())]);
        }
    }
    v
}

fn hash_match(x: &Hashes, h: &Hashes) -> bool {
    (x.md5.is_empty() || x.md5.eq_ignore_ascii_case(&h.md5)) && (x.sha1.is_empty() || x.sha1.eq_ignore_ascii_case(&h.sha1)) && (x.sha256.is_empty() || x.sha256.eq_ignore_ascii_case(&h.sha256))
}

const KINDS: &[(&str, &str)] = &[("file", "File"), ("event", "Event log record"), ("carved", "Carved file"), ("hit", "Search hit"), ("offset", "Byte range"), ("web", "Web history")];

fn kind_label(b: &Bookmark) -> String {
    let k = KINDS.iter().find(|(k, _)| *k == b.kind).map(|(_, l)| *l).unwrap_or(&b.kind);
    if b.region.is_some() {
        format!("{} (picture region)", k)
    } else {
        k.to_string()
    }
}

fn build(st: &AppState, case: &Case, username: &str, display_name: &str, o: &ReportOptions, id: &str, now: &str) -> anyhow::Result<(Doc, usize)> {
    let evidence = case.evidence();
    let names: HashMap<String, String> = evidence.iter().map(|e| (e.id.clone(), e.name.clone())).collect();
    let order: HashMap<String, usize> = evidence.iter().enumerate().map(|(i, e)| (e.id.clone(), i)).collect();
    let tag = o.tag.trim();
    let all = kokino_core::bookmarks::load(&case.bookmarks_path())?;
    let mut marks: Vec<&Bookmark> = all.iter().filter(|b| tag.is_empty() || b.tags.iter().any(|x| x.eq_ignore_ascii_case(tag))).collect();
    marks.sort_by(|a, b| order.get(&a.evidence).unwrap_or(&usize::MAX).cmp(order.get(&b.evidence).unwrap_or(&usize::MAX)).then_with(|| a.created_at.cmp(&b.created_at)));
    let entries = case.audit.entries()?;
    let chain = kokino_core::audit::verify(&case.dir.join("audit.jsonl"))?;
    let title = if o.title.trim().is_empty() { DEFAULT_TITLE.to_string() } else { o.title.trim().to_string() };
    let author = if display_name == username { username.to_string() } else { format!("{} ({})", display_name, username) };
    let scope = if tag.is_empty() { "All bookmarked items".to_string() } else { format!("Bookmarked items tagged \"{}\"", tag) };
    let mut cx = Ctx { st, case, names, loaded: HashMap::new(), photos: HashMap::new(), caveats: BTreeMap::new(), figures: 0 };

    // Exhibits first: their checks feed the summary and the limitations.
    let mut exhibit_blocks = vec![];
    let mut index_rows = vec![];
    let mut checks = vec![];
    for (n, b) in marks.iter().enumerate() {
        let label = format!("E-{:03}", n + 1);
        let (blocks, check) = exhibit(&mut cx, b, &label);
        index_rows.push(vec![
            vec![vec![bold(label.clone())]],
            vec![vec![t(b.title.clone())], vec![mono(b.path.clone()).tone(Tone::Muted)]],
            vec![vec![t(kind_label(b))]],
            vec![vec![t(cx.name(&b.evidence))]],
            vec![vec![t(b.tags.join(", "))]],
            vec![vec![check.label()]],
        ]);
        checks.push((label, b.title.clone(), check));
        exhibit_blocks.extend(blocks);
    }

    let mut d: Vec<Block> = vec![];
    d.push(Block::Title { title: title.clone(), sub: case.info.name.clone() });
    let mut front = vec![];
    if !o.reference.trim().is_empty() {
        front.push(kv1("Reference", vec![t(o.reference.trim())]));
    }
    if !o.requested_by.trim().is_empty() {
        front.push(kv1("Requested by", vec![t(o.requested_by.trim())]));
    }
    front.extend([
        kv1("Case", vec![t(case.info.name.clone()), muted(format!("  (case id {})", case.info.id))]),
        kv1("Prepared by", vec![t(author.clone())]),
        kv1("Report date", vec![t(when(now))]),
        kv1("Report id", vec![mono(id)]),
        kv1("Scope", vec![t(format!("{}: {} exhibit(s) from {} evidence item(s)", scope, marks.len(), evidence.len()))]),
        kv1("Tool", vec![t(format!("Kokino FTK {} ({}), {}", kokino_core::TOOL_VERSION, kokino_core::TOOL_NAME, kokino_core::VENDOR))]),
    ]);
    d.push(Block::Kv(front));
    d.push(Block::Small(vec![muted(
        "Contents: 1 Summary, 2 Case, 3 Evidence, 4 Exhibits, 5 Chain of custody, 6 Methods and tools, 7 Limitations, 8 Sign-off".to_string()
            + if o.full_audit { ", Appendix A Audit log" } else { "" }
            + ". " + zone_note(o.utc) + " Offsets are byte offsets in the logical evidence image.",
    )]));

    // 1 Summary
    d.push(Block::H1("1 Summary".into()));
    d.push(Block::P(vec![t(format!(
        "This report presents {} exhibit(s) ({}) from {} evidence item(s) of case \"{}\". Section 4 describes each exhibit: where it is in the evidence, its hashes, findings and the examiner's notes.",
        marks.len(),
        scope.to_lowercase(),
        evidence.len(),
        case.info.name
    ))]));
    let differ = checks.iter().filter(|c| c.2 == Check::Differs).count();
    let matched = checks.iter().filter(|c| c.2 == Check::Match).count();
    if matched + differ > 0 {
        d.push(Block::P(if differ == 0 {
            vec![t(format!("The content of {} exhibit(s) was read from the evidence again for this report; ", matched)), t("every hash matches").tone(Tone::Good), t(" the one taken when it was bookmarked.")]
        } else {
            vec![t(format!("The content of {} exhibit(s) was read from the evidence again; ", matched + differ)), t(format!("{} do(es) NOT match", differ)).tone(Tone::Bad), t(" the hash taken when bookmarked (see section 7).")]
        }));
    }
    if !o.summary.trim().is_empty() {
        d.push(Block::H2("Examiner's summary".into()));
        for p in o.summary.trim().split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
            d.push(Block::P(vec![t(p)]));
        }
    }
    if !index_rows.is_empty() {
        d.push(Block::H2("Exhibit index".into()));
        d.push(Block::Table { head: ["Exhibit", "Item", "Type", "Evidence", "Tags", "Content"].map(String::from).to_vec(), widths: vec![10, 34, 15, 17, 12, 12], rows: index_rows });
    }

    // 2 Case
    d.push(Block::H1("2 Case".into()));
    let members: Vec<Para> = case.info.members.iter().map(|(u, a)| vec![t(u.clone()), muted(format!(" ({:?})", a).to_lowercase())]).collect();
    d.push(Block::Kv(vec![
        kv1("Name", vec![t(case.info.name.clone())]),
        kv1("Case id", vec![mono(case.info.id.clone())]),
        kv1("Description", vec![t(case.info.description.clone())]),
        kv1("Created", vec![t(format!("{} by {}", when(&case.info.created), case.info.examiner))]),
        kv1("Created with", vec![t(format!("{} {}", case.info.tool, case.info.tool_version))]),
        kv("Assigned", members),
    ]));

    // 3 Evidence
    d.push(Block::H1("3 Evidence".into()));
    d.push(Block::P(vec![t("Every evidence item was opened read-only. Its hashes are computed by Kokino over the logical image stream (for E01, the media data inside the container) and compared with the hashes recorded at acquisition.")]));
    if evidence.is_empty() {
        d.push(Block::P(vec![muted("No evidence has been added to this case.")]));
    }
    for (i, rec) in evidence.iter().enumerate() {
        d.push(Block::H2(format!("3.{} {}", i + 1, rec.name)));
        d.push(Block::Kv(evidence_rows(&mut cx, rec, &marks)));
    }

    // 4 Exhibits
    d.push(Block::Break);
    d.push(Block::H1("4 Exhibits".into()));
    if marks.is_empty() {
        d.push(Block::P(vec![muted(if tag.is_empty() { "No items are bookmarked in this case.".to_string() } else { format!("No bookmarked item is tagged \"{}\".", tag) })]));
    } else {
        d.push(Block::P(vec![t("Each exhibit is an item the examiner bookmarked in Kokino. Its description, path and hashes were recorded when it was bookmarked; the content was then read from the evidence again for this report and hashed, and the result is shown as Re-verified.")]));
    }
    d.extend(exhibit_blocks);

    // 5 Chain of custody
    d.push(Block::Break);
    d.push(Block::H1("5 Chain of custody".into()));
    d.push(Block::P(if chain.ok {
        vec![
            t(format!("Every action on this case is written to its audit log, where each entry carries the SHA-256 of the entry before it. The log has {} entries; ", chain.entries)),
            t("the hash chain is intact").tone(Tone::Good),
            t(". Changing, removing or reordering any entry would break it. Chain head: "),
            mono(chain.head.clone()),
        ]
    } else {
        vec![t(format!("The case audit log has {} readable entries and ", chain.entries)), t(format!("its hash chain is BROKEN at entry {}", chain.broken_at.unwrap_or(0))).tone(Tone::Bad), t(": an entry was changed, removed or reordered after it was written. See section 7.")]
    }));
    d.push(Block::P(vec![t("Evidence handling, processing, exports and reports, in order:")]));
    let custody = |a: &str| a.starts_with("case.") || a.starts_with("evidence.") || a.starts_with("overlay.") || a.starts_with("report.") || a.ends_with(".export") || a == "bookmarks.report";
    let rows: Vec<Vec<Vec<Para>>> = entries
        .iter()
        .filter(|e| custody(&e.action))
        .map(|e| vec![vec![vec![t(e.seq.to_string())]], vec![vec![t(when(&e.time))]], vec![vec![t(e.examiner.clone())]], vec![vec![bold(action_label(&e.action))]], vec![vec![t(describe(e, &cx.names))]]])
        .collect();
    d.push(Block::Table { head: ["#", "Time", "By", "Event", "Details"].map(String::from).to_vec(), widths: vec![6, 17, 11, 16, 50], rows });
    let mut other: BTreeMap<&str, usize> = BTreeMap::new();
    for e in entries.iter().filter(|e| !custody(&e.action)) {
        *other.entry(e.action.as_str()).or_default() += 1;
    }
    if !other.is_empty() {
        let list: Vec<String> = other.iter().map(|(a, n)| format!("{} {}", n, action_label(a).to_lowercase())).collect();
        d.push(Block::Small(vec![muted(format!(
            "Also in the log, not listed above: {}.{}",
            list.join(", "),
            if o.full_audit { " Appendix A lists every entry." } else { "" }
        ))]));
    }

    // 6 Methods and tools
    d.push(Block::H1("6 Methods and tools".into()));
    d.push(Block::Kv(vec![
        kv1("Software", vec![t(format!("Kokino FTK {} ({}) by {}, Apache License 2.0", kokino_core::TOOL_VERSION, kokino_core::TOOL_NAME, kokino_core::VENDOR))]),
        kv1("Report", vec![t(format!("Generated {} by {}", when(now), author))]),
    ]));
    let steps = [("evidence.hash", "Hashing"), ("evidence.analyze", "File system analysis"), ("evidence.carve", "Carving"), ("evidence.index", "Text index"), ("evidence.photos", "Picture analysis"), ("evidence.filehash", "Hash analysis")];
    let mut ran: BTreeMap<(usize, usize), &AuditEntry> = BTreeMap::new();
    for e in &entries {
        if let (Some(si), Some(ei)) = (steps.iter().position(|(a, _)| *a == e.action), e.detail["evidence"].as_str().and_then(|x| order.get(x))) {
            ran.insert((*ei, si), e);
        }
    }
    if !ran.is_empty() {
        d.push(Block::Table {
            head: ["Evidence", "Processing", "Last run", "By", "Kokino"].map(String::from).to_vec(),
            widths: vec![28, 24, 22, 14, 12],
            rows: ran
                .iter()
                .map(|((ei, si), e)| vec![vec![vec![t(evidence[*ei].name.clone())]], vec![vec![t(steps[*si].1)]], vec![vec![t(when(&e.time))]], vec![vec![t(e.examiner.clone())]], vec![vec![t(e.tool_version.clone())]]])
                .collect(),
        });
    }
    let used: Vec<usize> = (0..steps.len()).filter(|si| ran.keys().any(|(_, s)| s == si)).collect();
    let mut methods: Vec<Para> = vec![vec![bold("Read-only access. "), t("Evidence images (raw, split raw, VHD, E01) are opened for reading only and never written. Hex overlay edits, where made, are stored in the case and are not applied to the exhibits in this report.")]];
    let texts = [
        "MD5, SHA-1 and SHA-256 are computed in one pass over the logical image stream and compared with the hashes supplied at intake and those stored in the image.",
        "Partition tables (MBR, GPT) are read and each NTFS, FAT12/16/32 and exFAT volume is parsed by Kokino's own readers: live and deleted entries, paths, timestamps (for NTFS both $STANDARD_INFORMATION and $FILE_NAME), data streams and allocation. Anti-forensics indicators are computed from these records.",
        "Unallocated clusters and space outside the volumes are scanned for file signatures; recovered files are recorded by offset, length and hash, without copies.",
        "Text (UTF-8 and UTF-16) is extracted from file streams, documents, deleted files and unallocated space into a SQLite FTS5 index for keyword and pattern search.",
        "Pictures (JPEG, PNG, BMP) are checked for metadata (EXIF, XMP), editing software traces, JPEG quantization tables, double compression, EXIF thumbnail mismatch, data after the end of the image and least-significant-bit embedding.",
        "MD5, SHA-1 and SHA-256 are computed for every file with content (live, and deleted where readable) and looked up in hash sets: known-good lists such as the NIST NSRL and known-bad lists. The sets used are named in section 3 with the SHA-256 of their source files.",
    ];
    for si in used {
        methods.push(vec![bold(format!("{}. ", steps[si].1)), t(texts[si])]);
    }
    methods.push(vec![bold("Exhibits. "), t("When an item is bookmarked, Kokino records its location, metadata and the MD5 and SHA-256 of its content. For this report the content was read from the evidence again and hashed; pictures are rendered from the evidence bytes, and byte ranges are shown as a hex dump of the evidence.")]);
    methods.push(vec![bold("Time. "), t(format!("{} The evidence stores NTFS times as UTC (100 ns resolution) and exFAT times with their UTC offset; FAT and EXIF times are the device's own clock with no zone recorded, so they are given as stored, without an offset (FAT: 2 s resolution for modification times). Audit log times are taken from the workstation clock and stored as UTC.", zone_note(o.utc)))]);
    d.push(Block::Bullets(methods));

    // 7 Limitations
    d.push(Block::H1("7 Limitations".into()));
    let mut lim: Vec<Para> = vec![
        vec![t("Only bookmarked items are presented as exhibits. An item missing from this report was not necessarily absent from the evidence, nor left unexamined.")],
        vec![t("Timestamps can be changed by users and software and depend on the clock of the system that wrote them; they are reported as recorded.")],
    ];
    if !chain.ok {
        lim.push(vec![t(format!("The case audit log's hash chain is broken at entry {}. Entries from there on cannot be shown to be unaltered.", chain.broken_at.unwrap_or(0))).tone(Tone::Bad)]);
    }
    for (label, title, c) in &checks {
        match c {
            Check::Differs => lim.push(vec![t(format!("Exhibit {} ({}): the content read for this report does not match the hash taken when it was bookmarked. The evidence file or the evidence item it points to may have changed; verify the evidence hash.", label, title)).tone(Tone::Bad)]),
            Check::NotChecked(why) if !why.is_empty() => lim.push(vec![t(format!("Exhibit {} ({}) was not read again: {}.", label, title, why))]),
            _ => {}
        }
    }
    for rec in &evidence {
        if let Ok(l) = cx.load(&rec.id) {
            for e in &l.analysis.errors {
                lim.push(vec![t(format!("{}: {}", rec.name, e))]);
            }
        }
        let errs = rec.acquisition.as_ref().and_then(|a| a["read_errors"].as_array()).map(|a| a.len()).unwrap_or(0);
        if errs > 0 {
            lim.push(vec![t(format!("{}: the imaging tool recorded {} unreadable range(s); those bytes are not available in the image.", rec.name, errs))]);
        }
        let patches = case.patches(&rec.id).map(|p| p.len()).unwrap_or(0);
        if patches > 0 {
            lim.push(vec![t(format!("{}: {} hex overlay edit(s) are stored in the case. They are never written to the evidence and are not applied to anything in this report.", rec.name, patches))]);
        }
    }
    d.push(Block::Bullets(lim));
    if !cx.caveats.is_empty() {
        d.push(Block::P(vec![t("Caveats of the automated findings cited in the exhibits:")]));
        d.push(Block::Bullets(cx.caveats.iter().map(|(k, v)| vec![bold(format!("{}: ", k)), t(v.clone())]).collect()));
    }

    // 8 Sign-off
    d.push(Block::H1("8 Sign-off".into()));
    d.push(Block::P(vec![t(format!(
        "Report {} was generated by Kokino FTK on {}. The SHA-256 of this document is recorded in the case audit log (action report.case), where it can be checked against the copy handed over.",
        id,
        when(now)
    ))]));
    d.push(Block::Sign(vec![format!("Prepared by: {}", author), "Reviewed by:".into()]));

    if o.full_audit {
        d.push(Block::Break);
        d.push(Block::H1("Appendix A Audit log".into()));
        d.push(Block::Small(vec![muted(format!("All {} entries of the case audit log at the time of this report.", entries.len()))]));
        d.push(Block::Table {
            head: ["#", "Time", "By", "Action", "Details"].map(String::from).to_vec(),
            widths: vec![6, 17, 11, 16, 50],
            rows: entries.iter().map(|e| vec![vec![vec![t(e.seq.to_string())]], vec![vec![t(when(&e.time))]], vec![vec![t(e.examiner.clone())]], vec![vec![mono(e.action.clone())]], vec![vec![t(describe(e, &cx.names))]]]).collect(),
        });
    }
    Ok((Doc { id: id.to_string(), title, case_name: case.info.name.clone(), author, blocks: d }, marks.len()))
}

fn evidence_rows(cx: &mut Ctx, rec: &EvidenceRecord, marks: &[&Bookmark]) -> Vec<(String, Vec<Para>)> {
    let mut rows = vec![
        kv1("Evidence id", vec![mono(rec.id.clone())]),
        kv1("Format", vec![t(rec.format.clone())]),
        kv1("Size", vec![t(size(rec.size))]),
        kv1("Path at intake", vec![mono(rec.path.clone())]),
        kv1("Added", vec![t(when(&rec.added))]),
    ];
    if !rec.notes.trim().is_empty() {
        rows.push(kv1("Intake notes", vec![t(rec.notes.trim())]));
    }
    match &rec.hashes {
        Some(h) => {
            let mut v = hash_paras(h);
            if let Some(at) = &rec.hashed_at {
                v.push(vec![muted(format!("computed {}", when(at)))]);
            }
            rows.push(kv("Hashes", v));
        }
        None => rows.push(kv1("Hashes", vec![t("not computed yet").tone(Tone::Bad)])),
    }
    for (label, x) in [("Acquisition hash", &rec.expected), ("Hash stored in the image", &rec.embedded)] {
        if let Some(x) = x {
            let mut v = hash_paras(x);
            v.push(match &rec.hashes {
                Some(h) if hash_match(x, h) => vec![t("matches the computed hash").tone(Tone::Good)],
                Some(_) => vec![t("DOES NOT match the computed hash").tone(Tone::Bad)],
                None => vec![muted("not compared (no computed hash)")],
            });
            rows.push(kv(label, v));
        }
    }
    if let Some(acq) = &rec.acquisition {
        let mut v: Vec<Para> = vec![];
        if let Some(m) = acq["acquisition"].as_object() {
            for (k, x) in m {
                if let Some(s) = x.as_str().filter(|s| !s.is_empty()) {
                    v.push(vec![muted(format!("{}: ", k.replace('_', " "))), t(s)]);
                }
            }
        }
        for (k, label) in [("media_type", "media type"), ("media_size", "media size"), ("set_identifier", "set identifier")] {
            if let Some(s) = acq[k].as_str().map(str::to_string).or_else(|| acq[k].as_u64().map(|n| n.to_string())) {
                v.push(vec![muted(format!("{}: ", label)), t(s)]);
            }
        }
        if !v.is_empty() {
            rows.push(kv("Acquisition (from the image)", v));
        }
    }
    match cx.load(&rec.id) {
        Ok(l) => {
            let a = &l.analysis;
            let mut v = vec![vec![t(format!("{} with Kokino {} (schema {})", when(&a.analyzed_at), a.tool_version, a.schema))]];
            for f in &a.filesystems {
                v.push(vec![muted(format!("volume {}: ", f.volume.index)), t(format!("{} \"{}\", {} entries", f.volume.fs_label, f.info.label, f.files.len()))]);
            }
            rows.push(kv("Analysis", v));
        }
        Err(e) => rows.push(kv1("Analysis", vec![muted(e)])),
    }
    if let Some(hs) = cx.st.hash_status(&cx.case.info.id, &rec.id) {
        use kokino_analysis::hashsets::SetKind;
        let fh = &hs.fh;
        let mut v = vec![vec![t(format!(
            "{} files hashed ({}), {} not readable; {} in known-good sets, {} in known-bad sets",
            fh.files.len(),
            size(fh.bytes),
            fh.errors(),
            fh.count(SetKind::Known),
            fh.count(SetKind::Notable)
        ))]];
        for s in &fh.sets {
            v.push(vec![muted(format!("{}: ", s.kind.label())), t(s.name.clone()), muted(format!(" from {}, SHA-256 ", s.source)), mono(s.source_sha256.clone())]);
        }
        rows.push(kv("Hash analysis", v));
    }
    let n = marks.iter().filter(|b| b.evidence == rec.id).count();
    rows.push(kv1("Exhibits", vec![t(n.to_string())]));
    rows
}

/// Reads `len` bytes at an image offset.
fn read_range(rec: &EvidenceRecord, offset: u64, len: u64) -> anyhow::Result<Vec<u8>> {
    let ev = kokino_image::Evidence::open(&rec.path)?;
    let mut buf = vec![0u8; len as usize];
    let n = kokino_image::read_at(&mut ev.reader()?, offset, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn is_picture(d: &[u8]) -> bool {
    d.starts_with(&[0xFF, 0xD8, 0xFF]) || d.starts_with(b"\x89PNG") || d.starts_with(b"BM")
}

fn exhibit(cx: &mut Ctx, b: &Bookmark, label: &str) -> (Vec<Block>, Check) {
    let mut out = vec![Block::H2(format!("Exhibit {}: {}", label, b.title))];
    let rec = cx.case.evidence_by_id(&b.evidence).ok();
    let mut rows = vec![kv1("Type", vec![t(kind_label(b))]), kv1("Evidence", vec![t(cx.name(&b.evidence)), muted(format!("  ({})", b.evidence))])];
    let mut findings: Vec<Para> = vec![];
    let mut content: Option<Vec<u8>> = None;
    let mut check = Check::NotChecked(String::new());
    let mut extra: Vec<Block> = vec![];
    let mut hash_sets = None;

    match b.kind.as_str() {
        "file" => {
            let mut loc = vec![vec![mono(b.path.clone())]];
            match (cx.load(&b.evidence), b.fi, b.record) {
                (Ok(l), Some(fi), Some(rec_no)) => {
                    let f = l.analysis.filesystems.get(fi);
                    let row = f.and_then(|f| f.files.iter().find(|r| r.e.record == rec_no));
                    if let Some(f) = f {
                        let ntfs = f.volume.fs == kokino_image::FsKind::Ntfs;
                        loc.push(vec![muted(format!("{} volume {}, {} {}", f.volume.fs_label, f.volume.index, if ntfs { "MFT record" } else { "directory entry" }, rec_no))]);
                        if let Some(hs) = cx.st.hash_status(&cx.case.info.id, &b.evidence) {
                            if let Some(&i) = hs.by_file.get(&(fi, rec_no)) {
                                let hits: Vec<(String, kokino_analysis::hashsets::SetKind, String)> =
                                    hs.hits.get(&i).map(|v| v.iter().filter_map(|(s, a)| hs.fh.sets.get(*s).map(|x| (x.name.clone(), x.kind, match a.as_str() { "md5" => "MD5", "sha1" => "SHA-1", _ => "SHA-256" }.to_string()))).collect()).unwrap_or_default();
                                for (name, kind, algo) in &hits {
                                    if *kind == kokino_analysis::hashsets::SetKind::Notable {
                                        findings.push(vec![bold("In a known-bad hash set: "), t(format!("{} (matched by {})", name, algo)), muted(" (hash analysis)")]);
                                        cx.caveats.insert("Hash set match".into(), "A match means the content is identical to a file in that list; it does not show how the file got there or whether it was opened. For deleted files the content read is what their clusters hold now.".into());
                                    }
                                }
                                if !hits.is_empty() {
                                    hash_sets = Some(kv1("Hash sets", vec![t(hits.iter().map(|(n, k, a)| format!("{} ({}, {})", n, k.label(), a)).collect::<Vec<_>>().join("; "))]));
                                }
                            }
                        }
                        for ind in f.indicators.iter().filter(|i| i.records.contains(&rec_no)) {
                            findings.push(vec![bold(format!("{}: ", ind.title)), t(ind.explanation.clone()), muted(format!(" (anti-forensics indicator, {})", ind.category))]);
                            cx.caveats.insert(ind.title.clone(), ind.caveat.clone());
                        }
                    }
                    match row {
                        Some(r) => {
                            let mut times: Vec<Para> = vec![];
                            // FAT12/16/32 hold the device's clock: never converted.
                            let device_clock = f.map(|f| matches!(f.volume.fs, kokino_image::FsKind::Fat12 | kokino_image::FsKind::Fat16 | kokino_image::FsKind::Fat32)).unwrap_or(false);
                            let names = if f.map(|f| f.volume.fs == kokino_image::FsKind::Ntfs).unwrap_or(false) {
                                ["created", "modified", "accessed", "MFT changed"]
                            } else {
                                ["created", "modified", "accessed", "changed"]
                            };
                            for (src, tm) in [("", r.e.si), ("$FILE_NAME ", r.e.fname)] {
                                if let Some(tm) = tm {
                                    for (k, v) in names.iter().zip([tm.created, tm.modified, tm.accessed, tm.mft_modified]) {
                                        if v != 0 {
                                            let iso = filetime_to_iso(v);
                                            times.push(vec![muted(format!("{}{}: ", src, k)), mono(if device_clock { human_as_stored(&iso) + " (device clock)" } else { human_full(&iso) })]);
                                        }
                                    }
                                }
                            }
                            if !times.is_empty() {
                                rows.push(kv("Timestamps", times));
                            }
                            rows.push(kv1("Size", vec![t(size(r.e.size))]));
                            if r.e.deleted {
                                rows.push(kv1("State", vec![t("deleted").b()]));
                            }
                            if r.e.is_dir {
                                check = Check::NotChecked("a directory has no content to hash".into());
                            } else if r.e.size > MAX_RECHECK {
                                check = Check::NotChecked(format!("larger than {}", size(MAX_RECHECK)));
                            } else {
                                match l.read_file(fi, &r.e, "", 0, r.e.size as usize) {
                                    Ok(data) => content = Some(data),
                                    Err(e) => check = Check::NotChecked(format!("content not readable: {:#}", e)),
                                }
                            }
                        }
                        None => check = Check::NotChecked("the entry is not in the current analysis of the evidence".into()),
                    }
                }
                (Err(e), _, _) => check = Check::NotChecked(e),
                _ => {}
            }
            rows.insert(2, kv("Location", loc));
        }
        "carved" => {
            rows.push(kv("Location", vec![vec![t(b.path.clone())], vec![muted(format!("image offset {}, {} bytes", b.offset.unwrap_or(0), b.len.unwrap_or(0)))]]));
            rows.push(kv1("Size", vec![t(size(b.len.unwrap_or(0)))]));
            match (&rec, b.offset, b.len) {
                (Some(rec), Some(off), Some(len)) if len <= MAX_RECHECK => match read_range(rec, off, len) {
                    Ok(d) => content = Some(d),
                    Err(e) => check = Check::NotChecked(format!("{:#}", e)),
                },
                (_, _, Some(len)) if len > MAX_RECHECK => check = Check::NotChecked(format!("larger than {}", size(MAX_RECHECK))),
                _ => check = Check::NotChecked("the evidence record or carved range is missing".into()),
            }
        }
        "hit" | "offset" => {
            let mut loc = vec![];
            let mut range_hash = None;
            if !b.path.is_empty() {
                loc.push(vec![t(b.path.clone())]);
            }
            match (b.offset, &rec) {
                (Some(off), Some(rec)) => {
                    let len = b.len.unwrap_or(1).max(1);
                    loc.push(vec![muted("image offset "), mono(format!("{} (0x{:X})", off, off)), muted(format!(", {} byte(s)", len))]);
                    if len <= MAX_RANGE_HASH {
                        match read_range(rec, off, len) {
                            Ok(data) if data.len() as u64 == len => {
                                range_hash = Some(kv1("SHA-256 of the bytes", vec![mono(sha256_hex(&data))]));
                                check = Check::Computed;
                            }
                            Ok(_) => check = Check::NotChecked("the range runs past the end of the image".into()),
                            Err(e) => check = Check::NotChecked(format!("{:#}", e)),
                        }
                    }
                    // A hex dump around the range, at most 256 bytes.
                    let start = if b.kind == "hit" { off.saturating_sub(32) & !15 } else { off & !15 };
                    let end = ((off + len + if b.kind == "hit" { 32 } else { 0 }).div_ceil(16) * 16).min(start + 256);
                    if let Ok(data) = read_range(rec, start, end - start) {
                        extra.push(Block::Pre(hex_dump(&data, start)));
                        extra.push(Block::Small(vec![muted(format!(
                            "Evidence bytes at offsets {} to {}; the bookmarked bytes are {} to {}{}.",
                            start,
                            start + data.len() as u64 - 1,
                            off,
                            off + len - 1,
                            if off + len > end { " (shown in part)" } else { "" }
                        ))]));
                    }
                }
                _ => check = Check::NotChecked("the hit is inside a carved or extracted file, not at an image offset".into()),
            }
            if !loc.is_empty() {
                rows.push(kv("Location", loc));
            }
            rows.extend(range_hash);
        }
        _ => {
            rows.push(kv1("Source", vec![t(b.path.clone())]));
            check = Check::NotChecked(String::new());
        }
    }
    if !b.time.is_empty() && b.kind != "file" {
        rows.push(kv1("Time", vec![mono(human_full(&b.time))]));
    }
    if !b.detail.is_empty() && !(b.region.is_some() && b.detail.ends_with(" view")) {
        rows.push(kv1("Detail", vec![t(b.detail.clone())]));
    }
    if !b.sha256.is_empty() {
        rows.push(kv("Hashes when bookmarked", vec![vec![muted("MD5 "), mono(b.md5.clone())], vec![muted("SHA-256 "), mono(b.sha256.clone())]]));
    }
    if let Some(data) = &content {
        let (h, _) = hash_reader(&data[..], |_| true).unwrap_or_default();
        check = if b.sha256.is_empty() { Check::Computed } else if h.sha256.eq_ignore_ascii_case(&b.sha256) { Check::Match } else { Check::Differs };
        rows.push(kv(
            "Re-verified",
            match check {
                Check::Match => vec![vec![t("SHA-256 computed from the evidence for this report matches").tone(Tone::Good)]],
                Check::Differs => vec![vec![t("DIFFERS: the content read for this report hashes to").tone(Tone::Bad)], vec![mono(h.sha256.clone())]],
                _ => vec![vec![muted("SHA-256 now "), mono(h.sha256.clone())]],
            },
        ));
    } else if let Check::NotChecked(why) = &check {
        if !why.is_empty() {
            rows.push(kv1("Re-verified", vec![muted(format!("not checked: {}", why))]));
        }
    }

    // Picture analysis findings recorded for this item.
    let (fi, rec_no, carved) = (b.fi, b.record, b.carved);
    let kind = b.kind.clone();
    if let Some(scan) = cx.photos(&b.evidence) {
        let row = scan.images.iter().find(|i| if kind == "carved" { i.carved.is_some() && i.carved == carved } else { i.source == "file" && i.fi == fi && i.record == rec_no }).cloned();
        if let Some(i) = row {
            let mut facts = vec![format!("{} {}x{}", i.format.to_uppercase(), i.width, i.height)];
            if !i.make.is_empty() || !i.model.is_empty() {
                facts.push(format!("{} {}", i.make, i.model).trim().to_string());
            }
            if !i.taken.is_empty() {
                facts.push(format!("taken {}", i.taken));
            }
            if let Some(q) = i.quality {
                facts.push(format!("JPEG quality about {}", q));
            }
            if let Some((la, lo)) = i.gps {
                facts.push(format!("GPS {:.6}, {:.6}", la, lo));
            }
            if !i.software.is_empty() {
                facts.push(format!("software: {}", i.software));
            }
            rows.push(kv1("Picture", vec![t(facts.join("; "))]));
            for f in &i.findings {
                if let Some(r) = photo::rule(&f.id) {
                    findings.push(vec![bold(format!("{}: ", r.title)), t(f.detail.clone()), muted(if r.flag { " (picture analysis)" } else { " (picture analysis, information)" })]);
                    cx.caveats.insert(r.title.to_string(), r.caveat.to_string());
                }
            }
        }
    }
    rows.extend(hash_sets);
    if let Some([x, y, w, h]) = b.region {
        rows.push(kv1("Region", vec![t(format!("{},{} {}x{} px", x, y, w, h)), muted(if b.view.is_empty() { String::new() } else { format!(", marked in the {} view", b.view) })]));
    }
    if !b.tags.is_empty() {
        rows.push(kv1("Tags", vec![t(b.tags.join(", "))]));
    }
    if !b.note.trim().is_empty() {
        rows.push(kv("Examiner's note", b.note.trim().lines().map(|l| vec![t(l)]).collect()));
    }
    let mut by = vec![vec![t(format!("{} by {}", when(&b.created_at), b.created_by))]];
    if b.updated_at != b.created_at {
        by.push(vec![muted(format!("last changed {} by {}", when(&b.updated_at), b.updated_by))]);
    }
    rows.push(kv("Bookmarked", by));
    out.push(Block::Kv(rows));
    if !findings.is_empty() {
        out.push(Block::P(vec![bold("Automated findings on this item"), muted(" (caveats in section 7)")]));
        out.push(Block::Bullets(findings));
    }
    if let Some(data) = content.as_deref().filter(|d| is_picture(d) && d.len() as u64 <= photo::MAX_BYTES) {
        out.extend(pictures(cx, data, b, label));
    }
    out.extend(extra);
    (out, check)
}

fn hex_dump(d: &[u8], base: u64) -> String {
    let mut s = String::new();
    for (i, row) in d.chunks(16).enumerate() {
        s.push_str(&format!("{:010X}  ", base + i as u64 * 16));
        for k in 0..16 {
            match row.get(k) {
                Some(b) => s.push_str(&format!("{:02X} ", b)),
                None => s.push_str("   "),
            }
            if k == 7 {
                s.push(' ');
            }
        }
        s.push(' ');
        s.extend(row.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        s.push('\n');
    }
    s.pop();
    s
}

// ---------------------------------------------------------------- pictures

/// Box-filter resize (averages when shrinking, repeats pixels when enlarging).
fn resize(img: &Rgb, nw: usize, nh: usize) -> Rgb {
    let mut px = Vec::with_capacity(nw * nh * 3);
    for y in 0..nh {
        let (y0, y1) = (y * img.h / nh, ((y + 1) * img.h / nh).max(y * img.h / nh + 1).min(img.h));
        for x in 0..nw {
            let (x0, x1) = (x * img.w / nw, ((x + 1) * img.w / nw).max(x * img.w / nw + 1).min(img.w));
            let mut acc = [0u32; 3];
            for sy in y0..y1 {
                for sx in x0..x1 {
                    let o = (sy * img.w + sx) * 3;
                    for c in 0..3 {
                        acc[c] += img.px[o + c] as u32;
                    }
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            px.extend(acc.iter().map(|a| (a / n) as u8));
        }
    }
    Rgb { w: nw, h: nh, px }
}

fn outline(img: &mut Rgb, x0: usize, y0: usize, x1: usize, y1: usize) {
    let (x1, y1) = (x1.min(img.w.saturating_sub(1)), y1.min(img.h.saturating_sub(1)));
    let mut set = |x: usize, y: usize| {
        let o = (y * img.w + x) * 3;
        img.px[o..o + 3].copy_from_slice(&[230, 0, 0]);
    };
    for k in 0..2 {
        for x in x0..=x1 {
            set(x, (y0 + k).min(y1));
            set(x, y1.saturating_sub(k).max(y0));
        }
        for y in y0..=y1 {
            set((x0 + k).min(x1), y);
            set(x1.saturating_sub(k).max(x0), y);
        }
    }
}

/// The whole picture (region outlined) and, for a region, the region enlarged.
fn pictures(cx: &mut Ctx, data: &[u8], b: &Bookmark, label: &str) -> Vec<Block> {
    let img = match photo::decode_rgb(data) {
        Ok(i) if i.w > 0 && i.h > 0 => i,
        Ok(_) => return vec![],
        Err(e) => return vec![Block::Small(vec![muted(format!("The picture is not shown here ({:#}); its hashes above identify it.", e))])],
    };
    let mut out = vec![];
    let s = (640.0 / img.w as f64).min(420.0 / img.h as f64).min(1.0);
    let (nw, nh) = (((img.w as f64 * s).round() as usize).max(1), ((img.h as f64 * s).round() as usize).max(1));
    let mut whole = if s < 1.0 { resize(&img, nw, nh) } else { img.clone() };
    let region = b.region.map(|[x, y, w, h]| {
        let (x, y) = ((x as usize).min(img.w - 1), (y as usize).min(img.h - 1));
        (x, y, (w as usize).clamp(1, img.w - x), (h as usize).clamp(1, img.h - y))
    });
    if let Some((x, y, w, h)) = region {
        let f = |v: usize, n: usize, d: usize| v * n / d;
        let (ww, wh) = (whole.w, whole.h);
        outline(&mut whole, f(x, ww, img.w), f(y, wh, img.h), f(x + w, ww, img.w).saturating_sub(1), f(y + h, wh, img.h).saturating_sub(1));
    }
    cx.figures += 1;
    out.push(Block::Img {
        png: png(&whole),
        w: whole.w as u32,
        h: whole.h as u32,
        pixelated: false,
        caption: format!("Figure {}. Exhibit {}, the whole picture ({}x{} px{}){}.", cx.figures, label, img.w, img.h, if s < 1.0 { ", reduced" } else { "" }, if region.is_some() { ", the bookmarked region outlined in red" } else { "" }),
    });
    if let Some((x, y, w, h)) = region {
        let mut px = Vec::with_capacity(w * h * 3);
        for row in y..y + h {
            px.extend_from_slice(&img.px[(row * img.w + x) * 3..(row * img.w + x + w) * 3]);
        }
        let crop = Rgb { w, h, px };
        let s = (640.0 / w as f64).min(420.0 / h as f64);
        let k = if s >= 1.0 { s.floor().min(8.0) } else { s };
        let (cw, ch) = (((w as f64 * k).round() as usize).max(1), ((h as f64 * k).round() as usize).max(1));
        let shown = if (cw, ch) == (w, h) { crop } else { resize(&crop, cw, ch) };
        cx.figures += 1;
        out.push(Block::Img {
            png: png(&shown),
            w: shown.w as u32,
            h: shown.h as u32,
            pixelated: k > 1.0,
            caption: format!(
                "Figure {}. Exhibit {}, region {},{} {}x{} px{}. Original pixels from the evidence{}.",
                cx.figures,
                label,
                x,
                y,
                w,
                h,
                if k > 1.0 { format!(", enlarged {}x", k) } else if k < 1.0 { ", reduced".to_string() } else { String::new() },
                if b.view.is_empty() { String::new() } else { format!("; the region was marked in the {} view", b.view) }
            ),
        });
    }
    out
}

fn png(img: &Rgb) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, ty: &[u8], data: &[u8]) {
        out.extend((data.len() as u32).to_be_bytes());
        let mut c = flate2::Crc::new();
        c.update(ty);
        c.update(data);
        out.extend(ty);
        out.extend(data);
        out.extend(c.sum().to_be_bytes());
    }
    let mut raw = Vec::with_capacity((img.w * 3 + 1) * img.h);
    for row in img.px.chunks_exact(img.w * 3) {
        raw.push(0);
        raw.extend_from_slice(row);
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&raw).expect("in-memory write");
    let idat = z.finish().expect("in-memory write");
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = vec![];
    ihdr.extend((img.w as u32).to_be_bytes());
    ihdr.extend((img.h as u32).to_be_bytes());
    ihdr.extend([8, 2, 0, 0, 0]);
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &idat);
    chunk(&mut out, b"IEND", &[]);
    out
}

// ---------------------------------------------------------------- audit wording

fn action_label(a: &str) -> String {
    match a {
        "case.create" => "Case created",
        "case.members" => "Assignments changed",
        "case.update" => "Case details changed",
        "case.delete" => "Case deleted",
        "case.restore" => "Case restored",
        "case.member_removed" => "Member removed",
        "evidence.add" => "Evidence added",
        "evidence.hash" => "Evidence hashed",
        "evidence.analyze" => "Analyzed",
        "evidence.carve" => "Carved",
        "evidence.index" => "Text indexed",
        "evidence.photos" => "Pictures analyzed",
        "evidence.filehash" => "Hash analysis",
        "evidence.size_changed" => "Evidence size changed",
        "evidence.path_moved" => "Evidence path updated",
        "file.export" => "File exported",
        "carved.export" => "Carved file exported",
        "range.export" => "Bytes exported",
        "overlay.set" => "Hex overlay edit",
        "overlay.remove" => "Hex overlay removed",
        "report.generate" => "Evidence report",
        "report.case" => "Case report",
        "bookmarks.report" => "Bookmark list",
        "bookmark.add" => "Bookmark added",
        "bookmark.update" => "Bookmark changed",
        "bookmark.delete" => "Bookmark removed",
        "search.text" => "Text search",
        other => return other.to_string(),
    }
    .to_string()
}

/// One line of plain words for an audit entry.
fn describe(e: &AuditEntry, names: &HashMap<String, String>) -> String {
    let d = &e.detail;
    let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
    let ev = || d["evidence"].as_str().map(|id| names.get(id).cloned().unwrap_or_else(|| id.to_string())).unwrap_or_default();
    let yn = |v: &Value| match v.as_bool() {
        Some(true) => "matches",
        Some(false) => "DOES NOT match",
        None => "n/a",
    };
    let text = match e.action.as_str() {
        "case.create" => format!("Case \"{}\" created; lead examiner {}", s("name"), s("examiner")),
        "case.update" => {
            let ch = |k: &str, label: &str| d.get(k).map(|v| format!("{} changed from \"{}\" to \"{}\"", label, v["before"].as_str().unwrap_or(""), v["after"].as_str().unwrap_or("")));
            let mut parts: Vec<String> = [ch("name", "name"), ch("description", "description"), ch("examiner", "lead examiner")].into_iter().flatten().collect();
            if let Some(m) = d["member_added"].as_str() {
                parts.push(format!("{} added as examiner", m));
            }
            parts.join("; ")
        }
        "evidence.add" => format!("{} ({}, {}) from {}", s("name"), s("format"), size(d["size"].as_u64().unwrap_or(0)), s("path")),
        "evidence.hash" => format!(
            "{}: {} hashed; MD5 {}, SHA-256 {}; acquisition hash: {}; hash in image: {}",
            ev(),
            size(d["bytes"].as_u64().unwrap_or(0)),
            d["hashes"]["md5"].as_str().unwrap_or(""),
            d["hashes"]["sha256"].as_str().unwrap_or(""),
            yn(&d["matches_expected"]),
            yn(&d["matches_embedded"])
        ),
        "evidence.index" => {
            let st = &d["stats"];
            format!(
                "{}: text of {} file streams ({} deleted), {} documents and {} of unallocated space indexed",
                ev(),
                st["streams"].as_u64().unwrap_or(0),
                st["deleted_streams"].as_u64().unwrap_or(0),
                st["documents"].as_u64().unwrap_or(0),
                size(st["unalloc_bytes"].as_u64().unwrap_or(0))
            )
        }
        "evidence.filehash" => {
            let sets: Vec<String> = d["sets"].as_array().map(|a| a.iter().map(|s| format!("{} ({})", s["name"].as_str().unwrap_or(""), s["kind"].as_str().unwrap_or(""))).collect()).unwrap_or_default();
            format!(
                "{}: {} files ({}); {} known good, {} known bad, {} not readable; sets: {}",
                ev(),
                d["files"],
                if d["hashed"] == "now" { "hashed" } else { "stored hashes checked again" },
                d["known"],
                d["notable"],
                d["unreadable"],
                if sets.is_empty() { "none".to_string() } else { sets.join(", ") }
            )
        }
        "evidence.analyze" => {
            let errs = d["errors"].as_array().map(|a| a.len()).unwrap_or(0);
            format!("{}: {} file system(s) analyzed (schema {}){}", ev(), d["filesystems"].as_array().map(|a| a.len()).unwrap_or(0), d["schema"], if errs > 0 { format!(", {} error(s), see section 7", errs) } else { String::new() })
        }
        "report.case" => {
            let files: Vec<String> = d["files"].as_array().map(|a| a.iter().map(|f| format!("{} SHA-256 {}", f["name"].as_str().unwrap_or(""), f["sha256"].as_str().unwrap_or(""))).collect()).unwrap_or_default();
            format!("Report {} ({} exhibits): {}", s("report"), d["exhibits"], files.join("; "))
        }
        _ => flatten(d, names, ""),
    };
    if text.chars().count() > 600 {
        text.chars().take(600).collect::<String>() + "..."
    } else {
        text
    }
}

fn flatten(v: &Value, names: &HashMap<String, String>, prefix: &str) -> String {
    let Some(m) = v.as_object() else { return v.to_string() };
    let mut parts = vec![];
    for (k, x) in m {
        let key = format!("{}{}", prefix, k.replace('_', " "));
        let val = match x {
            Value::Null => continue,
            Value::String(s) if k == "evidence" => names.get(s).cloned().unwrap_or_else(|| s.clone()),
            Value::String(s) if s.is_empty() => continue,
            Value::String(s) => s.clone(),
            Value::Object(_) => {
                let inner = flatten(x, names, &format!("{} ", key));
                if !inner.is_empty() {
                    parts.push(inner);
                }
                continue;
            }
            Value::Array(a) if a.is_empty() => continue,
            Value::Array(a) if a.len() <= 6 && a.iter().all(|y| !y.is_object() && !y.is_array()) => a.iter().map(|y| y.as_str().map(str::to_string).unwrap_or_else(|| y.to_string())).collect::<Vec<_>>().join(", "),
            Value::Array(a) => format!("{} items", a.len()),
            other => other.to_string(),
        };
        parts.push(format!("{}: {}", key, val));
    }
    parts.join("; ")
}

// ---------------------------------------------------------------- HTML

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn runs_html(p: &Para) -> String {
    let mut s = String::new();
    for r in p {
        let mut x = esc(&r.t).replace('\n', "<br>");
        if r.mono {
            x = format!("<code>{}</code>", x);
        }
        if r.b {
            x = format!("<b>{}</b>", x);
        }
        match r.tone {
            Tone::Muted => x = format!("<span class=muted>{}</span>", x),
            Tone::Good => x = format!("<span class=good>{}</span>", x),
            Tone::Bad => x = format!("<span class=bad>{}</span>", x),
            Tone::Normal => {}
        }
        s.push_str(&x);
    }
    s
}

fn cell_html(c: &[Para]) -> String {
    c.iter().map(runs_html).collect::<Vec<_>>().join("<br>")
}

fn render_html(d: &Doc) -> String {
    let mut h = format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>{} - {}</title><style>{}</style></head><body>",
        esc(&d.title),
        esc(&d.case_name),
        CSS.replace("@@ID@@", &d.id)
    );
    h.push_str("<p class=noprint>To make a PDF, print this page (Ctrl+P) and choose Save as PDF. Page numbers and the report id are added to every printed page.</p>");
    for b in &d.blocks {
        match b {
            Block::Title { title, sub } => h.push_str(&format!("<header class=cover><div class=brand>Kokino FTK &middot; {}</div><h1>{}</h1><p class=sub>{}</p></header>", esc(kokino_core::VENDOR), esc(title), esc(sub))),
            Block::H1(s) => h.push_str(&format!("<h2>{}</h2>", esc(s))),
            Block::H2(s) => h.push_str(&format!("<h3>{}</h3>", esc(s))),
            Block::P(p) => h.push_str(&format!("<p>{}</p>", runs_html(p))),
            Block::Small(p) => h.push_str(&format!("<p class=small>{}</p>", runs_html(p))),
            Block::Kv(rows) => {
                h.push_str("<table class=kv>");
                for (k, v) in rows {
                    h.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", esc(k), cell_html(v)));
                }
                h.push_str("</table>");
            }
            Block::Table { head, widths, rows } => {
                h.push_str("<table><colgroup>");
                for w in widths {
                    h.push_str(&format!("<col style=\"width:{}%\">", w));
                }
                h.push_str("</colgroup><thead><tr>");
                for x in head {
                    h.push_str(&format!("<th>{}</th>", esc(x)));
                }
                h.push_str("</tr></thead><tbody>");
                for r in rows {
                    h.push_str("<tr>");
                    for c in r {
                        h.push_str(&format!("<td>{}</td>", cell_html(c)));
                    }
                    h.push_str("</tr>");
                }
                h.push_str("</tbody></table>");
            }
            Block::Bullets(items) => {
                h.push_str("<ul>");
                for p in items {
                    h.push_str(&format!("<li>{}</li>", runs_html(p)));
                }
                h.push_str("</ul>");
            }
            Block::Pre(s) => h.push_str(&format!("<pre>{}</pre>", esc(s))),
            Block::Img { png, w, h: ht, pixelated, caption } => h.push_str(&format!(
                "<figure><img src=\"data:image/png;base64,{}\" width={} height={} alt=\"\"{}><figcaption>{}</figcaption></figure>",
                photo::b64(png),
                w,
                ht,
                if *pixelated { " class=px" } else { "" },
                esc(caption)
            )),
            Block::Break => h.push_str("<div class=pb></div>"),
            Block::Sign(labels) => {
                h.push_str("<table class=sign>");
                for l in labels {
                    h.push_str(&format!("<tr><th>{}</th><td><div class=line></div>Signature</td><td><div class=line></div>Date</td></tr>", esc(l)));
                }
                h.push_str("</table>");
            }
        }
    }
    h.push_str(&format!("<footer class=end>Kokino FTK report {} &middot; {} &middot; prepared by {}</footer></body></html>", esc(&d.id), esc(&d.case_name), esc(&d.author)));
    h
}

const CSS: &str = "@page{size:A4;margin:18mm 16mm 20mm;@bottom-left{content:\"Kokino FTK report @@ID@@\";font:8pt sans-serif;color:#666}@bottom-right{content:\"Page \" counter(page) \" of \" counter(pages);font:8pt sans-serif;color:#666}}\
body{font:10.5pt/1.45 \"Segoe UI\",system-ui,sans-serif;color:#1d1d1f;background:#fff;max-width:900px;margin:32px auto;padding:0 16px}\
.cover{border-bottom:3px solid #24425c;margin-bottom:14px;padding-bottom:6px}.brand{font-size:9pt;color:#24425c;letter-spacing:.06em;text-transform:uppercase}\
.cover h1{font-size:22pt;margin:6px 0 2px;color:#24425c}.sub{font-size:13pt;margin:0 0 8px;color:#444}\
h2{font-size:14.5pt;color:#24425c;border-bottom:1.5px solid #24425c;margin:28px 0 8px;padding-bottom:2px;break-after:avoid}\
h3{font-size:11.5pt;margin:20px 0 6px;break-after:avoid}\
table{border-collapse:collapse;width:100%;margin:6px 0 14px;font-size:9.5pt;table-layout:fixed}td,th{border:1px solid #c8c8c8;padding:3px 7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}\
th{background:#f2f2f4}table.kv th{width:25%;background:#f7f7f9;font-weight:600}tr{break-inside:avoid}\
code{font:8.6pt Consolas,ui-monospace,monospace;overflow-wrap:anywhere}\
pre{font:8.2pt/1.35 Consolas,ui-monospace,monospace;background:#f6f6f8;border:1px solid #ddd;padding:6px 8px;overflow-x:auto;break-inside:avoid}\
.muted{color:#666}.good{color:#1b7a3a;font-weight:600}.bad{color:#b3261e;font-weight:600}.small{font-size:9pt}\
figure{margin:8px 0 14px;break-inside:avoid}figure img{max-width:100%;height:auto;border:1px solid #bbb}img.px{image-rendering:pixelated}figcaption{font-size:9pt;color:#555;margin-top:3px}\
ul{padding-left:20px}li{margin:3px 0}.pb{break-before:page}\
table.sign td,table.sign th{border:none;background:none;padding:26px 12px 4px 0;vertical-align:bottom}table.sign th{width:34%}.line{border-bottom:1px solid #000;height:24px;margin-bottom:2px}table.sign td{font-size:8.5pt;color:#666}\
.end{margin-top:30px;border-top:1px solid #ccc;padding-top:6px;font-size:8.5pt;color:#666}\
.noprint{background:#eef3f8;border:1px solid #c9d8e6;padding:6px 10px;font-size:9.5pt}\
@media print{.noprint{display:none}body{margin:0;max-width:none;padding:0}.end{display:none}}";

// ---------------------------------------------------------------- Word (.docx)

const W_NS: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const R_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
/// Text width of an A4 page with 2 cm margins, in twentieths of a point.
const TEXT_TWIPS: u32 = 11906 - 2 * 1134;

/// XML text: escaped, with characters XML 1.0 forbids replaced.
fn xesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\t' | '\n' | '\r' => o.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => o.push('?'),
            c => o.push(c),
        }
    }
    o
}

fn runs_xml(p: &Para) -> String {
    let mut s = String::new();
    for r in p {
        let mut pr = String::new();
        if r.mono {
            pr.push_str("<w:rStyle w:val=\"Code\"/>");
        }
        if r.b {
            pr.push_str("<w:b/>");
        }
        match r.tone {
            Tone::Muted => pr.push_str("<w:color w:val=\"666666\"/>"),
            Tone::Good => pr.push_str("<w:b/><w:color w:val=\"1B7A3A\"/>".trim_start_matches(if r.b { "<w:b/>" } else { "" })),
            Tone::Bad => pr.push_str("<w:b/><w:color w:val=\"B3261E\"/>".trim_start_matches(if r.b { "<w:b/>" } else { "" })),
            Tone::Normal => {}
        }
        s.push_str("<w:r>");
        if !pr.is_empty() {
            s.push_str(&format!("<w:rPr>{}</w:rPr>", pr));
        }
        for (i, line) in r.t.split('\n').enumerate() {
            if i > 0 {
                s.push_str("<w:br/>");
            }
            s.push_str(&format!("<w:t xml:space=\"preserve\">{}</w:t>", xesc(line)));
        }
        s.push_str("</w:r>");
    }
    s
}

struct Docx {
    body: String,
    media: Vec<Vec<u8>>,
}

impl Docx {
    fn p(&mut self, style: &str, runs: &str) {
        if style.is_empty() {
            self.body.push_str(&format!("<w:p>{}</w:p>", runs));
        } else {
            self.body.push_str(&format!("<w:p><w:pPr><w:pStyle w:val=\"{}\"/></w:pPr>{}</w:p>", style, runs));
        }
    }

    fn cell(&mut self, twips: u32, fill: Option<&str>, paras: &[Para], bold_all: bool) {
        self.body.push_str(&format!("<w:tc><w:tcPr><w:tcW w:w=\"{}\" w:type=\"dxa\"/>", twips));
        if let Some(f) = fill {
            self.body.push_str(&format!("<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"{}\"/>", f));
        }
        self.body.push_str("</w:tcPr>");
        if paras.is_empty() {
            self.body.push_str("<w:p><w:pPr><w:pStyle w:val=\"Cell\"/></w:pPr></w:p>");
        }
        for p in paras {
            let p: Para = if bold_all { p.iter().cloned().map(Run::b).collect() } else { p.clone() };
            self.p("Cell", &runs_xml(&p));
        }
        self.body.push_str("</w:tc>");
    }

    fn table(&mut self, style: &str, head: Option<&[String]>, widths: &[u32], rows: &[Vec<Vec<Para>>], first_col: bool) {
        let total: u32 = widths.iter().sum::<u32>().max(1);
        let tw: Vec<u32> = widths.iter().map(|w| TEXT_TWIPS * w / total).collect();
        self.body.push_str(&format!("<w:tbl><w:tblPr><w:tblStyle w:val=\"{}\"/><w:tblW w:w=\"{}\" w:type=\"dxa\"/><w:tblLayout w:type=\"fixed\"/></w:tblPr><w:tblGrid>", style, TEXT_TWIPS));
        for w in &tw {
            self.body.push_str(&format!("<w:gridCol w:w=\"{}\"/>", w));
        }
        self.body.push_str("</w:tblGrid>");
        if let Some(head) = head {
            self.body.push_str("<w:tr><w:trPr><w:tblHeader/></w:trPr>");
            for (i, x) in head.iter().enumerate() {
                self.cell(tw[i], Some("F2F2F4"), &[vec![bold(x.clone())]], false);
            }
            self.body.push_str("</w:tr>");
        }
        for r in rows {
            self.body.push_str("<w:tr><w:trPr><w:cantSplit/></w:trPr>");
            for (i, c) in r.iter().enumerate() {
                let key = first_col && i == 0;
                self.cell(tw[i.min(tw.len() - 1)], if key { Some("F7F7F9") } else { None }, c, key);
            }
            self.body.push_str("</w:tr>");
        }
        self.body.push_str("</w:tbl>");
        self.p("Gap", "");
    }

    fn image(&mut self, png: &[u8], w: u32, h: u32) {
        self.media.push(png.to_vec());
        let n = self.media.len();
        // 96 dpi pixels to EMU, no wider than the text column.
        let max_cx = TEXT_TWIPS as u64 * 635;
        let (mut cx, mut cy) = (w as u64 * 9525, h as u64 * 9525);
        if cx > max_cx {
            cy = cy * max_cx / cx;
            cx = max_cx;
        }
        self.body.push_str(&format!(
            "<w:p><w:pPr><w:keepNext/></w:pPr><w:r><w:drawing><wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\"><wp:extent cx=\"{cx}\" cy=\"{cy}\"/><wp:docPr id=\"{n}\" name=\"Figure {n}\"/>\
<a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">\
<pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:nvPicPr><pic:cNvPr id=\"{n}\" name=\"image{n}.png\"/><pic:cNvPicPr/></pic:nvPicPr>\
<pic:blipFill><a:blip r:embed=\"rIdImg{n}\"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm>\
<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:ln w=\"6350\"><a:solidFill><a:srgbClr val=\"BBBBBB\"/></a:solidFill></a:ln></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"
        ));
    }

    fn block(&mut self, b: &Block) {
        match b {
            Block::Title { title, sub } => {
                self.p("Brand", &runs_xml(&vec![t(format!("KOKINO FTK  |  {}", kokino_core::VENDOR.to_uppercase()))]));
                self.p("Title", &runs_xml(&vec![t(title.clone())]));
                self.p("Subtitle", &runs_xml(&vec![t(sub.clone())]));
            }
            Block::H1(s) => self.p("Heading1", &runs_xml(&vec![t(s.clone())])),
            Block::H2(s) => self.p("Heading2", &runs_xml(&vec![t(s.clone())])),
            Block::P(p) => self.p("", &runs_xml(p)),
            Block::Small(p) => self.p("Small", &runs_xml(p)),
            Block::Kv(rows) => {
                let rows: Vec<Vec<Vec<Para>>> = rows.iter().map(|(k, v)| vec![vec![vec![t(k.clone())]], v.clone()]).collect();
                self.table("KTable", None, &[26, 74], &rows, true);
            }
            Block::Table { head, widths, rows } => self.table("KTable", Some(head), widths, rows, false),
            Block::Bullets(items) => {
                for p in items {
                    self.p("ListBullet", &runs_xml(p));
                }
            }
            Block::Pre(s) => {
                for line in s.lines() {
                    self.p("HexBlock", &runs_xml(&vec![t(line)]));
                }
                self.p("Gap", "");
            }
            Block::Img { png, w, h, caption, .. } => {
                self.image(png, *w, *h);
                self.p("Caption", &runs_xml(&vec![t(caption.clone())]));
            }
            Block::Break => self.body.push_str("<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>"),
            Block::Sign(labels) => {
                let rows: Vec<Vec<Vec<Para>>> = labels
                    .iter()
                    .map(|l| vec![vec![vec![bold(l.clone())]], vec![vec![t("\n\n______________________________")], vec![muted("Signature")]], vec![vec![t("\n\n__________________")], vec![muted("Date")]]])
                    .collect();
                self.table("PlainTable", None, &[38, 40, 22], &rows, false);
            }
        }
    }
}

fn render_docx(d: &Doc, now: &str) -> anyhow::Result<Vec<u8>> {
    let mut x = Docx { body: String::new(), media: vec![] };
    for b in &d.blocks {
        x.block(b);
    }
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<w:document xmlns:w=\"{W_NS}\" xmlns:r=\"{R_NS}\" xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\" xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><w:body>{}<w:sectPr><w:footerReference w:type=\"default\" r:id=\"rIdFtr\"/><w:pgSz w:w=\"11906\" w:h=\"16838\"/><w:pgMar w:top=\"1134\" w:right=\"1134\" w:bottom=\"1134\" w:left=\"1134\" w:header=\"567\" w:footer=\"567\" w:gutter=\"0\"/></w:sectPr></w:body></w:document>",
        x.body
    );
    let footer = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<w:ftr xmlns:w=\"{W_NS}\" xmlns:r=\"{R_NS}\"><w:p><w:pPr><w:pStyle w:val=\"Small\"/><w:tabs><w:tab w:val=\"right\" w:pos=\"{TEXT_TWIPS}\"/></w:tabs></w:pPr><w:r><w:t xml:space=\"preserve\">Kokino FTK report {} | {}</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t xml:space=\"preserve\">Page </w:t></w:r><w:fldSimple w:instr=\" PAGE \"><w:r><w:t>1</w:t></w:r></w:fldSimple><w:r><w:t xml:space=\"preserve\"> of </w:t></w:r><w:fldSimple w:instr=\" NUMPAGES \"><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>",
        xesc(&d.id),
        xesc(&d.case_name)
    );
    let mut rels = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rIdSty\" Type=\"{R_NS}/styles\" Target=\"styles.xml\"/><Relationship Id=\"rIdNum\" Type=\"{R_NS}/numbering\" Target=\"numbering.xml\"/><Relationship Id=\"rIdFtr\" Type=\"{R_NS}/footer\" Target=\"footer1.xml\"/>"
    );
    for n in 1..=x.media.len() {
        rels.push_str(&format!("<Relationship Id=\"rIdImg{n}\" Type=\"{R_NS}/image\" Target=\"media/image{n}.png\"/>"));
    }
    rels.push_str("</Relationships>");
    let created: String = now.chars().take(19).collect::<String>() + "Z";
    let core = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><dc:title>{}</dc:title><dc:subject>{}</dc:subject><dc:creator>{}</dc:creator><dc:identifier>{}</dc:identifier><dcterms:created xsi:type=\"dcterms:W3CDTF\">{created}</dcterms:created></cp:coreProperties>",
        xesc(&d.title),
        xesc(&d.case_name),
        xesc(&d.author),
        xesc(&d.id)
    );
    let mut z = Zip::new();
    z.add("[Content_Types].xml", CONTENT_TYPES.as_bytes())?;
    z.add("_rels/.rels", ROOT_RELS.as_bytes())?;
    z.add("docProps/core.xml", core.as_bytes())?;
    z.add("word/document.xml", document.as_bytes())?;
    z.add("word/_rels/document.xml.rels", rels.as_bytes())?;
    z.add("word/styles.xml", STYLES.replace("@@W@@", W_NS).as_bytes())?;
    z.add("word/numbering.xml", NUMBERING.replace("@@W@@", W_NS).as_bytes())?;
    z.add("word/footer1.xml", footer.as_bytes())?;
    for (i, m) in x.media.iter().enumerate() {
        z.add(&format!("word/media/image{}.png", i + 1), m)?;
    }
    Ok(z.finish())
}

const CONTENT_TYPES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Default Extension=\"png\" ContentType=\"image/png\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/><Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/><Override PartName=\"/word/numbering.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml\"/><Override PartName=\"/word/footer1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml\"/><Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/></Types>";

const ROOT_RELS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/><Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/></Relationships>";

const NUMBERING: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<w:numbering xmlns:w=\"@@W@@\"><w:abstractNum w:abstractNumId=\"0\"><w:multiLevelType w:val=\"singleLevel\"/><w:lvl w:ilvl=\"0\"><w:start w:val=\"1\"/><w:numFmt w:val=\"bullet\"/><w:lvlText w:val=\"&#xF0B7;\"/><w:lvlJc w:val=\"left\"/><w:pPr><w:ind w:left=\"360\" w:hanging=\"260\"/></w:pPr><w:rPr><w:rFonts w:ascii=\"Symbol\" w:hAnsi=\"Symbol\" w:hint=\"default\"/></w:rPr></w:lvl></w:abstractNum><w:num w:numId=\"1\"><w:abstractNumId w:val=\"0\"/></w:num></w:numbering>";

const STYLES: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<w:styles xmlns:w=\"@@W@@\">\
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii=\"Calibri\" w:hAnsi=\"Calibri\" w:eastAsia=\"Calibri\" w:cs=\"Calibri\"/><w:sz w:val=\"20\"/><w:szCs w:val=\"20\"/><w:lang w:val=\"en-GB\"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after=\"100\" w:line=\"264\" w:lineRule=\"auto\"/></w:pPr></w:pPrDefault></w:docDefaults>\
<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\"/><w:qFormat/></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Brand\"><w:name w:val=\"Brand\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:spacing w:before=\"600\" w:after=\"0\"/></w:pPr><w:rPr><w:color w:val=\"24425C\"/><w:spacing w:val=\"10\"/><w:sz w:val=\"17\"/><w:szCs w:val=\"17\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Title\"><w:name w:val=\"Title\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:spacing w:before=\"80\" w:after=\"40\"/></w:pPr><w:rPr><w:b/><w:color w:val=\"24425C\"/><w:sz w:val=\"44\"/><w:szCs w:val=\"44\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Subtitle\"><w:name w:val=\"Subtitle\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:pBdr><w:bottom w:val=\"single\" w:sz=\"18\" w:space=\"4\" w:color=\"24425C\"/></w:pBdr><w:spacing w:after=\"240\"/></w:pPr><w:rPr><w:color w:val=\"444444\"/><w:sz w:val=\"28\"/><w:szCs w:val=\"28\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading1\"><w:name w:val=\"heading 1\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:pBdr><w:bottom w:val=\"single\" w:sz=\"8\" w:space=\"2\" w:color=\"24425C\"/></w:pBdr><w:spacing w:before=\"360\" w:after=\"120\"/><w:outlineLvl w:val=\"0\"/></w:pPr><w:rPr><w:b/><w:color w:val=\"24425C\"/><w:sz w:val=\"29\"/><w:szCs w:val=\"29\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading2\"><w:name w:val=\"heading 2\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before=\"280\" w:after=\"80\"/><w:outlineLvl w:val=\"1\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"23\"/><w:szCs w:val=\"23\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Small\"><w:name w:val=\"Small\"/><w:basedOn w:val=\"Normal\"/><w:rPr><w:color w:val=\"666666\"/><w:sz w:val=\"17\"/><w:szCs w:val=\"17\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Cell\"><w:name w:val=\"Table Text\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:spacing w:after=\"0\" w:line=\"240\" w:lineRule=\"auto\"/></w:pPr><w:rPr><w:sz w:val=\"18\"/><w:szCs w:val=\"18\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Gap\"><w:name w:val=\"Gap\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:spacing w:after=\"0\" w:line=\"120\" w:lineRule=\"exact\"/></w:pPr><w:rPr><w:sz w:val=\"8\"/><w:szCs w:val=\"8\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Caption\"><w:name w:val=\"caption\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:spacing w:before=\"40\" w:after=\"200\"/></w:pPr><w:rPr><w:i/><w:color w:val=\"555555\"/><w:sz w:val=\"17\"/><w:szCs w:val=\"17\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"HexBlock\"><w:name w:val=\"Hex Dump\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:keepLines/><w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"F6F6F8\"/><w:spacing w:after=\"0\" w:line=\"240\" w:lineRule=\"auto\"/></w:pPr><w:rPr><w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\" w:cs=\"Consolas\"/><w:sz w:val=\"15\"/><w:szCs w:val=\"15\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"ListBullet\"><w:name w:val=\"List Bullet\"/><w:basedOn w:val=\"Normal\"/><w:pPr><w:numPr><w:numId w:val=\"1\"/></w:numPr><w:spacing w:after=\"60\"/></w:pPr></w:style>\
<w:style w:type=\"character\" w:styleId=\"Code\"><w:name w:val=\"Code\"/><w:rPr><w:rFonts w:ascii=\"Consolas\" w:hAnsi=\"Consolas\" w:cs=\"Consolas\"/><w:sz w:val=\"17\"/><w:szCs w:val=\"17\"/></w:rPr></w:style>\
<w:style w:type=\"table\" w:default=\"1\" w:styleId=\"TableNormal\"><w:name w:val=\"Normal Table\"/><w:tblPr><w:tblInd w:w=\"0\" w:type=\"dxa\"/><w:tblCellMar><w:top w:w=\"0\" w:type=\"dxa\"/><w:left w:w=\"108\" w:type=\"dxa\"/><w:bottom w:w=\"0\" w:type=\"dxa\"/><w:right w:w=\"108\" w:type=\"dxa\"/></w:tblCellMar></w:tblPr></w:style>\
<w:style w:type=\"table\" w:styleId=\"KTable\"><w:name w:val=\"Kokino Table\"/><w:basedOn w:val=\"TableNormal\"/><w:tblPr><w:tblBorders><w:top w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/><w:left w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/><w:bottom w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/><w:right w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/><w:insideH w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/><w:insideV w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"BFBFBF\"/></w:tblBorders><w:tblCellMar><w:top w:w=\"40\" w:type=\"dxa\"/><w:left w:w=\"100\" w:type=\"dxa\"/><w:bottom w:w=\"40\" w:type=\"dxa\"/><w:right w:w=\"100\" w:type=\"dxa\"/></w:tblCellMar></w:tblPr></w:style>\
<w:style w:type=\"table\" w:styleId=\"PlainTable\"><w:name w:val=\"Signature Table\"/><w:basedOn w:val=\"TableNormal\"/></w:style>\
</w:styles>";

/// Minimal ZIP writer (deflate), enough for an Office Open XML package.
struct Zip {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u16,
    time: u16,
    date: u16,
}

impl Zip {
    fn new() -> Self {
        use chrono::{Datelike, Timelike};
        let n = chrono::Utc::now();
        let time = ((n.hour() << 11) | (n.minute() << 5) | (n.second() / 2)) as u16;
        let date = ((((n.year() - 1980).max(0) as u32) << 9) | (n.month() << 5) | n.day()) as u16;
        Zip { out: vec![], central: vec![], count: 0, time, date }
    }

    fn add(&mut self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data)?;
        let comp = e.finish()?;
        let offset = self.out.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend(20u16.to_le_bytes()); // version needed
            v.extend(0u16.to_le_bytes()); // flags
            v.extend(8u16.to_le_bytes()); // deflate
            v.extend(self.time.to_le_bytes());
            v.extend(self.date.to_le_bytes());
            v.extend(crc.sum().to_le_bytes());
            v.extend((comp.len() as u32).to_le_bytes());
            v.extend((data.len() as u32).to_le_bytes());
            v.extend((name.len() as u16).to_le_bytes());
            v.extend(0u16.to_le_bytes()); // extra
        };
        let mut local = 0x04034b50u32.to_le_bytes().to_vec();
        common(&mut local);
        local.extend(name.as_bytes());
        let mut cen = 0x02014b50u32.to_le_bytes().to_vec();
        cen.extend(20u16.to_le_bytes()); // version made by
        common(&mut cen);
        cen.extend([0u8; 8]); // comment length, disk, internal and external attributes (part)
        cen.extend([0u8; 2]);
        cen.extend(offset.to_le_bytes());
        cen.extend(name.as_bytes());
        self.out.extend(local);
        self.out.extend(comp);
        self.central.extend(cen);
        self.count += 1;
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        let (cd_off, cd_len) = (self.out.len() as u32, self.central.len() as u32);
        self.out.extend(std::mem::take(&mut self.central));
        self.out.extend(0x06054b50u32.to_le_bytes());
        self.out.extend([0u8; 4]);
        self.out.extend(self.count.to_le_bytes());
        self.out.extend(self.count.to_le_bytes());
        self.out.extend(cd_len.to_le_bytes());
        self.out.extend(cd_off.to_le_bytes());
        self.out.extend(0u16.to_le_bytes());
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a ZIP written by `Zip` back: names, inflated data, CRCs.
    fn unzip(z: &[u8]) -> Vec<(String, Vec<u8>)> {
        let e = z.len() - 22;
        assert_eq!(&z[e..e + 4], &0x06054b50u32.to_le_bytes());
        let n = u16::from_le_bytes([z[e + 10], z[e + 11]]) as usize;
        let mut p = u32::from_le_bytes(z[e + 16..e + 20].try_into().unwrap()) as usize;
        let mut out = vec![];
        for _ in 0..n {
            assert_eq!(&z[p..p + 4], &0x02014b50u32.to_le_bytes());
            let rd16 = |o: usize| u16::from_le_bytes([z[p + o], z[p + o + 1]]) as usize;
            let rd32 = |o: usize| u32::from_le_bytes(z[p + o..p + o + 4].try_into().unwrap());
            let (crc, csize, nlen, off) = (rd32(16), rd32(20) as usize, rd16(28), rd32(42) as usize);
            let name = String::from_utf8(z[p + 46..p + 46 + nlen].to_vec()).unwrap();
            let data_at = off + 30 + nlen;
            let mut d = vec![];
            std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(&z[data_at..data_at + csize]), &mut d).unwrap();
            let mut c = flate2::Crc::new();
            c.update(&d);
            assert_eq!(c.sum(), crc, "{}", name);
            out.push((name, d));
            p += 46 + nlen;
        }
        out
    }

    fn sample_doc() -> Doc {
        let img = Rgb { w: 3, h: 2, px: vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 10, 20, 30, 40, 50, 60, 70, 80, 90] };
        Doc {
            id: "abcd1234".into(),
            title: DEFAULT_TITLE.into(),
            case_name: "Case <A & B>".into(),
            author: "Lab Examiner (labexam)".into(),
            blocks: vec![
                Block::Title { title: DEFAULT_TITLE.into(), sub: "Case <A & B>".into() },
                Block::H1("1 Summary".into()),
                Block::P(vec![t("Text with a control char \u{1} and\nnew line, "), bold("bold"), t(" ok").tone(Tone::Good)]),
                Block::Kv(vec![kv1("Key", vec![mono("value")])]),
                Block::Table { head: vec!["A".into(), "B".into()], widths: vec![30, 70], rows: vec![vec![vec![vec![t("1")]], vec![]]] },
                Block::Bullets(vec![vec![t("one")]]),
                Block::Pre(hex_dump(b"Kokino\x00\x01 forensic toolkit", 4096)),
                Block::Img { png: png(&img), w: 3, h: 2, pixelated: true, caption: "Figure 1.".into() },
                Block::Break,
                Block::Sign(vec!["Prepared by:".into()]),
            ],
        }
    }

    #[test]
    fn docx_package_is_complete_and_escaped() {
        let z = render_docx(&sample_doc(), "2026-10-29T10:00:00.000Z").unwrap();
        let parts = unzip(&z);
        let names: Vec<&str> = parts.iter().map(|p| p.0.as_str()).collect();
        assert_eq!(names[0], "[Content_Types].xml");
        for n in ["_rels/.rels", "word/document.xml", "word/styles.xml", "word/numbering.xml", "word/footer1.xml", "word/_rels/document.xml.rels", "docProps/core.xml", "word/media/image1.png"] {
            assert!(names.contains(&n), "{}", n);
        }
        let doc = String::from_utf8(parts.iter().find(|p| p.0 == "word/document.xml").unwrap().1.clone()).unwrap();
        assert!(doc.contains("Case &lt;A &amp; B&gt;"));
        assert!(!doc.contains('\u{1}'));
        assert!(doc.contains("r:embed=\"rIdImg1\""));
        // Every XML part is UTF-8 text with balanced paragraphs and tables.
        for (n, d) in &parts {
            if n.ends_with(".xml") || n.ends_with(".rels") {
                let s = std::str::from_utf8(d).unwrap();
                assert!(s.starts_with("<?xml"), "{}", n);
                assert_eq!(s.matches("<w:p>").count() + s.matches("<w:p><w:pPr>").count() + s.matches("<w:p/>").count(), s.matches("</w:p>").count() + s.matches("<w:p/>").count() + s.matches("<w:p><w:pPr>").count(), "{}", n);
                assert_eq!(s.matches("<w:tbl>").count(), s.matches("</w:tbl>").count(), "{}", n);
            }
        }
    }

    #[test]
    fn png_round_trips_through_the_picture_decoder() {
        let img = Rgb { w: 5, h: 3, px: (0..45).map(|i| (i * 5) as u8).collect() };
        let back = photo::decode_rgb(&png(&img)).unwrap();
        assert_eq!((back.w, back.h), (5, 3));
        assert_eq!(back.px, img.px);
    }

    #[test]
    fn html_escapes_and_embeds_figures() {
        let h = render_html(&sample_doc());
        assert!(h.contains("Case &lt;A &amp; B&gt;"));
        assert!(h.contains("data:image/png;base64,iVBORw0KGgo"));
        assert!(h.contains("class=px"));
        assert!(h.contains("Kokino FTK report abcd1234"));
    }

    #[test]
    fn hex_dump_layout() {
        let s = hex_dump(b"ABCDEFGHIJKLMNOPQR", 0x10);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000000010  41 42"));
        assert!(lines[0].ends_with("ABCDEFGHIJKLMNOP"));
        assert!(lines[1].ends_with("QR"));
    }

    #[test]
    fn resize_and_names() {
        let img = Rgb { w: 4, h: 2, px: vec![100; 24] };
        let r = resize(&img, 2, 1);
        assert_eq!(r.px, vec![100; 6]);
        assert_eq!(size(1536), "1,536 bytes (1.5 KiB)");
        assert_eq!(size(999), "999 bytes");
        let dir = std::env::temp_dir();
        let case = Case { dir: dir.clone(), info: serde_json::from_value(json!({"id":"x","name":"x","examiner":"x","description":"","created":"","tool":"","tool_version":""})).unwrap(), audit: kokino_core::audit::AuditLog::open(dir.join("none.jsonl")).unwrap() };
        assert!(file_path(&case, "report-20261029-100000-abcd1234.html").is_ok());
        for bad in ["../report-1.html", "report-1.html.exe", "report-1.docx/..", "case.json"] {
            assert!(file_path(&case, bad).is_err(), "{}", bad);
        }
    }
}
