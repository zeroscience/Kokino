//! Browser history: Chromium family (Chrome, Edge, Brave, Opera, Vivaldi)
//! `History`, Firefox `places.sqlite` and Safari `History.db` (with its
//! `Downloads.plist`). Internet Explorer's `index.dat`
//! files are read by [`crate::iecache`] into the same structures.
//!
//! Databases are given as bytes (read from the evidence by the caller),
//! written to a private temporary directory together with their `-wal` and
//! `-journal` companions, and opened there. SQLite then applies the WAL the
//! way the browser would have, so visits that were never checkpointed into
//! the main file are included. The evidence itself is never opened by SQLite.
//!
//! Schemas differ between browser versions; every query checks which
//! columns exist and degrades to what the database has.
//!
//! All times are returned as Windows FILETIME (100 ns since 1601, UTC):
//! Chromium stores microseconds since 1601, Firefox microseconds since 1970,
//! Safari seconds since 2001.

use anyhow::Context;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

const UNIX_EPOCH_FT: u64 = 116_444_736_000_000_000;
const MAX_ROWS: usize = 2_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Chromium,
    Firefox,
    /// Internet Explorer 4 to 9 (index.dat).
    Ie,
    Safari,
}

/// Where a history database came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebSource {
    pub browser: String,
    pub engine: Option<Engine>,
    pub user: String,
    pub profile: String,
    pub path: String,
    /// MFT record of the database file.
    pub record: u64,
    pub deleted: bool,
    pub size: u64,
    pub wal: bool,
    pub journal: bool,
    pub visits: u64,
    pub urls: u64,
    pub downloads: u64,
    pub searches: u64,
    pub oldest: u64,
    pub newest: u64,
    pub error: Option<String>,
    /// Internet Explorer cache entries in this file.
    #[serde(default)]
    pub cached: u64,
    #[serde(default)]
    pub cookies: u64,
    /// Deleted entries recovered from inside the file.
    #[serde(default)]
    pub recovered: u64,
    /// Anything the examiner should know about how this source was read.
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Visit {
    pub t: u64,
    pub src: u32,
    pub url: String,
    pub title: String,
    /// How the page was reached: typed, link, reload, form, bookmark, ...
    pub how: String,
    pub typed: bool,
    pub visit_count: i64,
    pub duration_ms: i64,
    /// True when only the URL table remembers this page (its visit rows are
    /// gone: expired, or deleted selectively).
    pub url_only: bool,
    /// A deleted entry recovered from free blocks inside the history file.
    #[serde(default)]
    pub recovered: bool,
}

/// A cookie Internet Explorer kept (Cookies folder: index.dat and one text
/// file per site).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cookie {
    pub src: u32,
    /// Site and path, as `example.test/` or `www.example.test/shop/`.
    pub site: String,
    pub name: String,
    /// The value (cut at 400 characters).
    pub value: String,
    pub created: u64,
    pub expires: u64,
    /// When the browser last used the site's cookie file (from index.dat).
    pub last_access: u64,
    /// The cookie file, e.g. `alice@shop[1].txt` or `1N9VWD9L.txt`.
    pub file: String,
    pub flags: u32,
    /// The index.dat entry is deleted (recovered from free blocks).
    pub recovered: bool,
    /// Anything unusual: the cookie file is gone, or it has no index entry.
    pub note: String,
}

/// A page part kept in Internet Explorer's cache (Content.IE5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Last access.
    pub t: u64,
    /// Last-modified date sent by the server.
    pub modified: u64,
    pub src: u32,
    pub url: String,
    /// Cache folder and file name, as `ABCD1234\name[1].png`.
    pub file: String,
    pub content_type: String,
    pub hits: u32,
    /// A deleted entry recovered from free blocks inside index.dat.
    pub recovered: bool,
    /// A LEAK entry: deleted, but its cached file could not be removed.
    pub leak: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Download {
    pub start: u64,
    pub end: u64,
    pub src: u32,
    pub url: String,
    pub referrer: String,
    pub target: String,
    pub received: i64,
    pub total: i64,
    pub state: String,
    pub danger: String,
    pub mime: String,
    pub opened: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Search {
    pub t: u64,
    pub src: u32,
    pub term: String,
    pub engine: String,
    pub url: String,
    /// "keyword table" (recorded by the browser) or "url" (parsed from a visited search URL).
    pub how: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebActivity {
    pub sources: Vec<WebSource>,
    pub visits: Vec<Visit>,
    pub downloads: Vec<Download>,
    pub searches: Vec<Search>,
    #[serde(default)]
    pub cache: Vec<CacheEntry>,
    #[serde(default)]
    pub cookies: Vec<Cookie>,
}

impl WebActivity {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// Recognizes a history database by file name and path. The caller should
/// also check for the SQLite signature.
pub fn classify(path: &str, name: &str) -> Option<WebSource> {
    let engine = if name.eq_ignore_ascii_case("History") {
        Engine::Chromium
    } else if name.eq_ignore_ascii_case("places.sqlite") {
        Engine::Firefox
    } else if name == "History.db" && path.contains("/Library/Safari/") {
        Engine::Safari
    } else {
        return None;
    };
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let lower = path.to_ascii_lowercase();
    let after = |marker: &str| -> String {
        parts.iter().position(|p| p.eq_ignore_ascii_case(marker)).and_then(|i| parts.get(i + 1)).map(|s| s.to_string()).unwrap_or_default()
    };
    let user = {
        let u = after("Users");
        if u.is_empty() { after("home") } else { u }
    };
    let (browser, profile) = match engine {
        Engine::Chromium => {
            let b = [
                ("google/chrome", "Chrome"),
                ("microsoft/edge", "Edge"),
                ("bravesoftware", "Brave"),
                ("opera software", "Opera"),
                ("vivaldi", "Vivaldi"),
                ("chromium", "Chromium"),
                ("yandex", "Yandex"),
            ]
            .iter()
            .find(|(k, _)| lower.contains(k))
            .map(|(_, v)| v.to_string())
            .unwrap_or_else(|| "Chromium-based".into());
            let p = after("User Data");
            let p = if p.is_empty() || p.eq_ignore_ascii_case(name) { parts.iter().rev().nth(1).map(|s| s.to_string()).unwrap_or_default() } else { p };
            (b, p)
        }
        Engine::Ie => return None,
        Engine::Safari => ("Safari".to_string(), String::new()),
        Engine::Firefox => {
            let b = if lower.contains("tor browser") { "Tor Browser" } else if lower.contains("waterfox") { "Waterfox" } else { "Firefox" };
            (b.to_string(), after("Profiles"))
        }
    };
    Some(WebSource { browser, engine: Some(engine), user, profile, path: path.to_string(), ..Default::default() })
}

/// Parses one database into `out`, filling in the counts of `src`.
pub fn parse(src: &mut WebSource, db: &[u8], wal: Option<&[u8]>, journal: Option<&[u8]>, out: &mut WebActivity) -> anyhow::Result<()> {
    if !db.starts_with(b"SQLite format 3\0") {
        anyhow::bail!("not a SQLite database (header overwritten or file wiped)");
    }
    let dir = TempDir::new()?;
    let p = dir.0.join("db");
    std::fs::write(&p, db)?;
    if let Some(w) = wal {
        std::fs::write(dir.0.join("db-wal"), w)?;
    }
    if let Some(j) = journal {
        std::fs::write(dir.0.join("db-journal"), j)?;
    }
    src.wal = wal.is_some();
    src.journal = journal.is_some();
    let conn = Connection::open_with_flags(&p, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX).context("opening database copy")?;
    crate::sqlite::harden(&conn, crate::sqlite::BUDGET)?;
    // Touch the schema so WAL recovery and hot-journal rollback happen now.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).context("reading schema")?;
    conn.execute_batch("PRAGMA query_only = 1;")?;
    let views = crate::sqlite::views_named(&conn, &["urls", "visits", "downloads", "downloads_url_chains", "keyword_search_terms", "moz_places", "moz_historyvisits", "moz_annos", "moz_anno_attributes", "history_items", "history_visits"]);
    if !views.is_empty() {
        anyhow::bail!("{} defined as a view, not a table: the database was altered, so it is not read", views.join(", "));
    }
    let idx = out.sources.len() as u32;
    let (v0, d0, s0) = (out.visits.len(), out.downloads.len(), out.searches.len());
    match src.engine {
        Some(Engine::Chromium) => chromium(&conn, idx, src, out).map_err(crate::sqlite::explain)?,
        Some(Engine::Firefox) => firefox(&conn, idx, src, out).map_err(crate::sqlite::explain)?,
        Some(Engine::Safari) => safari(&conn, idx, out).map_err(crate::sqlite::explain)?,
        Some(Engine::Ie) | None => anyhow::bail!("not a SQLite history engine"),
    }
    src.visits = out.visits[v0..].iter().filter(|v| !v.url_only).count() as u64;
    src.downloads = (out.downloads.len() - d0) as u64;
    src.searches = (out.searches.len() - s0) as u64;
    let times = out.visits[v0..].iter().map(|v| v.t).chain(out.downloads[d0..].iter().map(|d| d.start)).filter(|&t| t > 0);
    src.oldest = times.clone().min().unwrap_or(0);
    src.newest = times.max().unwrap_or(0);
    Ok(())
}

fn columns(c: &Connection, table: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Ok(mut st) = c.prepare(&format!("PRAGMA table_info({})", table)) {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(1)) {
            out.extend(rows.flatten());
        }
    }
    out
}

/// `col` if the table has it, otherwise a literal default.
fn col(cols: &HashSet<String>, alias: &str, name: &str, default: &str) -> String {
    if cols.contains(name) { format!("{}.{}", alias, name) } else { default.to_string() }
}

fn webkit_to_ft(us: i64) -> u64 {
    if us <= 0 { 0 } else { (us as u64).saturating_mul(10) }
}

fn prtime_to_ft(us: i64) -> u64 {
    if us <= 0 { 0 } else { (us as u64).saturating_mul(10).saturating_add(UNIX_EPOCH_FT) }
}

fn chromium_transition(t: i64) -> (&'static str, bool) {
    let core = t & 0xff;
    let s = match core {
        0 => "link",
        1 => "typed",
        2 => "bookmark",
        3 => "subframe (auto)",
        4 => "subframe (manual)",
        5 => "omnibox suggestion",
        6 => "start page",
        7 => "form submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword (generated)",
        _ => "other",
    };
    (s, core == 1)
}

fn chromium(c: &Connection, src: u32, s: &mut WebSource, out: &mut WebActivity) -> anyhow::Result<()> {
    let ucols = columns(c, "urls");
    let vcols = columns(c, "visits");
    if ucols.is_empty() {
        anyhow::bail!("no urls table: not a Chromium history database");
    }
    s.urls = c.query_row("SELECT count(*) FROM urls", [], |r| r.get::<_, i64>(0))? as u64;
    let mut seen_urls: HashSet<String> = HashSet::new();
    if !vcols.is_empty() {
        let sql = format!(
            "SELECT v.visit_time, u.url, COALESCE(u.title, ''), {}, {}, {} FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time",
            col(&vcols, "v", "transition", "0"),
            col(&ucols, "u", "visit_count", "0"),
            col(&vcols, "v", "visit_duration", "0"),
        );
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?)))?;
        for row in rows.take(MAX_ROWS) {
            let (t, url, title, tr, vc, dur) = row?;
            let (how, typed) = chromium_transition(tr);
            seen_urls.insert(url.clone());
            out.visits.push(Visit { t: webkit_to_ft(t), src, url, title, how: how.into(), typed, visit_count: vc, duration_ms: dur / 1000, url_only: false, recovered: false });
        }
    }
    // URLs whose visit rows are gone: Chrome expires visits after 90 days but
    // keeps typed/bookmarked URLs; selective deletion can leave them too.
    let sql = format!(
        "SELECT u.url, COALESCE(u.title, ''), {}, {}, {} FROM urls u",
        col(&ucols, "u", "last_visit_time", "0"),
        col(&ucols, "u", "visit_count", "0"),
        col(&ucols, "u", "typed_count", "0"),
    );
    let mut st = c.prepare(&sql)?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?)))?;
    for row in rows.take(MAX_ROWS) {
        let (url, title, t, vc, typed) = row?;
        if seen_urls.contains(&url) {
            continue;
        }
        out.visits.push(Visit { t: webkit_to_ft(t), src, url, title, how: "last visit (URL table only)".into(), typed: typed > 0, visit_count: vc, duration_ms: 0, url_only: true, recovered: false });
    }

    let dcols = columns(c, "downloads");
    if !dcols.is_empty() {
        let has_chain = !columns(c, "downloads_url_chains").is_empty();
        let url_expr = if has_chain {
            "COALESCE((SELECT ch.url FROM downloads_url_chains ch WHERE ch.id = d.id ORDER BY ch.chain_index DESC LIMIT 1), '')".to_string()
        } else {
            col(&dcols, "d", "url", "''")
        };
        let sql = format!(
            "SELECT {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM downloads d",
            col(&dcols, "d", "start_time", "0"),
            col(&dcols, "d", "end_time", "0"),
            url_expr,
            col(&dcols, "d", "referrer", "''"),
            if dcols.contains("target_path") { "d.target_path".to_string() } else { col(&dcols, "d", "full_path", "''") },
            col(&dcols, "d", "received_bytes", "0"),
            col(&dcols, "d", "total_bytes", "0"),
            col(&dcols, "d", "state", "-1"),
            col(&dcols, "d", "danger_type", "0"),
            col(&dcols, "d", "interrupt_reason", "0"),
            col(&dcols, "d", "mime_type", "''"),
            col(&dcols, "d", "opened", "0"),
        );
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, String>(10)?,
                r.get::<_, i64>(11)?,
            ))
        })?;
        for row in rows.take(MAX_ROWS) {
            let (start, end, url, referrer, target, received, total, state, danger, interrupt, mime, opened) = row?;
            let state = match state {
                0 => "in progress".to_string(),
                1 => "complete".to_string(),
                2 => "cancelled".to_string(),
                3 => "removed".to_string(),
                4 => format!("interrupted (reason {})", interrupt),
                x => format!("state {}", x),
            };
            let danger = match danger {
                0 => "",
                1 => "dangerous file",
                2 => "dangerous URL",
                3 => "dangerous content",
                4 => "maybe dangerous content",
                5 => "uncommon content",
                6 => "user validated",
                7 => "dangerous host",
                8 => "potentially unwanted",
                _ => "flagged",
            };
            out.downloads.push(Download { start: webkit_to_ft(start), end: webkit_to_ft(end), src, url, referrer, target, received, total, state, danger: danger.into(), mime, opened: opened != 0 });
        }
    }

    let mut keyword_urls = HashSet::new();
    if !columns(c, "keyword_search_terms").is_empty() {
        let sql = format!("SELECT k.term, u.url, {} FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id", col(&ucols, "u", "last_visit_time", "0"));
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))?;
        for row in rows.take(MAX_ROWS) {
            let (term, url, t) = row?;
            keyword_urls.insert(url.clone());
            let engine = search_in_url(&url).map(|(e, _)| e).unwrap_or_else(|| host_of(&url));
            out.searches.push(Search { t: webkit_to_ft(t), src, term, engine, url, how: "keyword table".into() });
        }
    }
    searches_from_visits(src, out, &keyword_urls);
    Ok(())
}

fn firefox_visit_type(t: i64) -> (&'static str, bool) {
    let s = match t {
        1 => "link",
        2 => "typed",
        3 => "bookmark",
        4 => "embed",
        5 => "redirect (permanent)",
        6 => "redirect (temporary)",
        7 => "download",
        8 => "framed link",
        9 => "reload",
        _ => "other",
    };
    (s, t == 2)
}

/// Safari: every visit (history_visits) with its page (history_items);
/// pages whose visits are gone are kept as URL-only.
fn safari(c: &Connection, src: u32, out: &mut WebActivity) -> anyhow::Result<()> {
    let has_col = |t: &str, col: &str| -> bool { c.prepare(&format!("SELECT {} FROM {} LIMIT 0", col, t)).is_ok() };
    let redirect = if has_col("history_visits", "redirect_source") { "v.redirect_source" } else { "NULL" };
    let mut st = c.prepare(&format!("SELECT v.visit_time, i.url, v.title, i.visit_count, {}, i.id FROM history_visits v JOIN history_items i ON v.history_item = i.id ORDER BY v.visit_time", redirect))?;
    let rows = st.query_map([], |r| Ok((r.get::<_, Option<f64>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<i64>>(3)?, r.get::<_, Option<i64>>(4)?, r.get::<_, i64>(5)?)))?;
    let mut seen = HashSet::new();
    for (t, url, title, count, redir, item) in rows.flatten().take(MAX_ROWS) {
        seen.insert(item);
        out.visits.push(Visit {
            t: t.map(crate::plist::mac_time).unwrap_or(0),
            src,
            url: url.unwrap_or_default(),
            title: title.unwrap_or_default(),
            how: if redir.is_some() { "redirect".into() } else { String::new() },
            typed: false,
            visit_count: count.unwrap_or(0),
            duration_ms: 0,
            url_only: false,
            recovered: false,
        });
    }
    let mut st = c.prepare("SELECT id, url, visit_count FROM history_items")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<i64>>(2)?)))?;
    for (id, url, count) in rows.flatten().take(MAX_ROWS) {
        if !seen.contains(&id) {
            out.visits.push(Visit { t: 0, src, url: url.unwrap_or_default(), title: String::new(), how: String::new(), typed: false, visit_count: count.unwrap_or(0), duration_ms: 0, url_only: true, recovered: false });
        }
    }
    searches_from_visits(src, out, &HashSet::new());
    Ok(())
}

/// Safari's Downloads.plist (next to History.db): each download with its
/// address, where it was saved and when. Returns how many were read.
pub fn safari_downloads(d: &[u8], src: u32, out: &mut WebActivity) -> anyhow::Result<usize> {
    let v = crate::plist::parse(d).ok_or_else(|| anyhow::anyhow!("Downloads.plist is not a property list"))?;
    let list = v.get("DownloadHistory").map(|x| x.array()).unwrap_or(&[]);
    let n0 = out.downloads.len();
    for e in list.iter().take(MAX_ROWS) {
        let s = |k: &str| e.get(k).and_then(|x| x.str()).unwrap_or("").to_string();
        let i = |k: &str| e.get(k).and_then(|x| x.int()).unwrap_or(0) as i64;
        let (got, total) = (i("DownloadEntryProgressBytesSoFar"), i("DownloadEntryProgressTotalToLoad"));
        let end = e.get("DownloadEntryDateFinishedKey").map(|x| x.time()).unwrap_or(0);
        out.downloads.push(Download {
            start: e.get("DownloadEntryDateAddedKey").map(|x| x.time()).unwrap_or(0),
            end,
            src,
            url: s("DownloadEntryURL"),
            referrer: String::new(),
            target: s("DownloadEntryPath"),
            received: got,
            total,
            state: if end > 0 || (total > 0 && got >= total) { "complete".into() } else { "interrupted or in progress".into() },
            danger: String::new(),
            mime: String::new(),
            opened: false,
        });
    }
    Ok(out.downloads.len() - n0)
}

fn firefox(c: &Connection, src: u32, s: &mut WebSource, out: &mut WebActivity) -> anyhow::Result<()> {
    let pcols = columns(c, "moz_places");
    if pcols.is_empty() {
        anyhow::bail!("no moz_places table: not a Firefox places database");
    }
    s.urls = c.query_row("SELECT count(*) FROM moz_places", [], |r| r.get::<_, i64>(0))? as u64;
    let mut visited: HashSet<i64> = HashSet::new();
    if !columns(c, "moz_historyvisits").is_empty() {
        let sql = format!(
            "SELECT p.id, v.visit_date, p.url, COALESCE(p.title, ''), v.visit_type, {} FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date",
            col(&pcols, "p", "visit_count", "0")
        );
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?)))?;
        for row in rows.take(MAX_ROWS) {
            let (id, t, url, title, vt, vc) = row?;
            visited.insert(id);
            let (how, typed) = firefox_visit_type(vt);
            out.visits.push(Visit { t: prtime_to_ft(t), src, url, title, how: how.into(), typed, visit_count: vc, duration_ms: 0, url_only: false, recovered: false });
        }
    }
    if pcols.contains("last_visit_date") {
        let sql = format!(
            "SELECT p.id, p.url, COALESCE(p.title, ''), p.last_visit_date, {}, {} FROM moz_places p WHERE p.last_visit_date IS NOT NULL",
            col(&pcols, "p", "visit_count", "0"),
            col(&pcols, "p", "typed", "0")
        );
        let mut st = c.prepare(&sql)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?)))?;
        for row in rows.take(MAX_ROWS) {
            let (id, url, title, t, vc, typed) = row?;
            if visited.contains(&id) {
                continue;
            }
            out.visits.push(Visit { t: prtime_to_ft(t), src, url, title, how: "last visit (URL table only)".into(), typed: typed > 0, visit_count: vc, duration_ms: 0, url_only: true, recovered: false });
        }
    }

    // Firefox 26+ keeps downloads as page annotations on the source URL.
    if !columns(c, "moz_annos").is_empty() && !columns(c, "moz_anno_attributes").is_empty() {
        let mut st = c.prepare(
            "SELECT a.place_id, p.url, n.name, COALESCE(a.content, ''), COALESCE(a.dateAdded, 0) FROM moz_annos a \
             JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id \
             WHERE n.name LIKE 'downloads/%' ORDER BY a.place_id",
        )?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)))?;
        let mut by_place: Vec<(i64, String, HashMap<String, (String, i64)>)> = vec![];
        for row in rows.take(MAX_ROWS) {
            let (pid, url, name, content, added) = row?;
            if by_place.last().map(|x| x.0) != Some(pid) {
                by_place.push((pid, url, HashMap::new()));
            }
            by_place.last_mut().unwrap().2.insert(name, (content, added));
        }
        for (_, url, m) in by_place {
            let (dest, added) = m.get("downloads/destinationFileURI").cloned().unwrap_or_default();
            let meta: serde_json::Value = m.get("downloads/metaData").and_then(|(c, _)| serde_json::from_str(c).ok()).unwrap_or_default();
            let end_ms = meta["endTime"].as_i64().unwrap_or(0);
            let state = match meta["state"].as_i64() {
                Some(0) => "in progress".to_string(),
                Some(1) => "complete".to_string(),
                Some(2) => "failed".to_string(),
                Some(3) => "cancelled".to_string(),
                Some(4) => "paused".to_string(),
                Some(x) => format!("state {}", x),
                None => String::new(),
            };
            let size = meta["fileSize"].as_i64().unwrap_or(-1);
            out.downloads.push(Download {
                start: prtime_to_ft(added),
                end: if end_ms > 0 { prtime_to_ft(end_ms * 1000) } else { 0 },
                src,
                url,
                referrer: String::new(),
                target: file_uri_to_path(&dest),
                received: size,
                total: size,
                state,
                danger: if meta["reputationCheckVerdict"].is_string() { meta["reputationCheckVerdict"].as_str().unwrap_or("").to_string() } else { String::new() },
                mime: String::new(),
                opened: false,
            });
        }
    }
    searches_from_visits(src, out, &HashSet::new());
    Ok(())
}

/// Search terms parsed out of visited search-engine URLs.
fn searches_from_visits(src: u32, out: &mut WebActivity, skip: &HashSet<String>) {
    let mut seen: HashSet<(String, u64)> = HashSet::new();
    let found: Vec<Search> = out
        .visits
        .iter()
        .filter(|v| v.src == src && !skip.contains(&v.url))
        .filter_map(|v| {
            let (engine, term) = search_in_url(&v.url)?;
            seen.insert((term.clone(), v.t)).then(|| Search { t: v.t, src, term, engine, url: v.url.clone(), how: "url".into() })
        })
        .collect();
    out.searches.extend(found);
}

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', '?', '#']).next().unwrap_or("").split('@').last().unwrap_or("").split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// (engine, term) when the URL is a search-engine results page.
pub fn search_in_url(url: &str) -> Option<(String, String)> {
    let host = host_of(url);
    let (engine, key) = if host.contains("google.") && (url.contains("/search") || url.contains("/webhp")) {
        ("Google", "q")
    } else if host.ends_with("bing.com") && url.contains("/search") {
        ("Bing", "q")
    } else if host.ends_with("duckduckgo.com") {
        ("DuckDuckGo", "q")
    } else if host.contains("search.yahoo.") {
        ("Yahoo", "p")
    } else if host.contains("yandex.") && url.contains("/search") {
        ("Yandex", "text")
    } else if host.ends_with("baidu.com") && url.contains("/s") {
        ("Baidu", "wd")
    } else if host.ends_with("ecosia.org") && url.contains("/search") {
        ("Ecosia", "q")
    } else if host.ends_with("startpage.com") {
        ("Startpage", "query")
    } else if host.ends_with("search.brave.com") {
        ("Brave Search", "q")
    } else {
        return None;
    };
    let query = url.split('?').nth(1)?.split('#').next()?;
    let raw = query.split('&').find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('=')))?;
    let term = percent_decode(&raw.replace('+', " "));
    let term = term.trim().to_string();
    if term.is_empty() { None } else { Some((engine.to_string(), term)) }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn file_uri_to_path(u: &str) -> String {
    match u.strip_prefix("file:///") {
        Some(p) => percent_decode(p).replace('/', "\\"),
        None => percent_decode(u),
    }
}

/// A private directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> anyhow::Result<TempDir> {
        let p = std::env::temp_dir().join(format!("kokino-sqlite-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&p)?;
        Ok(TempDir(p))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths() {
        let c = classify("/Users/alice/AppData/Local/Google/Chrome/User Data/Profile 2/History", "History").unwrap();
        assert_eq!((c.browser.as_str(), c.user.as_str(), c.profile.as_str()), ("Chrome", "alice", "Profile 2"));
        let e = classify("/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History", "History").unwrap();
        assert_eq!(e.browser, "Edge");
        let f = classify("/Users/carol/AppData/Roaming/Mozilla/Firefox/Profiles/x1y2.default-release/places.sqlite", "places.sqlite").unwrap();
        assert_eq!((f.browser.as_str(), f.user.as_str(), f.profile.as_str()), ("Firefox", "carol", "x1y2.default-release"));
        assert!(classify("/Users/alice/notes.txt", "notes.txt").is_none());
    }

    #[test]
    fn search_terms_from_urls() {
        assert_eq!(search_in_url("https://www.google.com/search?q=how+to+wipe+a+disk&oq=x").unwrap(), ("Google".into(), "how to wipe a disk".into()));
        assert_eq!(search_in_url("https://www.bing.com/search?form=QBLH&q=sdelete%20download").unwrap().1, "sdelete download");
        assert_eq!(search_in_url("https://duckduckgo.com/?q=caf%C3%A9&ia=web").unwrap().1, "caf\u{e9}");
        assert!(search_in_url("https://www.google.com/maps/place/x").is_none());
        assert!(search_in_url("https://example.com/search?q=x").is_none());
    }

    #[test]
    fn time_conversions() {
        // 2026-10-26T12:00:00Z
        let ft = 134_059_536_000_000_000u64;
        assert_eq!(webkit_to_ft((ft / 10) as i64), ft);
        assert_eq!(prtime_to_ft(((ft - UNIX_EPOCH_FT) / 10) as i64), ft);
        assert_eq!(webkit_to_ft(0), 0);
    }
}
