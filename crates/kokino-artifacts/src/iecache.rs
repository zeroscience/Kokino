//! Internet Explorer's `index.dat` (MSIE Cache File, "Client UrlCache MMF
//! Ver 5.2"), used by Internet Explorer 4 to 9 and by Windows itself.
//!
//! The same format holds the browsing history (`History.IE5`, a main file
//! plus daily and weekly files in `MSHist01...` folders), the cache of
//! downloaded page parts (`Content.IE5`), cookies, and from IE 9 the
//! download list (`IEDownloadHistory`).
//!
//! The file is a header, an allocation bitmap and 128-byte blocks from
//! offset 0x4000. Records (`URL `, `LEAK`, `REDR`) take one or more whole
//! blocks and are listed in a chain of `HASH` tables. When an entry is
//! deleted its blocks are marked free and its hash entry removed, but the
//! bytes stay until the blocks are reused; every block is checked here, so
//! such entries are returned too, marked as not listed.
//!
//! Records keep their 128-byte alignment when the file is deleted, so
//! [`record`] is also used to recover them from free space.
//!
//! Times: the primary time of a history record is the last visit (UTC). In
//! a daily history file the secondary time is the same moment in the
//! computer's local time, so the difference is the clock's offset from UTC
//! when the page was visited. In the cache the primary time is the last
//! access and the secondary time the server's last-modified date.

use crate::bin::*;
use crate::browser::{CacheEntry, Cookie, Download, Engine, Search, Visit, WebActivity, WebSource};
use serde::{Deserialize, Serialize};

pub const SIGNATURE: &[u8] = b"Client UrlCache MMF Ver ";
const BLOCK: usize = 0x80;
const DATA_START: usize = 0x4000;
const BITMAP: usize = 0x250;
/// Records larger than this are not believed (the largest seen are a few KiB).
const MAX_BLOCKS: u32 = 0x200;
const MAX_HASH_TABLES: usize = 4096;
pub const MAX_RECORDS: usize = 500_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    /// An entry (history, cache, cookie, download).
    Url,
    /// A cache entry whose file could not be deleted yet.
    Leak,
    /// A redirect.
    Redirect,
}

impl Kind {
    pub fn tag(self) -> &'static str {
        match self {
            Kind::Url => "URL",
            Kind::Leak => "LEAK",
            Kind::Redirect => "REDR",
        }
    }
}

/// A download recorded by IE 9 in `IEDownloadHistory`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadInfo {
    pub url: String,
    pub referrer: String,
    pub target: String,
    pub started: u64,
    pub total: u64,
    pub received: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub kind: Kind,
    /// Byte offset in the file (or in whatever was scanned).
    pub offset: u64,
    pub blocks: u32,
    /// Listed in the hash table. False: a deleted entry whose blocks were
    /// not reused yet (or, for LEAK, one waiting for its file to go).
    pub listed: bool,
    pub primary: u64,
    pub secondary: u64,
    pub hits: u32,
    pub location: String,
    /// Cached file name (in the cache directory `dir`).
    pub file: String,
    pub dir: u8,
    /// Page title kept with history entries.
    pub title: String,
    /// Content-Type from the cached HTTP response headers.
    pub content_type: String,
    /// The `~U:` user named in cached response headers.
    pub header_user: String,
    pub download: Option<DownloadInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    /// "5.2"
    pub version: String,
    /// Cache directory names (Content.IE5 subfolders), by index.
    pub dirs: Vec<String>,
    pub records: Vec<Record>,
    pub unlisted: usize,
    pub truncated: bool,
}

/// What a record's location says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// `Visited: user@url` (main history) or `:2011101920111020: user@url`
    /// (daily or weekly history; the two dates are the period).
    History { user: String, url: String, period: Option<(String, String)> },
    /// `:Host: name` summary entries of daily and weekly history.
    Host,
    Cookie { user: String, url: String },
    Download,
    /// A plain URL: the cache (or a redirect).
    Url(String),
    Other,
}

pub fn location(loc: &str) -> Location {
    if let Some(rest) = loc.strip_prefix("Visited: ") {
        let (user, url) = user_at(rest);
        return Location::History { user, url, period: None };
    }
    if let Some(rest) = loc.strip_prefix(':') {
        if let Some((range, rest)) = rest.split_once(": ") {
            if range.len() == 16 && range.bytes().all(|b| b.is_ascii_digit()) {
                let (user, url) = user_at(rest);
                if url.starts_with(":Host: ") {
                    return Location::Host;
                }
                let d = |s: &str| format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]);
                return Location::History { user, url, period: Some((d(&range[..8]), d(&range[8..]))) };
            }
        }
    }
    if let Some(rest) = loc.strip_prefix("Cookie:") {
        let (user, url) = user_at(rest);
        return Location::Cookie { user, url };
    }
    if loc.starts_with("iedownload:") {
        return Location::Download;
    }
    if loc.contains("://") || loc.starts_with("about:") || loc.starts_with("res:") || loc.starts_with("javascript:") || loc.starts_with("mailto:") {
        return Location::Url(loc.to_string());
    }
    Location::Other
}

fn user_at(s: &str) -> (String, String) {
    // The user name cannot contain '@'; the URL can.
    match s.split_once('@') {
        Some((u, url)) => (u.to_string(), url.to_string()),
        None => (String::new(), s.to_string()),
    }
}

/// Reads a whole index.dat.
pub fn parse(d: &[u8]) -> anyhow::Result<Index> {
    if !d.starts_with(SIGNATURE) {
        anyhow::bail!("not an index.dat file (no \"Client UrlCache MMF\" signature)");
    }
    let version = ansiz(d, SIGNATURE.len(), 4);
    let mut out = Index { version, ..Default::default() };
    if d.len() < DATA_START {
        anyhow::bail!("index.dat is {} bytes, shorter than its header", d.len());
    }
    let ndirs = u32_at(d, 0x48).unwrap_or(0).min(32) as usize;
    for i in 0..ndirs {
        out.dirs.push(ansi(slice(d, 0x4c + 12 * i + 4, 8).unwrap_or_default()));
    }
    // Offsets listed in the hash tables.
    let mut listed = std::collections::HashSet::new();
    let mut h = u32_at(d, 0x20).unwrap_or(0) as usize;
    let mut seen = std::collections::HashSet::new();
    while h != 0 && seen.len() < MAX_HASH_TABLES && seen.insert(h) && slice(d, h, 4) == Some(b"HASH") {
        let nb = u32_at(d, h + 4).unwrap_or(0).min(MAX_BLOCKS) as usize;
        let n = (nb * BLOCK).saturating_sub(16) / 8;
        for i in 0..n {
            let (Some(hv), Some(off)) = (u32_at(d, h + 16 + 8 * i), u32_at(d, h + 20 + 8 * i)) else { break };
            // 0x3: never used; 0x1: deleted.
            if hv != 0x3 && hv != 0x1 && off as usize >= DATA_START {
                listed.insert(off as usize);
            }
        }
        h = u32_at(d, h + 8).unwrap_or(0) as usize;
    }
    let mut o = DATA_START;
    while o + BLOCK <= d.len() {
        let mut step = BLOCK;
        if let Some(mut r) = record(d, o) {
            r.listed = listed.contains(&o) && allocated(d, o);
            if !r.listed && r.kind != Kind::Leak {
                out.unlisted += 1;
            }
            step = r.blocks as usize * BLOCK;
            // A deleted record may have been partly overwritten by a newer
            // one; always look at the next block too.
            if !r.listed {
                step = BLOCK;
            }
            if out.records.len() >= MAX_RECORDS {
                out.truncated = true;
                break;
            }
            out.records.push(r);
        }
        o += step;
    }
    Ok(out)
}

fn allocated(d: &[u8], o: usize) -> bool {
    let b = (o - DATA_START) / BLOCK;
    u8_at(d, BITMAP + b / 8).is_some_and(|v| v >> (b % 8) & 1 == 1)
}

/// The record that starts at `o`, if the bytes there really are one. Strict
/// enough to scan free space with: the signature, a sane size, a location
/// string of printable characters inside the record, and plausible times.
pub fn record(d: &[u8], o: usize) -> Option<Record> {
    let kind = match slice(d, o, 4)? {
        b"URL " => Kind::Url,
        b"LEAK" => Kind::Leak,
        b"REDR" => Kind::Redirect,
        _ => return None,
    };
    let blocks = u32_at(d, o + 4)?;
    if blocks == 0 || blocks > MAX_BLOCKS {
        return None;
    }
    let len = blocks as usize * BLOCK;
    let r = slice(d, o, len).or_else(|| d.get(o..))?;
    if kind == Kind::Redirect {
        let loc = text(r, 0x10)?;
        return Some(Record { kind, offset: o as u64, blocks, listed: false, primary: 0, secondary: 0, hits: 0, location: loc, file: String::new(), dir: 0, title: String::new(), content_type: String::new(), header_user: String::new(), download: None });
    }
    let secondary = u64_at(r, 0x08)?;
    let primary = u64_at(r, 0x10)?;
    for t in [primary, secondary] {
        if t != 0 && plausible(t) == 0 {
            return None;
        }
    }
    let loc_off = u32_at(r, 0x34)? as usize;
    if !(0x60..len).contains(&loc_off) {
        return None;
    }
    let location = text(r, loc_off)?;
    let file_off = u32_at(r, 0x3c)? as usize;
    let file = if file_off == 0 { String::new() } else if (0x60..len).contains(&file_off) { text(r, file_off).unwrap_or_default() } else { return None };
    let dir = u8_at(r, 0x38)?;
    let (data_off, data_len) = (u32_at(r, 0x44)? as usize, u32_at(r, 0x48)? as usize);
    // A record cut off by the end of the file may be shorter than it says.
    let data = if data_len > 0 && data_off >= 0x60 && data_off < len { r.get(data_off..(data_off + data_len).min(r.len())).unwrap_or_default() } else { &[][..] };
    let hits = u32_at(r, 0x54)?;
    let mut rec = Record { kind, offset: o as u64, blocks, listed: false, primary, secondary, hits, location, file, dir, title: String::new(), content_type: String::new(), header_user: String::new(), download: None };
    if data.starts_with(b"HTTP/") {
        let headers = ansi(data);
        for line in headers.lines() {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-type") {
                    rec.content_type = v.trim().to_string();
                }
            }
            if let Some(u) = line.strip_prefix("~U:") {
                rec.header_user = u.trim().to_string();
            }
        }
    } else if rec.location.starts_with("iedownload:") {
        rec.download = download(data);
    } else {
        rec.title = title(data);
    }
    Some(rec)
}

/// The cookies in one Internet Explorer cookie file: records of name,
/// value, site and path, flags, expiry (low, high), creation (low, high),
/// each ended by a line holding `*`.
pub fn cookie_text(d: &[u8]) -> Vec<Cookie> {
    let text = String::from_utf8_lossy(d);
    let mut out = vec![];
    let mut lines: Vec<&str> = vec![];
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line == "*" {
            if lines.len() >= 8 {
                let n = |i: usize| lines[i].trim().parse::<u64>().unwrap_or(0);
                out.push(Cookie {
                    name: lines[0].to_string(),
                    value: lines[1].chars().take(400).collect(),
                    site: lines[2].to_string(),
                    flags: n(3) as u32,
                    expires: plausible(n(5) << 32 | n(4)),
                    created: plausible(n(7) << 32 | n(6)),
                    ..Default::default()
                });
            }
            lines.clear();
            if out.len() >= 10_000 {
                break;
            }
        } else if lines.len() < 64 {
            lines.push(line);
        }
    }
    out
}

/// A NUL-terminated string of printable single-byte characters, at least
/// three long, wholly inside `r`.
fn text(r: &[u8], o: usize) -> Option<String> {
    let b = r.get(o..)?;
    let end = b.iter().position(|&c| c == 0)?;
    let s = &b[..end];
    if s.len() < 3 || s.iter().any(|&c| c < 0x20 || c == 0x7f) {
        return None;
    }
    Some(String::from_utf8(s.to_vec()).unwrap_or_else(|_| ansi(s)))
}

/// The page title in a history record's property list (id 0x1f10).
fn title(data: &[u8]) -> String {
    let mut p = 0usize;
    let mut n = 0;
    while let Some(size) = u16_at(data, p) {
        let size = size as usize;
        n += 1;
        if size < 4 || n > 64 {
            break;
        }
        if u16_at(data, p + 2) == Some(0x1f10) {
            if let Some(s) = slice(data, p + 4, size - 4).or_else(|| data.get(p + 4..)) {
                return utf16(s).trim().to_string();
            }
        }
        p += size;
    }
    String::new()
}

/// IE 9 download entry: sizes and start time at fixed places, then the
/// page it came from, the URL and the file it was saved as, as UTF-16.
fn download(data: &[u8]) -> Option<DownloadInfo> {
    let mut info = DownloadInfo { started: plausible(u64_at(data, 0x24).unwrap_or(0)), total: u64_at(data, 0x48).unwrap_or(0), received: u64_at(data, 0x50).unwrap_or(0), ..Default::default() };
    let mut urls = vec![];
    let mut p = 0x58;
    while p + 8 <= data.len() {
        let s = utf16z(data, p, 4096);
        let printable = s.chars().count() >= 4 && s.chars().all(|c| !c.is_control());
        if printable && (s.contains("://") || s.as_bytes().get(1..3) == Some(b":\\") || s.starts_with("\\\\")) {
            p += (s.encode_utf16().count() + 1) * 2;
            if s.contains("://") {
                urls.push(s);
            } else if info.target.is_empty() {
                info.target = s;
            }
            continue;
        }
        p += 2;
    }
    match urls.len() {
        0 => return None,
        1 => info.url = urls.remove(0),
        _ => {
            info.referrer = urls.remove(0);
            info.url = urls.remove(0);
        }
    }
    Some(info)
}

/// Which index.dat files are read as browser history, by path: the
/// history (main, daily, weekly), the cache and the IE 9 download list.
/// Cookies, DOM storage and Windows' own caches use the same format but
/// are not browsing history.
pub fn classify(path: &str, name: &str) -> Option<WebSource> {
    if !name.eq_ignore_ascii_case("index.dat") {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let n = parts.len();
    if n < 2 {
        return None;
    }
    let parent = parts[n - 2];
    let low = parts.iter().any(|p| p.eq_ignore_ascii_case("Low"));
    let low = if low { " (protected mode)" } else { "" };
    let profile = if parent.eq_ignore_ascii_case("History.IE5") {
        format!("History{}", low)
    } else if n >= 3 && parts[n - 3].eq_ignore_ascii_case("History.IE5") && parent.len() == 24 && parent.is_char_boundary(8) && parent[..8].eq_ignore_ascii_case("MSHist01") && parent[8..].bytes().all(|b| b.is_ascii_digit()) {
        let d = |s: &str| format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8]);
        let (a, b) = (&parent[8..16], &parent[16..24]);
        let days = day_number(a).zip(day_number(b)).map(|(x, y)| y - x).unwrap_or(0);
        if days == 1 {
            format!("History{}, day {}", low, d(a))
        } else {
            format!("History{}, {} to {}", low, d(a), d(b))
        }
    } else if parent.eq_ignore_ascii_case("Content.IE5") {
        format!("Cache{}", low)
    } else if parent.eq_ignore_ascii_case("IEDownloadHistory") {
        "Downloads".to_string()
    } else if parent.eq_ignore_ascii_case("Cookies") || (parent.eq_ignore_ascii_case("Low") && n >= 3 && parts[n - 3].eq_ignore_ascii_case("Cookies")) {
        format!("Cookies{}", low)
    } else {
        return None;
    };
    let after = |marker: &str| -> String { parts.iter().position(|p| p.eq_ignore_ascii_case(marker)).and_then(|i| parts.get(i + 1)).map(|s| s.to_string()).unwrap_or_default() };
    let user = {
        let u = after("Users");
        if u.is_empty() { after("Documents and Settings") } else { u }
    };
    Some(WebSource { browser: "Internet Explorer".into(), engine: Some(Engine::Ie), user, profile, path: path.to_string(), ..Default::default() })
}

fn day_number(s: &str) -> Option<i64> {
    let (y, m, d): (i64, i64, i64) = (s.get(0..4)?.parse().ok()?, s.get(4..6)?.parse().ok()?, s.get(6..8)?.parse().ok()?);
    // Days from civil (proleptic Gregorian).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    Some(era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy)
}

/// Reads one index.dat into `out` as visits, cache entries and downloads,
/// filling in the counts of `src`.
pub fn to_web(src: &mut WebSource, d: &[u8], out: &mut WebActivity) -> anyhow::Result<()> {
    let ix = parse(d)?;
    let idx = out.sources.len() as u32;
    let (v0, c0, d0, s0) = (out.visits.len(), out.cache.len(), out.downloads.len(), out.searches.len());
    let mut offsets: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
    let mut downloads: Vec<(Download, bool)> = vec![];
    for r in &ix.records {
        let recovered = !r.listed && r.kind != Kind::Leak;
        match location(&r.location) {
            Location::History { url, period, .. } if r.kind == Kind::Url => {
                if period.is_some() && r.primary != 0 && r.secondary != 0 {
                    // The clock's offset, to the nearest quarter hour (the local
                    // copy is kept to the millisecond only).
                    let q = (r.secondary as i64 - r.primary as i64 + 4_500_000_000).div_euclid(9_000_000_000);
                    if q.abs() <= 14 * 4 {
                        *offsets.entry(q).or_default() += 1;
                    }
                }
                let how = if period.is_none() { "last visit" } else { "visit" };
                out.visits.push(Visit { t: r.primary, src: idx, url, title: r.title.clone(), how: how.into(), typed: false, visit_count: r.hits as i64, duration_ms: 0, url_only: false, recovered });
            }
            Location::Url(url) if r.kind != Kind::Redirect && src.profile.starts_with("Cache") => {
                let file = match (ix.dirs.get(r.dir as usize), r.file.is_empty()) {
                    (_, true) => String::new(),
                    (Some(dir), false) => format!("{}\\{}", dir, r.file),
                    (None, false) => r.file.clone(),
                };
                out.cache.push(CacheEntry { t: r.primary, modified: r.secondary, src: idx, url, file, content_type: r.content_type.clone(), hits: r.hits, recovered, leak: r.kind == Kind::Leak });
            }
            Location::Cookie { url, .. } if r.kind == Kind::Url && src.profile.starts_with("Cookies") => {
                // The cookies themselves are in the text file; the caller
                // reads it (cookie_text) and fills in the rest.
                out.cookies.push(Cookie { src: idx, site: url, last_access: r.primary, file: r.file.clone(), recovered, ..Default::default() });
            }
            Location::Download => {
                if let Some(dl) = &r.download {
                    let complete = dl.total > 0 && dl.received == dl.total;
                    let d = Download {
                        start: if dl.started != 0 { dl.started } else { r.primary },
                        end: if complete { r.primary } else { 0 },
                        src: idx,
                        url: dl.url.clone(),
                        referrer: dl.referrer.clone(),
                        target: dl.target.clone(),
                        received: dl.received.min(i64::MAX as u64) as i64,
                        total: dl.total.min(i64::MAX as u64) as i64,
                        state: if complete { "complete".into() } else { "incomplete".into() },
                        danger: String::new(),
                        mime: String::new(),
                        opened: false,
                    };
                    // The same download is often written twice (in progress, then
                    // done); keep one per URL and file, the most complete.
                    match downloads.iter_mut().find(|(x, _)| x.url == d.url && x.target == d.target) {
                        Some((x, rec)) if d.received > x.received || (d.received == x.received && !recovered && *rec) => {
                            *x = d;
                            *rec = recovered;
                        }
                        Some(_) => {}
                        None => downloads.push((d, recovered)),
                    }
                }
            }
            _ => {}
        }
    }
    out.downloads.extend(downloads.into_iter().map(|(d, _)| d));
    // Search terms from visited search pages.
    let found: Vec<Search> = out.visits[v0..]
        .iter()
        .filter_map(|v| {
            let (engine, term) = crate::browser::search_in_url(&v.url)?;
            Some(Search { t: v.t, src: idx, term, engine, url: v.url.clone(), how: "url".into() })
        })
        .collect();
    out.searches.extend(found);
    src.visits = (out.visits.len() - v0) as u64;
    src.urls = src.visits;
    src.cached = (out.cache.len() - c0) as u64;
    src.cookies = out.cookies.iter().filter(|c| c.src == idx).count() as u64;
    src.downloads = (out.downloads.len() - d0) as u64;
    src.searches = (out.searches.len() - s0) as u64;
    src.recovered = out.visits[v0..].iter().filter(|v| v.recovered).count() as u64 + out.cache[c0..].iter().filter(|c| c.recovered).count() as u64;
    let times = out.visits[v0..].iter().map(|v| v.t).chain(out.cache[c0..].iter().map(|c| c.t)).chain(out.downloads[d0..].iter().map(|d| d.start)).filter(|&t| t > 0);
    src.oldest = times.clone().min().unwrap_or(0);
    src.newest = times.max().unwrap_or(0);
    let mut notes = vec![];
    if let Some((&q, _)) = offsets.iter().max_by_key(|(q, n)| (**n, -q.abs())) {
        let m = q * 15;
        notes.push(format!("the computer's clock was at UTC{}{:02}:{:02} when these pages were visited (from the local times this file keeps)", if m < 0 { "-" } else { "+" }, m.abs() / 60, m.abs() % 60));
    }
    if ix.truncated {
        notes.push(format!("only the first {} records were read", MAX_RECORDS));
    }
    src.note = notes.join("; ");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn put32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// A URL record the way IE writes one.
    pub fn url_record(loc: &str, file: &str, primary: u64, secondary: u64, hits: u32, data: &[u8]) -> Vec<u8> {
        let body = 0x68 + loc.len() + 1 + file.len() + 1 + data.len();
        let blocks = body.div_ceil(BLOCK);
        let mut r = vec![0u8; blocks * BLOCK];
        r[0..4].copy_from_slice(b"URL ");
        put32(&mut r, 4, blocks as u32);
        r[8..16].copy_from_slice(&secondary.to_le_bytes());
        r[16..24].copy_from_slice(&primary.to_le_bytes());
        put32(&mut r, 0x34, 0x68);
        r[0x38] = if file.is_empty() { 0xfe } else { 0 };
        r[0x68..0x68 + loc.len()].copy_from_slice(loc.as_bytes());
        let mut p = 0x68 + loc.len() + 1;
        if !file.is_empty() {
            put32(&mut r, 0x3c, p as u32);
            r[p..p + file.len()].copy_from_slice(file.as_bytes());
            p += file.len() + 1;
        }
        if !data.is_empty() {
            put32(&mut r, 0x44, p as u32);
            put32(&mut r, 0x48, data.len() as u32);
            r[p..p + data.len()].copy_from_slice(data);
        }
        put32(&mut r, 0x54, hits);
        r
    }

    /// History property list with a title.
    pub fn title_data(t: &str) -> Vec<u8> {
        let mut d = vec![0x10, 0, 2, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 2, 0, 0, 0];
        let s: Vec<u8> = t.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()).collect();
        d.extend_from_slice(&((4 + s.len()) as u16).to_le_bytes());
        d.extend_from_slice(&0x1f10u16.to_le_bytes());
        d.extend_from_slice(&s);
        d.extend_from_slice(&[0; 4]);
        d
    }

    /// An index.dat with the records given; `listed` says which go in the
    /// hash table (the others are written to free blocks).
    pub fn index(dirs: &[&str], recs: &[(Vec<u8>, bool)]) -> Vec<u8> {
        let mut d = vec![0u8; DATA_START];
        d[..SIGNATURE.len()].copy_from_slice(SIGNATURE);
        d[SIGNATURE.len()..SIGNATURE.len() + 3].copy_from_slice(b"5.2");
        put32(&mut d, 0x20, DATA_START as u32);
        put32(&mut d, 0x48, dirs.len() as u32);
        for (i, n) in dirs.iter().enumerate() {
            d[0x4c + 12 * i + 4..0x4c + 12 * i + 4 + n.len()].copy_from_slice(n.as_bytes());
        }
        // Hash table: 8 blocks.
        let mut hash = vec![0u8; 8 * BLOCK];
        hash[0..4].copy_from_slice(b"HASH");
        put32(&mut hash, 4, 8);
        let mut body = vec![];
        let mut entries = 0;
        let mut alloc = vec![(0usize, 8usize)];
        for (r, l) in recs {
            let off = DATA_START + hash.len() + body.len();
            if *l {
                put32(&mut hash, 16 + 8 * entries, 0x1234_5600);
                put32(&mut hash, 20 + 8 * entries, off as u32);
                entries += 1;
                alloc.push(((off - DATA_START) / BLOCK, r.len() / BLOCK));
            }
            body.extend_from_slice(r);
        }
        d.extend_from_slice(&hash);
        d.extend_from_slice(&body);
        for (b0, n) in alloc {
            for b in b0..b0 + n {
                d[BITMAP + b / 8] |= 1 << (b % 8);
            }
        }
        let len = d.len() as u32;
        put32(&mut d, 0x1c, len);
        d
    }

    /// Day of a FILETIME, for the tests.
    fn kokino_core_iso(ft: u64) -> String {
        let days = (ft / 10_000_000 / 86_400) as i64 - 134_774; // days since 1970
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        format!("{:04}-{:02}-{:02}", y, m, d)
    }

    // 2011-10-19 08:28:22 UTC and the same in UTC+3.
    pub const T: u64 = 129_634_865_020_000_000;
    pub const T_LOCAL: u64 = T + 3 * 3600 * 10_000_000;

    #[test]
    fn reads_history_cache_and_downloads() {
        let mut dl = vec![0u8; 0x58];
        dl[0x24..0x2c].copy_from_slice(&T.to_le_bytes());
        dl[0x48..0x50].copy_from_slice(&1000u64.to_le_bytes());
        dl[0x50..0x58].copy_from_slice(&400u64.to_le_bytes());
        for s in ["http://search.test/?q=wipe", "http://files.test/tool.zip", "C:\\Users\\alice\\Downloads\\tool.zip"] {
            dl.extend(s.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()));
        }
        let d = index(
            &["AB12CD34"],
            &[
                (url_record("Visited: alice@http://news.test/a.html", "", T, T, 7, &title_data("News")), true),
                (url_record(":2011101920111020: alice@http://bank.test/", "", T, T_LOCAL, 1, &[]), true),
                (url_record(":2011101920111020: alice@:Host: bank.test", "", T, T_LOCAL, 1, &[]), true),
                (url_record("Visited: alice@http://gone.test/", "", T, T, 1, &[]), false),
                (url_record("http://news.test/logo.png", "logo[1].png", T, 0, 3, b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n~U:alice\r\n\0"), true),
                (url_record("iedownload:{11111111-2222-3333-4444-555555555555}", "", T, 0, 1, &dl), true),
            ],
        );
        let ix = parse(&d).unwrap();
        assert_eq!((ix.version.as_str(), ix.dirs.clone(), ix.records.len(), ix.unlisted), ("5.2", vec!["AB12CD34".to_string()], 6, 1));
        let r = &ix.records;
        assert_eq!((r[0].title.as_str(), r[0].hits, r[0].listed), ("News", 7, true));
        assert_eq!(location(&r[0].location), Location::History { user: "alice".into(), url: "http://news.test/a.html".into(), period: None });
        assert_eq!(location(&r[1].location), Location::History { user: "alice".into(), url: "http://bank.test/".into(), period: Some(("2011-10-19".into(), "2011-10-20".into())) });
        assert_eq!(r[1].secondary - r[1].primary, 3 * 3600 * 10_000_000);
        assert_eq!(location(&r[2].location), Location::Host);
        assert!(!r[3].listed);
        assert_eq!((r[4].file.as_str(), r[4].content_type.as_str(), r[4].header_user.as_str()), ("logo[1].png", "image/png", "alice"));
        assert_eq!(location(&r[4].location), Location::Url("http://news.test/logo.png".into()));
        let dlr = r[5].download.as_ref().unwrap();
        assert_eq!((dlr.referrer.as_str(), dlr.url.as_str(), dlr.target.as_str(), dlr.total, dlr.received, dlr.started), ("http://search.test/?q=wipe", "http://files.test/tool.zip", "C:\\Users\\alice\\Downloads\\tool.zip", 1000, 400, T));
        assert_eq!(location("Cookie:alice@shop.test/"), Location::Cookie { user: "alice".into(), url: "shop.test/".into() });
    }

    #[test]
    fn web_sources() {
        let c = |p: &str| classify(p, "index.dat").map(|s| (s.user, s.profile));
        let h = "/Users/alice/AppData/Local/Microsoft/Windows/History";
        assert_eq!(c(&format!("{h}/History.IE5/index.dat")), Some(("alice".into(), "History".into())));
        assert_eq!(c(&format!("{h}/History.IE5/MSHist012011101920111020/index.dat")).unwrap().1, "History, day 2011-10-19");
        assert_eq!(c(&format!("{h}/History.IE5/MSHist012011101020111017/index.dat")).unwrap().1, "History, 2011-10-10 to 2011-10-17");
        assert_eq!(c(&format!("{h}/Low/History.IE5/index.dat")).unwrap().1, "History (protected mode)");
        assert_eq!(c("/Documents and Settings/bob/Local Settings/Temporary Internet Files/Content.IE5/index.dat"), Some(("bob".into(), "Cache".into())));
        assert_eq!(c("/Users/alice/AppData/Roaming/Microsoft/Windows/IEDownloadHistory/index.dat").unwrap().1, "Downloads");
        assert_eq!(c("/Users/alice/AppData/Roaming/Microsoft/Windows/Cookies/index.dat").unwrap().1, "Cookies");
        assert_eq!(c("/Users/alice/AppData/Roaming/Microsoft/Windows/Cookies/Low/index.dat").unwrap().1, "Cookies (protected mode)");
        assert!(c("/Users/alice/AppData/Roaming/Microsoft/Windows/IECompatCache/index.dat").is_none());
        let ck = cookie_text(b"sid\nabc123\nshop.test/\n1024\n3643744512\n30550353\n674454847\n30182824\n*\nlang\nen\nshop.test/\n0\n0\n0\n0\n0\n*\n");
        assert_eq!(ck.len(), 2);
        assert_eq!((ck[0].name.as_str(), ck[0].value.as_str(), ck[0].site.as_str(), ck[0].flags), ("sid", "abc123", "shop.test/", 1024));
        assert_eq!(kokino_core_iso(ck[0].created), "2011-10-18");
        assert_eq!(kokino_core_iso(ck[0].expires), "2016-10-18");
        assert_eq!(ck[1].created, 0);
        assert!(classify("/x/History.IE5/other.dat", "other.dat").is_none());
        assert_eq!(day_number("20111020").unwrap() - day_number("20111019").unwrap(), 1);
        assert_eq!(day_number("20120301").unwrap() - day_number("20120228").unwrap(), 2);

        let daily = index(&[], &[
            (url_record(":2011101920111020: alice@http://www.bing.com/search?q=wipe+disk&form=QBLH", "", T, T_LOCAL, 1, &[]), true),
            (url_record(":2011101920111020: alice@http://bank.test/", "", T + 10_009_954, T_LOCAL + 10_000_000, 1, &[]), true),
            (url_record(":2011101920111020: alice@:Host: bank.test", "", T, T_LOCAL, 1, &[]), true),
            (url_record(":2011101920111020: alice@http://gone.test/", "", T, T_LOCAL, 1, &[]), false),
        ]);
        let mut out = WebActivity::default();
        let mut src = classify(&format!("{h}/History.IE5/MSHist012011101920111020/index.dat"), "index.dat").unwrap();
        to_web(&mut src, &daily, &mut out).unwrap();
        assert_eq!((src.visits, src.searches, src.recovered), (3, 1, 1));
        assert!(src.note.contains("UTC+03:00"), "{}", src.note);
        assert_eq!(out.searches[0].term, "wipe disk");
        assert!(out.visits[2].recovered && out.visits.iter().all(|v| v.how == "visit"));

        let cache = index(&["AB12CD34"], &[(url_record("http://news.test/logo.png", "logo[1].png", T, 0, 3, b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\0"), true)]);
        let mut src = classify("/Users/alice/AppData/Local/Microsoft/Windows/Temporary Internet Files/Content.IE5/index.dat", "index.dat").unwrap();
        out.sources.push(WebSource::default());
        to_web(&mut src, &cache, &mut out).unwrap();
        assert_eq!((src.cached, src.visits), (1, 0));
        assert_eq!((out.cache[0].file.as_str(), out.cache[0].src), ("AB12CD34\\logo[1].png", 1));
    }

    #[test]
    fn free_space_lookalikes_are_rejected() {
        let good = url_record("Visited: alice@http://x.test/", "", T, T, 1, &[]);
        assert!(record(&good, 0).is_some());
        let mut bad = good.clone();
        bad[0x68] = 0x07; // control character in the URL
        assert!(record(&bad, 0).is_none());
        let mut bad = good.clone();
        bad[0x10..0x18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(record(&bad, 0).is_none());
        let mut bad = good.clone();
        bad[0x34..0x38].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(record(&bad, 0).is_none());
        assert!(record(b"URL \x01\0\0\0 and then text", 0).is_none());
        // Cut off by the end of the file before its data (found by fuzzing).
        let long = url_record("Visited: alice@http://x.test/", "", T, T, 1, &title_data(&"t".repeat(100)));
        let mut long = long;
        put32(&mut long, 0x44, 0x100);
        let cut = &long[..0x90];
        let r = record(cut, 0).unwrap();
        assert!(r.title.is_empty());
        assert!(parse(b"Client UrlCache MMF Ver 5.2\0").is_err());
        assert!(parse(b"not one").is_err());
    }
}
