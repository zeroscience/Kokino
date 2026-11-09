//! WebCache (WebCacheV01.dat, WebCacheV24.dat): the ESE database Internet
//! Explorer 10 and 11 and the old Edge keep in
//! %LOCALAPPDATA%\Microsoft\Windows\WebCache, in place of index.dat.
//!
//! The Containers table names each container (History, MSHist01... daily
//! and weekly history, Content, Cookies, iedownload, DOMStore...); each
//! container's entries are in the table Container_<id>, with the same URL
//! forms as index.dat ("Visited: user@url", ":20261020...: user@url",
//! "Cookie:user@site/", "iedownload:{...}") and FILETIME times. A download's
//! address, referrer and saved path are UTF-16 strings at the end of its
//! ResponseHeaders.
//!
//! The database is normally in use when copied ("dirty"): the newest
//! entries may still be only in its V01*.log files, which are not replayed.

use crate::browser::{CacheEntry, Cookie, Download, Engine, Search, Visit, WebActivity, WebSource};
use crate::ese::{Db, Value};
use crate::iecache::{location, Location};

const MAX_ROWS: usize = 2_000_000;

pub fn classify(path: &str, name: &str) -> Option<WebSource> {
    let n = name.to_ascii_lowercase();
    if !(n.starts_with("webcachev") && n.ends_with(".dat")) || !path.to_ascii_lowercase().contains("/microsoft/windows/webcache/") {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let user = parts.iter().position(|p| p.eq_ignore_ascii_case("Users")).and_then(|i| parts.get(i + 1)).map(|s| s.to_string()).unwrap_or_default();
    Some(WebSource { browser: "Internet Explorer / Edge (WebCache)".into(), engine: Some(Engine::Ie), user, profile: "WebCache".into(), path: path.to_string(), ..Default::default() })
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::Text(s)) => s.trim_end_matches('\0').to_string(),
        Some(Value::Bytes(b)) if b.len() % 2 == 0 => {
            let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&w).trim_end_matches('\0').to_string()
        }
        _ => String::new(),
    }
}

fn int(v: Option<&Value>) -> i64 {
    v.and_then(|x| x.i64()).unwrap_or(0)
}

fn time(v: Option<&Value>) -> u64 {
    let t = int(v);
    if t > 0 {
        t as u64
    } else {
        0
    }
}

/// UTF-16 strings of 4 characters or more in a blob.
fn utf16_strings(b: &[u8]) -> Vec<String> {
    let mut out = vec![];
    for start in [0usize, 1] {
        let w: Vec<u16> = b.get(start..).unwrap_or(&[]).chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let mut cur = String::new();
        for c in w {
            match char::from_u32(c as u32) {
                Some(ch) if c >= 0x20 && c != 0xFFFF => cur.push(ch),
                _ => {
                    if cur.chars().count() >= 4 {
                        out.push(std::mem::take(&mut cur));
                    }
                    cur.clear();
                }
            }
        }
        if cur.chars().count() >= 4 {
            out.push(cur);
        }
        if out.iter().any(|s| s.contains("://")) {
            break;
        }
    }
    out
}

pub fn to_web(src: &mut WebSource, d: &[u8], out: &mut WebActivity) -> anyhow::Result<()> {
    let db = Db::open(d)?;
    if db.dirty() {
        src.note = "The database was in use when copied (dirty): its newest entries may be only in the V01*.log files next to it, which are not read.".into();
    }
    let ct = db.table("Containers").ok_or_else(|| anyhow::anyhow!("no Containers table: not a WebCache database"))?;
    let idx = out.sources.len() as u32;
    let (v0, c0, k0, d0) = (out.visits.len(), out.cache.len(), out.cookies.len(), out.downloads.len());
    let mut total = 0usize;
    for c in db.rows(ct, 10_000) {
        let id = int(c.get("ContainerId"));
        let name = text(c.get("Name"));
        let Some(t) = db.table(&format!("Container_{}", id)) else { continue };
        let kind = if name == "History" || name.starts_with("MSHist") {
            "history"
        } else if name == "Content" {
            "content"
        } else if name == "Cookies" {
            "cookies"
        } else if name == "iedownload" {
            "download"
        } else {
            continue;
        };
        for e in db.rows(t, MAX_ROWS.saturating_sub(total)) {
            total += 1;
            let url = text(e.get("Url"));
            let accessed = time(e.get("AccessedTime"));
            match (kind, location(&url)) {
                ("history", Location::History { url, period, .. }) => {
                    out.visits.push(Visit { t: accessed, src: idx, url, title: String::new(), how: if period.is_none() { "last visit" } else { "visit" }.into(), typed: false, visit_count: int(e.get("AccessCount")), duration_ms: 0, url_only: false, recovered: false });
                }
                ("content", Location::Url(u)) => {
                    let headers = e.get("ResponseHeaders").and_then(|v| v.bytes()).map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
                    let ctype = headers.lines().find_map(|l| l.strip_prefix("Content-Type:").or_else(|| l.strip_prefix("content-type:"))).map(|s| s.trim().to_string()).unwrap_or_default();
                    out.cache.push(CacheEntry { t: accessed, modified: time(e.get("ModifiedTime")), src: idx, url: u, file: text(e.get("Filename")), content_type: ctype, hits: int(e.get("AccessCount")).max(0) as u32, recovered: false, leak: false });
                }
                ("cookies", Location::Cookie { url, .. }) => {
                    out.cookies.push(Cookie { src: idx, site: url, created: time(e.get("CreationTime")), expires: time(e.get("ExpiryTime")), last_access: accessed, file: text(e.get("Filename")), ..Default::default() });
                }
                ("download", _) => {
                    let strings = e.get("ResponseHeaders").and_then(|v| v.bytes()).map(utf16_strings).unwrap_or_default();
                    let urls: Vec<&String> = strings.iter().filter(|s| s.contains("://")).collect();
                    let target = strings.iter().find(|s| s.len() > 3 && (s.as_bytes()[1] == b':' && s.as_bytes()[2] == b'\\' || s.starts_with("\\\\"))).cloned().unwrap_or_default();
                    let size = int(e.get("FileSize"));
                    out.downloads.push(Download {
                        start: time(e.get("CreationTime")),
                        end: accessed,
                        src: idx,
                        url: urls.first().map(|s| s.to_string()).unwrap_or_default(),
                        referrer: urls.get(1).map(|s| s.to_string()).unwrap_or_default(),
                        target,
                        received: size,
                        total: size,
                        state: "recorded".into(),
                        danger: String::new(),
                        mime: String::new(),
                        opened: false,
                    });
                }
                _ => {}
            }
        }
    }
    // Search terms from visited search pages.
    let found: Vec<Search> = out.visits[v0..]
        .iter()
        .filter_map(|v| {
            let (engine, term) = crate::browser::search_in_url(&v.url)?;
            Some(Search { t: v.t, src: idx, term, engine, url: v.url.clone(), how: "url".into() })
        })
        .collect();
    src.searches = found.len() as u64;
    out.searches.extend(found);
    src.visits = (out.visits.len() - v0) as u64;
    src.cached = (out.cache.len() - c0) as u64;
    src.cookies = (out.cookies.len() - k0) as u64;
    src.downloads = (out.downloads.len() - d0) as u64;
    let times = out.visits[v0..].iter().map(|v| v.t).chain(out.downloads[d0..].iter().map(|d| d.start)).filter(|&t| t > 0);
    src.oldest = times.clone().min().unwrap_or(0);
    src.newest = times.max().unwrap_or(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tests/fixtures/win/WebCacheV01.dat, written by esent.dll
    /// (scripts/make_webcache_fixture.py).
    #[test]
    fn reads_webcache() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win/WebCacheV01.dat");
        let d = std::fs::read(&p).expect("run scripts/make_webcache_fixture.py on Windows");
        let path = "/Users/alice/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat";
        let mut src = classify(path, "WebCacheV01.dat").unwrap();
        assert_eq!(src.user, "alice");
        let mut out = WebActivity::default();
        to_web(&mut src, &d, &mut out).unwrap();
        let ft = |m: i64| (crate::bin::unix_to_filetime(1_792_483_530 + m * 60).unwrap());
        let mut v: Vec<(&str, &str, u64)> = out.visits.iter().map(|x| (x.url.as_str(), x.how.as_str(), x.t)).collect();
        v.sort_by_key(|x| x.2);
        assert_eq!(v, [("https://www.bing.com/search?q=sdelete+download&form=QBLH", "last visit", ft(10)), ("https://downloads.lab.test/tools.zip", "last visit", ft(12)), ("https://lab.test/admin", "visit", ft(30))]);
        assert_eq!(out.searches.iter().map(|s| s.term.as_str()).collect::<Vec<_>>(), ["sdelete download"]);
        let c = &out.cache[0];
        assert_eq!((c.url.as_str(), c.file.as_str(), c.content_type.as_str(), c.t), ("https://lab.test/logo.png", "logo[1].png", "image/png", ft(11)));
        let k = &out.cookies[0];
        assert_eq!((k.site.as_str(), k.file.as_str(), k.created), ("lab.test/", "QX7LAB01.cookie", ft(11)));
        let dl = &out.downloads[0];
        assert_eq!((dl.url.as_str(), dl.referrer.as_str(), dl.target.as_str(), dl.total), ("https://downloads.lab.test/tools.zip", "https://lab.test/tools", "C:\\Users\\alice\\Downloads\\tools.zip", 1_234_567));
        assert_eq!((src.visits, src.cached, src.cookies, src.downloads, src.searches), (3, 1, 1, 1, 1));
        assert!(to_web(&mut src.clone(), b"not a database", &mut WebActivity::default()).is_err());
    }
}
