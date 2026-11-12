//! Watchlist (IOC sweep): a list of indicators searched in every analyzed
//! evidence item of a case at once.
//!
//! The list is pasted lines, a STIX 2.1 bundle or a MISP event export
//! (kokino_analysis::ioc reads them). What each kind is looked for in:
//! - MD5, SHA-1, SHA-256: file contents, from the hashes Hash analysis took;
//! - IP addresses and networks: Windows and Linux events and logons, and web
//!   addresses that are IP addresses;
//! - email addresses: senders and recipients of email;
//! - domains (and URLs, by their host): web visits, downloads, cache and
//!   cookies of the domain and its subdomains, email addresses at the
//!   domain, and files of that exact name ("ld.so.preload" looks like a
//!   domain);
//! - file names (exact, any case) and path fragments; deleted files included;
//! - and in the rows plugins reported (their text and fields, word by word).
//!
//! Each sweep is compared with the one before it: hits it did not have are
//! marked new.

use crate::state::AppState;
use kokino_analysis::ioc::Matcher;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub use kokino_analysis::ioc::{format_of, parse, Indicator};

const MAX_HITS_PER: usize = 500;

#[derive(Debug, Serialize)]
pub struct Hit {
    pub evidence: String,
    pub evidence_name: String,
    pub fi: usize,
    /// "file", "web", "mail", "event", "logon", "plugin"
    pub what: String,
    pub detail: String,
    /// File index for files, so the GUI can open it.
    pub file: Option<usize>,
    pub time: String,
    pub deleted: bool,
    /// Not found by the previous sweep.
    pub new: bool,
}

impl Hit {
    fn key(&self) -> String {
        format!("{}|{}|{}|{}|{}", self.evidence, self.fi, self.what, self.detail, self.time)
    }
}

#[derive(Debug, Serialize)]
pub struct Matches {
    pub indicator: Indicator,
    pub hits: Vec<Hit>,
    pub truncated: bool,
}

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub results: Vec<Matches>,
    pub searched: Vec<String>,
    pub not_analyzed: Vec<String>,
    /// Items without file hashes (hash indicators cannot match there).
    pub not_hashed: Vec<String>,
    pub ignored: Vec<String>,
    /// "lines", "stix" or "misp".
    pub format: String,
    /// The sweep this one was compared with.
    pub previous: Option<Previous>,
    pub new_hits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Previous {
    pub at: String,
    pub by: String,
    pub indicators: usize,
    pub hits: usize,
}

/// What a sweep found, kept with the case to compare the next one with.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Last {
    pub at: String,
    pub by: String,
    /// Hit keys per indicator ("kind:value").
    pub hits: HashMap<String, Vec<String>>,
}

fn ind_key(i: &Indicator) -> String {
    format!("{}:{}", i.kind, i.value.to_lowercase())
}

pub fn sweep(st: &AppState, cid: &str, list: &[Indicator]) -> anyhow::Result<Report> {
    let case = st.case(cid)?;
    let mut rep = Report::default();
    let mut results: Vec<Matches> = list.iter().cloned().map(|indicator| Matches { indicator, hits: vec![], truncated: false }).collect();
    let m = Matcher::new(list);
    let iso = |t: u64| if t == 0 { String::new() } else { kokino_core::time::filetime_to_iso(t) };
    for rec in case.evidence() {
        let Ok(l) = st.loaded(cid, &rec.id) else {
            rep.not_analyzed.push(rec.name.clone());
            continue;
        };
        rep.searched.push(rec.name.clone());
        let hs = st.hash_status(cid, &rec.id);
        if hs.is_none() {
            rep.not_hashed.push(rec.name.clone());
        }
        let mut add = |idx: &[usize], fi: usize, what: &str, detail: &dyn Fn() -> String, file: Option<usize>, time: String, deleted: bool| {
            let mut seen = HashSet::new();
            for &i in idx {
                if !seen.insert(i) {
                    continue;
                }
                let r = &mut results[i];
                if r.hits.len() < MAX_HITS_PER {
                    r.hits.push(Hit { evidence: rec.id.clone(), evidence_name: rec.name.clone(), fi, what: what.into(), detail: detail(), file, time: time.clone(), deleted, new: false });
                } else {
                    r.truncated = true;
                }
            }
        };
        for (fi, f) in l.analysis.filesystems.iter().enumerate() {
            let mtime = |r: &kokino_analysis::FileRow| iso(r.e.si.map(|t| t.modified).unwrap_or(0));
            for (idx, r) in f.files.iter().enumerate() {
                let hit = m.file(&r.e.name, &r.e.path);
                if !hit.is_empty() {
                    add(&hit, fi, "file", &|| r.e.path.clone(), Some(idx), mtime(r), r.e.deleted);
                }
            }
            if let (Some(h), true) = (&hs, m.has_hashes()) {
                let by_record: HashMap<u64, usize> = f.files.iter().enumerate().map(|(i, r)| (r.e.record, i)).collect();
                for x in h.fh.files.iter().filter(|x| x.fi == fi) {
                    let mut hit: Vec<usize> = m.hash(&x.hashes.md5).to_vec();
                    hit.extend(m.hash(&x.hashes.sha1));
                    hit.extend(m.hash(&x.hashes.sha256));
                    if hit.is_empty() {
                        continue;
                    }
                    if let Some(&idx) = by_record.get(&x.record) {
                        let r = &f.files[idx];
                        add(&hit, fi, "file", &|| r.e.path.clone(), Some(idx), mtime(r), r.e.deleted);
                    }
                }
            }
            let w = &f.web;
            for v in &w.visits {
                add(&m.url(&v.url), fi, "web", &|| format!("visit {}", v.url), None, iso(v.t), false);
            }
            for d in &w.downloads {
                add(&m.url(&d.url), fi, "web", &|| format!("download {} to {}", d.url, d.target), None, iso(d.start), false);
            }
            for c in &w.cache {
                add(&m.url(&c.url), fi, "web", &|| format!("cached {}", c.url), None, iso(c.t), false);
            }
            for c in &w.cookies {
                add(&m.host(c.site.trim_start_matches('.')), fi, "web", &|| format!("cookie {}", c.site), None, iso(c.last_access.max(c.created)), false);
            }
            for msg in &f.mail.messages {
                let mut hit = m.mail_field(&msg.from);
                hit.extend(m.mail_field(&msg.to));
                hit.extend(m.mail_field(&msg.cc));
                add(&hit, fi, "mail", &|| format!("{}: from {} to {}", msg.subject, msg.from, msg.to), None, iso(msg.date), msg.deleted || msg.expunged);
            }
            for e in &f.windows.events {
                add(&m.ip(&e.ip), fi, "event", &|| format!("{} ({} {})", e.summary, e.channel, e.event_id), None, iso(e.time), false);
            }
            for e in &f.linux.events {
                add(&m.ip(&e.ip), fi, "event", &|| format!("{} ({})", e.summary, e.source), None, iso(e.time), false);
            }
            for x in &f.linux.logons {
                add(&m.ip(&x.from), fi, "logon", &|| format!("{} {} from {} ({})", x.kind, x.user, x.from, x.source), None, iso(x.time), false);
            }
        }
        // What plugins reported: every word of a row's text and fields.
        if let Some(p) = st.plugin_rows(cid, &rec.id) {
            for run in &p.results.runs {
                for row in &run.rows {
                    let hit = plugin_row_hits(&m, row);
                    if !hit.is_empty() {
                        let t = kokino_analysis::plugins::row_time(&row.time).map(iso).unwrap_or_default();
                        add(&hit, row.fi, "plugin", &|| format!("{}: {} ({})", run.name, row.what, row.path), Some(row.file), t, false);
                    }
                }
            }
        }
    }
    rep.results = results;
    Ok(rep)
}

/// Indicators found in a plugin row, word by word: addresses, URLs and hosts,
/// email addresses, hashes, and paths or names.
fn plugin_row_hits(m: &Matcher, row: &kokino_analysis::plugins::Row) -> Vec<usize> {
    let mut texts: Vec<&str> = vec![&row.what, &row.detail];
    for v in row.fields.values() {
        if let Some(s) = v.as_str() {
            texts.push(s);
        }
    }
    let mut out = vec![];
    for t in texts {
        for w in t.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}')).take(10_000) {
            let w = w.trim_matches(|c: char| matches!(c, '.' | ':' | '|'));
            if w.len() < 3 {
                continue;
            }
            out.extend(m.ip(w));
            // host:port, [v6]:port
            if w.contains(':') && !w.contains("://") {
                let h = kokino_analysis::ioc::host(w);
                if h != w {
                    out.extend(m.host(h.trim_start_matches('[').trim_end_matches(']')));
                }
            }
            if w.contains("://") {
                out.extend(m.url(w));
            } else if w.contains('@') {
                out.extend(m.mail_field(w));
            } else if w.contains('.') && !w.contains('/') && !w.contains('\\') {
                out.extend(m.host(w));
            }
            if matches!(w.len(), 32 | 40 | 64) && w.chars().all(|c| c.is_ascii_hexdigit()) {
                out.extend(m.hash(w));
            }
            if w.contains('/') || w.contains('\\') || w.contains('.') {
                let name = w.rsplit(['/', '\\']).next().unwrap_or(w);
                out.extend(m.file(name, &w.replace('\\', "/")));
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Marks the hits the previous sweep did not have (all of them for an
/// indicator it did not search for), and returns what to keep for the next.
pub fn compare(rep: &mut Report, prev: Option<Last>, by: &str, at: &str) -> Last {
    let mut new_hits = 0;
    if let Some(p) = &prev {
        let total: usize = p.hits.values().map(Vec::len).sum();
        rep.previous = Some(Previous { at: p.at.clone(), by: p.by.clone(), indicators: p.hits.len(), hits: total });
        for r in rep.results.iter_mut() {
            let old: HashSet<&str> = p.hits.get(&ind_key(&r.indicator)).map(|v| v.iter().map(String::as_str).collect()).unwrap_or_default();
            for h in r.hits.iter_mut() {
                if !old.contains(h.key().as_str()) {
                    h.new = true;
                    new_hits += 1;
                }
            }
        }
    }
    rep.new_hits = new_hits;
    Last { at: at.into(), by: by.into(), hits: rep.results.iter().map(|r| (ind_key(&r.indicator), r.hits.iter().map(Hit::key).collect())).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Linux server and the UAC collection of it: an IP from the logs,
    /// a file name, a domain and an email address found in both.
    #[test]
    fn sweeps_a_case() {
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let root = std::env::temp_dir().join(format!("kokino-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let st = AppState::new(root.clone(), 7311, false, vec![]).unwrap();
        let case = kokino_core::case::Case::create(&root, "Watch", "tester", "").unwrap();
        let cid = case.info.id.clone();
        for (id, f) in [("e1", "linux-server.img"), ("e2", "collection-uac.tar.gz")] {
            let p = fx.join(f);
            let ev = kokino_image::Evidence::open(&p).unwrap();
            let rec = kokino_core::case::EvidenceRecord { id: id.into(), name: f.into(), path: p.display().to_string(), format: ev.format_label(), size: ev.size, added: String::new(), notes: String::new(), hashes: None, hashed_at: None, expected: None, embedded: None, acquisition: None };
            case.save_evidence(&rec).unwrap();
            let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true).unwrap();
            st.put(&cid, id, a, ev);
        }
        let (list, _) = parse("192.0.2.10\nld.so.preload\n/home/alice/.ssh/authorized_keys\nnobody-here.test\n");
        let r = sweep(&st, &cid, &list).unwrap();
        let count = |i: usize, ev: &str| r.results[i].hits.iter().filter(|h| h.evidence == ev).count();
        assert!(count(0, "e1") > 0 && count(0, "e2") > 0, "IP in both: {:?}", r.results[0].hits);
        assert!(count(1, "e1") == 1 && count(1, "e2") == 1, "{:?}", r.results[1].hits.iter().map(|h| (&h.evidence, &h.detail)).collect::<Vec<_>>());
        assert_eq!(count(2, "e1"), 1);
        assert_eq!(count(2, "e2"), 1, "the collection keeps the path under [root]");
        assert!(r.results[3].hits.is_empty());
        // Compared with a sweep that only had the IP's first hit: the rest are new.
        let mut r = r;
        let first = r.results[0].hits[0].key();
        let prev = Last { at: "2026-11-10T09:00:00Z".into(), by: "tester".into(), hits: [(ind_key(&r.results[0].indicator), vec![first])].into_iter().collect() };
        let last = compare(&mut r, Some(prev), "tester", "2026-11-11T09:00:00Z");
        assert!(!r.results[0].hits[0].new && r.results[0].hits[1..].iter().all(|h| h.new));
        assert!(r.results[1].hits.iter().all(|h| h.new), "an indicator not in the previous sweep");
        assert_eq!(r.new_hits, r.results.iter().map(|x| x.hits.len()).sum::<usize>() - 1);
        assert_eq!(last.hits.len(), 4);
        std::fs::remove_dir_all(&root).ok();
    }
}
