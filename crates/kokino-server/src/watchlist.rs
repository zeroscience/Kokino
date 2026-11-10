//! Watchlist (IOC sweep): a list of indicators searched in every analyzed
//! evidence item of a case at once.
//!
//! Each line is one indicator, recognized by its form:
//! - MD5, SHA-1 or SHA-256 (32, 40 or 64 hex digits): file contents, from
//!   the hashes taken at analysis;
//! - an IPv4 or IPv6 address: logons and events (Windows, Linux, macOS);
//! - an email address: senders and recipients of email;
//! - a URL or a domain: web visits, downloads, cache and cookies (the
//!   domain and its subdomains), email addresses at that domain, and files
//!   of that exact name ("ld.so.preload" looks like a domain);
//! - anything else: a file name (exact, any case) or, with a / or \ in it,
//!   a path fragment; deleted files included.
//!
//! Lines starting with # are comments; "value # note" keeps the note. The
//! parsing is kokino_analysis::ioc.

use crate::state::AppState;
use serde::Serialize;

pub use kokino_analysis::ioc::{parse, Indicator};
use kokino_analysis::ioc::{host, in_domain, ip_eq};

const MAX_HITS_PER: usize = 500;

#[derive(Debug, Serialize)]
pub struct Hit {
    pub evidence: String,
    pub evidence_name: String,
    pub fi: usize,
    /// "file", "web", "mail", "event", "logon"
    pub what: String,
    pub detail: String,
    /// File index for files, so the GUI can open it.
    pub file: Option<usize>,
    pub time: String,
    pub deleted: bool,
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
}

pub fn sweep(st: &AppState, cid: &str, list: &[Indicator]) -> anyhow::Result<Report> {
    let case = st.case(cid)?;
    let mut rep = Report::default();
    let mut results: Vec<Matches> = list.iter().cloned().map(|indicator| Matches { indicator, hits: vec![], truncated: false }).collect();
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
        for res in results.iter_mut() {
            let ind = &res.indicator;
            let push = |h: Hit, res_hits: &mut Vec<Hit>, trunc: &mut bool| {
                if res_hits.len() < MAX_HITS_PER {
                    res_hits.push(h);
                } else {
                    *trunc = true;
                }
            };
            let mk = |fi: usize, what: &str, detail: String, file: Option<usize>, time: String, deleted: bool| Hit { evidence: rec.id.clone(), evidence_name: rec.name.clone(), fi, what: what.into(), detail, file, time, deleted };
            for (fi, f) in l.analysis.filesystems.iter().enumerate() {
                match ind.kind.as_str() {
                    "md5" | "sha1" | "sha256" => {
                        let Some(h) = &hs else { continue };
                        for x in h.fh.files.iter().filter(|x| x.fi == fi) {
                            let v = match ind.kind.as_str() {
                                "md5" => &x.hashes.md5,
                                "sha1" => &x.hashes.sha1,
                                _ => &x.hashes.sha256,
                            };
                            if v.eq_ignore_ascii_case(&ind.value) {
                                if let Some(idx) = f.files.iter().position(|r| r.e.record == x.record) {
                                    let r = &f.files[idx];
                                    push(mk(fi, "file", r.e.path.clone(), Some(idx), iso(r.e.si.map(|t| t.modified).unwrap_or(0)), r.e.deleted), &mut res.hits, &mut res.truncated);
                                }
                            }
                        }
                    }
                    "name" | "path" => {
                        let needle = ind.value.replace('\\', "/").to_lowercase();
                        for (idx, r) in f.files.iter().enumerate() {
                            let hit = if ind.kind == "name" { r.e.name.eq_ignore_ascii_case(&ind.value) } else { r.e.path.to_lowercase().contains(&needle) };
                            if hit {
                                push(mk(fi, "file", r.e.path.clone(), Some(idx), iso(r.e.si.map(|t| t.modified).unwrap_or(0)), r.e.deleted), &mut res.hits, &mut res.truncated);
                            }
                        }
                    }
                    "domain" => {
                        // "ld.so.preload" reads as a domain too: a file of that name is a hit.
                        for (idx, r) in f.files.iter().enumerate().filter(|(_, r)| r.e.name.eq_ignore_ascii_case(&ind.value)) {
                            push(mk(fi, "file", r.e.path.clone(), Some(idx), iso(r.e.si.map(|t| t.modified).unwrap_or(0)), r.e.deleted), &mut res.hits, &mut res.truncated);
                        }
                        let w = &f.web;
                        for v in w.visits.iter().filter(|v| in_domain(&host(&v.url), &ind.value)) {
                            push(mk(fi, "web", format!("visit {}", v.url), None, iso(v.t), false), &mut res.hits, &mut res.truncated);
                        }
                        for d in w.downloads.iter().filter(|d| in_domain(&host(&d.url), &ind.value)) {
                            push(mk(fi, "web", format!("download {} to {}", d.url, d.target), None, iso(d.start), false), &mut res.hits, &mut res.truncated);
                        }
                        for c in w.cache.iter().filter(|c| in_domain(&host(&c.url), &ind.value)) {
                            push(mk(fi, "web", format!("cached {}", c.url), None, iso(c.t), false), &mut res.hits, &mut res.truncated);
                        }
                        for c in w.cookies.iter().filter(|c| in_domain(&host(&format!("x://{}", c.site)), &ind.value)) {
                            push(mk(fi, "web", format!("cookie {}", c.site), None, iso(c.last_access.max(c.created)), false), &mut res.hits, &mut res.truncated);
                        }
                        for m in f.mail.messages.iter().filter(|m| [&m.from, &m.to, &m.cc].iter().any(|s| s.to_lowercase().contains(&format!("@{}", ind.value)))) {
                            push(mk(fi, "mail", format!("{}: from {} to {}", m.subject, m.from, m.to), None, iso(m.date), m.deleted || m.expunged), &mut res.hits, &mut res.truncated);
                        }
                    }
                    "email" => {
                        for m in f.mail.messages.iter().filter(|m| [&m.from, &m.to, &m.cc].iter().any(|s| s.to_lowercase().contains(&ind.value))) {
                            push(mk(fi, "mail", format!("{}: from {} to {}", m.subject, m.from, m.to), None, iso(m.date), m.deleted || m.expunged), &mut res.hits, &mut res.truncated);
                        }
                    }
                    "ip" => {
                        for e in f.windows.events.iter().filter(|e| ip_eq(&e.ip, &ind.value)) {
                            push(mk(fi, "event", format!("{} ({} {})", e.summary, e.channel, e.event_id), None, iso(e.time), false), &mut res.hits, &mut res.truncated);
                        }
                        for e in f.linux.events.iter().filter(|e| ip_eq(&e.ip, &ind.value)) {
                            push(mk(fi, "event", format!("{} ({})", e.summary, e.source), None, iso(e.time), false), &mut res.hits, &mut res.truncated);
                        }
                        for x in f.linux.logons.iter().filter(|x| ip_eq(&x.from, &ind.value)) {
                            push(mk(fi, "logon", format!("{} {} from {} ({})", x.kind, x.user, x.from, x.source), None, iso(x.time), false), &mut res.hits, &mut res.truncated);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    rep.results = results;
    Ok(rep)
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
        std::fs::remove_dir_all(&root).ok();
    }
}
