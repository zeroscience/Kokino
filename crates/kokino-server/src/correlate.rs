//! Cross-evidence correlation: what two or more evidence items of a case
//! have in common. From each analyzed item: user names, computer names,
//! email addresses (senders and recipients), web domains (visits and
//! downloads), IP addresses (logons and events), USB device serial
//! numbers, wireless networks, and, where hash analysis was run, file
//! contents (SHA-256 of files of 1 KiB or more).
//!
//! Values are compared case-insensitively; each shared value lists the
//! evidence items it was found in and how many times.

use crate::state::AppState;
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_ITEMS: usize = 5_000;
const MIN_HASHED_SIZE: u64 = 1024;

#[derive(Debug, Serialize)]
pub struct Found {
    pub evidence: String,
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct Shared {
    pub kind: &'static str,
    pub value: String,
    pub found: Vec<Found>,
}

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub items: Vec<Shared>,
    /// Evidence items compared, and those left out (not analyzed yet).
    pub compared: Vec<String>,
    pub not_analyzed: Vec<String>,
    /// Items whose file contents were compared (hash analysis run).
    pub hashed: Vec<String>,
    pub truncated: bool,
}

fn emails(s: &str, out: &mut Vec<String>) {
    for w in s.split(|c: char| c.is_whitespace() || "<>,;\"'()[]".contains(c)) {
        let w = w.trim_matches('.');
        if let Some((l, d)) = w.split_once('@') {
            if !l.is_empty() && d.contains('.') && !d.starts_with('.') && w.len() < 120 && w.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-@".contains(c)) {
                out.push(w.to_ascii_lowercase());
            }
        }
    }
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let h = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?.split(':').next()?.to_ascii_lowercase();
    let h = h.strip_prefix("www.").unwrap_or(&h).to_string();
    (!h.is_empty() && h.contains('.')).then_some(h)
}

fn ip(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches("::ffff:");
    let v4 = s.parse::<std::net::Ipv4Addr>().ok().filter(|a| !a.is_loopback() && !a.is_unspecified()).map(|a| a.to_string());
    v4.or_else(|| s.parse::<std::net::Ipv6Addr>().ok().filter(|a| !a.is_loopback() && !a.is_unspecified()).map(|a| a.to_string()))
}

pub fn report(st: &AppState, cid: &str) -> anyhow::Result<Report> {
    let case = st.case(cid)?;
    let mut rep = Report::default();
    // (kind, value lowercased) -> (value as first seen, evidence id -> (name, count))
    let mut map: BTreeMap<(&'static str, String), (String, BTreeMap<String, (String, u64)>)> = BTreeMap::new();
    for rec in case.evidence() {
        let Ok(l) = st.loaded(cid, &rec.id) else {
            rep.not_analyzed.push(rec.name.clone());
            continue;
        };
        rep.compared.push(rec.name.clone());
        let mut add = |kind: &'static str, v: String| {
            let v = v.trim().to_string();
            if v.is_empty() || v.len() > 300 {
                return;
            }
            let slot = map.entry((kind, v.to_lowercase())).or_insert_with(|| (v.clone(), BTreeMap::new()));
            let e = slot.1.entry(rec.id.clone()).or_insert((rec.name.clone(), 0));
            e.1 += 1;
        };
        for f in &l.analysis.filesystems {
            for u in &f.stats.users {
                add("user", u.clone());
            }
            for u in f.linux.users.iter().filter(|u| u.login_shell && u.uid >= 500 || u.name == "root") {
                if u.name != "root" {
                    add("user", u.name.clone());
                }
            }
            add("computer", f.windows.computer.name.clone());
            add("computer", f.linux.computer.hostname.clone());
            for d in &f.windows.usb {
                if d.serial.len() > 6 && !d.serial.contains('&') {
                    add("USB serial", d.serial.clone());
                }
            }
            for d in &f.linux.usb {
                if d.serial.len() > 6 {
                    add("USB serial", d.serial.clone());
                }
            }
            for n in f.windows.networks.iter().chain(f.linux.networks.iter()) {
                if n.kind.to_ascii_lowercase().contains("wi") || n.kind.to_ascii_lowercase().contains("wireless") || n.kind == "802.11" {
                    add("wireless network", n.name.clone());
                }
            }
            for m in &f.mail.messages {
                let mut a = vec![];
                emails(&m.from, &mut a);
                emails(&m.to, &mut a);
                emails(&m.cc, &mut a);
                for x in a {
                    add("email address", x);
                }
            }
            for v in &f.web.visits {
                if let Some(h) = host(&v.url) {
                    add("web domain", h);
                }
            }
            for d in &f.web.downloads {
                if let Some(h) = host(&d.url) {
                    add("web domain", h);
                }
            }
            for e in &f.linux.events {
                if let Some(i) = ip(&e.ip) {
                    add("IP address", i);
                }
            }
            for x in &f.linux.logons {
                if let Some(i) = ip(&x.from) {
                    add("IP address", i);
                }
            }
            for e in &f.windows.events {
                if let Some(i) = ip(&e.ip) {
                    add("IP address", i);
                }
            }
        }
        if let Some(h) = st.hash_status(cid, &rec.id) {
            rep.hashed.push(rec.name.clone());
            for x in h.fh.files.iter().filter(|x| x.size >= MIN_HASHED_SIZE && !x.hashes.sha256.is_empty()) {
                add("file content (SHA-256)", x.hashes.sha256.clone());
            }
        }
    }
    let order = ["user", "computer", "email address", "IP address", "USB serial", "wireless network", "web domain", "file content (SHA-256)"];
    let mut items: Vec<Shared> = map
        .into_iter()
        .filter(|(_, (_, ev))| ev.len() >= 2)
        .map(|((kind, _), (value, ev))| Shared { kind, value, found: ev.into_iter().map(|(id, (name, count))| Found { evidence: id, name, count }).collect() })
        .collect();
    items.sort_by(|a, b| {
        let k = |x: &Shared| order.iter().position(|o| *o == x.kind).unwrap_or(99);
        k(a).cmp(&k(b)).then(b.found.len().cmp(&a.found.len())).then(a.value.to_lowercase().cmp(&b.value.to_lowercase()))
    });
    rep.truncated = items.len() > MAX_ITEMS;
    items.truncate(MAX_ITEMS);
    rep.items = items;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_values() {
        let mut a = vec![];
        emails("Alice Lab <Alice@Lab.test>, bob@lab.test; \"x\" <not an address>", &mut a);
        assert_eq!(a, ["alice@lab.test", "bob@lab.test"]);
        assert_eq!(host("https://www.Lab.test:8443/a?b").as_deref(), Some("lab.test"));
        assert_eq!(host("about:blank"), None);
        assert_eq!(ip("192.0.2.10").as_deref(), Some("192.0.2.10"));
        assert_eq!(ip("127.0.0.1"), None);
        assert_eq!(ip("lab-srv"), None);
    }

    /// Two evidence items of one case: the Windows test disk and the same
    /// artifacts collected by KAPE share the computer, user, networks...
    #[test]
    fn shared_between_evidence() {
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let root = std::env::temp_dir().join(format!("kokino-correlate-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let st = AppState::new(root.clone(), 7311, false, vec![]).unwrap();
        let case = kokino_core::case::Case::create(&root, "Correlate", "tester", "").unwrap();
        let cid = case.info.id.clone();
        for (id, f) in [("e1", "disk-win.img"), ("e2", "collection-kape.zip"), ("e3", "linux-server.img")] {
            let p = fx.join(f);
            let ev = kokino_image::Evidence::open(&p).unwrap();
            let rec = kokino_core::case::EvidenceRecord { id: id.into(), name: f.into(), path: p.display().to_string(), format: ev.format_label(), size: ev.size, added: String::new(), notes: String::new(), hashes: None, hashed_at: None, expected: None, embedded: None, acquisition: None };
            case.save_evidence(&rec).unwrap();
            let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true).unwrap();
            st.put(&cid, id, a, ev);
        }
        let r = report(&st, &cid).unwrap();
        assert_eq!(r.compared.len(), 3);
        let has = |kind: &str, v: &str| r.items.iter().find(|x| x.kind == kind && x.value.eq_ignore_ascii_case(v)).map(|x| x.found.iter().map(|f| f.evidence.as_str()).collect::<Vec<_>>());
        assert_eq!(has("computer", "lab-pc"), Some(vec!["e1", "e2"]));
        assert_eq!(has("user", "alice").map(|v| v.len()), Some(3), "{:?}", r.items.iter().filter(|x| x.kind == "user").collect::<Vec<_>>());
        assert!(r.items.iter().all(|x| x.found.len() >= 2));
        std::fs::remove_dir_all(&root).ok();
    }
}
