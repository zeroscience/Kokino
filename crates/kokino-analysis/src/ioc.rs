//! Indicators of compromise as people paste them: one per line, recognized
//! by their form.
//!
//! - MD5, SHA-1 or SHA-256 (32, 40 or 64 hex digits);
//! - an IPv4 or IPv6 address;
//! - an email address;
//! - a URL (kept as its host) or a domain;
//! - anything else: a file name or, with a / or \ in it, a path fragment.
//!
//! Lines starting with # are comments; "value # note" keeps the note.
//! Defanged forms from reports (hxxp, [.], (.), [:], [@]) are read too.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_INDICATORS: usize = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Indicator {
    pub value: String,
    /// "md5", "sha1", "sha256", "ip", "email", "domain", "path", "name"
    pub kind: String,
    pub note: String,
}

/// The indicators in `text`, and the lines that could not be read.
pub fn parse(text: &str) -> (Vec<Indicator>, Vec<String>) {
    let mut out: Vec<Indicator> = vec![];
    let mut seen: HashSet<(&'static str, String)> = HashSet::new();
    let mut ignored = vec![];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() >= MAX_INDICATORS {
            ignored.push(format!("more than {} indicators: the rest were not read", MAX_INDICATORS));
            break;
        }
        let (v, note) = match line.split_once(" #") {
            Some((v, n)) => (v.trim(), n.trim()),
            None => (line, ""),
        };
        let mut v = v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@");
        let lower = v.get(..8).unwrap_or(&v).to_ascii_lowercase();
        if lower.starts_with("hxxp://") || lower.starts_with("hxxps://") {
            v.replace_range(..4, "http");
        }
        let v = v.trim_matches(|c: char| c == '"' || c == '\'' || c == ',').to_string();
        if v.is_empty() || v.len() > 500 {
            ignored.push(line.chars().take(100).collect());
            continue;
        }
        let kind = kind_of(&v);
        let value = match kind {
            "domain" => host(&v),
            "md5" | "sha1" | "sha256" | "email" => v.to_ascii_lowercase(),
            _ => v,
        };
        if value.is_empty() {
            ignored.push(line.chars().take(100).collect());
            continue;
        }
        if seen.insert((kind, value.to_lowercase())) {
            out.push(Indicator { value, kind: kind.into(), note: note.chars().take(200).collect() });
        }
    }
    (out, ignored)
}

fn kind_of(v: &str) -> &'static str {
    let hex = v.chars().all(|c| c.is_ascii_hexdigit());
    if hex && v.len() == 32 {
        "md5"
    } else if hex && v.len() == 40 {
        "sha1"
    } else if hex && v.len() == 64 {
        "sha256"
    } else if v.parse::<std::net::IpAddr>().is_ok() {
        "ip"
    } else if !v.contains('/') && v.split_once('@').is_some_and(|(u, d)| !u.is_empty() && d.contains('.')) {
        "email"
    } else if v.contains("://") {
        "domain"
    } else if v.contains('/') || v.contains('\\') {
        "path"
    } else if !v.contains(' ') && v.contains('.') && v.rsplit('.').next().is_some_and(|tld| tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())) && !looks_like_file(v) {
        "domain"
    } else {
        "name"
    }
}

/// "evil.exe", "report.docx": a file name, not a domain.
fn looks_like_file(v: &str) -> bool {
    let ext = v.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "jar" | "zip" | "rar" | "7z" | "doc" | "docx" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pdf" | "txt" | "lnk" | "iso" | "img" | "dmg" | "msi" | "py" | "sh" | "elf" | "so" | "dat" | "log" | "tmp" | "scr" | "hta" | "png" | "jpg" | "gif" | "plist" | "db" | "sqlite" | "pst" | "eml"
    )
}

/// The host of a URL, lower case ("HTTPS://user@Lab.test:8443/x" is "lab.test").
pub fn host(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let h = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    let h = if h.starts_with('[') { h } else { h.split(':').next().unwrap_or("") };
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether host `h` is domain `d` or one of its subdomains.
pub fn in_domain(h: &str, d: &str) -> bool {
    h == d || (h.len() > d.len() && h.ends_with(d) && h.as_bytes()[h.len() - d.len() - 1] == b'.')
}

/// The same IP address, in any notation (IPv4-mapped IPv6 included).
pub fn ip_eq(a: &str, b: &str) -> bool {
    use std::net::IpAddr;
    let ip = |s: &str| -> Option<IpAddr> {
        match s.trim().parse::<IpAddr>().ok()? {
            IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
            v4 => Some(v4),
        }
    };
    matches!((ip(a), ip(b)), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_indicators() {
        let (l, ign) = parse("# from the lab report\n198.51.100.7\nhxxps://c2[.]lab[.]test/a\nEvil.EXE # dropper\nC:\\Users\\Public\\x.ps1\nd41d8cd98f00b204e9800998ecf8427e\nALICE@lab.test\nlab.test\n2001:db8::1\n198.51.100.7\nhxxpd.exe\n");
        let got: Vec<(&str, &str)> = l.iter().map(|i| (i.kind.as_str(), i.value.as_str())).collect();
        assert_eq!(got, [("ip", "198.51.100.7"), ("domain", "c2.lab.test"), ("name", "Evil.EXE"), ("path", "C:\\Users\\Public\\x.ps1"), ("md5", "d41d8cd98f00b204e9800998ecf8427e"), ("email", "alice@lab.test"), ("domain", "lab.test"), ("ip", "2001:db8::1"), ("name", "hxxpd.exe")]);
        assert_eq!(l[2].note, "dropper");
        assert!(ign.is_empty());
        assert!(in_domain("downloads.lab.test", "lab.test") && !in_domain("notlab.test", "lab.test") && !in_domain("test", "lab.test"));
        assert_eq!(host("HTTPS://user@Lab.test:8443/x"), "lab.test");
        assert!(ip_eq("::ffff:192.0.2.1", "192.0.2.1") && ip_eq("::ffff:192.0.2.1", "::FFFF:192.0.2.1") && ip_eq("192.0.2.1", "::ffff:c000:201") && !ip_eq("192.0.2.1", "192.0.2.10"));
    }

    #[test]
    fn long_lists_stop_at_the_limit() {
        let text: String = (0..MAX_INDICATORS + 10).map(|i| format!("file{}.exe\n", i)).collect();
        let (l, ign) = parse(&text);
        assert_eq!(l.len(), MAX_INDICATORS);
        assert_eq!(ign.len(), 1);
    }
}
