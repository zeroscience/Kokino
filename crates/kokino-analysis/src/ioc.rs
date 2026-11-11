//! Indicators of compromise as people bring them: pasted lines, a STIX 2.1
//! bundle or a MISP event export.
//!
//! Lines are recognized by their form:
//! - MD5, SHA-1 or SHA-256 (32, 40 or 64 hex digits);
//! - an IPv4 or IPv6 address, or a network in CIDR form (198.51.100.0/24);
//! - an email address;
//! - a URL (kept as its host) or a domain;
//! - anything else: a file name or, with a / or \ in it, a path fragment.
//!
//! Lines starting with # are comments; "value # note" keeps the note.
//! Defanged forms from reports (hxxp, [.], (.), [:], [@]) are read too.
//!
//! A STIX 2.1 bundle gives its indicators' patterns (file hashes and names,
//! IPv4 and IPv6 addresses and networks, domain names, URLs, email
//! addresses) and the same kinds of observable objects; the indicator's name
//! becomes the note. A MISP event (or a list of events, as the REST API
//! returns them) gives its attributes and its objects' attributes, deleted
//! ones left out; the category and comment become the note.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const MAX_INDICATORS: usize = 50_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Indicator {
    pub value: String,
    /// "md5", "sha1", "sha256", "ip", "email", "domain", "path", "name"
    pub kind: String,
    pub note: String,
}

/// What a text was read as: "lines", "stix" or "misp".
pub fn format_of(text: &str) -> &'static str {
    match serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')) {
        Ok(v) if is_stix(&v) => "stix",
        Ok(v) if is_misp(&v) => "misp",
        _ => "lines",
    }
}

/// The indicators in `text`, and what could not be read.
pub fn parse(text: &str) -> (Vec<Indicator>, Vec<String>) {
    let mut b = Builder::default();
    let t = text.trim_start_matches('\u{feff}');
    let first = t.trim_start().chars().next();
    if matches!(first, Some('{') | Some('[')) {
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            if is_stix(&v) {
                stix(&v, &mut b);
                return b.done();
            }
            if is_misp(&v) {
                misp(&v, &mut b);
                return b.done();
            }
        }
    }
    for line in t.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (v, note) = match line.split_once(" #") {
            Some((v, n)) => (v.trim(), n.trim()),
            None => (line, ""),
        };
        if !b.add(v, note, None) {
            break;
        }
    }
    b.done()
}

#[derive(Default)]
struct Builder {
    out: Vec<Indicator>,
    seen: HashSet<(&'static str, String)>,
    ignored: Vec<String>,
    full: bool,
}

impl Builder {
    /// Adds one value; `hint` is the kind the source says it is. False once
    /// the list is full.
    fn add(&mut self, raw: &str, note: &str, hint: Option<&'static str>) -> bool {
        if self.full {
            return false;
        }
        if self.out.len() >= MAX_INDICATORS {
            self.ignored.push(format!("more than {} indicators: the rest were not read", MAX_INDICATORS));
            self.full = true;
            return false;
        }
        let v = refang(raw);
        if v.is_empty() || v.len() > 500 {
            if self.ignored.len() < 1000 {
                self.ignored.push(raw.chars().take(100).collect());
            }
            return true;
        }
        let kind = match hint {
            // A file name that looks like a domain is still a file name.
            Some("name") if !v.contains('/') && !v.contains('\\') => "name",
            Some(h) if h != "name" => h,
            _ => kind_of(&v),
        };
        let value = match kind {
            "domain" => host(&v),
            "md5" | "sha1" | "sha256" | "email" => v.to_ascii_lowercase(),
            "ip" => match net(&v) {
                Some((a, p)) if p == max_prefix(&a) => a.to_string(),
                Some((a, p)) => format!("{}/{}", a, p),
                None => String::new(),
            },
            _ => v,
        };
        if value.is_empty() {
            if self.ignored.len() < 1000 {
                self.ignored.push(raw.chars().take(100).collect());
            }
            return true;
        }
        if self.seen.insert((kind, value.to_lowercase())) {
            self.out.push(Indicator { value, kind: kind.into(), note: note.chars().take(200).collect() });
        }
        true
    }

    fn done(self) -> (Vec<Indicator>, Vec<String>) {
        (self.out, self.ignored)
    }
}

fn refang(raw: &str) -> String {
    let mut v = raw.trim().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@");
    let lower = v.get(..8).unwrap_or(&v).to_ascii_lowercase();
    if lower.starts_with("hxxp://") || lower.starts_with("hxxps://") {
        v.replace_range(..4, "http");
    }
    v.trim_matches(|c: char| c == '"' || c == '\'' || c == ',').to_string()
}

fn kind_of(v: &str) -> &'static str {
    let hex = v.chars().all(|c| c.is_ascii_hexdigit());
    if hex && v.len() == 32 {
        "md5"
    } else if hex && v.len() == 40 {
        "sha1"
    } else if hex && v.len() == 64 {
        "sha256"
    } else if net(v).is_some() {
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

/// An address as compared: IPv4-mapped IPv6 addresses as IPv4.
fn ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    let s = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(s);
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
        v4 => Some(v4),
    }
}

fn max_prefix(a: &IpAddr) -> u8 {
    if a.is_ipv4() {
        32
    } else {
        128
    }
}

/// An address or a network ("198.51.100.0/24"), with its prefix length.
fn net(s: &str) -> Option<(IpAddr, u8)> {
    match s.split_once('/') {
        None => ip(s).map(|a| (a, max_prefix(&a))),
        Some((a, p)) => {
            // A mapped IPv6 prefix becomes an IPv4 one.
            let raw: IpAddr = a.trim().parse().ok()?;
            let a = ip(a)?;
            let mut p: u8 = p.trim().parse().ok()?;
            if raw.is_ipv6() && a.is_ipv4() {
                p = p.checked_sub(96)?;
            }
            (p <= max_prefix(&a)).then_some((a, p))
        }
    }
}

fn in_net(a: &IpAddr, n: &IpAddr, p: u8) -> bool {
    match (a, n) {
        (IpAddr::V4(a), IpAddr::V4(n)) => p == 0 || (u32::from(*a) ^ u32::from(*n)) >> (32 - p as u32) == 0,
        (IpAddr::V6(a), IpAddr::V6(n)) => p == 0 || (u128::from(*a) ^ u128::from(*n)) >> (128 - p as u32) == 0,
        _ => false,
    }
}

/// The host of a URL, lower case ("HTTPS://user@Lab.test:8443/x" is "lab.test").
pub fn host(url: &str) -> String {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let h = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    let h = if h.starts_with('[') { h.split(']').next().map(|x| format!("{}]", x)).unwrap_or_default() } else { h.split(':').next().unwrap_or("").to_string() };
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether host `h` is domain `d` or one of its subdomains.
pub fn in_domain(h: &str, d: &str) -> bool {
    h == d || (h.len() > d.len() && h.ends_with(d) && h.as_bytes()[h.len() - d.len() - 1] == b'.')
}

/// Whether address `a` is indicator `ind`: the same address in any notation
/// (IPv4-mapped IPv6 included), or inside the indicator's network.
pub fn ip_eq(a: &str, ind: &str) -> bool {
    match (ip(a), net(ind)) {
        (Some(x), Some((n, p))) => in_net(&x, &n, p),
        _ => false,
    }
}

// ------------------------------------------------------------------ STIX

fn is_stix(v: &Value) -> bool {
    v.get("type").and_then(Value::as_str) == Some("bundle") && v.get("objects").is_some_and(Value::is_array)
}

fn stix(v: &Value, b: &mut Builder) {
    let objs = v["objects"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    for o in objs {
        let t = o.get("type").and_then(Value::as_str).unwrap_or("");
        let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("");
        let ok = match t {
            "indicator" => {
                let pattern = s("pattern");
                if !s("pattern_type").is_empty() && s("pattern_type") != "stix" {
                    b.ignored.push(format!("indicator {}: {} patterns are not read", s("name"), s("pattern_type")));
                    continue;
                }
                let note = [s("name"), s("description")].into_iter().find(|x| !x.is_empty()).unwrap_or("");
                let found = stix_pattern(pattern);
                if found.is_empty() && b.ignored.len() < 1000 {
                    b.ignored.push(format!("pattern not read: {}", pattern.chars().take(100).collect::<String>()));
                }
                found.into_iter().all(|(hint, val)| b.add(&val, note, hint))
            }
            "file" => {
                let mut ok = true;
                if let Some(h) = o.get("hashes").and_then(Value::as_object) {
                    for x in h.values().filter_map(Value::as_str) {
                        ok &= b.add(x, s("name"), None);
                    }
                }
                if !s("name").is_empty() {
                    ok &= b.add(s("name"), "", Some("name"));
                }
                ok
            }
            "ipv4-addr" | "ipv6-addr" => b.add(s("value"), "", Some("ip")),
            "domain-name" | "url" => b.add(s("value"), "", Some("domain")),
            "email-addr" => b.add(s("value"), s("display_name"), Some("email")),
            _ => true,
        };
        if !ok {
            break;
        }
    }
}

/// The comparisons in a STIX pattern that Kokino can look for, as (kind,
/// value): "[file:hashes.'SHA-256' = '...' OR ipv4-addr:value = '...']".
fn stix_pattern(p: &str) -> Vec<(Option<&'static str>, String)> {
    let mut out = vec![];
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // object-type:path
        let Some(colon) = p[i..].find(':').map(|x| x + i) else { break };
        let start = p[..colon].char_indices().rev().find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '-')).map(|(x, c)| x + c.len_utf8()).unwrap_or(0);
        let obj = &p[start..colon];
        let Some(eq) = p[colon..].find('=').map(|x| x + colon) else { break };
        let path = p[colon + 1..eq].trim().trim_end_matches('!').trim();
        let negated = p[colon + 1..eq].trim_end().ends_with('!');
        // The value: a quoted string with \' and \\ escapes.
        let Some(q) = p[eq..].find('\'').map(|x| x + eq) else { break };
        let mut val = String::new();
        let mut j = q + 1;
        let mut closed = false;
        while j < b.len() {
            match b[j] {
                b'\\' if j + 1 < b.len() => {
                    let c = p[j + 1..].chars().next().unwrap_or(' ');
                    val.push(c);
                    j += 1 + c.len_utf8();
                }
                b'\'' => {
                    closed = true;
                    j += 1;
                    break;
                }
                _ => {
                    let c = p[j..].chars().next().unwrap_or(' ');
                    val.push(c);
                    j += c.len_utf8();
                }
            }
        }
        if !closed {
            break;
        }
        // Only plain equality (not != or LIKE) between the object and the value.
        if !negated && !p[colon + 1..q].contains(" LIKE ") && !p[colon + 1..q].contains(" MATCHES ") {
            let path_l = path.to_ascii_lowercase();
            let hint = match obj {
                "file" if path_l.starts_with("hashes.") => Some(None),
                "file" if path_l == "name" => Some(Some("name")),
                "ipv4-addr" | "ipv6-addr" if path_l == "value" => Some(Some("ip")),
                "domain-name" | "url" if path_l == "value" => Some(Some("domain")),
                "email-addr" if path_l == "value" => Some(Some("email")),
                "email-message" if path_l.ends_with("_ref.value") || path_l.contains("_refs[") => Some(Some("email")),
                "network-traffic" if path_l.ends_with("_ref.value") => Some(Some("ip")),
                "process" if path_l == "name" => Some(Some("name")),
                _ => None,
            };
            if let Some(h) = hint {
                out.push((h, val));
            }
        }
        i = j;
    }
    out
}

// ------------------------------------------------------------------ MISP

fn misp_event(v: &Value) -> Option<&Value> {
    v.get("Event").or_else(|| v.get("response").and_then(|r| r.get(0)).and_then(|e| e.get("Event")))
}

fn is_misp(v: &Value) -> bool {
    if let Some(a) = v.as_array() {
        return a.first().is_some_and(|e| e.get("Event").is_some());
    }
    misp_event(v).is_some() || v.get("Attribute").is_some()
}

fn misp(v: &Value, b: &mut Builder) {
    let events: Vec<&Value> = match v.as_array() {
        Some(a) => a.iter().filter_map(|e| e.get("Event")).collect(),
        None => match v.get("response").and_then(Value::as_array) {
            Some(r) => r.iter().filter_map(|e| e.get("Event")).collect(),
            None => vec![misp_event(v).unwrap_or(v)],
        },
    };
    'ev: for e in events {
        let info = e.get("info").and_then(Value::as_str).unwrap_or("");
        let mut attrs: Vec<&Value> = e.get("Attribute").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
        for o in e.get("Object").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
            if o.get("deleted").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            attrs.extend(o.get("Attribute").and_then(Value::as_array).map(|a| a.iter()).into_iter().flatten());
        }
        for a in attrs {
            if a.get("deleted").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let t = a.get("type").and_then(Value::as_str).unwrap_or("");
            let val = a.get("value").and_then(Value::as_str).unwrap_or("");
            let note = {
                let cat = a.get("category").and_then(Value::as_str).unwrap_or("");
                let com = a.get("comment").and_then(Value::as_str).unwrap_or("");
                [cat, com, info].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(": ")
            };
            // Composite types: "filename|md5", "ip-dst|port", "domain|ip".
            let parts: Vec<&str> = val.split('|').collect();
            let types: Vec<&str> = t.split('|').collect();
            for (k, ty) in types.iter().enumerate() {
                let Some(x) = parts.get(k) else { break };
                let hint = match *ty {
                    "md5" | "sha1" | "sha256" | "authentihash" => Some(None),
                    "filename" => Some(Some("name")),
                    "ip-src" | "ip-dst" | "ip" => Some(Some("ip")),
                    "domain" | "hostname" | "url" | "uri" => Some(Some("domain")),
                    "email" | "email-src" | "email-dst" | "email-reply-to" | "target-email" | "whois-registrant-email" => Some(Some("email")),
                    _ => None,
                };
                let Some(hint) = hint else { continue };
                if *ty == "uri" && !x.contains("://") {
                    continue;
                }
                if !b.add(x, &note, hint) {
                    break 'ev;
                }
            }
        }
    }
}

// ------------------------------------------------------------------ matching

/// The indicators of a list, indexed for looking up many values fast.
#[derive(Default)]
pub struct Matcher {
    hashes: HashMap<String, Vec<usize>>,
    names: HashMap<String, Vec<usize>>,
    domains: HashMap<String, Vec<usize>>,
    emails: HashMap<String, Vec<usize>>,
    ips: HashMap<IpAddr, Vec<usize>>,
    nets: Vec<(IpAddr, u8, usize)>,
    paths: Vec<(String, usize)>,
}

impl Matcher {
    pub fn new(list: &[Indicator]) -> Matcher {
        let mut m = Matcher::default();
        for (i, ind) in list.iter().enumerate() {
            let v = ind.value.to_lowercase();
            match ind.kind.as_str() {
                "md5" | "sha1" | "sha256" => m.hashes.entry(v).or_default().push(i),
                "name" => m.names.entry(v).or_default().push(i),
                // A domain is also a file of that name ("ld.so.preload").
                "domain" => {
                    m.names.entry(v.clone()).or_default().push(i);
                    m.domains.entry(v).or_default().push(i);
                }
                "email" => m.emails.entry(v).or_default().push(i),
                "path" => m.paths.push((v.replace('\\', "/"), i)),
                "ip" => match net(&v) {
                    Some((a, p)) if p == max_prefix(&a) => m.ips.entry(a).or_default().push(i),
                    Some((a, p)) => m.nets.push((a, p, i)),
                    None => {}
                },
                _ => {}
            }
        }
        m
    }

    pub fn has_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }

    pub fn hash(&self, h: &str) -> &[usize] {
        if h.is_empty() {
            return &[];
        }
        self.hashes.get(&h.to_ascii_lowercase()).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Indicators matching a file: by its name, or a fragment of its path.
    pub fn file(&self, name: &str, path: &str) -> Vec<usize> {
        let mut out: Vec<usize> = self.names.get(&name.to_lowercase()).cloned().unwrap_or_default();
        if !self.paths.is_empty() {
            let p = path.to_lowercase();
            out.extend(self.paths.iter().filter(|(n, _)| p.contains(n.as_str())).map(|x| x.1));
        }
        out
    }

    /// Indicators matching a host: the domain or one above it.
    pub fn host(&self, h: &str) -> Vec<usize> {
        let mut out = vec![];
        if self.domains.is_empty() || h.is_empty() {
            return out;
        }
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = h.as_str();
        loop {
            if let Some(v) = self.domains.get(rest) {
                out.extend(v);
            }
            match rest.split_once('.') {
                Some((_, r)) if !r.is_empty() => rest = r,
                _ => break,
            }
        }
        // Hosts that are addresses ("http://198.51.100.7/x").
        if let Some(a) = ip(&h) {
            out.extend(self.address(a));
        }
        out
    }

    pub fn url(&self, u: &str) -> Vec<usize> {
        self.host(&host(u))
    }

    /// Indicators matching any address in a From, To or Cc field: the
    /// address itself, or its domain.
    pub fn mail_field(&self, field: &str) -> Vec<usize> {
        let mut out = vec![];
        if self.emails.is_empty() && self.domains.is_empty() {
            return out;
        }
        for tok in field.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '<' | '>' | '"' | '(' | ')')) {
            let Some((_, d)) = tok.rsplit_once('@') else { continue };
            let t = tok.to_lowercase();
            if let Some(v) = self.emails.get(&t) {
                out.extend(v);
            }
            out.extend(self.host(d));
        }
        out
    }

    pub fn ip(&self, s: &str) -> Vec<usize> {
        match ip(s) {
            Some(a) => self.address(a),
            None => vec![],
        }
    }

    fn address(&self, a: IpAddr) -> Vec<usize> {
        let mut out = self.ips.get(&a).cloned().unwrap_or_default();
        out.extend(self.nets.iter().filter(|(n, p, _)| in_net(&a, n, *p)).map(|x| x.2));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_indicators() {
        let (l, ign) = parse("# from the lab report\n198.51.100.7\nhxxps://c2[.]lab[.]test/a\nEvil.EXE # dropper\nC:\\Users\\Public\\x.ps1\nd41d8cd98f00b204e9800998ecf8427e\nALICE@lab.test\nlab.test\n2001:db8::1\n198.51.100.7\nhxxpd.exe\n203.0.113.0/24\n203.0.113.5/32\n");
        let got: Vec<(&str, &str)> = l.iter().map(|i| (i.kind.as_str(), i.value.as_str())).collect();
        assert_eq!(got, [("ip", "198.51.100.7"), ("domain", "c2.lab.test"), ("name", "Evil.EXE"), ("path", "C:\\Users\\Public\\x.ps1"), ("md5", "d41d8cd98f00b204e9800998ecf8427e"), ("email", "alice@lab.test"), ("domain", "lab.test"), ("ip", "2001:db8::1"), ("name", "hxxpd.exe"), ("ip", "203.0.113.0/24"), ("ip", "203.0.113.5")]);
        assert_eq!(l[2].note, "dropper");
        assert!(ign.is_empty());
        assert!(in_domain("downloads.lab.test", "lab.test") && !in_domain("notlab.test", "lab.test") && !in_domain("test", "lab.test"));
        assert_eq!(host("HTTPS://user@Lab.test:8443/x"), "lab.test");
        assert_eq!(host("http://[2001:db8::2]:80/"), "[2001:db8::2]");
        assert!(ip_eq("::ffff:192.0.2.1", "192.0.2.1") && ip_eq("::ffff:192.0.2.1", "::FFFF:192.0.2.1") && ip_eq("192.0.2.1", "::ffff:c000:201") && !ip_eq("192.0.2.1", "192.0.2.10"));
        assert!(ip_eq("203.0.113.77", "203.0.113.0/24") && !ip_eq("203.0.114.1", "203.0.113.0/24") && ip_eq("::ffff:203.0.113.9", "203.0.113.0/24"));
        assert!(ip_eq("2001:db8:5::1", "2001:db8::/32") && ip_eq("192.0.2.200", "::ffff:192.0.2.0/120"));
        assert_eq!(format_of("lab.test\n"), "lines");
    }

    #[test]
    fn long_lists_stop_at_the_limit() {
        let text: String = (0..MAX_INDICATORS + 10).map(|i| format!("file{}.exe\n", i)).collect();
        let (l, ign) = parse(&text);
        assert_eq!(l.len(), MAX_INDICATORS);
        assert_eq!(ign.len(), 1);
    }

    const STIX: &str = r#"{"type": "bundle", "id": "bundle--1", "objects": [
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--1", "name": "Dropper", "pattern_type": "stix",
       "pattern": "[file:hashes.'SHA-256' = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' OR file:name = 'update.lab.test']"},
      {"type": "indicator", "id": "indicator--2", "name": "C2", "pattern": "[ipv4-addr:value = '198.51.100.0/24'] OR [domain-name:value = 'c2.lab.test'] OR [url:value = 'http://dl.lab.test/a.ps1']"},
      {"type": "indicator", "id": "indicator--3", "name": "Phish", "pattern": "[email-message:from_ref.value = 'Bob@Lab.test' AND email-message:subject = 'Invoice']"},
      {"type": "indicator", "id": "indicator--4", "name": "Not this", "pattern": "[file:name != 'good.exe' AND file:name LIKE 'x%']"},
      {"type": "indicator", "id": "indicator--5", "name": "Sigma", "pattern_type": "sigma", "pattern": "title: x"},
      {"type": "indicator", "id": "indicator--6", "name": "Quote", "pattern": "[file:name = 'it\\'s.exe']"},
      {"type": "ipv6-addr", "id": "ipv6-addr--1", "value": "2001:db8::7"},
      {"type": "file", "id": "file--1", "name": "payload.bin", "hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e"}},
      {"type": "malware", "id": "malware--1", "name": "x"}
    ]}"#;

    #[test]
    fn reads_stix_bundles() {
        assert_eq!(format_of(STIX), "stix");
        let (l, ign) = parse(STIX);
        let got: Vec<(&str, &str, &str)> = l.iter().map(|i| (i.kind.as_str(), i.value.as_str(), i.note.as_str())).collect();
        assert_eq!(
            got,
            [
                ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Dropper"),
                ("name", "update.lab.test", "Dropper"),
                ("ip", "198.51.100.0/24", "C2"),
                ("domain", "c2.lab.test", "C2"),
                ("domain", "dl.lab.test", "C2"),
                ("email", "bob@lab.test", "Phish"),
                ("name", "it's.exe", "Quote"),
                ("ip", "2001:db8::7", ""),
                ("md5", "d41d8cd98f00b204e9800998ecf8427e", "payload.bin"),
                ("name", "payload.bin", ""),
            ]
        );
        assert_eq!(ign.len(), 2, "{:?}", ign);
    }

    const MISP: &str = r#"{"Event": {"info": "LAB-PC intrusion", "Attribute": [
        {"type": "ip-dst|port", "category": "Network activity", "value": "192.0.2.10|443", "comment": "C2"},
        {"type": "filename|sha1", "category": "Payload delivery", "value": "evil.dll|DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"},
        {"type": "hostname", "category": "Network activity", "value": "beacon.lab.test"},
        {"type": "email-src", "category": "Payload delivery", "value": "mallory@lab.test"},
        {"type": "text", "category": "Other", "value": "not an indicator"},
        {"type": "domain", "value": "old.lab.test", "deleted": true}
      ],
      "Object": [{"name": "file", "Attribute": [{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "category": "Payload delivery"}]}]
    }}"#;

    #[test]
    fn reads_misp_events() {
        assert_eq!(format_of(MISP), "misp");
        let (l, _) = parse(MISP);
        let got: Vec<(&str, &str)> = l.iter().map(|i| (i.kind.as_str(), i.value.as_str())).collect();
        assert_eq!(got, [("ip", "192.0.2.10"), ("name", "evil.dll"), ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"), ("domain", "beacon.lab.test"), ("email", "mallory@lab.test"), ("md5", "d41d8cd98f00b204e9800998ecf8427e")]);
        assert_eq!(l[0].note, "Network activity: C2: LAB-PC intrusion");
        // The REST API's list of events.
        let list = format!("[{}]", MISP);
        assert_eq!(parse(&list).0.len(), 6);
        let resp = format!("{{\"response\": [{}]}}", MISP);
        assert_eq!(parse(&resp).0.len(), 6);
    }

    #[test]
    fn matcher_finds_by_kind() {
        let (l, _) = parse("lab.test\n203.0.113.0/24\n192.0.2.1\nalice@corp.test\n/home/alice/.ssh\nld.so.preload\nE3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n");
        let m = Matcher::new(&l);
        assert_eq!(m.url("https://a.b.lab.test/x"), [0]);
        assert!(m.url("https://notlab.test/").is_empty());
        assert_eq!(m.ip("203.0.113.9"), [1]);
        assert_eq!(m.ip("::ffff:192.0.2.1"), [2]);
        assert_eq!(m.url("http://192.0.2.1/x"), [2]);
        assert_eq!(m.mail_field("\"Alice\" <ALICE@corp.test>, bob@lab.test"), [3, 0]);
        assert_eq!(m.file("authorized_keys", "/home/alice/.ssh/authorized_keys"), [4]);
        assert_eq!(m.file("ld.so.preload", "/etc/ld.so.preload"), [5]);
        assert_eq!(m.hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), [6]);
    }
}

