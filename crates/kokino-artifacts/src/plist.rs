//! Apple property lists: binary (`bplist00`) and XML.
//!
//! Binary: a trailer gives the offset table and the top object; each object
//! starts with a marker byte (type in the high nibble, a count in the low
//! one, 0xF meaning "an integer object follows with the count"). Objects
//! refer to each other by index, so every reference is bounded and a list
//! that contains itself is cut off.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Real(f64),
    /// Seconds since 2001-01-01 (Apple's reference date).
    Date(f64),
    Data(Vec<u8>),
    String(String),
    Uid(u64),
    Array(Vec<Value>),
    Dict(BTreeMap<String, Value>),
}

/// Seconds between 1601-01-01 and 2001-01-01, as FILETIME ticks.
const MAC_EPOCH_FT: i128 = 126_227_808_000_000_000;

/// Apple absolute time (seconds since 2001-01-01) to FILETIME; 0 if out of range.
pub fn mac_time(secs: f64) -> u64 {
    if !secs.is_finite() {
        return 0;
    }
    let ft = MAC_EPOCH_FT.saturating_add((secs * 10_000_000.0) as i128);
    if ft <= 0 || ft > u64::MAX as i128 {
        0
    } else {
        ft as u64
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.get(key),
            _ => None,
        }
    }
    /// A path of keys ("System/System/ComputerName"), through dicts.
    pub fn path(&self, keys: &str) -> Option<&Value> {
        keys.split('/').try_fold(self, |v, k| v.get(k))
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            // dslocal user records keep every value in a one-element array.
            Value::Array(a) => a.first().and_then(|v| v.str()),
            _ => None,
        }
    }
    pub fn int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Real(r) => Some(*r as i128),
            Value::Bool(b) => Some(*b as i128),
            Value::String(s) => s.trim().parse().ok(),
            Value::Array(a) => a.first().and_then(|v| v.int()),
            _ => None,
        }
    }
    pub fn bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::Int(i) => Some(*i != 0),
            _ => None,
        }
    }
    pub fn array(&self) -> &[Value] {
        match self {
            Value::Array(a) => a,
            _ => &[],
        }
    }
    /// FILETIME of a date value; 0 otherwise.
    pub fn time(&self) -> u64 {
        match self {
            Value::Date(d) => mac_time(*d),
            Value::Array(a) => a.first().map(|v| v.time()).unwrap_or(0),
            _ => 0,
        }
    }
}

/// Parses a property list, binary or XML.
pub fn parse(d: &[u8]) -> Option<Value> {
    if d.starts_with(b"bplist00") {
        return binary(d);
    }
    let head = String::from_utf8_lossy(&d[..d.len().min(512)]);
    if head.contains("<plist") || head.trim_start().starts_with("<?xml") {
        return xml(&String::from_utf8_lossy(d));
    }
    None
}

// ---------------------------------------------------------------- binary

const MAX_OBJECTS: u64 = 4_000_000;
const MAX_DEPTH: usize = 64;

struct Bin<'a> {
    d: &'a [u8],
    offsets: Vec<usize>,
    refsize: usize,
    budget: usize,
}

fn be(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0u64, |a, &c| (a << 8) | c as u64)
}

fn binary(d: &[u8]) -> Option<Value> {
    if d.len() < 8 + 32 {
        return None;
    }
    let t = &d[d.len() - 32..];
    let (osize, refsize) = (t[6] as usize, t[7] as usize);
    let (count, top, table) = (be(&t[8..16]), be(&t[16..24]), be(&t[24..32]) as usize);
    if !(1..=8).contains(&osize) || !(1..=8).contains(&refsize) || count == 0 || count > MAX_OBJECTS || top >= count {
        return None;
    }
    let end = table.checked_add(count as usize * osize)?;
    if end > d.len() - 32 {
        return None;
    }
    let offsets = (0..count as usize).map(|i| be(&d[table + i * osize..table + (i + 1) * osize]) as usize).collect();
    let mut b = Bin { d, offsets, refsize, budget: 1_000_000 };
    b.object(top as usize, 0)
}

impl Bin<'_> {
    fn object(&mut self, i: usize, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH || self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        let o = *self.offsets.get(i)?;
        let m = *self.d.get(o)?;
        let (kind, low) = (m >> 4, (m & 15) as usize);
        // A count: the low nibble, or an integer object after the marker.
        let count = |b: &Bin| -> Option<(usize, usize)> {
            if low != 15 {
                return Some((low, o + 1));
            }
            let im = *b.d.get(o + 1)?;
            if im >> 4 != 1 {
                return None;
            }
            let n = 1usize << (im & 15);
            let v = be(b.d.get(o + 2..o + 2 + n)?);
            Some((usize::try_from(v).ok()?, o + 2 + n))
        };
        Some(match kind {
            0 => match m {
                8 => Value::Bool(false),
                9 => Value::Bool(true),
                _ => Value::Null,
            },
            1 => {
                let n = 1usize << low.min(4);
                let b = self.d.get(o + 1..o + 1 + n)?;
                let v = if n == 16 { i128::from_be_bytes(b.try_into().ok()?) } else if n == 8 { be(b) as i64 as i128 } else { be(b) as i128 };
                Value::Int(v)
            }
            2 => {
                let n = 1usize << low.min(3);
                let b = self.d.get(o + 1..o + 1 + n)?;
                Value::Real(if n == 4 { f32::from_be_bytes(b.try_into().ok()?) as f64 } else if n == 8 { f64::from_be_bytes(b.try_into().ok()?) } else { 0.0 })
            }
            3 => Value::Date(f64::from_be_bytes(self.d.get(o + 1..o + 9)?.try_into().ok()?)),
            4 => {
                let (n, s) = count(self)?;
                Value::Data(self.d.get(s..s.checked_add(n)?)?.to_vec())
            }
            5 => {
                let (n, s) = count(self)?;
                Value::String(self.d.get(s..s.checked_add(n)?)?.iter().map(|&c| c as char).collect())
            }
            6 => {
                let (n, s) = count(self)?;
                let b = self.d.get(s..s.checked_add(n.checked_mul(2)?)?)?;
                let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Value::String(String::from_utf16_lossy(&w))
            }
            7 => {
                let (n, s) = count(self)?;
                Value::String(String::from_utf8_lossy(self.d.get(s..s.checked_add(n)?)?).into_owned())
            }
            8 => Value::Uid(be(self.d.get(o + 1..o + 2 + low)?)),
            0xA | 0xC => {
                let (n, s) = count(self)?;
                let refs = self.refs(s, n)?;
                Value::Array(refs.into_iter().filter_map(|r| self.object(r, depth + 1)).collect())
            }
            0xD => {
                let (n, s) = count(self)?;
                let keys = self.refs(s, n)?;
                let vals = self.refs(s + n * self.refsize, n)?;
                let mut out = BTreeMap::new();
                for (k, v) in keys.into_iter().zip(vals) {
                    let key = match self.object(k, depth + 1) {
                        Some(Value::String(s)) => s,
                        _ => continue,
                    };
                    if let Some(val) = self.object(v, depth + 1) {
                        out.insert(key, val);
                    }
                }
                Value::Dict(out)
            }
            _ => Value::Null,
        })
    }

    fn refs(&self, at: usize, n: usize) -> Option<Vec<usize>> {
        let len = n.checked_mul(self.refsize)?;
        let b = self.d.get(at..at.checked_add(len)?)?;
        Some(b.chunks_exact(self.refsize).map(|c| be(c) as usize).collect())
    }
}

// ---------------------------------------------------------------- XML

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn b64(s: &str) -> Vec<u8> {
    let v = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let vals: Vec<u8> = s.bytes().filter_map(v).collect();
    let mut out = vec![];
    for c in vals.chunks(4) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, &x)| a | (x as u32) << (18 - 6 * i));
        out.extend(&n.to_be_bytes()[1..c.len()]);
    }
    out
}

/// XML: a small tokenizer over tags and text.
fn xml(s: &str) -> Option<Value> {
    let mut toks: Vec<(String, String)> = vec![]; // (tag, text before it)
    let mut rest = s;
    while let Some(i) = rest.find('<') {
        let text = &rest[..i];
        let j = rest[i..].find('>')? + i;
        let tag = rest[i + 1..j].trim().to_string();
        rest = &rest[j + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        toks.push((tag, text.to_string()));
        if toks.len() > 4_000_000 {
            return None;
        }
    }
    let start = toks.iter().position(|(t, _)| t.starts_with("plist"))? + 1;
    let mut pos = start;
    xml_value(&toks, &mut pos, 0)
}

fn xml_value(t: &[(String, String)], pos: &mut usize, depth: usize) -> Option<Value> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (tag, _) = t.get(*pos)?;
    *pos += 1;
    let closed = |pos: &mut usize, name: &str| -> String {
        // The text before the closing tag.
        let text = t.get(*pos).map(|(_, x)| x.clone()).unwrap_or_default();
        if t.get(*pos).is_some_and(|(c, _)| c == &format!("/{}", name)) {
            *pos += 1;
        }
        unescape(&text)
    };
    Some(match tag.as_str() {
        "true/" => Value::Bool(true),
        "false/" => Value::Bool(false),
        "string/" => Value::String(String::new()),
        "dict/" => Value::Dict(BTreeMap::new()),
        "array/" => Value::Array(vec![]),
        "string" => Value::String(closed(pos, "string")),
        "integer" => Value::Int(closed(pos, "integer").trim().parse().unwrap_or(0)),
        "real" => Value::Real(closed(pos, "real").trim().parse().unwrap_or(0.0)),
        "data" => Value::Data(b64(&closed(pos, "data"))),
        "date" => {
            let s = closed(pos, "date");
            let t = chrono::DateTime::parse_from_rfc3339(s.trim()).map(|d| d.timestamp() as f64 - 978_307_200.0).unwrap_or(0.0);
            Value::Date(t)
        }
        "array" => {
            let mut out = vec![];
            while t.get(*pos).is_some_and(|(c, _)| c != "/array") {
                out.push(xml_value(t, pos, depth + 1)?);
            }
            *pos += 1;
            Value::Array(out)
        }
        "dict" => {
            let mut out = BTreeMap::new();
            while t.get(*pos).is_some_and(|(c, _)| c != "/dict") {
                let (k, _) = t.get(*pos)?;
                if k != "key" {
                    xml_value(t, pos, depth + 1)?;
                    continue;
                }
                *pos += 1;
                let key = closed(pos, "key");
                let v = xml_value(t, pos, depth + 1)?;
                out.insert(key, v);
            }
            *pos += 1;
            Value::Dict(out)
        }
        _ => Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_plist() {
        let x = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>14.4.1</string>
	<key>Args</key>
	<array><string>/usr/bin/curl</string><string>-s</string></array>
	<key>RunAtLoad</key>
	<true/>
	<key>When</key>
	<date>2026-10-20T08:05:30Z</date>
	<key>Blob</key>
	<data>bGFi</data>
	<key>N</key>
	<integer>42</integer>
	<key>Esc</key>
	<string>a &amp; b</string>
</dict>
</plist>"#;
        let v = parse(x).unwrap();
        assert_eq!(v.get("ProductVersion").and_then(|x| x.str()), Some("14.4.1"));
        assert_eq!(v.get("Args").unwrap().array().len(), 2);
        assert_eq!(v.get("RunAtLoad").and_then(|x| x.bool()), Some(true));
        assert_eq!(v.get("N").and_then(|x| x.int()), Some(42));
        assert_eq!(v.get("Blob"), Some(&Value::Data(b"lab".to_vec())));
        assert_eq!(v.get("Esc").and_then(|x| x.str()), Some("a & b"));
        assert_eq!(Some(v.get("When").unwrap().time()), crate::bin::unix_to_filetime(1_792_483_530));
    }

    /// A binary plist as Python's plistlib writes it (scripts/make_mac_collection.py
    /// makes the same kinds).
    #[test]
    fn binary_plist() {
        // {"name": ["alice"], "uid": ["501"], "n": 3, "t": True, "d": <date 2026-10-20T08:05:30Z>}
        let mut objs: Vec<Vec<u8>> = vec![];
        let s = |t: &str| [vec![0x50 | t.len() as u8], t.as_bytes().to_vec()].concat();
        objs.push(vec![]); // 0: dict, filled below
        for k in ["name", "uid", "n", "t", "d"] {
            objs.push(s(k)); // 1..5 keys
        }
        objs.push(vec![0xA1, 8]); // 6: array [obj 8]
        objs.push(vec![0xA1, 9]); // 7: array [obj 9]
        objs.push(s("alice")); // 8
        objs.push(s("501")); // 9
        objs.push(vec![0x10, 3]); // 10: int 3
        objs.push(vec![0x09]); // 11: true
        let mut d = vec![0x33];
        d.extend((1_792_483_530.0f64 - 978_307_200.0).to_be_bytes());
        objs.push(d); // 12: date
        objs[0] = vec![0xD5, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12];
        let mut out = b"bplist00".to_vec();
        let mut offs = vec![];
        for o in &objs {
            offs.push(out.len() as u8);
            out.extend(o);
        }
        let table = out.len();
        out.extend(&offs);
        let mut trailer = vec![0u8; 6];
        trailer.extend([1, 1]);
        trailer.extend((objs.len() as u64).to_be_bytes());
        trailer.extend(0u64.to_be_bytes());
        trailer.extend((table as u64).to_be_bytes());
        out.extend(trailer);
        let v = parse(&out).unwrap();
        assert_eq!(v.get("name").and_then(|x| x.str()), Some("alice"));
        assert_eq!(v.get("uid").and_then(|x| x.int()), Some(501));
        assert_eq!((v.get("n").and_then(|x| x.int()), v.get("t").and_then(|x| x.bool())), (Some(3), Some(true)));
        assert_eq!(Some(v.get("d").unwrap().time()), crate::bin::unix_to_filetime(1_792_483_530));
        // A dict that refers to itself is cut off, not followed for ever.
        let mut loopy = out.clone();
        let at = 8; // the dict's first value reference -> itself
        loopy[at + 6] = 0;
        assert!(parse(&loopy).is_some());
        assert!(parse(b"bplist00garbage").is_none());
    }
}
