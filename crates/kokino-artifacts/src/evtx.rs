//! Windows XML event log (.evtx) reader.
//!
//! The file is a 4 KiB header followed by 64 KiB chunks of records. Each
//! record holds "binary XML": a token stream that usually instantiates a
//! template (defined once per chunk, reused by later records) with a list of
//! typed substitution values. This reader renders that into a small element
//! tree and pulls out what an examiner needs: event id, time, provider,
//! channel, computer, user SID and the EventData / UserData fields.
//!
//! Chunks are found by signature at every 64 KiB boundary rather than by
//! trusting the header's chunk count, so chunks after a "cleared" header or
//! in a damaged file are still read. Each chunk is parsed on its own and any
//! error only loses that chunk's remaining records.

use crate::bin::*;
use serde::Serialize;
use std::collections::HashMap;

const CHUNK: usize = 65_536;

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize, PartialEq)]
pub struct Event {
    pub record_id: u64,
    /// FILETIME of System/TimeCreated (the record header time when absent).
    pub time: u64,
    pub event_id: u32,
    pub level: u8,
    pub provider: String,
    pub channel: String,
    pub computer: String,
    pub user_sid: Option<String>,
    /// EventData Data elements (Name -> value) or UserData leaf elements.
    pub data: Vec<(String, String)>,
}

impl Event {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.data.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty() && *v != "-")
    }
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct LogInfo {
    pub chunks: u32,
    pub header_chunks: u32,
    pub records: u64,
    pub first_record: u64,
    pub last_record: u64,
    pub oldest: u64,
    pub newest: u64,
    /// Header flag: the log was not closed cleanly.
    pub dirty: bool,
    /// Header flag: the log reached its maximum size.
    pub full: bool,
    /// Records that could not be decoded.
    pub errors: u64,
}

#[derive(Debug, Clone)]
enum Node {
    Elem(Elem),
    Text(String),
}

#[derive(Debug, Clone, Default)]
struct Elem {
    name: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

impl Elem {
    fn text(&self) -> String {
        let mut s = String::new();
        for c in &self.children {
            match c {
                Node::Text(t) => s.push_str(t),
                Node::Elem(e) => s.push_str(&e.text()),
            }
        }
        s
    }
    fn child(&self, name: &str) -> Option<&Elem> {
        self.children.iter().find_map(|c| match c {
            Node::Elem(e) if e.name == name => Some(e),
            _ => None,
        })
    }
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// A substitution value as rendered text, or nested binary XML.
#[derive(Debug, Clone)]
enum Sub {
    Text(String),
    Xml(Vec<Node>),
}

struct Chunk<'a> {
    d: &'a [u8],
    names: HashMap<u32, String>,
}

/// Parses every record of every chunk; `f` gets each event.
pub fn parse(data: &[u8], f: &mut dyn FnMut(Event)) -> anyhow::Result<LogInfo> {
    if data.get(0..8) != Some(b"ElfFile\0") {
        anyhow::bail!("not an EVTX file (no ElfFile signature)");
    }
    let flags = u32_at(data, 120).unwrap_or(0);
    let mut info = LogInfo { header_chunks: u16_at(data, 42).unwrap_or(0) as u32, dirty: flags & 1 != 0, full: flags & 2 != 0, ..Default::default() };
    let mut off = 4096;
    while off + 512 <= data.len() {
        if data.get(off..off + 8) == Some(b"ElfChnk\0") {
            info.chunks += 1;
            let end = (off + CHUNK).min(data.len());
            parse_chunk(&data[off..end], &mut info, f);
        }
        off += CHUNK;
    }
    Ok(info)
}

fn parse_chunk(d: &[u8], info: &mut LogInfo, f: &mut dyn FnMut(Event)) {
    let free = (u32_at(d, 48).unwrap_or(0) as usize).clamp(512, d.len());
    let mut cx = Chunk { d, names: HashMap::new() };
    let mut p = 512;
    while p + 24 <= free {
        if u32_at(d, p) != Some(0x0000_2a2a) {
            break;
        }
        let size = u32_at(d, p + 4).unwrap_or(0) as usize;
        if size < 28 || p + size > d.len() {
            break;
        }
        let rid = u64_at(d, p + 8).unwrap_or(0);
        let written = u64_at(d, p + 16).unwrap_or(0);
        let mut pos = p + 24;
        let end = p + size - 4;
        match cx.nodes(&mut pos, end, &[], 0) {
            Ok(nodes) => {
                let ev = to_event(&nodes, rid, written);
                info.records += 1;
                if info.first_record == 0 || rid < info.first_record {
                    info.first_record = rid;
                }
                info.last_record = info.last_record.max(rid);
                if ev.time > 0 {
                    if info.oldest == 0 || ev.time < info.oldest {
                        info.oldest = ev.time;
                    }
                    info.newest = info.newest.max(ev.time);
                }
                f(ev);
            }
            Err(_) => info.errors += 1,
        }
        p += size;
    }
}

fn to_event(nodes: &[Node], rid: u64, written: u64) -> Event {
    let mut ev = Event { record_id: rid, time: written, ..Default::default() };
    let Some(root) = nodes.iter().find_map(|n| if let Node::Elem(e) = n { Some(e) } else { None }) else { return ev };
    if let Some(sys) = root.child("System") {
        if let Some(p) = sys.child("Provider") {
            ev.provider = p.attr("Name").or(p.attr("EventSourceName")).unwrap_or("").to_string();
        }
        ev.event_id = sys.child("EventID").and_then(|e| e.text().trim().parse().ok()).unwrap_or(0);
        ev.level = sys.child("Level").and_then(|e| e.text().trim().parse().ok()).unwrap_or(0);
        // The record header number is renumbered when a log is exported; the
        // XML keeps the original.
        if let Some(n) = sys.child("EventRecordID").and_then(|e| e.text().trim().parse().ok()) {
            ev.record_id = n;
        }
        if let Some(t) = sys.child("TimeCreated").and_then(|e| e.attr("SystemTime")).and_then(parse_iso) {
            ev.time = t;
        }
        ev.channel = sys.child("Channel").map(|e| e.text()).unwrap_or_default();
        ev.computer = sys.child("Computer").map(|e| e.text()).unwrap_or_default();
        ev.user_sid = sys.child("Security").and_then(|e| e.attr("UserID")).filter(|s| !s.is_empty()).map(String::from);
    }
    if let Some(ed) = root.child("EventData") {
        let mut n = 0;
        for c in &ed.children {
            if let Node::Elem(e) = c {
                let name = e.attr("Name").map(String::from).unwrap_or_else(|| {
                    n += 1;
                    if e.name == "Data" { format!("Data{}", n) } else { e.name.clone() }
                });
                ev.data.push((name, e.text()));
            }
        }
    } else if let Some(ud) = root.child("UserData") {
        fn leaves(e: &Elem, out: &mut Vec<(String, String)>) {
            let kids: Vec<&Elem> = e.children.iter().filter_map(|c| if let Node::Elem(x) = c { Some(x) } else { None }).collect();
            if kids.is_empty() {
                out.push((e.name.clone(), e.text()));
            } else {
                for k in kids {
                    leaves(k, out);
                }
            }
        }
        for c in &ud.children {
            if let Node::Elem(e) = c {
                leaves(e, &mut ev.data);
            }
        }
    }
    ev
}

/// "2026-10-20T09:30:15.1234567Z" to FILETIME.
fn parse_iso(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let n = |a: usize, l: usize| s.get(a..a + l)?.parse::<u16>().ok();
    let mut st = vec![];
    for v in [n(0, 4)?, n(5, 2)?, 0, n(8, 2)?, n(11, 2)?, n(14, 2)?, n(17, 2)?, 0] {
        st.extend_from_slice(&v.to_le_bytes());
    }
    let base = systemtime(&st)?;
    let frac = s.get(20..).map(|f| f.trim_end_matches('Z')).filter(|f| !f.is_empty() && f.bytes().all(|c| c.is_ascii_digit())).map(|f| {
        let f7: String = f.chars().chain(std::iter::repeat('0')).take(7).collect();
        f7.parse::<u64>().unwrap_or(0)
    });
    Some(base + frac.unwrap_or(0))
}

fn filetime_iso(ft: u64) -> String {
    if ft < UNIX_EPOCH_FT {
        return ft.to_string();
    }
    let secs = ((ft - UNIX_EPOCH_FT) / 10_000_000) as i64;
    let frac = (ft - UNIX_EPOCH_FT) % 10_000_000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60, frac)
}

impl<'a> Chunk<'a> {
    fn name_at(&mut self, off: u32) -> anyhow::Result<String> {
        if let Some(n) = self.names.get(&off) {
            return Ok(n.clone());
        }
        let o = off as usize;
        let len = u16_at(self.d, o + 6).ok_or_else(|| anyhow::anyhow!("name out of range"))? as usize;
        let s = utf16(slice(self.d, o + 8, 2 * len).ok_or_else(|| anyhow::anyhow!("name out of range"))?);
        self.names.insert(off, s.clone());
        Ok(s)
    }

    /// Reads a name reference at `pos`; when the name is defined inline (its
    /// offset is the current position) the definition is skipped.
    fn name_ref(&mut self, pos: &mut usize) -> anyhow::Result<String> {
        let off = u32_at(self.d, *pos).ok_or_else(|| anyhow::anyhow!("eof"))?;
        *pos += 4;
        let name = self.name_at(off)?;
        if off as usize == *pos {
            *pos += 8 + 2 * name.encode_utf16().count() + 2;
        }
        Ok(name)
    }

    /// Parses tokens until EOF / end tag at this level.
    fn nodes(&mut self, pos: &mut usize, end: usize, subs: &[Sub], depth: usize) -> anyhow::Result<Vec<Node>> {
        if depth > 64 {
            anyhow::bail!("nesting too deep");
        }
        let mut out = vec![];
        while *pos < end {
            let tok = self.d[*pos];
            match tok & 0x0F {
                0x00 => {
                    *pos += 1;
                    break;
                }
                0x0F => *pos += 4, // fragment header
                0x01 => out.push(Node::Elem(self.element(pos, end, subs, depth)?)),
                0x04 => {
                    *pos += 1;
                    break;
                }
                0x05 => {
                    *pos += 1;
                    out.push(Node::Text(self.value_text(pos)?));
                }
                0x07 => {
                    let n = u16_at(self.d, *pos + 1).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
                    out.push(Node::Text(utf16(slice(self.d, *pos + 3, 2 * n).unwrap_or(&[]))));
                    *pos += 3 + 2 * n;
                }
                0x08 => {
                    let c = u16_at(self.d, *pos + 1).unwrap_or(0x3F);
                    out.push(Node::Text(char::from_u32(c as u32).unwrap_or('?').to_string()));
                    *pos += 3;
                }
                0x09 => {
                    *pos += 1;
                    let n = self.name_ref(pos)?;
                    out.push(Node::Text(match n.as_str() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    }
                    .into()));
                }
                0x0A => {
                    *pos += 1;
                    self.name_ref(pos)?;
                }
                0x0B => {
                    let n = u16_at(self.d, *pos + 1).unwrap_or(0) as usize;
                    *pos += 3 + 2 * n;
                }
                0x0C => out.extend(self.template(pos, depth)?),
                0x0D | 0x0E => {
                    let id = u16_at(self.d, *pos + 1).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
                    *pos += 4;
                    match subs.get(id) {
                        Some(Sub::Text(t)) => out.push(Node::Text(t.clone())),
                        Some(Sub::Xml(n)) => out.extend(n.iter().cloned()),
                        None => {}
                    }
                }
                _ => anyhow::bail!("unknown token {:#x} at {}", tok, *pos),
            }
        }
        Ok(out)
    }

    fn element(&mut self, pos: &mut usize, end: usize, subs: &[Sub], depth: usize) -> anyhow::Result<Elem> {
        let tok = self.d[*pos];
        // token, dependency id (2), data size (4), name reference
        *pos += 7;
        let name = self.name_ref(pos)?;
        let mut e = Elem { name, ..Default::default() };
        if tok & 0x40 != 0 {
            let alen = u32_at(self.d, *pos).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
            *pos += 4;
            let aend = (*pos + alen).min(end);
            while *pos < aend && self.d[*pos] & 0x0F == 0x06 {
                *pos += 1;
                let an = self.name_ref(pos)?;
                let mut val = String::new();
                // Attribute value: value, substitution or char/entity refs.
                while *pos < aend {
                    match self.d[*pos] & 0x0F {
                        0x05 => {
                            *pos += 1;
                            val.push_str(&self.value_text(pos)?);
                        }
                        0x0D | 0x0E => {
                            let id = u16_at(self.d, *pos + 1).unwrap_or(0) as usize;
                            *pos += 4;
                            if let Some(Sub::Text(t)) = subs.get(id) {
                                val.push_str(t);
                            }
                        }
                        0x08 => {
                            let c = u16_at(self.d, *pos + 1).unwrap_or(0x3F);
                            val.push(char::from_u32(c as u32).unwrap_or('?'));
                            *pos += 3;
                        }
                        0x09 => {
                            *pos += 1;
                            let n = self.name_ref(pos)?;
                            val.push_str(match n.as_str() {
                                "amp" => "&",
                                "lt" => "<",
                                "gt" => ">",
                                "quot" => "\"",
                                _ => "'",
                            });
                        }
                        _ => break,
                    }
                }
                e.attrs.push((an, val));
            }
        }
        match self.d.get(*pos).map(|t| t & 0x0F) {
            Some(0x02) => {
                *pos += 1;
                e.children = self.nodes(pos, end, subs, depth + 1)?;
            }
            Some(0x03) => *pos += 1,
            other => anyhow::bail!("unexpected token {:?} after element {}", other, e.name),
        }
        Ok(e)
    }

    /// A Value token's payload (the token byte already consumed).
    fn value_text(&mut self, pos: &mut usize) -> anyhow::Result<String> {
        let ty = *self.d.get(*pos).ok_or_else(|| anyhow::anyhow!("eof"))?;
        *pos += 1;
        match ty {
            0x01 => {
                let n = u16_at(self.d, *pos).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
                let s = utf16(slice(self.d, *pos + 2, 2 * n).unwrap_or(&[]));
                *pos += 2 + 2 * n;
                Ok(s)
            }
            0x02 => {
                let n = u16_at(self.d, *pos).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
                let s = ansi(slice(self.d, *pos + 2, n).unwrap_or(&[]));
                *pos += 2 + n;
                Ok(s)
            }
            _ => anyhow::bail!("unsupported inline value type {:#x}", ty),
        }
    }

    /// Template instance: parse (or reuse) the definition, read the
    /// substitution array, then render the template body with it.
    fn template(&mut self, pos: &mut usize, depth: usize) -> anyhow::Result<Vec<Node>> {
        let def = u32_at(self.d, *pos + 6).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
        *pos += 10;
        let body_size = u32_at(self.d, def + 20).ok_or_else(|| anyhow::anyhow!("template out of range"))? as usize;
        let body = def + 24;
        if def == *pos {
            *pos = body + body_size; // inline definition: skip it
        }
        let count = u32_at(self.d, *pos).ok_or_else(|| anyhow::anyhow!("eof"))? as usize;
        if count > 4096 {
            anyhow::bail!("implausible substitution count");
        }
        *pos += 4;
        let mut desc = Vec::with_capacity(count);
        for i in 0..count {
            let size = u16_at(self.d, *pos + 4 * i).unwrap_or(0) as usize;
            let ty = u8_at(self.d, *pos + 4 * i + 2).unwrap_or(0);
            desc.push((size, ty));
        }
        *pos += 4 * count;
        let mut subs = Vec::with_capacity(count);
        for (size, ty) in desc {
            let v = slice(self.d, *pos, size).ok_or_else(|| anyhow::anyhow!("substitution out of range"))?;
            subs.push(if ty == 0x21 {
                let mut p = *pos;
                Sub::Xml(self.nodes(&mut p, *pos + size, &[], depth + 1).unwrap_or_default())
            } else {
                Sub::Text(render(ty, v))
            });
            *pos += size;
        }
        let mut p = body;
        let body_end = (body + body_size).min(self.d.len()).max(p);
        self.nodes(&mut p, body_end, &subs, depth + 1)
    }
}

/// Substitution value as text.
fn render(ty: u8, v: &[u8]) -> String {
    let arr = ty & 0x80 != 0;
    let base = ty & 0x7F;
    if arr && base == 0x01 {
        let w: Vec<u16> = v.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return w.split(|&u| u == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect::<Vec<_>>().join(", ");
    }
    let one = |b: &[u8]| -> String {
        match base {
            0x00 => String::new(),
            0x01 => utf16(b),
            0x02 => ansi(b),
            0x03 => (b.first().copied().unwrap_or(0) as i8).to_string(),
            0x04 => b.first().copied().unwrap_or(0).to_string(),
            0x05 => (u16_at(b, 0).unwrap_or(0) as i16).to_string(),
            0x06 => u16_at(b, 0).unwrap_or(0).to_string(),
            0x07 => i32_at(b, 0).unwrap_or(0).to_string(),
            0x08 => u32_at(b, 0).unwrap_or(0).to_string(),
            0x09 => (u64_at(b, 0).unwrap_or(0) as i64).to_string(),
            0x0A => u64_at(b, 0).unwrap_or(0).to_string(),
            0x0B => u32_at(b, 0).map(|x| f32::from_bits(x).to_string()).unwrap_or_default(),
            0x0C => u64_at(b, 0).map(|x| f64::from_bits(x).to_string()).unwrap_or_default(),
            0x0D => (u32_at(b, 0).unwrap_or(0) != 0).to_string(),
            0x0F => guid(b),
            0x10 => match b.len() {
                4 => format!("{:#x}", u32_at(b, 0).unwrap_or(0)),
                _ => format!("{:#x}", u64_at(b, 0).unwrap_or(0)),
            },
            0x11 => filetime_iso(u64_at(b, 0).unwrap_or(0)),
            0x12 => systemtime(b).map(filetime_iso).unwrap_or_default(),
            0x13 => sid(b).unwrap_or_default(),
            0x14 => format!("{:#010x}", u32_at(b, 0).unwrap_or(0)),
            0x15 => format!("{:#018x}", u64_at(b, 0).unwrap_or(0)),
            _ => b.iter().map(|x| format!("{:02X}", x)).collect(),
        }
    };
    if arr {
        let w = match base {
            0x03 | 0x04 => 1,
            0x05 | 0x06 => 2,
            0x07 | 0x08 | 0x0B | 0x0D | 0x14 => 4,
            0x09 | 0x0A | 0x0C | 0x11 | 0x15 => 8,
            0x0F | 0x12 => 16,
            _ => 0,
        };
        if w > 0 {
            return v.chunks(w).map(one).collect::<Vec<_>>().join(", ");
        }
    }
    one(v)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Writes EVTX files the way Windows does: one template per event kind,
    /// defined inline on first use and referenced afterwards, with typed
    /// substitution values.
    pub struct Writer {
        chunk: Vec<u8>,
        names: HashMap<String, u32>,
        templates: HashMap<String, u32>,
        next_id: u64,
        pub chunks: Vec<Vec<u8>>,
    }

    pub enum V<'a> {
        Str(&'a str),
        U16(u16),
        U8(u8),
        U64(u64),
        Ft(u64),
        Sid(&'a [u8]),
    }

    impl Writer {
        pub fn new() -> Writer {
            let mut w = Writer { chunk: vec![], names: HashMap::new(), templates: HashMap::new(), next_id: 1, chunks: vec![] };
            w.reset();
            w
        }
        fn reset(&mut self) {
            self.chunk = vec![0u8; 512];
            self.chunk[0..8].copy_from_slice(b"ElfChnk\0");
            self.names.clear();
            self.templates.clear();
        }
        fn name(&mut self, buf: &mut Vec<u8>, base: usize, n: &str) {
            if let Some(o) = self.names.get(n) {
                buf.extend_from_slice(&o.to_le_bytes());
                return;
            }
            let here = (base + buf.len() + 4) as u32;
            buf.extend_from_slice(&here.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&(n.encode_utf16().count() as u16).to_le_bytes());
            for u in n.encode_utf16().chain([0]) {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            self.names.insert(n.to_string(), here);
        }
        /// Template body for an event with `data` named EventData fields.
        /// Substitutions: 0 provider, 1 event id, 2 level, 3 time, 4 record
        /// id, 5 channel, 6 computer, 7 user sid, 8.. data values.
        fn body(&mut self, buf: &mut Vec<u8>, base: usize, data: &[&str]) {
            buf.extend_from_slice(&[0x0F, 1, 1, 0]);
            let elem = |w: &mut Writer, buf: &mut Vec<u8>, name: &str, attrs: &[(&str, u16)], text: Option<u16>, kids: &mut dyn FnMut(&mut Writer, &mut Vec<u8>)| {
                buf.push(if attrs.is_empty() { 0x01 } else { 0x41 });
                buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
                buf.extend_from_slice(&0u32.to_le_bytes());
                w.name(buf, base, name);
                if !attrs.is_empty() {
                    let at = buf.len();
                    buf.extend_from_slice(&0u32.to_le_bytes());
                    for (an, sub) in attrs {
                        buf.push(0x06);
                        w.name(buf, base, an);
                        buf.push(0x0E);
                        buf.extend_from_slice(&sub.to_le_bytes());
                        buf.push(0x01);
                    }
                    let len = (buf.len() - at - 4) as u32;
                    buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
                }
                buf.push(0x02);
                if let Some(s) = text {
                    buf.push(0x0E);
                    buf.extend_from_slice(&s.to_le_bytes());
                    buf.push(0x01);
                }
                kids(w, buf);
                buf.push(0x04);
            };
            elem(self, buf, "Event", &[], None, &mut |w, buf| {
                elem(w, buf, "System", &[], None, &mut |w, buf| {
                    elem(w, buf, "Provider", &[("Name", 0)], None, &mut |_, _| {});
                    elem(w, buf, "EventID", &[], Some(1), &mut |_, _| {});
                    elem(w, buf, "Level", &[], Some(2), &mut |_, _| {});
                    elem(w, buf, "TimeCreated", &[("SystemTime", 3)], None, &mut |_, _| {});
                    elem(w, buf, "EventRecordID", &[], Some(4), &mut |_, _| {});
                    elem(w, buf, "Channel", &[], Some(5), &mut |_, _| {});
                    elem(w, buf, "Computer", &[], Some(6), &mut |_, _| {});
                    elem(w, buf, "Security", &[("UserID", 7)], None, &mut |_, _| {});
                });
                elem(w, buf, "EventData", &[], None, &mut |w, buf| {
                    for (i, n) in data.iter().enumerate() {
                        // Data Name="..." uses a literal value, not a substitution.
                        buf.push(0x41);
                        buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
                        buf.extend_from_slice(&0u32.to_le_bytes());
                        w.name(buf, base, "Data");
                        let at = buf.len();
                        buf.extend_from_slice(&0u32.to_le_bytes());
                        buf.push(0x06);
                        w.name(buf, base, "Name");
                        buf.push(0x05);
                        buf.push(0x01);
                        buf.extend_from_slice(&(n.encode_utf16().count() as u16).to_le_bytes());
                        for u in n.encode_utf16() {
                            buf.extend_from_slice(&u.to_le_bytes());
                        }
                        let len = (buf.len() - at - 4) as u32;
                        buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
                        buf.push(0x02);
                        buf.push(0x0E);
                        buf.extend_from_slice(&((8 + i) as u16).to_le_bytes());
                        buf.push(0x01);
                        buf.push(0x04);
                    }
                });
            });
            buf.push(0x00);
        }

        pub fn event(&mut self, provider: &str, channel: &str, computer: &str, event_id: u16, ft: u64, user_sid: Option<&[u8]>, data: &[(&str, V)]) {
            let key = format!("{}|{}|{}", provider, event_id, data.iter().map(|d| d.0).collect::<Vec<_>>().join(","));
            let rec_start = self.chunk.len();
            let mut x = vec![0x0F, 1, 1, 0, 0x0C, 0x01];
            x.extend_from_slice(&0u32.to_le_bytes()); // template id
            let base = rec_start + 24;
            match self.templates.get(&key) {
                Some(off) => x.extend_from_slice(&off.to_le_bytes()),
                None => {
                    let def = (base + x.len() + 4) as u32;
                    x.extend_from_slice(&def.to_le_bytes());
                    x.extend_from_slice(&0u32.to_le_bytes()); // next template
                    x.extend_from_slice(&[0x11; 16]); // guid
                    let size_at = x.len();
                    x.extend_from_slice(&0u32.to_le_bytes());
                    let mut body = vec![];
                    let names: Vec<&str> = data.iter().map(|d| d.0).collect();
                    self.body(&mut body, base + x.len(), &names);
                    x[size_at..size_at + 4].copy_from_slice(&(body.len() as u32).to_le_bytes());
                    x.extend_from_slice(&body);
                    self.templates.insert(key, def);
                }
            }
            let sid_v = user_sid.map(|s| V::Sid(s));
            let mut vals: Vec<(u8, Vec<u8>)> = vec![];
            let enc = |v: &V| -> (u8, Vec<u8>) {
                match v {
                    V::Str(s) => (0x01, s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
                    V::U16(n) => (0x06, n.to_le_bytes().to_vec()),
                    V::U8(n) => (0x04, vec![*n]),
                    V::U64(n) => (0x0A, n.to_le_bytes().to_vec()),
                    V::Ft(n) => (0x11, n.to_le_bytes().to_vec()),
                    V::Sid(b) => (0x13, b.to_vec()),
                }
            };
            for v in [V::Str(provider), V::U16(event_id), V::U8(4), V::Ft(ft), V::U64(self.next_id), V::Str(channel), V::Str(computer)] {
                vals.push(enc(&v));
            }
            vals.push(sid_v.as_ref().map(enc).unwrap_or((0x00, vec![])));
            for (_, v) in data {
                vals.push(enc(v));
            }
            x.extend_from_slice(&(vals.len() as u32).to_le_bytes());
            for (ty, b) in &vals {
                x.extend_from_slice(&(b.len() as u16).to_le_bytes());
                x.push(*ty);
                x.push(0);
            }
            for (_, b) in &vals {
                x.extend_from_slice(b);
            }
            x.push(0x00);
            let size = 24 + x.len() + 4;
            if rec_start + size > CHUNK {
                self.flush();
                return self.event(provider, channel, computer, event_id, ft, user_sid, data);
            }
            self.chunk.extend_from_slice(&0x2a2au32.to_le_bytes());
            self.chunk.extend_from_slice(&(size as u32).to_le_bytes());
            self.chunk.extend_from_slice(&self.next_id.to_le_bytes());
            self.chunk.extend_from_slice(&ft.to_le_bytes());
            self.chunk.extend_from_slice(&x);
            self.chunk.extend_from_slice(&(size as u32).to_le_bytes());
            self.next_id += 1;
        }

        pub fn flush(&mut self) {
            if self.chunk.len() > 512 {
                let free = self.chunk.len() as u32;
                self.chunk[48..52].copy_from_slice(&free.to_le_bytes());
                let mut c = std::mem::take(&mut self.chunk);
                c.resize(CHUNK, 0);
                self.chunks.push(c);
            }
            self.reset();
        }

        pub fn finish(mut self) -> Vec<u8> {
            self.flush();
            let mut out = vec![0u8; 4096];
            out[0..8].copy_from_slice(b"ElfFile\0");
            out[32..36].copy_from_slice(&128u32.to_le_bytes());
            out[42..44].copy_from_slice(&(self.chunks.len() as u16).to_le_bytes());
            for c in self.chunks {
                out.extend_from_slice(&c);
            }
            out
        }
    }

    pub const SID_ALICE: [u8; 28] = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe9, 3, 0, 0];

    #[test]
    fn reads_template_records_and_reuses_definitions() {
        let mut w = Writer::new();
        let t0 = 134_000_000_000_000_000u64;
        w.event("Microsoft-Windows-Security-Auditing", "Security", "LAB-PC", 4624, t0, None, &[("TargetUserName", V::Str("alice")), ("LogonType", V::Str("10")), ("IpAddress", V::Str("10.0.0.7"))]);
        w.event("Microsoft-Windows-Security-Auditing", "Security", "LAB-PC", 4624, t0 + 10, None, &[("TargetUserName", V::Str("bob")), ("LogonType", V::Str("2")), ("IpAddress", V::Str("-"))]);
        w.event("Microsoft-Windows-Eventlog", "Security", "LAB-PC", 1102, t0 + 20, Some(&SID_ALICE), &[("SubjectUserName", V::Str("alice"))]);
        let data = w.finish();
        let mut evs = vec![];
        let info = parse(&data, &mut |e| evs.push(e)).unwrap();
        assert_eq!((info.chunks, info.records, info.errors, info.first_record, info.last_record), (1, 3, 0, 1, 3));
        assert_eq!(evs.iter().map(|e| e.record_id).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(evs[0].event_id, 4624);
        assert_eq!(evs[0].time, t0);
        assert_eq!(evs[0].channel, "Security");
        assert_eq!(evs[0].computer, "LAB-PC");
        assert_eq!(evs[0].get("TargetUserName"), Some("alice"));
        assert_eq!(evs[1].get("TargetUserName"), Some("bob")); // reused template
        assert_eq!(evs[1].get("IpAddress"), None); // "-" means empty
        assert_eq!(evs[2].event_id, 1102);
        assert_eq!(evs[2].user_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
        assert_eq!(evs[2].provider, "Microsoft-Windows-Eventlog");
        assert_eq!(info.oldest, t0);
        assert_eq!(info.newest, t0 + 20);
        assert!(parse(b"nope", &mut |_| {}).is_err());
    }

    #[test]
    fn damage_loses_only_the_record() {
        let mut w = Writer::new();
        for i in 0..5u16 {
            w.event("P", "System", "PC", 7045, 134_000_000_000_000_000 + i as u64, None, &[("ServiceName", V::Str("svc"))]);
        }
        let mut data = w.finish();
        // Break the 3rd record's binary XML; its size field stays intact, so
        // the records after it are still read.
        let mut p = 4096 + 512;
        for _ in 0..2 {
            p += u32_at(&data, p + 4).unwrap() as usize;
        }
        data[p + 24] = 0x02; // a close-start token cannot open a record
        let mut n = 0;
        let info = parse(&data, &mut |_| n += 1).unwrap();
        assert_eq!((n, info.errors), (4, 1));
    }

    #[test]
    fn iso_round_trip() {
        let ft = parse_iso("2026-10-20T09:30:15.1234567Z").unwrap();
        assert_eq!(filetime_iso(ft), "2026-10-20T09:30:15.1234567Z");
    }
}
