//! AFF4 (Advanced Forensic Format 4, the AFF4 Standard v1.0 that Evimetry
//! and pyaff4 write): a ZIP container (ZIP64 too) whose `information.turtle`
//! describes what is in it in RDF.
//!
//! - Disk images: an `aff4:Image` whose `aff4:dataStream` is an `aff4:Map`
//!   (runs of the image mapped onto streams) or an `aff4:ImageStream` (the
//!   data in chunks, grouped in "bevies" with an index, compressed with
//!   snappy, LZ4, deflate or zlib, or stored). A map's gaps read from its
//!   gap stream (zeros by default); the symbolic streams read as the
//!   standard defines them: `aff4:Zero`, `aff4:SymbolicStreamXX` (the byte
//!   XX), `aff4:UnknownData` ("UNKNOWN" repeated) and `aff4:UnreadableData`
//!   ("UNREADABLEDATA" repeated: what the imager could not read).
//!   Streams in other containers of a striped set are found next to the
//!   first one.
//! - Logical images (AFF4-L): `aff4:FileImage` and `aff4:FolderImage`
//!   entries with their original names, times and hashes; a file's content
//!   is a ZIP member or an image stream.
//!
//! Everything is read on demand; nothing is held whole except the map and
//! the bevy indexes in use.

use anyhow::{bail, Context};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const AFF4: &str = "http://aff4.org/Schema#";
const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const MAX_MEMBERS: u64 = 2_000_000;
const MAX_CD: u64 = 512 << 20;
const MAX_TURTLE: u64 = 64 << 20;
const MAX_MAP: u64 = 128 << 20;
const MAX_IDX: u64 = 1 << 20;
const MAX_CHUNK: u64 = 64 << 20;
const MAX_VOLUMES: usize = 64;
const MAX_DEPTH: usize = 4;
const CACHE_CHUNKS: usize = 32;

fn u16_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u64).unwrap_or(0)
}
fn u32_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64).unwrap_or(0)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

/// Up to `n` bytes at `off` (fewer at the end).
fn rd<R: Read + Seek + ?Sized>(r: &mut R, off: u64, n: usize) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    // Grows with what is there, never by what a damaged length claims.
    let mut b = Vec::new();
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}

/// %XX escapes undone (member names and URNs).
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let hexv = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexv(b[i + 1]), hexv(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ------------------------------------------------------------------ ZIP

/// One member of the container.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    method: u16,
    csize: u64,
    pub size: u64,
    local: u64,
}

#[derive(Debug, Clone, Default)]
struct Zip {
    /// By name with %XX escapes undone.
    members: HashMap<String, Member>,
    comment: String,
}

fn zip_dir<R: Read + Seek + ?Sized>(r: &mut R, len: u64) -> anyhow::Result<Zip> {
    let tail_len = len.min(65_557);
    let tail = rd(r, len - tail_len, tail_len as usize)?;
    let e = tail.windows(4).rposition(|w| w == b"PK\x05\x06").context("not a ZIP file (no end of central directory)")?;
    let eocd = &tail[e..];
    let (mut count, mut cd_size, mut cd_off) = (u16_at(eocd, 10), u32_at(eocd, 12), u32_at(eocd, 16));
    let clen = u16_at(eocd, 20) as usize;
    let comment = String::from_utf8_lossy(eocd.get(22..22 + clen).unwrap_or(&[])).trim_end_matches('\0').trim().to_string();
    if e >= 20 && &tail[e - 20..e - 16] == b"PK\x06\x07" {
        let rec = rd(r, u64_at(&tail, e - 20 + 8), 56)?;
        if rec.starts_with(b"PK\x06\x06") {
            count = u64_at(&rec, 32);
            cd_size = u64_at(&rec, 40);
            cd_off = u64_at(&rec, 48);
        }
    }
    if cd_size > MAX_CD || count > MAX_MEMBERS || cd_off.checked_add(cd_size).is_none_or(|x| x > len) {
        bail!("the ZIP central directory is damaged or too large");
    }
    let cd = rd(r, cd_off, cd_size as usize)?;
    let mut members = HashMap::new();
    let mut p = 0usize;
    for _ in 0..count {
        let Some(h) = cd.get(p..p + 46) else { break };
        if &h[0..4] != b"PK\x01\x02" {
            break;
        }
        let (nl, xl, cl) = (u16_at(h, 28) as usize, u16_at(h, 30) as usize, u16_at(h, 32) as usize);
        let name = String::from_utf8_lossy(cd.get(p + 46..p + 46 + nl).unwrap_or(&[])).into_owned();
        let (mut csize, mut size, mut local) = (u32_at(h, 20), u32_at(h, 24), u32_at(h, 42));
        // ZIP64: the values set to all ones are in the extra field, in order.
        let extra = cd.get(p + 46 + nl..p + 46 + nl + xl).unwrap_or(&[]);
        let mut x = 0;
        while x + 4 <= extra.len() {
            let (id, sz) = (u16_at(extra, x), u16_at(extra, x + 2) as usize);
            if id == 1 {
                let mut q = x + 4;
                for v in [&mut size, &mut csize, &mut local] {
                    if *v == 0xFFFF_FFFF && q + 8 <= x + 4 + sz {
                        *v = u64_at(extra, q);
                        q += 8;
                    }
                }
            }
            x += 4 + sz;
        }
        members.insert(unescape(&name), Member { name, method: u16_at(h, 10) as u16, csize, size, local });
        p += 46 + nl + xl + cl;
    }
    Ok(Zip { members, comment })
}

impl Member {
    fn data_offset<R: Read + Seek + ?Sized>(&self, r: &mut R) -> io::Result<u64> {
        let h = rd(r, self.local, 30)?;
        if !h.starts_with(b"PK\x03\x04") {
            return Err(io::Error::other(format!("{}: no local header", self.name)));
        }
        Ok(self.local + 30 + u16_at(&h, 26) + u16_at(&h, 28))
    }

    /// The whole member, up to `max` bytes.
    fn read_all<R: Read + Seek + ?Sized>(&self, r: &mut R, max: u64) -> io::Result<Vec<u8>> {
        if self.size > max || self.csize > max.saturating_mul(2).max(1 << 20) {
            return Err(io::Error::other(format!("{} is larger than {} bytes", self.name, max)));
        }
        let at = self.data_offset(r)?;
        let d = rd(r, at, self.csize as usize)?;
        match self.method {
            0 => Ok(d),
            8 => {
                let mut out = Vec::with_capacity(self.size.min(1 << 24) as usize);
                flate2::read::DeflateDecoder::new(&d[..]).take(max).read_to_end(&mut out)?;
                Ok(out)
            }
            m => Err(io::Error::other(format!("{}: ZIP compression method {} is not supported", self.name, m))),
        }
    }
}

// --------------------------------------------------------------- Turtle

#[derive(Debug, Clone, PartialEq)]
pub enum Obj {
    Iri(String),
    Lit(String),
}

impl Obj {
    pub fn text(&self) -> &str {
        match self {
            Obj::Iri(s) | Obj::Lit(s) => s,
        }
    }
}

/// The statements of `information.turtle`, IRIs expanded.
#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub triples: Vec<(String, String, Obj)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Iri(String),
    Name(String),
    Str(String),
    Punct(char),
    Type,
}

fn tokens(s: &str) -> Vec<Tok> {
    let c: Vec<char> = s.chars().collect();
    let mut out = vec![];
    let mut i = 0;
    while i < c.len() && out.len() < 4_000_000 {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '#' {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '<' {
            let j = c[i + 1..].iter().position(|&x| x == '>').map(|k| i + 1 + k).unwrap_or(c.len());
            out.push(Tok::Iri(c[i + 1..j].iter().collect()));
            i = j + 1;
        } else if ch == '"' || ch == '\'' {
            let long = c.get(i + 1) == Some(&ch) && c.get(i + 2) == Some(&ch);
            i += if long { 3 } else { 1 };
            let mut v = String::new();
            while i < c.len() {
                if c[i] == '\\' && i + 1 < c.len() {
                    let e = c[i + 1];
                    i += 2;
                    match e {
                        'n' => v.push('\n'),
                        't' => v.push('\t'),
                        'r' => v.push('\r'),
                        'u' | 'U' => {
                            let n = if e == 'u' { 4 } else { 8 };
                            let hex: String = c[i..(i + n).min(c.len())].iter().collect();
                            if let Some(x) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                                v.push(x);
                            }
                            i += n;
                        }
                        x => v.push(x),
                    }
                    continue;
                }
                if long {
                    if c[i] == ch && c.get(i + 1) == Some(&ch) && c.get(i + 2) == Some(&ch) {
                        i += 3;
                        break;
                    }
                } else if c[i] == ch {
                    i += 1;
                    break;
                }
                v.push(c[i]);
                i += 1;
            }
            out.push(Tok::Str(v));
        } else if ch == '^' && c.get(i + 1) == Some(&'^') {
            out.push(Tok::Type);
            i += 2;
        } else if matches!(ch, '.' | ';' | ',' | '[' | ']' | '(' | ')') {
            out.push(Tok::Punct(ch));
            i += 1;
        } else {
            let j = c[i..].iter().position(|&x| x.is_whitespace() || matches!(x, '<' | '"' | ';' | ',' | '[' | ']' | '(' | ')')).map(|k| i + k).unwrap_or(c.len());
            let mut w: String = c[i..j].iter().collect();
            let mut end = j;
            // A final '.' ends the statement, not the name.
            while w.ends_with('.') && !w.chars().all(|d| d.is_ascii_digit() || d == '.' || d == '-') {
                w.pop();
                end -= 1;
            }
            if w.is_empty() {
                out.push(Tok::Punct('.'));
                i += 1;
                continue;
            }
            out.push(Tok::Name(w));
            i = end;
        }
    }
    out
}

pub fn parse_turtle(text: &str) -> Graph {
    let toks = tokens(text);
    let mut prefixes: HashMap<String, String> = HashMap::new();
    let mut g = Graph::default();
    let expand = |prefixes: &HashMap<String, String>, t: &Tok| -> Option<Obj> {
        match t {
            Tok::Iri(s) => Some(Obj::Iri(s.clone())),
            Tok::Str(s) => Some(Obj::Lit(s.clone())),
            Tok::Name(n) if n == "a" => Some(Obj::Iri(RDF_TYPE.into())),
            Tok::Name(n) => match n.split_once(':') {
                Some((p, local)) => Some(Obj::Iri(format!("{}{}", prefixes.get(p).cloned().unwrap_or_else(|| format!("{}:", p)), local))),
                None => Some(Obj::Lit(n.clone())),
            },
            _ => None,
        }
    };
    let mut i = 0;
    while i < toks.len() && g.triples.len() < 2_000_000 {
        match &toks[i] {
            Tok::Name(d) if d == "@prefix" || d.eq_ignore_ascii_case("prefix") => {
                if let (Some(Tok::Name(p)), Some(Tok::Iri(iri))) = (toks.get(i + 1), toks.get(i + 2)) {
                    prefixes.insert(p.trim_end_matches(':').to_string(), iri.clone());
                }
                i += 3;
                if toks.get(i) == Some(&Tok::Punct('.')) {
                    i += 1;
                }
                continue;
            }
            Tok::Name(d) if d == "@base" || d.eq_ignore_ascii_case("base") => {
                i += 2;
                if toks.get(i) == Some(&Tok::Punct('.')) {
                    i += 1;
                }
                continue;
            }
            Tok::Punct(_) => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(Obj::Iri(subject)) = expand(&prefixes, &toks[i]) else {
            i += 1;
            continue;
        };
        i += 1;
        // predicate object (, object)* (; predicate ...)* .
        'pred: while i < toks.len() {
            let Some(Obj::Iri(pred)) = toks.get(i).and_then(|t| expand(&prefixes, t)) else { break };
            i += 1;
            loop {
                let Some(t) = toks.get(i) else { break 'pred };
                if *t == Tok::Punct('[') {
                    // Blank nodes are not used by AFF4: skipped.
                    let mut depth = 0;
                    while i < toks.len() {
                        match toks[i] {
                            Tok::Punct('[') => depth += 1,
                            Tok::Punct(']') => {
                                depth -= 1;
                                if depth == 0 {
                                    i += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                } else if let Some(o) = expand(&prefixes, t) {
                    i += 1;
                    if toks.get(i) == Some(&Tok::Type) {
                        i += 2;
                    } else if let Some(Tok::Name(n)) = toks.get(i) {
                        if n.starts_with('@') {
                            i += 1;
                        }
                    }
                    g.triples.push((subject.clone(), pred.clone(), o));
                } else {
                    i += 1;
                }
                match toks.get(i) {
                    Some(Tok::Punct(',')) => i += 1,
                    Some(Tok::Punct(';')) => {
                        i += 1;
                        while toks.get(i) == Some(&Tok::Punct(';')) {
                            i += 1;
                        }
                        if toks.get(i) == Some(&Tok::Punct('.')) {
                            i += 1;
                            break 'pred;
                        }
                        continue 'pred;
                    }
                    Some(Tok::Punct('.')) => {
                        i += 1;
                        break 'pred;
                    }
                    _ => break 'pred,
                }
            }
        }
    }
    g
}

impl Graph {
    fn values<'a>(&'a self, s: &'a str, p: &'a str) -> impl Iterator<Item = &'a Obj> + 'a {
        let p = format!("{}{}", AFF4, p);
        self.triples.iter().filter(move |t| t.0 == s && t.1 == p).map(|t| &t.2)
    }

    pub fn get(&self, s: &str, p: &str) -> Option<String> {
        self.values(s, p).next().map(|o| o.text().to_string())
    }

    fn num(&self, s: &str, p: &str) -> Option<u64> {
        self.get(s, p).and_then(|v| v.trim().parse().ok())
    }

    pub fn is(&self, s: &str, ty: &str) -> bool {
        let ty = format!("{}{}", AFF4, ty);
        self.triples.iter().any(|t| t.0 == s && t.1 == RDF_TYPE && t.2 == Obj::Iri(ty.clone()))
    }

    /// Subjects of a type, in the order they are described.
    pub fn of_type(&self, ty: &str) -> Vec<String> {
        let ty = format!("{}{}", AFF4, ty);
        let mut out: Vec<String> = vec![];
        for t in &self.triples {
            if t.1 == RDF_TYPE && t.2 == Obj::Iri(ty.clone()) && !out.contains(&t.0) {
                out.push(t.0.clone());
            }
        }
        out
    }

    /// Hashes recorded for a subject: (algorithm, hex).
    pub fn hashes(&self, s: &str) -> Vec<(String, String)> {
        let p = format!("{}hash", AFF4);
        let mut out = vec![];
        // The datatype is dropped by the parser; tell them apart by length.
        for t in self.triples.iter().filter(|t| t.0 == s && t.1 == p) {
            let v = t.2.text().to_ascii_lowercase();
            let alg = match v.len() {
                32 => "MD5",
                40 => "SHA-1",
                64 => "SHA-256",
                128 => "SHA-512",
                _ => continue,
            };
            out.push((alg.to_string(), v));
        }
        out
    }
}

// ---------------------------------------------------------- compression

#[derive(Debug, Clone, Copy, PartialEq)]
enum Comp {
    Stored,
    Snappy,
    Lz4,
    Deflate,
    Zlib,
}

fn comp_of(iri: &str) -> anyhow::Result<Comp> {
    let l = iri.to_ascii_lowercase();
    Ok(if l.is_empty() || l.contains("nullcompressor") || l.ends_with("#stored") {
        Comp::Stored
    } else if l.contains("snappy") {
        Comp::Snappy
    } else if l.contains("lz4") {
        Comp::Lz4
    } else if l.contains("rfc1951") || l.contains("deflate") {
        Comp::Deflate
    } else if l.contains("zlib") || l.contains("rfc1950") {
        Comp::Zlib
    } else {
        bail!("AFF4 compression {} is not supported", iri)
    })
}

/// Snappy, raw block format.
pub fn snappy(d: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut p = 0usize;
    let mut want = 0u64;
    let mut shift = 0;
    loop {
        let b = *d.get(p)?;
        p += 1;
        want |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    if want as usize > max {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(want as usize);
    while p < d.len() {
        let tag = d[p];
        p += 1;
        let (len, off) = match tag & 3 {
            0 => {
                let mut n = (tag >> 2) as usize;
                if n >= 60 {
                    let k = n - 59;
                    let b = d.get(p..p + k)?;
                    n = b.iter().rev().fold(0usize, |a, &x| (a << 8) | x as usize);
                    p += k;
                }
                let n = n + 1;
                out.extend_from_slice(d.get(p..p + n)?);
                p += n;
                if out.len() > want as usize {
                    return None;
                }
                continue;
            }
            1 => {
                let b = *d.get(p)? as usize;
                p += 1;
                ((((tag >> 2) & 7) + 4) as usize, (((tag >> 5) as usize) << 8) | b)
            }
            2 => {
                let o = u16_at(d, p) as usize;
                d.get(p + 1)?;
                p += 2;
                (((tag >> 2) + 1) as usize, o)
            }
            _ => {
                d.get(p + 3)?;
                let o = u32_at(d, p) as usize;
                p += 4;
                (((tag >> 2) + 1) as usize, o)
            }
        };
        if off == 0 || off > out.len() || out.len() + len > want as usize {
            return None;
        }
        let start = out.len() - off;
        for k in 0..len {
            out.push(out[start + k]);
        }
    }
    (out.len() as u64 == want).then_some(out)
}

/// LZ4, block format.
pub fn lz4(d: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut p = 0usize;
    while p < d.len() {
        let token = d[p];
        p += 1;
        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            loop {
                let b = *d.get(p)?;
                p += 1;
                lit += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        out.extend_from_slice(d.get(p..p + lit)?);
        p += lit;
        if out.len() > max {
            return None;
        }
        if p >= d.len() {
            break;
        }
        let off = u16_at(d, p) as usize;
        d.get(p + 1)?;
        p += 2;
        let mut m = (token & 15) as usize;
        if m == 15 {
            loop {
                let b = *d.get(p)?;
                p += 1;
                m += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        m += 4;
        if off == 0 || off > out.len() || out.len() + m > max {
            return None;
        }
        let start = out.len() - off;
        for k in 0..m {
            out.push(out[start + k]);
        }
    }
    Some(out)
}

fn decompress(c: Comp, d: &[u8], chunk: usize) -> io::Result<Vec<u8>> {
    // A chunk that would not shrink is stored as it is.
    if c == Comp::Stored || d.len() == chunk {
        return Ok(d.to_vec());
    }
    let bad = || io::Error::other("an AFF4 chunk does not decompress");
    match c {
        Comp::Snappy => snappy(d, chunk).ok_or_else(bad),
        Comp::Lz4 => lz4(d, chunk).ok_or_else(bad),
        Comp::Deflate | Comp::Zlib => {
            let mut out = Vec::with_capacity(chunk);
            let r = if c == Comp::Deflate { flate2::read::DeflateDecoder::new(d).take(chunk as u64).read_to_end(&mut out) } else { flate2::read::ZlibDecoder::new(d).take(chunk as u64).read_to_end(&mut out) };
            r.map_err(|_| bad())?;
            Ok(out)
        }
        Comp::Stored => unreachable!(),
    }
}

// -------------------------------------------------------------- streams

#[derive(Debug, Clone)]
struct ImageStream {
    vol: usize,
    /// Member names start with this.
    prefix: String,
    chunk: u64,
    per_bevy: u64,
    size: u64,
    comp: Comp,
}

#[derive(Debug, Clone)]
struct Run {
    mapped: u64,
    len: u64,
    target_off: u64,
    target: usize,
}

#[derive(Debug, Clone)]
enum Stream {
    Image(ImageStream),
    Map { size: u64, runs: Vec<Run>, gap: usize },
    Pattern(Vec<u8>),
    /// A stream that is not in any container found.
    Missing(String),
}

/// The volumes of a container set and the streams in them.
#[derive(Debug, Clone, Default)]
struct Set {
    vols: Vec<(String, Zip)>,
    graph: Graph,
    streams: Vec<Stream>,
    by_urn: HashMap<String, usize>,
}

/// Reads `n` bytes at `off` from volume `vol`.
type ReadVol<'a> = dyn FnMut(usize, u64, usize) -> io::Result<Vec<u8>> + 'a;

/// A reader over one volume's bytes for the ZIP code.
struct VolReader<'a, 'b> {
    vol: usize,
    f: &'a mut ReadVol<'b>,
    pos: u64,
}

impl Read for VolReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let d = (self.f)(self.vol, self.pos, buf.len())?;
        buf[..d.len()].copy_from_slice(&d);
        self.pos += d.len() as u64;
        Ok(d.len())
    }
}

impl Seek for VolReader<'_, '_> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        if let SeekFrom::Start(x) = p {
            self.pos = x;
        } else if let SeekFrom::Current(x) = p {
            self.pos = (self.pos as i64 + x).max(0) as u64;
        }
        Ok(self.pos)
    }
}

fn pattern(urn: &str) -> Option<Vec<u8>> {
    let l = urn.strip_prefix(AFF4).or_else(|| urn.strip_prefix("aff4:"))?;
    Some(match l {
        "Zero" => vec![0],
        "UnknownData" => b"UNKNOWN".to_vec(),
        "UnreadableData" => b"UNREADABLEDATA".to_vec(),
        x => {
            let hex = x.strip_prefix("SymbolicStream")?;
            vec![u8::from_str_radix(hex, 16).ok()?]
        }
    })
}

impl Set {
    /// The member names a stream's parts may have: the URN escaped, or the
    /// part after the volume's URN.
    fn member_prefixes(&self, urn: &str) -> Vec<(usize, String)> {
        let mut out = vec![];
        for (i, (vurn, _)) in self.vols.iter().enumerate() {
            if let Some(rel) = urn.strip_prefix(vurn.as_str()) {
                out.push((i, rel.strip_prefix('/').unwrap_or(rel).to_string()));
            }
        }
        for i in 0..self.vols.len() {
            out.push((i, urn.to_string()));
        }
        out
    }

    fn find(&self, urn: &str, suffixes: &[&str]) -> Option<(usize, String)> {
        self.member_prefixes(urn).into_iter().find(|(v, p)| suffixes.iter().any(|s| self.vols[*v].1.members.contains_key(&format!("{}{}", p, s))))
    }

    fn member(&self, vol: usize, name: &str) -> Option<&Member> {
        self.vols.get(vol)?.1.members.get(name)
    }

    fn read_member(&self, rv: &mut ReadVol, vol: usize, name: &str, max: u64) -> anyhow::Result<Vec<u8>> {
        let m = self.member(vol, name).with_context(|| format!("{} is not in the container", name))?.clone();
        let mut r = VolReader { vol, f: rv, pos: 0 };
        Ok(m.read_all(&mut r, max)?)
    }

    /// The stream a URN names, read in (maps) once.
    fn resolve(&mut self, rv: &mut ReadVol, urn: &str, depth: usize) -> anyhow::Result<usize> {
        if let Some(&i) = self.by_urn.get(urn) {
            return Ok(i);
        }
        if self.streams.len() > 100_000 {
            bail!("an AFF4 container names too many streams");
        }
        // Known before it is read: a map that names itself (or a map that
        // names it) gets this placeholder, not another round.
        self.streams.push(Stream::Missing(urn.to_string()));
        let i = self.streams.len() - 1;
        self.by_urn.insert(urn.to_string(), i);
        let s = self.load(rv, urn, depth)?;
        self.streams[i] = s;
        Ok(i)
    }

    fn load(&mut self, rv: &mut ReadVol, urn: &str, depth: usize) -> anyhow::Result<Stream> {
        if let Some(p) = pattern(urn) {
            return Ok(Stream::Pattern(p));
        }
        if depth > MAX_DEPTH {
            bail!("AFF4 streams nest too deep");
        }
        let g = &self.graph;
        if g.is(urn, "Map") || self.find(urn, &["/map"]).is_some() {
            let Some((vol, prefix)) = self.find(urn, &["/map"]) else { return Ok(Stream::Missing(urn.to_string())) };
            let size = g.num(urn, "size").unwrap_or(0);
            let gap_urn = g.get(urn, "mapGapDefaultStream").unwrap_or_else(|| format!("{}Zero", AFF4));
            let map = self.read_member(rv, vol, &format!("{}/map", prefix), MAX_MAP)?;
            let idx = self.read_member(rv, vol, &format!("{}/idx", prefix), MAX_IDX)?;
            let targets: Vec<String> = String::from_utf8_lossy(&idx).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            if targets.len() > 65_536 {
                bail!("the AFF4 map {} names too many streams", urn);
            }
            let mut ids = vec![];
            for t in &targets {
                ids.push(self.resolve(rv, t, depth + 1)?);
            }
            let gap = self.resolve(rv, &gap_urn, depth + 1)?;
            let mut runs: Vec<Run> = map
                .chunks_exact(28)
                .filter_map(|e| {
                    let target = *ids.get(u32_at(e, 24) as usize)?;
                    let len = u64_at(e, 8);
                    (len > 0).then(|| Run { mapped: u64_at(e, 0), len, target_off: u64_at(e, 16), target })
                })
                .collect();
            runs.sort_by_key(|r| r.mapped);
            let size = size.max(runs.last().map(|r| r.mapped.saturating_add(r.len)).unwrap_or(0));
            return Ok(Stream::Map { size, runs, gap });
        }
        let Some((vol, prefix)) = self.find(urn, &["/00000000", "/00000000.index"]) else {
            if let Some(ds) = g.get(urn, "dataStream") {
                return self.load(rv, &ds, depth + 1);
            }
            return Ok(Stream::Missing(urn.to_string()));
        };
        let chunk = g.num(urn, "chunkSize").unwrap_or(32_768);
        let per_bevy = g.num(urn, "chunksInSegment").unwrap_or(2048);
        if chunk == 0 || chunk > MAX_CHUNK || per_bevy == 0 || per_bevy > 1 << 24 {
            bail!("AFF4 stream {} has an unreadable chunk layout", urn);
        }
        let comp = comp_of(&g.get(urn, "compressionMethod").unwrap_or_default())?;
        let size = g.num(urn, "size").unwrap_or(0);
        Ok(Stream::Image(ImageStream { vol, prefix, chunk, per_bevy, size, comp }))
    }

    fn size(&self, i: usize) -> u64 {
        match &self.streams[i] {
            Stream::Image(s) => s.size,
            Stream::Map { size, .. } => *size,
            Stream::Pattern(_) | Stream::Missing(_) => u64::MAX,
        }
    }
}

/// Bevy indexes and chunks read lately, per reader.
#[derive(Default)]
pub struct Cache {
    /// (stream, bevy) -> (data offset of the bevy member, chunk index entries).
    bevies: HashMap<(usize, u64), Arc<(u64, Vec<(u64, u32)>)>>,
    chunks: HashMap<(usize, u64), Arc<Vec<u8>>>,
    order: Vec<(usize, u64)>,
}

impl Set {
    fn chunk(&self, rv: &mut ReadVol, cache: &mut Cache, i: usize, s: &ImageStream, n: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Some(c) = cache.chunks.get(&(i, n)) {
            return Ok(c.clone());
        }
        let bevy = n / s.per_bevy;
        let key = (i, bevy);
        let b = match cache.bevies.get(&key) {
            Some(b) => b.clone(),
            None => {
                let name = format!("{}/{:08}", s.prefix, bevy);
                let m = self.member(s.vol, &name).ok_or_else(|| io::Error::other(format!("{} is not in the container", name)))?.clone();
                if m.method != 0 {
                    return Err(io::Error::other(format!("{} is compressed in the ZIP, not in chunks", name)));
                }
                let idx = self.member(s.vol, &format!("{}.index", name)).cloned();
                let at = {
                    let mut r = VolReader { vol: s.vol, f: rv, pos: 0 };
                    m.data_offset(&mut r)?
                };
                let entries: Vec<(u64, u32)> = match idx {
                    Some(ix) => {
                        let mut r = VolReader { vol: s.vol, f: rv, pos: 0 };
                        let d = ix.read_all(&mut r, MAX_IDX * 16)?;
                        d.chunks_exact(12).map(|e| (u64_at(e, 0), u32_at(e, 8) as u32)).collect()
                    }
                    None => return Err(io::Error::other(format!("{}.index is not in the container", name))),
                };
                let b = Arc::new((at, entries));
                if cache.bevies.len() > 64 {
                    cache.bevies.clear();
                }
                cache.bevies.insert(key, b.clone());
                b
            }
        };
        let k = (n % s.per_bevy) as usize;
        let &(off, len) = b.1.get(k).ok_or_else(|| io::Error::other("an AFF4 chunk is not in its bevy index"))?;
        if len as u64 > s.chunk.saturating_mul(2) + 1024 {
            return Err(io::Error::other("an AFF4 chunk is larger than its stream allows"));
        }
        let raw = rv(s.vol, b.0.checked_add(off).ok_or_else(|| io::Error::other("an AFF4 chunk offset is damaged"))?, len as usize)?;
        // The last chunk may be short; a full one decompresses to the chunk size.
        let want = s.chunk.min(s.size.saturating_sub(n * s.chunk).max(1)) as usize;
        let d = decompress(s.comp, &raw, if raw.len() == want { want } else { s.chunk as usize })?;
        let d = Arc::new(d);
        cache.chunks.insert((i, n), d.clone());
        cache.order.push((i, n));
        if cache.order.len() > CACHE_CHUNKS {
            let old = cache.order.remove(0);
            cache.chunks.remove(&old);
        }
        Ok(d)
    }

    /// Fills `buf` from stream `i` at `off`.
    fn read(&self, rv: &mut ReadVol, cache: &mut Cache, i: usize, off: u64, buf: &mut [u8], depth: usize) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("AFF4 streams nest too deep"));
        }
        match &self.streams[i] {
            Stream::Pattern(p) => {
                for (k, b) in buf.iter_mut().enumerate() {
                    *b = p[(off.wrapping_add(k as u64) % p.len() as u64) as usize];
                }
                Ok(())
            }
            Stream::Missing(u) => Err(io::Error::other(format!("AFF4 stream {} is in a container that was not found (another part of a striped set?)", u))),
            Stream::Image(s) => {
                let mut done = 0usize;
                while done < buf.len() {
                    let at = off.saturating_add(done as u64);
                    if at >= s.size {
                        buf[done..].fill(0);
                        break;
                    }
                    let c = self.chunk(rv, cache, i, s, at / s.chunk)?;
                    let w = (at % s.chunk) as usize;
                    let n = (buf.len() - done).min(c.len().saturating_sub(w));
                    if n == 0 {
                        buf[done..].fill(0);
                        break;
                    }
                    buf[done..done + n].copy_from_slice(&c[w..w + n]);
                    done += n;
                }
                Ok(())
            }
            Stream::Map { runs, gap, .. } => {
                let mut done = 0usize;
                while done < buf.len() {
                    let at = off.saturating_add(done as u64);
                    // The run at or before `at`.
                    let k = runs.partition_point(|r| r.mapped <= at);
                    let (n, target, toff) = match k.checked_sub(1).map(|j| &runs[j]) {
                        Some(r) if at < r.mapped.saturating_add(r.len) => (((r.mapped.saturating_add(r.len) - at).min(usize::MAX as u64) as usize).min(buf.len() - done), r.target, r.target_off.saturating_add(at - r.mapped)),
                        _ => {
                            let next = runs.get(k).map(|r| r.mapped).unwrap_or(u64::MAX);
                            (((next - at).min(usize::MAX as u64) as usize).min(buf.len() - done), *gap, at)
                        }
                    };
                    if n == 0 {
                        // The end of the 64-bit range: nothing maps there.
                        buf[done..].fill(0);
                        break;
                    }
                    self.read(rv, cache, target, toff, &mut buf[done..done + n], depth + 1)?;
                    done += n;
                }
                Ok(())
            }
        }
    }
}

fn open_set(rv: &mut ReadVol, lens: &[u64]) -> anyhow::Result<Set> {
    let mut set = Set::default();
    for (v, &len) in lens.iter().enumerate() {
        let mut r = VolReader { vol: v, f: rv, pos: 0 };
        let zip = zip_dir(&mut r, len)?;
        let t = zip.members.get("information.turtle").cloned().context("an AFF4 container has information.turtle; this ZIP has none")?;
        let text = t.read_all(&mut r, MAX_TURTLE)?;
        let g = parse_turtle(&String::from_utf8_lossy(&text));
        let mut urn = zip.comment.clone();
        if !urn.starts_with("aff4://") {
            if let Some(d) = zip.members.get("container.description").cloned() {
                urn = String::from_utf8_lossy(&d.read_all(&mut r, 4096)?).trim().to_string();
            }
        }
        if !urn.starts_with("aff4://") {
            urn = g.of_type("ZipVolume").into_iter().next().unwrap_or_default();
        }
        set.graph.triples.extend(g.triples);
        set.vols.push((urn, zip));
    }
    Ok(set)
}

/// Whether a file starts like an AFF4 container: a ZIP holding
/// information.turtle.
pub fn is_container<R: Read + Seek + ?Sized>(r: &mut R, len: u64) -> bool {
    let head = rd(r, 0, 4).unwrap_or_default();
    if !head.starts_with(b"PK") {
        return false;
    }
    zip_dir(r, len).is_ok_and(|z| z.members.contains_key("information.turtle"))
}

// ----------------------------------------------------------- disk images

/// An AFF4 disk image (one container or a striped set).
#[derive(Debug)]
pub struct Aff4Disk {
    pub size: u64,
    pub label: String,
    /// Case details, the device, how the acquisition ended, read errors.
    pub notes: Vec<String>,
    pub files: Vec<PathBuf>,
    /// Hashes recorded for the image streams, by stream URN.
    pub stream_hashes: Vec<(String, Vec<(String, String)>)>,
    /// Whether the image has runs read as UnreadableData or UnknownData.
    pub has_unreadable: bool,
    set: Set,
    root: usize,
}

fn file_reader<'a>(files: &'a [PathBuf], handles: &'a mut [Option<File>]) -> impl FnMut(usize, u64, usize) -> io::Result<Vec<u8>> + 'a {
    move |v, off, n| {
        if handles[v].is_none() {
            handles[v] = Some(File::open(&files[v])?);
        }
        rd(handles[v].as_mut().unwrap(), off, n)
    }
}

/// Opens `path` as an AFF4 disk image; None when it is not an AFF4
/// container or holds only logical files.
pub fn open_disk(path: &Path) -> anyhow::Result<Option<Aff4Disk>> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    if len < 22 || !is_container(&mut f, len) {
        return Ok(None);
    }
    let mut files = vec![path.to_path_buf()];
    let mut lens = vec![len];
    let mut handles: Vec<Option<File>> = vec![None];
    let mut set = {
        let mut rv = file_reader(&files, &mut handles);
        open_set(&mut rv, &lens)?
    };
    // The image to read: one with a data stream, a disk image first.
    let images: Vec<String> = set.graph.of_type("Image").into_iter().filter(|s| set.graph.get(s, "dataStream").is_some() && !set.graph.is(s, "FileImage")).collect();
    let pick = images.iter().find(|s| set.graph.is(s, "DiskImage")).or(images.first()).cloned();
    let Some(image) = pick else { return Ok(None) };
    let data = set.graph.get(&image, "dataStream").unwrap();
    // Streams a striped set keeps in other containers: next to this one.
    let needed: Vec<String> = set.graph.triples.iter().filter(|t| t.1 == format!("{}dependentStream", AFF4) || t.1 == format!("{}dataStream", AFF4)).map(|t| t.2.text().to_string()).collect();
    let missing = |set: &Set| needed.iter().any(|u| set.find(u, &["/00000000", "/map"]).is_none() && pattern(u).is_none());
    if missing(&set) {
        if let Some(dir) = path.parent() {
            let mut others: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("aff4")) && p != path).collect()).unwrap_or_default();
            others.sort();
            for o in others.into_iter().take(MAX_VOLUMES) {
                let Ok(mut of) = File::open(&o) else { continue };
                let olen = of.metadata().map(|m| m.len()).unwrap_or(0);
                if !is_container(&mut of, olen) {
                    continue;
                }
                files.push(o);
                lens.push(olen);
                handles.push(None);
                let mut rv = file_reader(&files, &mut handles);
                set = open_set(&mut rv, &lens)?;
                if !missing(&set) {
                    break;
                }
            }
        }
    }
    let root = {
        let mut rv = file_reader(&files, &mut handles);
        set.resolve(&mut rv, &data, 0)?
    };
    let g = &set.graph;
    let size = g.num(&image, "size").unwrap_or_else(|| set.size(root));
    let mut notes = vec![];
    let field = |s: &str, p: &str| g.get(s, p).filter(|v| !v.trim().is_empty());
    for cd in g.of_type("CaseDetails") {
        let parts: Vec<String> = [("caseName", "case"), ("caseDescription", "")].iter().filter_map(|(p, l)| field(&cd, p).map(|v| if l.is_empty() { v } else { format!("{} {}", l, v) })).collect();
        if !parts.is_empty() {
            notes.push(format!("Case details: {}", parts.join("; ")));
        }
    }
    for cn in g.of_type("CaseNotes") {
        let parts: Vec<String> = [("caseNumber", ""), ("evidenceNumber", "evidence"), ("examiner", "examiner"), ("notes", "")].iter().filter_map(|(p, l)| field(&cn, p).map(|v| if l.is_empty() { v } else { format!("{} {}", l, v) })).collect();
        if !parts.is_empty() {
            notes.push(format!("Case notes{}: {}", field(&cn, "timestamp").map(|t| format!(" ({})", day_first(&t))).unwrap_or_default(), parts.join("; ")));
        }
    }
    let dev: Vec<String> = ["diskMake", "diskModel", "diskSerial", "diskDeviceName", "diskInterfaceType"].iter().filter_map(|p| field(&image, p)).collect();
    if !dev.is_empty() {
        notes.push(format!("Device: {}", dev.join(", ")));
    }
    if let Some(s) = field(&image, "acquisitionCompletionState") {
        notes.push(format!("Acquisition: {}", s));
    }
    let used_unreadable = set.streams.iter().any(|s| match s {
        Stream::Map { runs, .. } => runs.iter().any(|r| matches!(&set.streams[r.target], Stream::Pattern(p) if p == b"UNREADABLEDATA" || p == b"UNKNOWN")),
        _ => false,
    });
    if used_unreadable {
        notes.push("Parts of the device could not be read when it was imaged: they read as the text UNREADABLEDATA (or UNKNOWN), repeated, as the AFF4 standard defines.".into());
    }
    if let Stream::Map { runs, .. } = &set.streams[root] {
        let mapped: u64 = runs.iter().filter(|r| !matches!(set.streams[r.target], Stream::Pattern(_))).map(|r| r.len).sum();
        if mapped < size {
            notes.push(format!("{} of {} bytes were imaged; the rest reads from the map's gap stream (zeros unless it says otherwise).", grouped(mapped), grouped(size)));
        }
    }
    let missing_streams: Vec<String> = set.streams.iter().filter_map(|s| if let Stream::Missing(u) = s { Some(u.clone()) } else { None }).collect();
    if !missing_streams.is_empty() {
        notes.push(format!("{} stream(s) of this image are in containers not found next to it; those parts cannot be read.", missing_streams.len()));
    }
    if images.len() > 1 {
        notes.push(format!("The container holds {} images; the first disk image is read.", images.len()));
    }
    if files.len() > 1 {
        notes.push(format!("A striped set of {} containers.", files.len()));
    }
    let stream_hashes: Vec<(String, Vec<(String, String)>)> = g.of_type("ImageStream").into_iter().map(|s| (s.clone(), g.hashes(&s))).filter(|x| !x.1.is_empty()).collect();
    let comp = set.streams.iter().find_map(|s| if let Stream::Image(i) = s { Some(i.comp) } else { None });
    let label = format!("AFF4{}", comp.map(|c| format!(" ({})", format!("{:?}", c).to_lowercase())).unwrap_or_default());
    Ok(Some(Aff4Disk { size, label, notes, files, stream_hashes, has_unreadable: used_unreadable, set, root }))
}

impl Aff4Disk {
    pub fn reader(self: &Arc<Self>) -> Aff4Reader {
        Aff4Reader { d: self.clone(), handles: (0..self.files.len()).map(|_| None).collect(), pos: 0, cache: Cache::default() }
    }

    /// Reads one stream of the image whole and returns its hashes, to
    /// check against the recorded ones.
    #[cfg(test)]
    fn hash_stream(&self, urn: &str) -> anyhow::Result<(String, String)> {
        use md5::Digest as _;
        let i = *self.set.by_urn.get(urn).context("no such stream")?;
        let mut handles: Vec<Option<File>> = (0..self.files.len()).map(|_| None).collect();
        let mut rv = file_reader(&self.files, &mut handles);
        let mut cache = Cache::default();
        let size = self.set.size(i);
        let mut md5 = md5::Md5::new();
        let mut sha1 = sha1::Sha1::new();
        let mut off = 0;
        let mut buf = vec![0u8; 1 << 20];
        while off < size {
            let n = ((size - off) as usize).min(buf.len());
            self.set.read(&mut rv, &mut cache, i, off, &mut buf[..n], 0)?;
            md5.update(&buf[..n]);
            sha1.update(&buf[..n]);
            off += n as u64;
        }
        Ok((hex(&md5.finalize()), hex(&sha1.finalize())))
    }
}

#[cfg(test)]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// `Read + Seek` over an AFF4 disk image.
pub struct Aff4Reader {
    d: Arc<Aff4Disk>,
    handles: Vec<Option<File>>,
    pos: u64,
    cache: Cache,
}

impl Read for Aff4Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.d.size || buf.is_empty() {
            return Ok(0);
        }
        let n = ((self.d.size - self.pos) as usize).min(buf.len());
        let d = self.d.clone();
        let mut rv = file_reader(&d.files, &mut self.handles);
        d.set.read(&mut rv, &mut self.cache, d.root, self.pos, &mut buf[..n], 0)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Aff4Reader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(x) => self.d.size as i128 + x as i128,
            SeekFrom::Current(x) => self.pos as i128 + x as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

// --------------------------------------------------------- logical images

/// A file or folder of an AFF4-L logical image.
#[derive(Debug, Clone)]
pub struct LogicalFile {
    /// From the image's top, '/' separated, without a leading slash.
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// FILETIMEs (UTC), 0 when not recorded.
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub changed: u64,
    pub hashes: Vec<(String, String)>,
    content: Content,
}

#[derive(Debug, Clone)]
enum Content {
    None,
    Member(String),
    Stream(usize),
}

/// An AFF4-L logical image: files with their original names.
#[derive(Debug)]
pub struct Aff4Logical {
    pub files: Vec<LogicalFile>,
    pub notes: Vec<String>,
    set: Set,
}

/// An xsd:dateTime as people read it: day first, in UTC.
fn day_first(s: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(s.trim()) {
        Ok(t) => t.with_timezone(&chrono::Utc).format("%d-%m-%Y %H:%M:%S UTC").to_string(),
        Err(_) => s.to_string(),
    }
}

/// 1234567 as "1,234,567".
fn grouped(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// An xsd:dateTime as a FILETIME (UTC).
fn filetime(s: &str) -> u64 {
    let Ok(t) = chrono::DateTime::parse_from_rfc3339(s.trim()) else { return 0 };
    let t = t.with_timezone(&chrono::Utc);
    let secs = t.timestamp() + 11_644_473_600;
    if secs < 0 {
        return 0;
    }
    secs as u64 * 10_000_000 + (t.timestamp_subsec_nanos() / 100) as u64
}

/// Whether the bytes are an AFF4 container with logical files.
pub fn is_logical<R: Read + Seek + ?Sized>(r: &mut R, len: u64) -> bool {
    let mut f = |_: usize, off: u64, n: usize| rd(r, off, n);
    let Ok(set) = open_set(&mut f, &[len]) else { return false };
    !set.graph.of_type("FileImage").is_empty() || !set.graph.of_type("FolderImage").is_empty()
}

pub fn open_logical<R: Read + Seek + ?Sized>(r: &mut R, len: u64) -> anyhow::Result<Aff4Logical> {
    let mut f = |_: usize, off: u64, n: usize| rd(r, off, n);
    let mut set = open_set(&mut f, &[len])?;
    let vurn = set.vols[0].0.clone();
    let mut subjects = set.graph.of_type("FolderImage");
    subjects.extend(set.graph.of_type("FileImage"));
    let mut files = vec![];
    let mut notes = vec![];
    let mut missing = 0;
    for s in subjects {
        let g = &set.graph;
        let is_dir = g.is(&s, "FolderImage");
        let path = g.get(&s, "originalFileName").unwrap_or_else(|| unescape(s.strip_prefix(vurn.as_str()).unwrap_or(&s)));
        let path = path.replace('\\', "/");
        let path = path.trim_start_matches("./").trim_start_matches('/').trim_end_matches('/').to_string();
        if path.is_empty() {
            continue;
        }
        let t = |p: &str| g.get(&s, p).map(|v| filetime(&v)).unwrap_or(0);
        let (created, modified, accessed, changed) = (t("birthTime"), t("lastWritten"), t("lastAccessed"), t("recordChanged"));
        let size = g.num(&s, "size").unwrap_or(0);
        let hashes = g.hashes(&s);
        let content = if is_dir {
            Content::None
        } else if g.is(&s, "ImageStream") || set.find(&s, &["/00000000"]).is_some() {
            match set.resolve(&mut f, &s, 0) {
                Ok(i) => Content::Stream(i),
                Err(_) => Content::None,
            }
        } else {
            let rel = s.strip_prefix(vurn.as_str()).unwrap_or(&s);
            let cands = [rel.strip_prefix('/').unwrap_or(rel).to_string(), rel.to_string(), unescape(rel.strip_prefix('/').unwrap_or(rel)), s.clone()];
            match cands.iter().find(|c| set.vols[0].1.members.contains_key(c.as_str())) {
                Some(m) => Content::Member(m.clone()),
                None => Content::None,
            }
        };
        if !is_dir && matches!(content, Content::None) && size > 0 {
            missing += 1;
        }
        files.push(LogicalFile { path, is_dir, size, created, modified, accessed, changed, hashes, content });
    }
    if files.is_empty() {
        bail!("the AFF4 container lists no logical files");
    }
    if missing > 0 {
        notes.push(format!("{} file(s) are listed without content in the container.", missing));
    }
    Ok(Aff4Logical { files, notes, set })
}

impl Aff4Logical {
    /// Up to `len` bytes of file `i` from `off`. Members compressed in the
    /// ZIP are inflated whole (into `whole`, kept for the next read).
    pub fn read<R: Read + Seek + ?Sized>(&self, r: &mut R, i: usize, off: u64, len: usize, cache: &mut Cache, whole: &mut Option<(usize, Arc<Vec<u8>>)>) -> anyhow::Result<Vec<u8>> {
        let lf = self.files.get(i).context("no such file")?;
        match &lf.content {
            Content::None => Ok(vec![]),
            Content::Member(name) => {
                let m = self.set.vols[0].1.members.get(name).context("member gone")?.clone();
                if off >= m.size {
                    return Ok(vec![]);
                }
                let n = len.min((m.size - off) as usize);
                if m.method == 0 {
                    let at = m.data_offset(r)?;
                    return Ok(rd(r, at + off, n)?);
                }
                if whole.as_ref().is_none_or(|w| w.0 != i) {
                    *whole = Some((i, Arc::new(m.read_all(r, 2 << 30)?)));
                }
                let d = &whole.as_ref().unwrap().1;
                let o = (off as usize).min(d.len());
                Ok(d[o..(o + n).min(d.len())].to_vec())
            }
            Content::Stream(s) => {
                let size = lf.size.min(self.set.size(*s));
                if off >= size {
                    return Ok(vec![]);
                }
                let n = len.min((size - off) as usize);
                let mut buf = vec![0u8; n];
                let mut f = |_: usize, o: u64, k: usize| rd(r, o, k);
                self.set.read(&mut f, cache, *s, off, &mut buf, 0)?;
                Ok(buf)
            }
        }
    }

    /// Where a stored member's bytes are in the container (none for
    /// compressed content).
    pub fn extent<R: Read + Seek + ?Sized>(&self, r: &mut R, i: usize) -> Option<(u64, u64)> {
        match &self.files.get(i)?.content {
            Content::Member(name) => {
                let m = self.set.vols[0].1.members.get(name)?;
                (m.method == 0).then(|| m.data_offset(r).ok().map(|a| (a, m.size))).flatten()
            }
            _ => None,
        }
    }
}

/// Fuzzing: one container from memory, its images and logical files read.
pub fn fuzz(d: &[u8]) {
    let len = d.len() as u64;
    let mut c = io::Cursor::new(d);
    {
        let mut f = |_: usize, off: u64, n: usize| rd(&mut c, off, n.min(1 << 24));
        if let Ok(mut set) = open_set(&mut f, &[len]) {
            let images = set.graph.of_type("Image");
            for s in images.iter().take(4) {
                let Some(ds) = set.graph.get(s, "dataStream") else { continue };
                let Ok(i) = set.resolve(&mut f, &ds, 0) else { continue };
                let mut cache = Cache::default();
                for off in [0, 4096, 65_536, set.size(i).saturating_sub(512)] {
                    let mut b = vec![0u8; 4096];
                    let _ = set.read(&mut f, &mut cache, i, off, &mut b, 0);
                }
            }
        }
    }
    let mut c = io::Cursor::new(d);
    if let Ok(l) = open_logical(&mut c, len) {
        let mut cache = Cache::default();
        let mut whole = None;
        for i in 0..l.files.len().min(16) {
            let _ = l.read(&mut c, i, 0, 1 << 16, &mut cache, &mut whole);
            let _ = l.extent(&mut c, i);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn snappy_and_lz4() {
        // Snappy: "abcabcabcabc" as a literal and a copy.
        let s = [12u8, (2 << 2) | 0, b'a', b'b', b'c', ((9 - 1) << 2) | 2, 3, 0];
        assert_eq!(snappy(&s, 64).unwrap(), b"abcabcabcabc");
        assert!(snappy(&s[..5], 64).is_none(), "cut short");
        // LZ4: literal "abc", then a match of 9 at offset 3.
        let l = [0x35u8, b'a', b'b', b'c', 3, 0, 0x00];
        assert_eq!(lz4(&l[..6], 64).unwrap(), b"abcabcabcabc");
    }

    /// A stored ZIP: (name, data), the comment last.
    pub(crate) fn zip(members: &[(String, Vec<u8>)], comment: &str) -> Vec<u8> {
        fn le16(v: &mut Vec<u8>, x: u16) {
            v.extend(x.to_le_bytes());
        }
        fn le32(v: &mut Vec<u8>, x: u32) {
            v.extend(x.to_le_bytes());
        }
        let mut out = vec![];
        let mut cd = vec![];
        for (name, data) in members {
            let off = out.len() as u32;
            out.extend(b"PK\x03\x04");
            le16(&mut out, 20);
            le16(&mut out, 0);
            le16(&mut out, 0);
            le32(&mut out, 0);
            le32(&mut out, 0);
            le32(&mut out, data.len() as u32);
            le32(&mut out, data.len() as u32);
            le16(&mut out, name.len() as u16);
            le16(&mut out, 0);
            out.extend(name.as_bytes());
            out.extend(data);
            cd.extend(b"PK\x01\x02");
            le16(&mut cd, 20);
            le16(&mut cd, 20);
            le16(&mut cd, 0);
            le16(&mut cd, 0);
            le32(&mut cd, 0);
            le32(&mut cd, 0);
            le32(&mut cd, data.len() as u32);
            le32(&mut cd, data.len() as u32);
            le16(&mut cd, name.len() as u16);
            le16(&mut cd, 0);
            le16(&mut cd, 0);
            le16(&mut cd, 0);
            le16(&mut cd, 0);
            le32(&mut cd, 0);
            le32(&mut cd, off);
            cd.extend(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend(&cd);
        out.extend(b"PK\x05\x06\0\0\0\0");
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((cd.len() as u32).to_le_bytes());
        out.extend(cd_off.to_le_bytes());
        out.extend((comment.len() as u16).to_le_bytes());
        out.extend(comment.as_bytes());
        out
    }

    /// Snappy for a run of one repeated 7-byte text: a literal, then copies.
    fn snappy_repeat(text: &[u8; 7], n: usize) -> Vec<u8> {
        let mut v = vec![];
        let mut x = n as u64;
        loop {
            let b = (x & 0x7F) as u8;
            x >>= 7;
            if x == 0 {
                v.push(b);
                break;
            }
            v.push(b | 0x80);
        }
        v.push(6 << 2);
        v.extend(text);
        let mut left = n - 7;
        while left > 0 {
            let k = left.min(64);
            v.push((((k - 1) << 2) | 2) as u8);
            v.extend(7u16.to_le_bytes());
            left -= k;
        }
        v
    }

    /// A disk image: a map over a 3-chunk snappy stream in 2 bevies (the
    /// middle chunk stored), a gap, and a run that could not be read.
    pub(crate) fn disk_container() -> (Vec<u8>, Vec<u8>) {
        let chunk = 4096usize;
        let c0: Vec<u8> = b"LAB-PC ".iter().copied().cycle().take(chunk).collect();
        let c1: Vec<u8> = (0..chunk as u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let c2: Vec<u8> = b"BOB-LAB".iter().copied().cycle().take(chunk).collect();
        let z0 = snappy_repeat(b"LAB-PC ", chunk);
        let z2 = snappy_repeat(b"BOB-LAB", chunk);
        let bevy0 = [z0.clone(), c1.clone()].concat();
        let mut idx0 = vec![];
        idx0.extend(0u64.to_le_bytes());
        idx0.extend((z0.len() as u32).to_le_bytes());
        idx0.extend((z0.len() as u64).to_le_bytes());
        idx0.extend((c1.len() as u32).to_le_bytes());
        let mut idx1 = vec![];
        idx1.extend(0u64.to_le_bytes());
        idx1.extend((z2.len() as u32).to_le_bytes());
        // The image: stream bytes 0..4096 at 0, 4096..12288 at 8192, a
        // read error of 512 bytes at 20480, zeros elsewhere (64 KiB).
        let mut map = vec![];
        for (mapped, len, toff, t) in [(0u64, 4096u64, 0u64, 0u32), (8192, 8192, 4096, 0), (20_480, 512, 0, 1)] {
            map.extend(mapped.to_le_bytes());
            map.extend(len.to_le_bytes());
            map.extend(toff.to_le_bytes());
            map.extend(t.to_le_bytes());
        }
        let turtle = "@prefix :      <aff4://lab-volume> .
@prefix aff4:  <http://aff4.org/Schema#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .

<aff4://lab-stream>
        a                      aff4:ImageStream ;
        aff4:chunkSize         \"4096\"^^xsd:int ;
        aff4:chunksInSegment   \"2\"^^xsd:int ;
        aff4:compressionMethod <http://code.google.com/p/snappy/> ;
        aff4:size              \"12288\"^^xsd:long ;
        aff4:stored            : .

<aff4://lab-map>
        a                         aff4:Map ;
        aff4:dependentStream      <aff4://lab-stream> ;
        aff4:mapGapDefaultStream  aff4:Zero ;
        aff4:size                 \"65536\"^^xsd:long ;
        aff4:stored               : .

<aff4://lab-image>
        a                     aff4:ContiguousImage , aff4:DiskImage , aff4:Image ;
        aff4:dataStream       <aff4://lab-map> ;
        aff4:diskMake         \"Lab\" ;
        aff4:diskSerial       \"LAB0001\" ;
        aff4:size             \"65536\"^^xsd:long ;
        aff4:acquisitionCompletionState \"Completed With Errors\" ;
        aff4:stored           : .

<aff4://lab-case>
        a                    aff4:CaseNotes ;
        aff4:caseNumber      \"LAB-2026-001\" ;
        aff4:examiner        \"alice\" ;
        aff4:stored          : .
";
        let members = vec![
            ("container.description".to_string(), b"aff4://lab-volume".to_vec()),
            ("aff4%3A%2F%2Flab-stream/00000000".to_string(), bevy0),
            ("aff4%3A%2F%2Flab-stream/00000000.index".to_string(), idx0),
            ("aff4%3A%2F%2Flab-stream/00000001".to_string(), z2),
            ("aff4%3A%2F%2Flab-stream/00000001.index".to_string(), idx1),
            ("aff4%3A%2F%2Flab-map/map".to_string(), map),
            ("aff4%3A%2F%2Flab-map/idx".to_string(), b"aff4://lab-stream\nhttp://aff4.org/Schema#UnreadableData\n".to_vec()),
            ("information.turtle".to_string(), turtle.as_bytes().to_vec()),
        ];
        let stream = [c0, c1, c2].concat();
        let mut want = vec![0u8; 65_536];
        want[..4096].copy_from_slice(&stream[..4096]);
        want[8192..16_384].copy_from_slice(&stream[4096..12_288]);
        for (k, b) in want[20_480..20_992].iter_mut().enumerate() {
            *b = b"UNREADABLEDATA"[k % 14];
        }
        (zip(&members, "aff4://lab-volume"), want)
    }

    /// A logical image: a folder and a file stored as a ZIP member.
    pub(crate) fn logical_container() -> Vec<u8> {
        let turtle = "@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://lab-logical//Users/alice> a aff4:FolderImage, aff4:Image ;
    aff4:originalFileName \"./Users/alice/\"^^xsd:string ;
    aff4:birthTime \"2026-10-20T08:00:00+02:00\"^^xsd:datetime .
<aff4://lab-logical//Users/alice/notes.txt> a aff4:FileImage, aff4:Image, aff4:zip_segment ;
    aff4:birthTime \"2026-10-20T08:00:00+02:00\"^^xsd:datetime ;
    aff4:lastWritten \"2026-10-21T02:30:00Z\"^^xsd:datetime ;
    aff4:originalFileName \"./Users/alice/notes.txt\"^^xsd:string ;
    aff4:size 23 .
";
        zip(&[("/Users/alice/notes.txt".to_string(), b"meet at the lab at noon".to_vec()), ("information.turtle".to_string(), turtle.as_bytes().to_vec())], "aff4://lab-logical")
    }

    #[test]
    fn reads_a_disk_image() {
        let (c, want) = disk_container();
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/aff4");
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("lab-disk.aff4"), &c).unwrap();
        }
        let p = std::env::temp_dir().join(format!("kokino-aff4-test-{}.aff4", std::process::id()));
        std::fs::write(&p, &c).unwrap();
        let img = Arc::new(open_disk(&p).unwrap().expect("a disk image"));
        assert_eq!((img.size, img.label.as_str()), (65_536, "AFF4 (snappy)"));
        assert!(img.has_unreadable);
        assert!(img.notes.iter().any(|n| n.contains("LAB-2026-001") && n.contains("examiner alice")), "{:?}", img.notes);
        assert!(img.notes.iter().any(|n| n == "Device: Lab, LAB0001"), "{:?}", img.notes);
        let mut r = img.reader();
        let mut got = vec![];
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), want.len());
        assert!(got == want, "the image reads as mapped");
        // Across a chunk and a bevy boundary.
        r.seek(SeekFrom::Start(12_280)).unwrap();
        let mut b = [0u8; 16];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &want[12_280..12_296]);
        std::fs::remove_file(&p).ok();
        // Damaged compressed data: an error, never a panic.
        let mut bad = c.clone();
        let at = bad.windows(4).position(|w| w == b"BOB-").unwrap();
        bad[at - 1] = 0xFF;
        std::fs::write(&p, &bad).unwrap();
        if let Ok(Some(img)) = open_disk(&p) {
            let mut r = Arc::new(img).reader();
            let mut got = vec![];
            let _ = r.read_to_end(&mut got);
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn reads_a_logical_image() {
        let c = logical_container();
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/aff4");
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("lab-logical.aff4"), &c).unwrap();
        }
        let mut r = io::Cursor::new(&c);
        assert!(is_logical(&mut r, c.len() as u64));
        let l = open_logical(&mut r, c.len() as u64).unwrap();
        let f = l.files.iter().position(|x| x.path == "Users/alice/notes.txt").unwrap();
        assert!(l.files.iter().any(|x| x.path == "Users/alice" && x.is_dir));
        assert_eq!(l.read(&mut r, f, 5, 100, &mut Cache::default(), &mut None).unwrap(), b"at the lab at noon");
        assert_eq!(l.files[f].modified, filetime("2026-10-21T02:30:00Z"));
        assert_eq!(l.files[f].created, filetime("2026-10-20T06:00:00Z"), "to UTC");
        assert!(l.extent(&mut r, f).is_some());
        // The disk container is not a logical one.
        let (d, _) = disk_container();
        assert!(!is_logical(&mut io::Cursor::new(&d), d.len() as u64));
    }

    #[test]
    fn turtle_statements() {
        let t = r#"@prefix :      <aff4://vol> .
@prefix aff4:  <http://aff4.org/Schema#> .
@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
<aff4://s1>
        a                    aff4:ImageStream ;
        aff4:chunkSize       "32768"^^xsd:int ;
        aff4:hash            "d5825dc1152a42958c8219ff11ed01a3"^^aff4:MD5 , "fbac22cca549310bc5df03b7560afcf490995fbb"^^aff4:SHA1 ;
        aff4:stored          : .
<aff4://f//a/b.txt> a aff4:FileImage, aff4:Image ;
    aff4:size 8688 ;
    aff4:originalFileName "./a/b.txt"^^xsd:string .
"#;
        let g = parse_turtle(t);
        assert!(g.is("aff4://s1", "ImageStream"));
        assert_eq!(g.num("aff4://s1", "chunkSize"), Some(32768));
        assert_eq!(g.hashes("aff4://s1").len(), 2);
        assert_eq!(g.get("aff4://s1", "stored").as_deref(), Some("aff4://vol"));
        assert_eq!(g.num("aff4://f//a/b.txt", "size"), Some(8688));
        assert_eq!(g.get("aff4://f//a/b.txt", "originalFileName").as_deref(), Some("./a/b.txt"));
        assert_eq!(g.of_type("Image"), ["aff4://f//a/b.txt"]);
    }
}

/// Local validation on the AFF4 reference images (not in the repository):
/// runs only when `target/validation/aff4/` holds them.
#[cfg(test)]
mod validation {
    use super::*;

    fn dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/aff4")
    }

    #[test]
    fn reference_images() {
        let d = dir();
        if !d.is_dir() {
            return;
        }
        let mut whole: Vec<(String, String)> = vec![];
        for name in ["Base-Linear.aff4", "Base-Linear-AllHashes.aff4", "Base-Allocated.aff4", "Base-Linear-ReadError.aff4", "Striped/Base-Linear_1.aff4", "Base-ExabyteSparse.aff4"] {
            let p = d.join(name);
            if !p.is_file() {
                continue;
            }
            let img = Arc::new(open_disk(&p).unwrap().expect("a disk image"));
            eprintln!("== {} {} size {} files {} notes {:?}", name, img.label, img.size, img.files.len(), img.notes);
            // Every image stream reads back to the hashes recorded for it.
            for (urn, hashes) in &img.stream_hashes {
                if img.set.by_urn.get(urn).is_none() {
                    continue;
                }
                let (md5, sha1) = img.hash_stream(urn).unwrap();
                for (alg, want) in hashes {
                    match alg.as_str() {
                        "MD5" => assert_eq!(&md5, want, "{} {} MD5", name, urn),
                        "SHA-1" => assert_eq!(&sha1, want, "{} {} SHA-1", name, urn),
                        _ => {}
                    }
                }
                eprintln!("   stream {} matches {} recorded hash(es)", urn, hashes.len());
            }
            if img.size < 1 << 32 {
                use md5::Digest as _;
                let mut r = img.reader();
                let mut h = md5::Md5::new();
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = r.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                whole.push((name.to_string(), hex(&h.finalize())));
            } else {
                // The 9 EB image: the small file system in its middle.
                let mut r = img.reader();
                r.seek(SeekFrom::Start(0x400000000000000)).unwrap();
                let mut b = vec![0u8; 512];
                r.read_exact(&mut b).unwrap();
                eprintln!("   at 0x400000000000000: {:02x?}", &b[..16]);
                r.seek(SeekFrom::Start(0)).unwrap();
                r.read_exact(&mut b).unwrap();
                assert!(b.iter().all(|&x| x == 0xFF), "1 MB of 0xFF at the start");
            }
        }
        eprintln!("whole-image MD5: {:?}", whole);
        // The same device imaged four ways reads the same.
        let linear: Vec<&String> = whole.iter().filter(|(n, _)| n.contains("Linear") && !n.contains("ReadError")).map(|x| &x.1).collect();
        assert!(linear.windows(2).all(|w| w[0] == w[1]), "{:?}", whole);
    }

    #[test]
    fn logical_images() {
        let d = dir().join("AFF4-L");
        for name in ["dream.aff4", "unicode.aff4"] {
            let p = d.join(name);
            let Ok(mut f) = File::open(&p) else { continue };
            let len = f.metadata().unwrap().len();
            assert!(is_logical(&mut f, len));
            let l = open_logical(&mut f, len).unwrap();
            eprintln!("== {} {} files, notes {:?}", name, l.files.len(), l.notes);
            let mut cache = Cache::default();
            let mut whole = None;
            let mut checked = 0;
            for (i, x) in l.files.iter().enumerate() {
                if x.is_dir {
                    continue;
                }
                let data = l.read(&mut f, i, 0, x.size as usize, &mut cache, &mut whole).unwrap();
                assert_eq!(data.len() as u64, x.size, "{}", x.path);
                use md5::Digest as _;
                let md5 = hex(&md5::Md5::digest(&data));
                if let Some((_, want)) = x.hashes.iter().find(|h| h.0 == "MD5") {
                    assert_eq!(&md5, want, "{}", x.path);
                    checked += 1;
                }
                if checked < 4 {
                    eprintln!("   {} {} bytes created {} md5 ok", x.path, x.size, x.created);
                }
            }
            eprintln!("   {} file(s) match their recorded MD5", checked);
            assert!(checked > 0);
        }
        if let Ok(t) = std::fs::read(d.join("dream.txt")) {
            let mut f = File::open(d.join("dream.aff4")).unwrap();
            let len = f.metadata().unwrap().len();
            let l = open_logical(&mut f, len).unwrap();
            let i = l.files.iter().position(|x| x.path.ends_with("dream.txt")).unwrap();
            assert_eq!(l.read(&mut f, i, 0, t.len(), &mut Cache::default(), &mut None).unwrap(), t);
        }
    }
}
