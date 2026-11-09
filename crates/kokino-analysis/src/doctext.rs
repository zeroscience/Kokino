//! Text inside compressed documents, for the full-text index.
//!
//! The raw `strings` pass cannot see words that are deflate-compressed, which
//! is how ZIP archives, Office Open XML (DOCX, XLSX, PPTX), OpenDocument and
//! most PDFs store them. This module decodes them:
//!
//! - ZIP (and everything built on it): every entry is inflated; XML and HTML
//!   parts become plain text, plain-text entries are kept, nested containers
//!   are opened up to `Limits::max_depth`, other binaries get a strings pass.
//!   Package plumbing (relationships, content types, styles, themes) is
//!   skipped. Encrypted entries are reported, not guessed.
//! - GZIP: inflated and handled like any other content.
//! - Word, Excel and PowerPoint 97-2003, Outlook .msg and RTF: see
//!   `oletext`.
//! - PDF: objects are found by scanning (not by trusting the xref table, so
//!   damaged and incrementally updated files work), Flate streams and object
//!   streams are decoded, page text is read from the content streams with
//!   each font's ToUnicode map, and the document info and XMP metadata are
//!   kept. Encrypted PDFs are reported.
//!
//! Every decode is bounded (`Limits`), so a "zip bomb" or a hostile PDF costs
//! at most a fixed amount of memory and time.

use regex::bytes::Regex as BRegex;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// Where the text came from: "word/document.xml", "notes.zip/a.txt",
    /// "page 3", "metadata".
    pub name: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Most bytes inflated from one ZIP entry or PDF stream.
    pub max_entry: u64,
    /// Most bytes inflated from one top-level container, nested ones included.
    pub max_total: u64,
    pub max_entries: usize,
    /// Containers inside containers (a DOCX inside a ZIP is depth 2).
    pub max_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_entry: 64 << 20, max_total: 256 << 20, max_entries: 20_000, max_depth: 4 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Pdf,
    Gzip,
    /// OLE compound file: Word, Excel and PowerPoint 97-2003, Outlook .msg.
    Ole,
    Rtf,
    /// An mbox mailbox or one email message.
    Mail,
}

/// Container kind from the first bytes, if this module can decode it.
pub fn detect(head: &[u8]) -> Option<Kind> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        Some(Kind::Zip)
    } else if head.starts_with(b"%PDF-") {
        Some(Kind::Pdf)
    } else if head.starts_with(b"\x1f\x8b\x08") {
        Some(Kind::Gzip)
    } else if kokino_artifacts::cfb::is_cfb(head) {
        Some(Kind::Ole)
    } else if head.starts_with(b"{\\rtf") {
        Some(Kind::Rtf)
    } else if crate::mail::detect(head).is_some() {
        Some(Kind::Mail)
    } else {
        None
    }
}

/// Outcome of one document: the text parts and anything that could not be read.
#[derive(Debug, Default)]
pub struct Extracted {
    pub parts: Vec<Part>,
    /// Human-readable notes: encrypted entries, unsupported compression,
    /// limits reached.
    pub notes: Vec<String>,
}

pub fn extract(data: &[u8]) -> Extracted {
    extract_with(data, Limits::default())
}

pub fn extract_with(data: &[u8], limits: Limits) -> Extracted {
    let mut cx = Cx { limits, left: limits.max_total, out: Extracted::default() };
    cx.container(data, "", 1);
    cx.out.parts.retain(|p| !p.text.trim().is_empty());
    cx.out
}

struct Cx {
    limits: Limits,
    /// Inflate budget left for this top-level document.
    left: u64,
    out: Extracted,
}

impl Cx {
    fn note(&mut self, s: String) {
        if self.out.notes.len() < 50 && !self.out.notes.contains(&s) {
            self.out.notes.push(s);
        }
    }

    fn push(&mut self, name: &str, text: String) {
        self.out.parts.push(Part { name: name.to_string(), text });
    }

    fn container(&mut self, data: &[u8], prefix: &str, depth: u32) {
        match detect(data) {
            Some(Kind::Zip) => self.zip(data, prefix, depth),
            Some(Kind::Pdf) => self.pdf(data, prefix),
            Some(Kind::Gzip) => {
                let max = self.limits.max_entry.min(self.left);
                let (inner, capped) = inflate(flate2::read::GzDecoder::new(data), max);
                self.left = self.left.saturating_sub(inner.len() as u64);
                if capped {
                    self.note(format!("{}: decompressed size limit reached", label(prefix, "gzip")));
                }
                let name = format!("{}(gunzipped)", prefix);
                self.content(&inner, &name, depth + 1);
            }
            Some(Kind::Ole) => {
                let o = crate::oletext::ole(data);
                for n in o.notes {
                    self.note(format!("{}: {}", label(prefix, "OLE file"), n));
                }
                for (name, text) in o.parts {
                    self.push(&format!("{}{}", prefix, name), text);
                }
            }
            Some(Kind::Rtf) => {
                let text = crate::oletext::rtf(data);
                self.push(&format!("{}text", prefix), text);
            }
            Some(Kind::Mail) => {
                // Each message: its headers and text; document attachments
                // are opened like any other content.
                let ranges = if data.starts_with(b"From ") { crate::mail::split_mbox(data) } else { vec![(0, data.len())] };
                for (k, (o, n)) in ranges.into_iter().enumerate().take(100_000) {
                    let p = crate::mail::parse(&data[o..o + n]);
                    let label = format!("{}message {}", prefix, k + 1);
                    let head: Vec<String> = ["Date", "From", "To", "Cc", "Subject"].iter().map(|h| format!("{}: {}", h, crate::mail::decode_words(&p.header(h)))).collect();
                    let names: Vec<String> = p.attachments.iter().map(|(a, _)| a.name.clone()).collect();
                    let mut text = head.join("\n");
                    text.push('\n');
                    text.push_str(&p.text);
                    if !names.is_empty() {
                        text.push_str(&format!("\nAttachments: {}", names.join(", ")));
                    }
                    self.push(&label, text);
                    for (a, bytes) in p.attachments {
                        if self.left == 0 {
                            break;
                        }
                        self.content(&bytes, &format!("{}/{}", label, a.name), depth + 1);
                    }
                }
            }
            None => {}
        }
    }

    /// Bytes of unknown kind found inside a container.
    fn content(&mut self, data: &[u8], name: &str, depth: u32) {
        if detect(data).is_some() {
            if depth <= self.limits.max_depth {
                self.container(data, &format!("{}/", name), depth);
            } else {
                self.note(format!("{}: nested deeper than {} containers, not opened", name, self.limits.max_depth));
            }
            return;
        }
        let lower = name.to_ascii_lowercase();
        let ext = lower.rsplit('.').next().unwrap_or("");
        if is_media(data) || MEDIA_EXT.contains(&ext) {
            return;
        }
        if XML_EXT.contains(&ext) || looks_like_xml(data) {
            self.push(name, xml_text(&decode_text(data)));
        } else if TEXT_EXT.contains(&ext) || plain_text(data) {
            self.push(name, decode_text(data));
        } else {
            let (runs, _) = crate::textindex::extract(data, 0, true);
            let text: Vec<String> = runs.into_iter().map(|r| r.text).collect();
            self.push(name, text.join("\n"));
        }
    }

    fn zip(&mut self, data: &[u8], prefix: &str, depth: u32) {
        let entries = match zip_entries(data) {
            Ok(e) => e,
            Err(e) => {
                self.note(format!("{}: {}", label(prefix, "zip"), e));
                return;
            }
        };
        if entries.len() > self.limits.max_entries {
            self.note(format!("{}: {} entries, only the first {} read", label(prefix, "zip"), entries.len(), self.limits.max_entries));
        }
        for e in entries.into_iter().take(self.limits.max_entries) {
            if e.name.ends_with('/') || skip_part(&e.name) {
                continue;
            }
            let full = format!("{}{}", prefix, e.name);
            if e.flags & 1 != 0 {
                self.note(format!("{}: encrypted entry, not readable without the password", full));
                continue;
            }
            if self.left == 0 {
                self.note(format!("{}: total decompressed size limit reached, remaining entries skipped", label(prefix, "zip")));
                break;
            }
            let Some(raw) = data.get(e.data_start..) else { continue };
            let max = self.limits.max_entry.min(self.left);
            let (bytes, capped) = match e.method {
                0 => {
                    let n = (e.csize as usize).min(raw.len()).min(max as usize);
                    (raw[..n].to_vec(), e.csize > max)
                }
                8 => {
                    let end = if e.csize > 0 { (e.csize as usize).min(raw.len()) } else { raw.len() };
                    inflate(flate2::read::DeflateDecoder::new(&raw[..end]), max)
                }
                m => {
                    self.note(format!("{}: compression method {} not supported", full, m));
                    continue;
                }
            };
            self.left = self.left.saturating_sub(bytes.len() as u64);
            if capped {
                self.note(format!("{}: decompressed size limit reached, text cut", full));
            }
            self.content(&bytes, &full, depth + 1);
        }
    }

    fn pdf(&mut self, data: &[u8], prefix: &str) {
        let name = |s: &str| format!("{}{}", prefix, s);
        let doc = Pdf::parse(data, self.limits.max_entry, &mut self.left);
        if doc.encrypted {
            self.note(format!("{}: encrypted PDF, page text not readable without the password", label(prefix, "pdf")));
        }
        if !doc.info.is_empty() {
            self.push(&name("metadata"), doc.info.join("\n"));
        }
        for (i, x) in doc.xmp.iter().enumerate() {
            let n = if doc.xmp.len() > 1 { format!("XMP metadata {}", i + 1) } else { "XMP metadata".into() };
            self.push(&name(&n), xml_text(x));
        }
        if doc.encrypted {
            return;
        }
        for (i, t) in doc.pages().into_iter().enumerate() {
            self.push(&name(&format!("page {}", i + 1)), t);
        }
        if doc.capped {
            self.note(format!("{}: decompressed size limit reached, some streams skipped", label(prefix, "pdf")));
        }
    }
}

fn label(prefix: &str, kind: &str) -> String {
    let p = prefix.trim_end_matches('/');
    if p.is_empty() { kind.to_string() } else { p.to_string() }
}

/// Reads at most `max` bytes; the flag says the source had more.
fn inflate<R: Read>(r: R, max: u64) -> (Vec<u8>, bool) {
    let mut out = vec![];
    let mut t = r.take(max + 1);
    let _ = t.read_to_end(&mut out); // keep what decoded before an error
    let capped = out.len() as u64 > max;
    out.truncate(max as usize);
    (out, capped)
}

const MEDIA_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "emf", "wmf", "ico", "webp", "mp3", "mp4", "wav", "m4a", "avi", "mov", "ttf", "otf", "woff", "woff2", "odttf",
];
const XML_EXT: &[&str] = &["xml", "html", "htm", "xhtml", "svg", "xaml", "opf", "ncx", "vml"];
const TEXT_EXT: &[&str] = &[
    "txt", "csv", "tsv", "json", "md", "log", "ini", "cfg", "conf", "yml", "yaml", "js", "css", "ps1", "bat", "cmd", "sh", "py", "eml", "rtf", "sql", "reg", "vbs",
];

fn is_media(d: &[u8]) -> bool {
    d.starts_with(b"\xff\xd8\xff") || d.starts_with(b"\x89PNG") || d.starts_with(b"GIF8") || d.starts_with(b"BM") && d.len() > 14 && d[6..10] == [0, 0, 0, 0]
}

/// OOXML / ODF plumbing that holds no user text.
fn skip_part(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let file = n.rsplit('/').next().unwrap_or(&n);
    n.ends_with(".rels")
        || file == "[content_types].xml"
        || file == "manifest.xml" && n.contains("meta-inf")
        || file == "mimetype"
        || file == "styles.xml"
        || file == "fonttable.xml"
        || file == "settings.xml"
        || file == "websettings.xml"
        || file == "numbering.xml"
        || file == "presprops.xml"
        || file == "viewprops.xml"
        || file == "tablestyles.xml"
        || n.contains("/theme/")
        || n.starts_with("theme/")
        || n.contains("slidelayouts/")
        || n.contains("slidemasters/")
        || n.contains("notesmasters/")
        || n.contains("handoutmasters/")
}

fn looks_like_xml(d: &[u8]) -> bool {
    let s = d.strip_prefix(b"\xef\xbb\xbf").unwrap_or(d);
    s.starts_with(b"<?xml") || s.starts_with(b"<html") || s.starts_with(b"<!DOCTYPE")
}

fn plain_text(d: &[u8]) -> bool {
    let sample = &d[..d.len().min(4096)];
    !sample.is_empty() && std::str::from_utf8(sample).map(|s| !s.chars().any(|c| c.is_control() && !"\r\n\t".contains(c))).unwrap_or(false)
}

/// UTF-8, or UTF-16 with a byte-order mark.
fn decode_text(d: &[u8]) -> String {
    if let Some(b) = d.strip_prefix(b"\xff\xfe") {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u);
    }
    if let Some(b) = d.strip_prefix(b"\xfe\xff") {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u);
    }
    String::from_utf8_lossy(d.strip_prefix(b"\xef\xbb\xbf").unwrap_or(d)).into_owned()
}

/// Elements whose end starts a new line of text (paragraphs, table cells,
/// spreadsheet cells and rows, list items...), by local name.
const BLOCK: &[&str] = &[
    "p", "h", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr", "tc", "td", "th", "c", "row", "si", "div", "br", "title", "table-row", "table-cell", "line-break", "list-item",
    "comment", "footnote", "endnote", "txbxcontent", "sp", "is", "creator", "lastmodifiedby", "subject", "description", "keywords", "company", "manager",
];
/// Empty elements that stand for a space.
const SPACE: &[&str] = &["tab", "s", "space"];

/// Plain text of an XML or HTML document: tags removed (word runs split by
/// formatting are joined again), entities decoded, one line per block.
pub fn xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() / 3);
    let mut rest = s;
    let mut skip_until: Option<&str> = None;
    while !rest.is_empty() {
        if let Some(end) = skip_until {
            match rest.find(end) {
                Some(i) => rest = &rest[i + end.len()..],
                None => break,
            }
            skip_until = None;
            continue;
        }
        let Some(lt) = rest.find('<') else {
            out.push_str(&decode_entities(rest));
            break;
        };
        out.push_str(&decode_entities(&rest[..lt]));
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<!--") {
            rest = r;
            skip_until = Some("-->");
            continue;
        }
        if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").unwrap_or(r.len());
            out.push_str(&r[..end]);
            rest = r.get(end + 3..).unwrap_or("");
            continue;
        }
        let Some(gt) = rest.find('>') else { break };
        let tag = &rest[1..gt];
        rest = &rest[gt + 1..];
        let closing = tag.starts_with('/');
        let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
        if !closing && (local == "script" || local == "style") && !tag.ends_with('/') {
            skip_until = Some(if local == "script" { "</script>" } else { "</style>" });
            continue;
        }
        if SPACE.contains(&local.as_str()) {
            out.push(' ');
        } else if (closing || tag.ends_with('/')) && BLOCK.contains(&local.as_str()) {
            out.push('\n');
        }
    }
    tidy(&out)
}

/// Trims every line and drops empty ones.
fn tidy(s: &str) -> String {
    s.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(semi) = rest.char_indices().take(12).find(|(_, c)| *c == ';').map(|(i, _)| i) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..semi];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ------------------------------------------------------------------ ZIP

#[derive(Debug)]
struct ZipEntry {
    name: String,
    method: u16,
    flags: u16,
    csize: u64,
    data_start: usize,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Entries from the central directory, or, when it is missing or damaged
/// (truncated or carved files), from a scan of local headers.
fn zip_entries(d: &[u8]) -> anyhow::Result<Vec<ZipEntry>> {
    match central_directory(d) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => {
            let v = local_scan(d);
            if v.is_empty() {
                anyhow::bail!("no readable ZIP entries");
            }
            Ok(v)
        }
    }
}

fn data_start(d: &[u8], local: usize) -> Option<usize> {
    if u32_at(d, local)? != 0x0403_4b50 {
        return None;
    }
    Some(local + 30 + u16_at(d, local + 26)? as usize + u16_at(d, local + 28)? as usize)
}

fn central_directory(d: &[u8]) -> Option<Vec<ZipEntry>> {
    let from = d.len().saturating_sub(22 + 65_535);
    let eocd = (from..d.len().saturating_sub(21)).rev().find(|&i| u32_at(d, i) == Some(0x0605_4b50))?;
    let mut count = u16_at(d, eocd + 10)? as u64;
    let mut cd = u32_at(d, eocd + 16)? as u64;
    // ZIP64 end of central directory, via its locator just before the EOCD.
    if (count == 0xFFFF || cd == 0xFFFF_FFFF) && eocd >= 20 && u32_at(d, eocd - 20) == Some(0x0706_4b50) {
        let z = u64_at(d, eocd - 12)? as usize;
        if u32_at(d, z) == Some(0x0606_4b50) {
            count = u64_at(d, z + 32)?;
            cd = u64_at(d, z + 48)?;
        }
    }
    let mut out = vec![];
    let mut p = cd as usize;
    for _ in 0..count.min(1_000_000) {
        if u32_at(d, p)? != 0x0201_4b50 {
            break;
        }
        let flags = u16_at(d, p + 8)?;
        let method = u16_at(d, p + 10)?;
        let mut csize = u32_at(d, p + 20)? as u64;
        let usize_ = u32_at(d, p + 24)? as u64;
        let (n, m, k) = (u16_at(d, p + 28)? as usize, u16_at(d, p + 30)? as usize, u16_at(d, p + 32)? as usize);
        let mut local = u32_at(d, p + 42)? as u64;
        let name = String::from_utf8_lossy(d.get(p + 46..p + 46 + n)?).into_owned();
        // ZIP64 extra field: only the fields that overflowed are present, in order.
        let mut e = p + 46 + n;
        let end = e + m;
        while e + 4 <= end {
            let (id, len) = (u16_at(d, e)?, u16_at(d, e + 2)? as usize);
            if id == 1 {
                let mut q = e + 4;
                if usize_ == 0xFFFF_FFFF {
                    q += 8;
                }
                if csize == 0xFFFF_FFFF {
                    csize = u64_at(d, q)?;
                    q += 8;
                }
                if local == 0xFFFF_FFFF {
                    local = u64_at(d, q)?;
                }
            }
            e += 4 + len;
        }
        if let Some(ds) = data_start(d, local as usize) {
            out.push(ZipEntry { name, method, flags, csize, data_start: ds });
        }
        p += 46 + n + m + k;
    }
    Some(out)
}

fn local_scan(d: &[u8]) -> Vec<ZipEntry> {
    let mut out = vec![];
    let mut p = 0;
    while p + 30 <= d.len() && out.len() < 1_000_000 {
        if u32_at(d, p) != Some(0x0403_4b50) {
            p += 1;
            continue;
        }
        let (Some(flags), Some(method), Some(cs), Some(n), Some(ds)) = (u16_at(d, p + 6), u16_at(d, p + 8), u32_at(d, p + 18), u16_at(d, p + 26), data_start(d, p)) else { break };
        let name = String::from_utf8_lossy(d.get(p + 30..p + 30 + n as usize).unwrap_or(&[])).into_owned();
        // With a data descriptor (flag bit 3) the size is 0 here; inflate
        // simply runs to the end of the deflate stream.
        let csize = if flags & 8 != 0 { 0 } else { cs as u64 };
        out.push(ZipEntry { name, method, flags, csize, data_start: ds });
        p = if csize > 0 { ds + csize as usize } else { ds.max(p + 4) };
    }
    out
}

// ------------------------------------------------------------------ PDF

struct Obj {
    dict: String,
    stream: Option<Vec<u8>>,
}

struct Pdf {
    objs: HashMap<u32, Obj>,
    /// Object numbers in file order, for pages that no page tree reaches.
    order: Vec<u32>,
    encrypted: bool,
    capped: bool,
    info: Vec<String>,
    xmp: Vec<String>,
}

fn re(cell: &'static OnceLock<BRegex>, pat: &str) -> &'static BRegex {
    cell.get_or_init(|| BRegex::new(pat).unwrap())
}

/// Bytes as Latin-1 text, so dictionaries can be searched with &str tools.
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if from >= h.len() || n.is_empty() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|i| i + from)
}

/// Raw value text of `/key` in a dictionary: a nested <<dict>>, an [array],
/// a reference "5 0 R" or a single token.
fn dict_value(d: &str, key: &str) -> Option<String> {
    let mut search = 0;
    let at = loop {
        let i = d[search..].find(key)? + search;
        let after = d[i + key.len()..].chars().next();
        if after.map(|c| !(c.is_alphanumeric() || c == '_')).unwrap_or(true) {
            break i + key.len();
        }
        search = i + key.len();
    };
    let v = d[at..].trim_start();
    if v.starts_with("<<") {
        let mut depth = 0;
        let b = v.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            if &b[i..i + 2] == b"<<" {
                depth += 1;
                i += 2;
            } else if &b[i..i + 2] == b">>" {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(v[..i].to_string());
                }
            } else {
                i += 1;
            }
        }
        Some(v.to_string())
    } else if v.starts_with('[') {
        Some(v[..v.find(']').map(|i| i + 1).unwrap_or(v.len())].to_string())
    } else if v.starts_with('(') {
        // literal string: balanced parentheses, backslash escapes
        let (mut depth, mut esc) = (0, false);
        for (i, c) in v.char_indices() {
            match c {
                _ if esc => esc = false,
                '\\' => esc = true,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(v[..=i].to_string());
                    }
                }
                _ => {}
            }
        }
        Some(v.to_string())
    } else if v.starts_with('<') {
        Some(v[..v.find('>').map(|i| i + 1).unwrap_or(v.len())].to_string())
    } else {
        static REF: OnceLock<regex::Regex> = OnceLock::new();
        let r = REF.get_or_init(|| regex::Regex::new(r"^\d+\s+\d+\s+R").unwrap());
        if let Some(m) = r.find(v) {
            return Some(m.as_str().to_string());
        }
        // Past the first character, which may be more than one byte.
        let first = v.chars().next().map_or(0, char::len_utf8);
        let end = v[first..].find(|c: char| c.is_whitespace() || "/<>[]()".contains(c)).map(|i| i + first).unwrap_or(v.len());
        Some(v[..end].to_string())
    }
}

fn refs(v: &str) -> Vec<u32> {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    let r = R.get_or_init(|| regex::Regex::new(r"(\d+)\s+\d+\s+R").unwrap());
    r.captures_iter(v).filter_map(|c| c[1].parse().ok()).collect()
}

fn has_type(dict: &str, t: &str) -> bool {
    dict_value(dict, "/Type").map(|v| v == format!("/{}", t)).unwrap_or(false)
}

impl Pdf {
    fn parse(data: &[u8], max_stream: u64, budget: &mut u64) -> Pdf {
        static OBJ: OnceLock<BRegex> = OnceLock::new();
        static STREAM: OnceLock<BRegex> = OnceLock::new();
        let obj_re = re(&OBJ, r"(?-u)(?:^|[^0-9])(\d{1,10})\s+\d{1,5}\s+obj\b");
        let stream_re = re(&STREAM, r"(?-u)stream(?:\r\n|\n|\r)");
        let mut pdf = Pdf { objs: HashMap::new(), order: vec![], encrypted: false, capped: false, info: vec![], xmp: vec![] };
        let mut pos = 0;
        while let Some(c) = obj_re.captures_at(data, pos) {
            let m = c.get(0).unwrap();
            let num: u32 = match std::str::from_utf8(&c[1]).ok().and_then(|s| s.parse().ok()) {
                Some(n) => n,
                None => {
                    pos = m.end();
                    continue;
                }
            };
            let body_start = m.end();
            let endobj = find(data, b"endobj", body_start).unwrap_or(data.len());
            let s = stream_re.find_at(data, body_start).filter(|s| s.start() < endobj);
            let (dict, stream, next) = match s {
                Some(s) => {
                    let ds = s.end();
                    let es = find(data, b"endstream", ds).unwrap_or(data.len());
                    let mut raw = &data[ds..es];
                    while raw.last().map(|b| *b == b'\n' || *b == b'\r').unwrap_or(false) {
                        raw = &raw[..raw.len() - 1];
                    }
                    let after = find(data, b"endobj", es).unwrap_or(data.len());
                    (latin1(&data[body_start..s.start()]), Some(raw.to_vec()), after)
                }
                None => (latin1(&data[body_start..endobj]), None, endobj),
            };
            pdf.order.retain(|n| *n != num);
            pdf.order.push(num);
            pdf.objs.insert(num, Obj { dict, stream });
            pos = next.max(m.end());
        }
        pdf.encrypted = find(data, b"/Encrypt", 0).is_some();

        // Decode streams once (Flate only; others are left as they are).
        let nums: Vec<u32> = pdf.order.clone();
        for n in &nums {
            let o = pdf.objs.get_mut(n).unwrap();
            if let Some(raw) = o.stream.take() {
                let filter = dict_value(&o.dict, "/Filter").unwrap_or_default();
                o.stream = if filter.is_empty() {
                    Some(raw)
                } else if filter.contains("/FlateDecode") || filter.contains("/Fl") && !filter.contains("/Fla") {
                    if filter.matches('/').count() > 1 {
                        None // a chain of filters we do not decode
                    } else {
                        let max = max_stream.min(*budget);
                        let (b, capped) = inflate(flate2::read::ZlibDecoder::new(&raw[..]), max);
                        *budget = budget.saturating_sub(b.len() as u64);
                        pdf.capped |= capped;
                        Some(b)
                    }
                } else {
                    None
                };
            }
        }
        // Object streams hold more objects (fonts and pages in modern files).
        for n in &nums {
            let Some(o) = pdf.objs.get(n) else { continue };
            if !has_type(&o.dict, "ObjStm") {
                continue;
            }
            let (Some(s), Some(first)) = (o.stream.clone(), dict_value(&o.dict, "/First").and_then(|v| v.parse::<usize>().ok())) else { continue };
            let head = latin1(&s[..first.min(s.len())]);
            let nums_offs: Vec<usize> = head.split_whitespace().filter_map(|t| t.parse().ok()).collect();
            let pairs: Vec<(u32, usize)> = nums_offs.chunks_exact(2).map(|p| (p[0] as u32, p[1])).collect();
            for (i, (num, off)) in pairs.iter().enumerate() {
                let start = first + off;
                let end = pairs.get(i + 1).map(|p| first + p.1).unwrap_or(s.len()).min(s.len());
                if start < end && !pdf.objs.contains_key(num) {
                    pdf.objs.insert(*num, Obj { dict: latin1(&s[start..end]), stream: None });
                    pdf.order.push(*num);
                }
            }
        }

        // Document info (any dictionary with the usual keys) and XMP packets.
        for n in &pdf.order {
            let o = &pdf.objs[n];
            if has_type(&o.dict, "Metadata") {
                if let Some(s) = &o.stream {
                    pdf.xmp.push(String::from_utf8_lossy(s).into_owned());
                }
                continue;
            }
            if o.stream.is_none() && ["/Producer", "/Creator", "/Author", "/Title"].iter().any(|k| o.dict.contains(k)) && !o.dict.contains("/Type") {
                for k in ["/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Company"] {
                    if let Some(v) = dict_value(&o.dict, k) {
                        let t = pdf_string_value(&v);
                        if !t.is_empty() {
                            pdf.info.push(format!("{}: {}", &k[1..], t));
                        }
                    }
                }
            }
        }
        pdf
    }

    fn obj_dict(&self, v: &str) -> Option<String> {
        if v.starts_with("<<") {
            return Some(v.to_string());
        }
        refs(v).first().and_then(|n| self.objs.get(n)).map(|o| o.dict.clone())
    }

    /// Resource font name -> ToUnicode map (None for simple fonts without one).
    fn fonts(&self, resources: &str) -> HashMap<String, Option<CMap>> {
        let mut out = HashMap::new();
        let Some(fd) = dict_value(resources, "/Font").and_then(|v| self.obj_dict(&v)) else { return out };
        static F: OnceLock<regex::Regex> = OnceLock::new();
        let r = F.get_or_init(|| regex::Regex::new(r"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R").unwrap());
        for c in r.captures_iter(&fd) {
            let Some(font) = c[2].parse::<u32>().ok().and_then(|n| self.objs.get(&n)) else { continue };
            let cmap = dict_value(&font.dict, "/ToUnicode")
                .and_then(|v| refs(&v).first().copied())
                .and_then(|n| self.objs.get(&n))
                .and_then(|o| o.stream.as_ref())
                .map(|s| CMap::parse(&latin1(s)));
            out.insert(c[1].to_string(), cmap);
        }
        out
    }

    /// Pages in reading order with their inherited resources.
    fn page_list(&self) -> Vec<(u32, String)> {
        let mut out = vec![];
        let root = self.order.iter().find(|n| has_type(&self.objs[n].dict, "Catalog")).and_then(|n| dict_value(&self.objs[n].dict, "/Pages")).and_then(|v| refs(&v).first().copied());
        let mut seen = std::collections::HashSet::new();
        fn walk(pdf: &Pdf, n: u32, inherited: &str, out: &mut Vec<(u32, String)>, seen: &mut std::collections::HashSet<u32>) {
            if !seen.insert(n) || seen.len() > 200_000 {
                return;
            }
            let Some(o) = pdf.objs.get(&n) else { return };
            let res = dict_value(&o.dict, "/Resources").and_then(|v| pdf.obj_dict(&v)).unwrap_or_else(|| inherited.to_string());
            if has_type(&o.dict, "Pages") {
                for k in dict_value(&o.dict, "/Kids").map(|v| refs(&v)).unwrap_or_default() {
                    walk(pdf, k, &res, out, seen);
                }
            } else if has_type(&o.dict, "Page") {
                out.push((n, res));
            }
        }
        if let Some(r) = root {
            walk(self, r, "", &mut out, &mut seen);
        }
        // Pages the tree does not reach (damaged or orphaned by an update).
        for n in &self.order {
            if !seen.contains(n) && has_type(&self.objs[n].dict, "Page") {
                let res = dict_value(&self.objs[n].dict, "/Resources").and_then(|v| self.obj_dict(&v)).unwrap_or_default();
                out.push((*n, res));
            }
        }
        out
    }

    fn pages(&self) -> Vec<String> {
        self.page_list()
            .into_iter()
            .map(|(n, res)| {
                let fonts = self.fonts(&res);
                let mut content = vec![];
                for c in dict_value(&self.objs[&n].dict, "/Contents").map(|v| refs(&v)).unwrap_or_default() {
                    if let Some(s) = self.objs.get(&c).and_then(|o| o.stream.as_ref()) {
                        content.extend_from_slice(s);
                        content.push(b'\n');
                    }
                }
                tidy(&content_text(&content, &fonts))
            })
            .collect()
    }
}

/// A PDF string value from a dictionary: (literal) or <hex>, with UTF-16BE
/// when it starts with a byte-order mark.
fn pdf_string_value(v: &str) -> String {
    let b: Vec<u8> = v.chars().map(|c| c as u32 as u8).collect();
    let raw = if v.starts_with('(') {
        literal(&b, 0).0
    } else if v.starts_with('<') && !v.starts_with("<<") {
        hex_string(&b, 0).0
    } else {
        return String::new();
    };
    text_from_pdf_bytes(&raw)
}

fn text_from_pdf_bytes(raw: &[u8]) -> String {
    if let Some(u) = raw.strip_prefix(b"\xfe\xff") {
        let w: Vec<u16> = u.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&w);
    }
    raw.iter().map(|&c| c as char).filter(|c| !c.is_control()).collect()
}

/// Literal string starting at `i` (on the opening parenthesis). Returns the
/// bytes and the index after the closing parenthesis.
fn literal(b: &[u8], i: usize) -> (Vec<u8>, usize) {
    let mut out = vec![];
    let mut depth = 0;
    let mut j = i;
    while j < b.len() {
        let c = b[j];
        match c {
            b'(' => {
                if depth > 0 {
                    out.push(c);
                }
                depth += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (out, j + 1);
                }
                out.push(c);
            }
            b'\\' if j + 1 < b.len() => {
                j += 1;
                let e = b[j];
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'\r' => {
                        if b.get(j + 1) == Some(&b'\n') {
                            j += 1;
                        }
                    }
                    b'\n' => {}
                    b'0'..=b'7' => {
                        let mut v = 0u32;
                        let mut k = 0;
                        while k < 3 && j < b.len() && (b'0'..=b'7').contains(&b[j]) {
                            v = v * 8 + (b[j] - b'0') as u32;
                            j += 1;
                            k += 1;
                        }
                        out.push(v as u8);
                        continue;
                    }
                    _ => out.push(e),
                }
            }
            _ => out.push(c),
        }
        j += 1;
    }
    (out, j)
}

fn hex_string(b: &[u8], i: usize) -> (Vec<u8>, usize) {
    let end = b[i..].iter().position(|&c| c == b'>').map(|p| i + p).unwrap_or(b.len());
    let mut digits: Vec<u8> = b[i + 1..end].iter().filter(|c| c.is_ascii_hexdigit()).copied().collect();
    if digits.len() % 2 == 1 {
        digits.push(b'0');
    }
    let out = digits.chunks(2).filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect();
    (out, end + 1)
}

#[derive(Debug, Default, Clone)]
struct CMap {
    map: HashMap<u32, String>,
    /// Bytes per character code (1 for simple fonts, usually 2 for CID fonts).
    width: usize,
}

impl CMap {
    fn parse(s: &str) -> CMap {
        static CHAR: OnceLock<regex::Regex> = OnceLock::new();
        static RANGE: OnceLock<regex::Regex> = OnceLock::new();
        static BLOCK: OnceLock<regex::Regex> = OnceLock::new();
        static SPACE: OnceLock<regex::Regex> = OnceLock::new();
        let block = BLOCK.get_or_init(|| regex::Regex::new(r"(?s)begin(bfchar|bfrange|codespacerange)(.*?)end(?:bfchar|bfrange|codespacerange)").unwrap());
        let ch = CHAR.get_or_init(|| regex::Regex::new(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>").unwrap());
        let rg = RANGE.get_or_init(|| regex::Regex::new(r"(?s)<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[.*?\])").unwrap());
        let sp = SPACE.get_or_init(|| regex::Regex::new(r"<([0-9A-Fa-f]+)>\s*<[0-9A-Fa-f]+>").unwrap());
        let utf16 = |hex: &str| -> String {
            let b: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect();
            let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&w)
        };
        let mut m = CMap::default();
        for b in block.captures_iter(s) {
            let body = &b[2];
            match &b[1] {
                "codespacerange" => {
                    for c in sp.captures_iter(body) {
                        m.width = m.width.max(c[1].len() / 2);
                    }
                }
                "bfchar" => {
                    for c in ch.captures_iter(body) {
                        if let Ok(code) = u32::from_str_radix(&c[1], 16) {
                            m.width = m.width.max(c[1].len() / 2);
                            m.map.insert(code, utf16(&c[2]));
                        }
                    }
                }
                _ => {
                    for c in rg.captures_iter(body) {
                        let (Ok(lo), Ok(hi)) = (u32::from_str_radix(&c[1], 16), u32::from_str_radix(&c[2], 16)) else { continue };
                        m.width = m.width.max(c[1].len() / 2);
                        if hi < lo || hi - lo > 0xFFFF {
                            continue;
                        }
                        let dst = &c[3];
                        if let Some(arr) = dst.strip_prefix('[') {
                            static H: OnceLock<regex::Regex> = OnceLock::new();
                            let h = H.get_or_init(|| regex::Regex::new(r"<([0-9A-Fa-f]*)>").unwrap());
                            for (k, x) in h.captures_iter(arr).enumerate() {
                                m.map.insert(lo + k as u32, utf16(&x[1]));
                            }
                        } else {
                            let base: Vec<u16> = {
                                let hex = &dst[1..dst.len() - 1];
                                let b: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect();
                                b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
                            };
                            let Some((&last, head)) = base.split_last() else { continue };
                            for code in lo..=hi {
                                let mut w = head.to_vec();
                                w.push(last.wrapping_add((code - lo) as u16));
                                m.map.insert(code, String::from_utf16_lossy(&w));
                            }
                        }
                    }
                }
            }
        }
        m.width = m.width.clamp(1, 4);
        m
    }

    fn decode(&self, b: &[u8]) -> String {
        let mut out = String::new();
        for c in b.chunks(self.width) {
            let code = c.iter().fold(0u32, |a, &x| (a << 8) | x as u32);
            match self.map.get(&code) {
                Some(s) => out.push_str(s),
                None if self.width == 1 && (0x20..0x7f).contains(&code) => out.push(code as u8 as char),
                None => {}
            }
        }
        out
    }
}

/// Text shown by a page content stream: Tj, TJ, ' and " operators, with a
/// new line on text-line moves and a space for wide TJ gaps.
fn content_text(b: &[u8], fonts: &HashMap<String, Option<CMap>>) -> String {
    #[derive(Debug)]
    enum Tok {
        Num(f64),
        Str(Vec<u8>),
        Name(String),
        ArrOpen,
        ArrClose,
    }
    let mut out = String::new();
    let mut stack: Vec<Tok> = vec![];
    let mut font: Option<&CMap> = None;
    let show = |s: &[u8], font: Option<&CMap>, out: &mut String| match font {
        Some(cm) => out.push_str(&cm.decode(s)),
        None => out.extend(s.iter().map(|&c| c as char).filter(|c| !c.is_control())),
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' | 0 | 12 => i += 1,
            b'%' => {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            b'(' => {
                let (s, j) = literal(b, i);
                stack.push(Tok::Str(s));
                i = j;
            }
            b'<' if b.get(i + 1) == Some(&b'<') => {
                // inline dictionary (marked content properties): skip it
                let mut depth = 0;
                while i + 1 < b.len() {
                    if &b[i..i + 2] == b"<<" {
                        depth += 1;
                        i += 2;
                    } else if &b[i..i + 2] == b">>" {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'<' => {
                let (s, j) = hex_string(b, i);
                stack.push(Tok::Str(s));
                i = j;
            }
            b'[' => {
                stack.push(Tok::ArrOpen);
                i += 1;
            }
            b']' => {
                stack.push(Tok::ArrClose);
                i += 1;
            }
            b'/' => {
                let j = b[i + 1..].iter().position(|c| c.is_ascii_whitespace() || b"/<>[]()".contains(c)).map(|p| i + 1 + p).unwrap_or(b.len());
                stack.push(Tok::Name(latin1(&b[i + 1..j])));
                i = j;
            }
            b'0'..=b'9' | b'-' | b'+' | b'.' => {
                let j = b[i..].iter().position(|c| !(c.is_ascii_digit() || b"-+.".contains(c))).map(|p| i + p).unwrap_or(b.len());
                stack.push(Tok::Num(std::str::from_utf8(&b[i..j]).ok().and_then(|s| s.parse().ok()).unwrap_or(0.0)));
                i = j.max(i + 1);
            }
            _ => {
                let j = b[i..].iter().position(|c| c.is_ascii_whitespace() || b"/<>[]()%".contains(c)).map(|p| i + p).unwrap_or(b.len());
                let op = &b[i..j.max(i + 1)];
                i = j.max(i + 1);
                match op {
                    b"Tf" => {
                        let name = stack.iter().rev().find_map(|t| if let Tok::Name(n) = t { Some(n.clone()) } else { None });
                        font = name.and_then(|n| fonts.get(&n)).and_then(|f| f.as_ref());
                    }
                    b"Tj" | b"'" | b"\"" => {
                        if op != b"Tj" {
                            out.push('\n');
                        }
                        if let Some(Tok::Str(s)) = stack.last() {
                            show(s, font, &mut out);
                        }
                    }
                    b"TJ" => {
                        let start = stack.iter().rposition(|t| matches!(t, Tok::ArrOpen)).map(|p| p + 1).unwrap_or(0);
                        for t in &stack[start..] {
                            match t {
                                Tok::Str(s) => show(s, font, &mut out),
                                Tok::Num(n) if *n < -200.0 => out.push(' '),
                                _ => {}
                            }
                        }
                    }
                    b"Td" | b"TD" => {
                        let nums: Vec<f64> = stack.iter().filter_map(|t| if let Tok::Num(n) = t { Some(*n) } else { None }).collect();
                        if nums.len() >= 2 && nums[nums.len() - 1].abs() > 0.01 {
                            out.push('\n');
                        } else {
                            out.push(' ');
                        }
                    }
                    b"T*" | b"ET" | b"Tm" => out.push('\n'),
                    b"BI" => {
                        // Inline image: skip binary data up to "EI".
                        let id = find(b, b"ID", i).unwrap_or(b.len());
                        let mut k = id + 2;
                        while let Some(e) = find(b, b"EI", k) {
                            let ws_before = e > 0 && b[e - 1].is_ascii_whitespace();
                            let ws_after = b.get(e + 2).map(|c| c.is_ascii_whitespace()).unwrap_or(true);
                            if ws_before && ws_after {
                                k = e + 2;
                                break;
                            }
                            k = e + 2;
                        }
                        i = k.max(i);
                    }
                    _ => {}
                }
                stack.clear();
            }
        }
        if stack.len() > 4096 {
            stack.clear();
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Minimal ZIP writer for tests: (name, data, deflate). `size`, when set,
    /// pads the archive to exactly that many bytes with a ZIP comment.
    pub fn zip(entries: &[(&str, &[u8], bool)], size: Option<usize>) -> Vec<u8> {
        let mut out = vec![];
        let mut cd = vec![];
        for (name, data, deflate) in entries {
            let body = if *deflate {
                let mut e = flate2::write::DeflateEncoder::new(vec![], flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let off = out.len() as u32;
            let mut h = vec![];
            h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            h.extend_from_slice(&[20, 0, 0, 0]);
            h.extend_from_slice(&method.to_le_bytes());
            h.extend_from_slice(&[0; 8]); // time, date, crc (not checked by the reader)
            h.extend_from_slice(&(body.len() as u32).to_le_bytes());
            h.extend_from_slice(&(data.len() as u32).to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&[0, 0]);
            h.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&h);
            out.extend_from_slice(&body);
            cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        let pad = size.map(|s| s - out.len() - 2).unwrap_or(0);
        out.extend_from_slice(&(pad as u16).to_le_bytes());
        out.extend(std::iter::repeat(b' ').take(pad));
        out
    }

    fn zlib(d: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }

    /// A PDF with: an inherited font resource, a CID font whose ToUnicode
    /// map (bfchar + bfrange) sits in a Flate stream, both fonts stored in an
    /// object stream, a simple font, a Flate content stream, and an Info
    /// dictionary with a UTF-16 author.
    pub fn pdf() -> Vec<u8> {
        let cmap = "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n\
            2 beginbfchar\n<0003> <0421>\n<0004> <043A>\nendbfchar\n2 beginbfrange\n<0005> <0006> <043E>\n<0010> <0012> <0041>\nendbfrange\nendcmap";
        let content = "BT /F2 12 Tf 72 700 Td (Hello \\(PDF\\) world) Tj ET\n\
            BT /F1 12 Tf 72 680 Td [<00030004> -100 <0005>] TJ <0006> Tj ET\n\
            BT /F1 12 Tf 72 660 Td [<0010> -400 <00110012>] TJ ET\n\
            BI /W 2 /H 2 /BPC 8 /CS /G ID \x00\x01 Tj \x02\x03 EI\n";
        let f1 = "<< /Type /Font /Subtype /Type0 /BaseFont /Fancy /Encoding /Identity-H /ToUnicode 6 0 R >>";
        let f2 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
        let header = format!("4 0 5 {} ", f1.len() + 1);
        let first = header.len();
        let objstm_body = format!("{}{} {}", header, f1, f2);
        let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut obj = |n: u32, dict: &str, stream: Option<&[u8]>| {
            out.extend_from_slice(format!("{} 0 obj\n{}", n, dict).as_bytes());
            if let Some(s) = stream {
                out.extend_from_slice(b"\nstream\n");
                out.extend_from_slice(s);
                out.extend_from_slice(b"\nendstream");
            }
            out.extend_from_slice(b"\nendobj\n");
        };
        obj(1, "<< /Type /Catalog /Pages 2 0 R >>", None);
        obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> >>", None);
        obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 7 0 R >>", None);
        let c = zlib(cmap.as_bytes());
        obj(6, &format!("<< /Length {} /Filter /FlateDecode >>", c.len()), Some(&c));
        let c = zlib(content.as_bytes());
        obj(7, &format!("<< /Length {} /Filter /FlateDecode >>", c.len()), Some(&c));
        let c = zlib(objstm_body.as_bytes());
        obj(9, &format!("<< /Type /ObjStm /N 2 /First {} /Length {} /Filter /FlateDecode >>", first, c.len()), Some(&c));
        obj(10, "<< /Title (Quarterly plan) /Author <FEFF0410043D0430> /Producer (Kokino test) >>", None);
        out.extend_from_slice(b"trailer\n<< /Root 1 0 R /Info 10 0 R >>\n%%EOF\n");
        out
    }

    fn find_part<'a>(x: &'a Extracted, name: &str) -> &'a Part {
        x.parts.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("{} not in {:?}", name, x.parts.iter().map(|p| &p.name).collect::<Vec<_>>()))
    }

    #[test]
    fn docx_text_joins_split_runs_and_keeps_metadata() {
        let doc = br#"<?xml version="1.0"?><w:document xmlns:w="x"><w:body>
            <w:p><w:r><w:t>Pass</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>word</w:t></w:r><w:r><w:tab/><w:t>Q&amp;A &#x41;&#66;</w:t></w:r></w:p>
            <w:p><w:del><w:r><w:delText>removed sentence</w:delText></w:r></w:del></w:p></w:body></w:document>"#;
        let core = br#"<cp:coreProperties><dc:creator>Alice Example</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy></cp:coreProperties>"#;
        let z = zip(&[("[Content_Types].xml", b"<Types/>", true), ("_rels/.rels", b"<Relationships/>", true), ("word/document.xml", doc, true), ("word/styles.xml", b"<w:styles>Normal</w:styles>", true), ("docProps/core.xml", core, false)], None);
        let x = extract(&z);
        assert_eq!(find_part(&x, "word/document.xml").text, "Password Q&A AB\nremoved sentence");
        assert_eq!(find_part(&x, "docProps/core.xml").text, "Alice Example\nBob");
        assert_eq!(x.parts.len(), 2, "plumbing parts must be skipped: {:?}", x.parts);
    }

    #[test]
    fn xlsx_and_pptx() {
        let shared = br#"<sst><si><t>Invoice total</t></si><si><r><t>Ko</t></r><r><t>kino</t></r></si></sst>"#;
        let sheet = br#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>4521.5</v></c><c r="C1" t="inlineStr"><is><t>inline note</t></is></c></row></sheetData></worksheet>"#;
        let slide = br#"<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Meeting at</a:t></a:r><a:r><a:t> Vodno</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"#;
        let x = extract(&zip(&[("xl/sharedStrings.xml", shared, true), ("xl/worksheets/sheet1.xml", sheet, true)], None));
        assert_eq!(find_part(&x, "xl/sharedStrings.xml").text, "Invoice total\nKokino");
        assert_eq!(find_part(&x, "xl/worksheets/sheet1.xml").text, "0\n4521.5\ninline note");
        let x = extract(&zip(&[("ppt/slides/slide1.xml", slide, true), ("ppt/slideLayouts/slideLayout1.xml", b"<a:t>Click to edit</a:t>", true)], None));
        assert_eq!(find_part(&x, "ppt/slides/slide1.xml").text, "Meeting at Vodno");
        assert_eq!(x.parts.len(), 1);
    }

    #[test]
    fn nested_containers_gzip_and_plain_entries() {
        let docx = zip(&[("word/document.xml", b"<w:p><w:t>inner secret</w:t></w:p>", true)], None);
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(b"gzipped log line\n").unwrap();
        let gz = gz.finish().unwrap();
        let outer = zip(&[("docs/report.docx", &docx, false), ("notes.txt", "Sastanok kaj Vodno\r\n".as_bytes(), true), ("logs/app.log.gz", &gz, false), ("pic.png", b"\x89PNG....", false)], None);
        let x = extract(&outer);
        assert_eq!(find_part(&x, "docs/report.docx/word/document.xml").text, "inner secret");
        assert_eq!(find_part(&x, "notes.txt").text.trim(), "Sastanok kaj Vodno");
        assert_eq!(find_part(&x, "logs/app.log.gz/(gunzipped)").text.trim(), "gzipped log line");
        assert!(x.parts.iter().all(|p| p.name != "pic.png"));
    }

    #[test]
    fn zip_bombs_and_damage_are_bounded() {
        let zeros = vec![b'A'; 5 << 20];
        let z = zip(&[("big.txt", &zeros, true), ("after.txt", b"still read", true)], None);
        let lim = Limits { max_entry: 1 << 20, max_total: 3 << 20, ..Default::default() };
        let x = extract_with(&z, lim);
        assert_eq!(find_part(&x, "big.txt").text.len(), 1 << 20);
        assert_eq!(find_part(&x, "after.txt").text, "still read");
        assert!(x.notes.iter().any(|n| n.contains("big.txt") && n.contains("limit")), "{:?}", x.notes);

        // No central directory (truncated or carved): local headers still work.
        let z = zip(&[("a.txt", b"carved text", true)], None);
        let cut = z.windows(4).position(|w| w == [0x50, 0x4b, 0x01, 0x02]).unwrap();
        assert_eq!(find_part(&extract(&z[..cut]), "a.txt").text, "carved text");

        // Encrypted entries are reported.
        let mut z = zip(&[("secret.txt", b"xxxx", false)], None);
        z[6] = 1;
        let cd = z.windows(4).position(|w| w == [0x50, 0x4b, 0x01, 0x02]).unwrap();
        z[cd + 8] = 1;
        let x = extract(&z);
        assert!(x.parts.is_empty());
        assert!(x.notes[0].contains("encrypted"), "{:?}", x.notes);

        // Garbage never panics.
        let mut garbage = b"PK".to_vec();
        garbage.extend([0xff; 60]);
        for n in [0, 3, 30, 34, 64] {
            let _ = extract(&garbage[..n]);
        }
        let _ = extract(b"%PDF-1.4\n1 0 obj << /Type /Page /Contents 2 0 R >> endobj 2 0 obj << /Filter /FlateDecode >> stream\nnot zlib\nendstream endobj");
    }

    #[test]
    fn pdf_pages_with_tounicode_object_streams_and_info() {
        let x = extract(&pdf());
        let page = &find_part(&x, "page 1").text;
        let lines: Vec<&str> = page.lines().collect();
        assert_eq!(lines, vec!["Hello (PDF) world", "\u{0421}\u{043A}\u{043E}\u{043F}", "A BC"], "{:?}", page);
        let meta = &find_part(&x, "metadata").text;
        assert!(meta.contains("Title: Quarterly plan") && meta.contains("Author: \u{0410}\u{043D}\u{0430}"), "{}", meta);
        assert!(x.notes.is_empty(), "{:?}", x.notes);
    }

    #[test]
    fn encrypted_pdf_is_reported() {
        let mut p = pdf();
        let at = p.windows(7).position(|w| w == b"trailer").unwrap();
        p.splice(at + 8..at + 8, b"<< /Encrypt 11 0 R >>\n".iter().copied());
        let x = extract(&p);
        assert!(x.parts.iter().all(|p| !p.name.starts_with("page")));
        assert!(x.notes.iter().any(|n| n.contains("encrypted PDF")));
    }

    #[test]
    fn html_and_entities() {
        assert_eq!(xml_text("<html><head><style>p{}</style><script>var x='<p>';</script><title>T&amp;C</title></head><body><p>a&lt;b &#1050;</p><!-- hidden --><div>c<br/>d</div></body></html>"), "T&C\na<b \u{041A}\nc\nd");
    }
}
