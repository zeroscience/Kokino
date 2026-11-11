//! File carving: recovers files from unallocated space by their content.
//!
//! Every 512-byte boundary of every free region is checked for a file
//! header. Each format then has its own small parser that finds where the
//! file really ends (JPEG segment walk, PNG chunks, ZIP central directory,
//! PE section table, SQLite page count, GZIP deflate stream...), so a
//! carved file is a whole file, not "header plus N megabytes", and random
//! bytes that only look like a header are rejected.
//!
//! Regions: clusters marked free in each NTFS $Bitmap, the space outside
//! partitions, and volumes whose file system is not parsed (carved whole).
//! Files are assumed contiguous; one that runs past the end of its free
//! region is kept but marked, because its tail may belong to another file
//! or the original was fragmented. JPEG pictures split in two pieces are
//! joined again (bifragment gap carving): where the compressed data stops
//! looking like JPEG data, the second piece is looked for further on (a run
//! of sectors that look like JPEG data, ending with the end-of-image
//! marker), and a join is kept only when the joined picture decodes into
//! exactly the blocks its header promises and ends where its data ends.
//!
//! Nothing is copied: results are offsets and lengths in the image, with
//! MD5 and SHA-256 of the carved bytes. Exports read from the image.
//! Free space of an unlocked BitLocker volume is carved in its decrypted
//! form: those results carry the volume (`space`) and offsets within it,
//! and are read back through `space_reader`.
//!
//! Internet Explorer history and cache records (index.dat `URL `, `LEAK`,
//! `REDR`) are also recovered one by one: they keep their 128-byte
//! alignment when the file is deleted, and a single record is enough to
//! show a visit, so every 128-byte boundary is checked for one (as HstEx
//! does). Whole index.dat files are carved as files as well.

use crate::{volume_reader, Analysis, Progress};
use kokino_image::{read_at, BlockCache, Evidence, FsKind, Volume, VolumeKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Seek};

/// 2: Internet Explorer records.
pub const CARVE_SCHEMA: u32 = 2;
const IE_STEP: usize = 128;
const MAX_RECORDS: usize = 200_000;
const SECTOR: u64 = 512;
const WINDOW: usize = 1 << 20;
const MAX_FILES: usize = 100_000;

pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

/// Where carved bytes are read from, and its size: the image (`space` None)
/// or the decrypted volume with that index.
pub fn space_reader(ev: &Evidence, volumes: &[Volume], space: Option<usize>) -> anyhow::Result<(Box<dyn ReadSeek>, u64)> {
    match space {
        None => Ok((Box::new(ev.reader()?), ev.size)),
        Some(vi) => {
            let v = volumes.iter().find(|v| v.index == vi).ok_or_else(|| anyhow::anyhow!("volume {} not found", vi))?;
            Ok((Box::new(volume_reader(ev, v)?), v.length))
        }
    }
}

/// Reads `len` bytes of a carved file (or record) from its space.
pub fn read_carved(ev: &Evidence, volumes: &[Volume], space: Option<usize>, offset: u64, len: u64) -> anyhow::Result<Vec<u8>> {
    let (mut r, size) = space_reader(ev, volumes, space)?;
    let mut buf = vec![0u8; len.min(size.saturating_sub(offset)) as usize];
    let got = read_at(&mut r, offset, &mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// "image offset 123" or "offset 123 in decrypted volume 2".
pub fn where_label(space: Option<usize>, offset: u64) -> String {
    match space {
        None => format!("image offset {}", offset),
        Some(v) => format!("offset {} in decrypted volume {}", offset, v),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Carved {
    pub id: u32,
    /// Absolute offset in the image.
    pub offset: u64,
    pub len: u64,
    /// jpeg, png, pdf, docx, sqlite, exe, evtx-chunk...
    pub kind: String,
    pub ext: String,
    pub label: String,
    /// The format's end marker or declared size was found.
    pub complete: bool,
    /// Dimensions, page count, entries, records...
    pub detail: String,
    pub note: String,
    pub region: String,
    pub fi: Option<usize>,
    /// Part of the file lies outside the free region it starts in.
    pub beyond_region: bool,
    pub md5: String,
    pub sha256: String,
    /// Set when carved from a decrypted volume: `offset` is within it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<usize>,
    /// A file in two pieces: (start, length) of the bytes between them,
    /// which are not part of it. `len` counts the file's own bytes only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<(u64, u64)>,
}

impl Carved {
    /// The pieces of the file: (start, length), in order.
    pub fn pieces(&self) -> Vec<(u64, u64)> {
        match self.gap {
            Some((g, glen)) if g > self.offset && g - self.offset < self.len => {
                let first = g - self.offset;
                vec![(self.offset, first), (g.saturating_add(glen), self.len - first)]
            }
            _ => vec![(self.offset, self.len)],
        }
    }

    /// "image offset 123", with the second piece when there is one.
    pub fn where_label(&self) -> String {
        let w = where_label(self.space, self.offset);
        match self.pieces().get(1) {
            Some((at, len)) => format!("{} ({} bytes), then {} bytes at {}", w, self.len - len, len, at),
            None => w,
        }
    }
}

/// A carved file's bytes, its pieces joined.
pub struct CarvedReader {
    r: Box<dyn ReadSeek>,
    pieces: Vec<(u64, u64)>,
    len: u64,
    pos: u64,
}

impl Read for CarvedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut skip = self.pos;
        for &(at, n) in &self.pieces {
            if skip >= n {
                skip -= n;
                continue;
            }
            let want = (buf.len() as u64).min(n - skip) as usize;
            let got = read_at(&mut self.r, at + skip, &mut buf[..want]).map_err(|e| std::io::Error::other(e.to_string()))?;
            self.pos += got as u64;
            return Ok(got);
        }
        Ok(0)
    }
}

impl Seek for CarvedReader {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let p = match to {
            std::io::SeekFrom::Start(p) => p as i128,
            std::io::SeekFrom::End(d) => self.len as i128 + d as i128,
            std::io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

/// A reader over a carved file's own bytes (pieces joined), and its length.
pub fn carved_reader(ev: &Evidence, volumes: &[Volume], f: &Carved) -> anyhow::Result<(CarvedReader, u64)> {
    let (r, size) = space_reader(ev, volumes, f.space)?;
    let pieces: Vec<(u64, u64)> = f.pieces().into_iter().map(|(at, n)| (at, n.min(size.saturating_sub(at)))).collect();
    let len = pieces.iter().map(|x| x.1).sum();
    Ok((CarvedReader { r, pieces, len, pos: 0 }, len))
}

/// A carved file's bytes, pieces joined.
pub fn read_carved_file(ev: &Evidence, volumes: &[Volume], f: &Carved) -> anyhow::Result<Vec<u8>> {
    let (mut r, len) = carved_reader(ev, volumes, f)?;
    let mut buf = Vec::with_capacity(len as usize);
    r.read_to_end(&mut buf)?;
    Ok(buf)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarveResult {
    pub schema: u32,
    pub tool_version: String,
    pub carved_at: String,
    pub scanned_bytes: u64,
    pub regions: u64,
    pub files: Vec<Carved>,
    /// Stopped at MAX_FILES.
    pub truncated: bool,
    /// Internet Explorer records found in free space.
    #[serde(default)]
    pub records: Vec<CarvedRecord>,
    /// Stopped at MAX_RECORDS.
    #[serde(default)]
    pub records_truncated: bool,
}

/// One Internet Explorer index.dat record recovered from free space.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CarvedRecord {
    /// Absolute offset in the image.
    pub offset: u64,
    pub len: u64,
    /// URL, LEAK or REDR.
    pub tag: String,
    /// "history", "daily history", "cache", "cookie", "download", "redirect"
    pub what: String,
    /// Last visit or last access (UTC).
    pub t: u64,
    pub secondary: u64,
    pub user: String,
    pub url: String,
    pub title: String,
    /// Cached file name, or the saved-as path of a download.
    pub file: String,
    pub hits: u32,
    pub region: String,
    pub fi: Option<usize>,
    /// Inside the carved index.dat with this id.
    pub in_file: Option<u32>,
    /// Set when found in a decrypted volume: `offset` is within it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<usize>,
}

/// Internet Explorer records at every 128-byte boundary of `win`, which
/// starts at image offset `p`.
fn scan_records(src: &mut dyn Bytes, p: u64, win: &[u8], label: &str, fi: Option<usize>, space: Option<usize>, res: &mut CarveResult) {
    if res.records_truncated {
        return;
    }
    let mut k = (p.div_ceil(IE_STEP as u64) * IE_STEP as u64 - p) as usize;
    while k + 8 <= win.len() {
        let s = &win[k..k + 4];
        if s == b"URL " || s == b"LEAK" || s == b"REDR" {
            if let Some(mut rec) = ie_record(src, p + k as u64) {
                rec.region = label.to_string();
                rec.fi = fi;
                rec.space = space;
                res.records.push(rec);
                if res.records.len() >= MAX_RECORDS {
                    res.records_truncated = true;
                    return;
                }
            }
        }
        k += IE_STEP;
    }
}

/// The record at `at` in `src`, described for the examiner. Host summaries
/// and Windows' own caches that share the format are left out.
pub fn ie_record(src: &mut dyn Bytes, at: u64) -> Option<CarvedRecord> {
    use kokino_artifacts::iecache::{self, Location};
    let head = src.read(at, 8);
    if !matches!(head.get(..4), Some(b"URL ") | Some(b"LEAK") | Some(b"REDR")) {
        return None;
    }
    let blocks = le32(&head, 4)?.min(0x200);
    let b = src.read(at, blocks as usize * IE_STEP);
    let r = iecache::record(&b, 0)?;
    let mut c = CarvedRecord { offset: at, len: r.blocks as u64 * IE_STEP as u64, tag: r.kind.tag().into(), t: r.primary, secondary: r.secondary, hits: r.hits, title: r.title.clone(), ..Default::default() };
    match iecache::location(&r.location) {
        Location::History { user, url, period } => {
            c.what = if period.is_some() { "daily history" } else { "history" }.into();
            c.user = user;
            c.url = url;
        }
        Location::Cookie { user, url } => {
            c.what = "cookie".into();
            c.user = user;
            c.url = url;
        }
        Location::Download => {
            let d = r.download?;
            c.what = "download".into();
            c.url = d.url;
            c.file = d.target;
        }
        Location::Url(url) if r.kind == iecache::Kind::Redirect => {
            c.what = "redirect".into();
            c.url = url;
        }
        Location::Url(url) => {
            c.what = "cache".into();
            c.url = url;
            c.file = r.file;
            c.user = r.header_user;
        }
        Location::Host | Location::Other => return None,
    }
    Some(c)
}

/// Random access to the image for the format parsers.
pub trait Bytes {
    fn size(&self) -> u64;
    /// Up to `n` bytes at `off` (fewer at the end of the image).
    fn read(&mut self, off: u64, n: usize) -> Vec<u8>;
    /// First occurrence of `pat` in [from, end).
    fn find(&mut self, from: u64, end: u64, pat: &[u8]) -> Option<u64> {
        let end = end.min(self.size());
        let mut p = from;
        while p < end {
            let n = ((end - p) as usize).min(WINDOW);
            let b = self.read(p, n + pat.len() - 1);
            if let Some(i) = b.windows(pat.len()).position(|w| w == pat) {
                let at = p + i as u64;
                return (at + pat.len() as u64 <= end).then_some(at);
            }
            if b.len() < pat.len() {
                return None;
            }
            p += n as u64;
        }
        None
    }
}

struct Img<R: Read + Seek> {
    r: R,
    size: u64,
}

impl<R: Read + Seek> Bytes for Img<R> {
    fn size(&self) -> u64 {
        self.size
    }
    fn read(&mut self, off: u64, n: usize) -> Vec<u8> {
        if off >= self.size {
            return vec![];
        }
        let n = n.min((self.size - off) as usize);
        let mut b = vec![0u8; n];
        let got = read_at(&mut self.r, off, &mut b).unwrap_or(0);
        b.truncate(got);
        b
    }
}

impl Bytes for &[u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read(&mut self, off: u64, n: usize) -> Vec<u8> {
        let o = (off as usize).min(self.len());
        self[o..(o + n).min(self.len())].to_vec()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hit {
    pub len: u64,
    pub complete: bool,
    pub kind: &'static str,
    pub ext: &'static str,
    pub label: &'static str,
    pub detail: String,
}

fn be16(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 2).map(|x| u16::from_be_bytes([x[0], x[1]]) as u64)
}
fn be32(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64)
}
fn le16(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64)
}
fn le32(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64)
}
fn le64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap()))
}

/// Header test and parser per format. Order matters only for speed.
type Carver = fn(&mut dyn Bytes, u64) -> Option<Hit>;
const CARVERS: &[(&[u8], Carver)] = &[
    (b"\xFF\xD8\xFF", jpeg),
    (b"\x89PNG\r\n\x1a\n", png),
    (b"GIF8", gif),
    (b"BM", bmp),
    (b"%PDF-", pdf),
    (b"PK\x03\x04", zip),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", ole),
    (b"SQLite format 3\0", sqlite),
    (b"MZ", pe),
    (b"\x1F\x8B\x08", gzip),
    (b"7z\xBC\xAF\x27\x1C", sevenzip),
    (b"RIFF", riff),
    (b"ElfChnk\0", evtx_chunk),
    (b"Client UrlCache MMF Ver ", index_dat),
];

/// Tries every carver whose magic matches at `at`.
pub fn identify(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let head = src.read(at, 32);
    for (magic, f) in CARVERS {
        if head.starts_with(magic) {
            if let Some(h) = f(src, at) {
                return Some(h);
            }
        }
    }
    // MP4 / MOV: the magic is at offset 4.
    if head.get(4..8) == Some(b"ftyp") {
        return mp4(src, at);
    }
    None
}

fn jpeg(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const MAX: u64 = 64 << 20;
    let mut p = at + 2;
    let mut dims = String::new();
    let mut seen_sos = false;
    loop {
        if p - at > MAX {
            return None;
        }
        let m = src.read(p, 4);
        if m.len() < 2 || m[0] != 0xFF {
            // Ran out mid-file: keep what is there once real image data was seen.
            return seen_sos.then(|| Hit { len: p - at, complete: false, kind: "jpeg", ext: "jpg", label: "JPEG image", detail: dims.clone() });
        }
        let marker = m[1];
        match marker {
            0xD9 => return Some(Hit { len: p + 2 - at, complete: true, kind: "jpeg", ext: "jpg", label: "JPEG image", detail: dims }),
            0xFF => p += 1,
            0x01 | 0xD0..=0xD7 => p += 2,
            0xD8 | 0x00 => return None,
            _ => {
                let len = be16(&m, 2)?;
                if len < 2 {
                    return None;
                }
                if matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) && dims.is_empty() {
                    let s = src.read(p + 4, 5);
                    if let (Some(hh), Some(ww)) = (be16(&s, 1), be16(&s, 3)) {
                        dims = format!("{} x {}", ww, hh);
                    }
                }
                p += 2 + len;
                if marker == 0xDA {
                    seen_sos = true;
                    // Entropy-coded data: next 0xFF not followed by 00, RSTn or FF.
                    loop {
                        if p - at > MAX {
                            return Some(Hit { len: p - at, complete: false, kind: "jpeg", ext: "jpg", label: "JPEG image", detail: dims });
                        }
                        let b = src.read(p, 65_536);
                        if b.len() < 2 {
                            return Some(Hit { len: p + b.len() as u64 - at, complete: false, kind: "jpeg", ext: "jpg", label: "JPEG image", detail: dims });
                        }
                        let pos = b.windows(2).position(|w| w[0] == 0xFF && w[1] != 0x00 && !(0xD0..=0xD7).contains(&w[1]) && w[1] != 0xFF);
                        match pos {
                            Some(i) => {
                                p += i as u64;
                                break;
                            }
                            None => p += b.len() as u64 - 1,
                        }
                    }
                }
            }
        }
    }
}

/// How far the second piece of a split JPEG is looked for.
const MAX_GAP: u64 = 16 << 20;

/// What a sector of a JPEG's compressed data looks like.
enum Look {
    /// Possible JPEG data.
    Data,
    /// Holds the end-of-image marker; the picture ends this many bytes in.
    End(u64),
    /// Not JPEG data: a marker that cannot be there, a long run of zeros,
    /// or text.
    Foreign,
}

fn look(b: &[u8]) -> Look {
    // Compressed data is about 37% printable; a sector of text is not it.
    if b.len() >= 256 && b.iter().filter(|&&c| (0x20..0x7F).contains(&c) || matches!(c, 9 | 10 | 13)).count() * 100 >= b.len() * 94 {
        return Look::Foreign;
    }
    let mut zeros = 0;
    for i in 0..b.len() {
        if b[i] == 0 {
            zeros += 1;
            if zeros >= 64 {
                return Look::Foreign;
            }
        } else {
            zeros = 0;
        }
        if b[i] == 0xFF {
            match b.get(i + 1) {
                Some(0xD9) => return Look::End(i as u64 + 2),
                Some(0x00) | Some(0xD0..=0xD7) | Some(0xFF) | None => {}
                Some(_) => return Look::Foreign,
            }
        }
    }
    Look::Data
}

/// A JPEG at `at` whose compressed data stops looking like JPEG data before
/// its end: the second piece, joined. Returns (first piece length, second
/// piece start, second piece length, dimensions).
fn jpeg_two(src: &mut dyn Bytes, at: u64) -> Option<(u64, u64, u64, String)> {
    // The headers, up to the start of the compressed data.
    let head = src.read(at, 1 << 18);
    let mut p = 2usize;
    let mut dims = String::new();
    let data = loop {
        if head.get(p) != Some(&0xFF) {
            return None;
        }
        let m = *head.get(p + 1)?;
        if m == 0xFF {
            p += 1;
            continue;
        }
        let len = be16(&head, p + 2)? as usize;
        if len < 2 || matches!(m, 0xD8 | 0xD9 | 0x00) {
            return None;
        }
        if matches!(m, 0xC2 | 0xC6 | 0xCA | 0xCE) {
            return None; // progressive: not decoded
        }
        if m == 0xC0 || m == 0xC1 {
            if let (Some(hh), Some(ww)) = (be16(&head, p + 5), be16(&head, p + 7)) {
                dims = format!("{} x {}", ww, hh);
            }
        }
        p += 2 + len;
        if m == 0xDA {
            break at + p as u64;
        }
    };
    // The first sector that is not JPEG data: where the first piece ends.
    let mut s = data;
    let first_end = loop {
        if s - at > MAX_GAP * 4 {
            return None;
        }
        let next = (s / SECTOR + 1) * SECTOR;
        let b = src.read(s, (next - s) as usize);
        if b.is_empty() {
            return None;
        }
        match look(&b) {
            Look::Data => s = next,
            Look::End(_) => return None, // whole: the ordinary walk carves it
            Look::Foreign => break (s / SECTOR) * SECTOR,
        }
    };
    if first_end <= data {
        return None;
    }
    // Further on: sectors that end the picture, after a run of JPEG data.
    let mut tried = 0;
    let mut run_start: Option<u64> = None;
    let mut q = first_end + SECTOR;
    let limit = (first_end + MAX_GAP).min(src.size());
    while q < limit && tried < 8 {
        let chunk = src.read(q, (limit - q).min(1 << 20) as usize);
        if chunk.len() < SECTOR as usize {
            break;
        }
        for (k, sec) in chunk.chunks_exact(SECTOR as usize).enumerate() {
            let here = q + k as u64 * SECTOR;
            // A new JPEG starts here: not a continuation.
            if sec.starts_with(&[0xFF, 0xD8, 0xFF]) {
                run_start = None;
                continue;
            }
            match look(sec) {
                Look::Data => {
                    run_start.get_or_insert(here);
                }
                Look::Foreign => run_start = None,
                Look::End(e) => {
                    let start = run_start.unwrap_or(here);
                    let end = here + e;
                    tried += 1;
                    // The first piece may end a little before the first odd sector,
                    // and the second may start a little after the run does.
                    for back in 0..4u64 {
                        let fe = first_end.saturating_sub(back * SECTOR);
                        if fe <= data {
                            break;
                        }
                        for fwd in 0..4u64 {
                            let ss = start + fwd * SECTOR;
                            if ss >= end {
                                break;
                            }
                            let mut joined = src.read(at, (fe - at) as usize);
                            joined.extend(src.read(ss, (end - ss) as usize));
                            if let Ok(j) = crate::photo::jpeg::parse(&joined) {
                                if j.is_baseline() && crate::photo::jpeg::scan_fits(&joined, &j) {
                                    return Some((fe - at, ss, end - ss, dims));
                                }
                            }
                        }
                    }
                    run_start = None;
                    if tried >= 8 {
                        break;
                    }
                }
            }
        }
        q += (chunk.len() as u64 / SECTOR) * SECTOR;
    }
    None
}

/// The JPEG join on raw bytes, for the fuzzer.
pub fn fuzz_jpeg_two(d: &[u8]) {
    let mut s: &[u8] = d;
    let _ = jpeg_two(&mut s, 0);
}

fn png(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const MAX: u64 = 64 << 20;
    let mut p = at + 8;
    let mut dims = String::new();
    let mut n = 0;
    loop {
        let c = src.read(p, 16);
        let len = be32(&c, 0)?;
        let ty = c.get(4..8)?;
        if !ty.iter().all(|b| b.is_ascii_alphabetic()) || len > MAX {
            return (n > 1).then(|| Hit { len: p - at, complete: false, kind: "png", ext: "png", label: "PNG image", detail: dims.clone() });
        }
        if n == 0 && ty != b"IHDR" {
            return None;
        }
        if ty == b"IHDR" {
            dims = format!("{} x {}", be32(&c, 8).unwrap_or(0), be32(&c, 12).unwrap_or(0));
        }
        p += 12 + len;
        n += 1;
        if ty == b"IEND" {
            return Some(Hit { len: p - at, complete: true, kind: "png", ext: "png", label: "PNG image", detail: dims });
        }
        if p - at > MAX {
            return None;
        }
    }
}

fn gif(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 13);
    if !(h.starts_with(b"GIF87a") || h.starts_with(b"GIF89a")) || h.len() < 13 {
        return None;
    }
    let dims = format!("{} x {}", le16(&h, 6)?, le16(&h, 8)?);
    let mut p = at + 13;
    if h[10] & 0x80 != 0 {
        p += 3 << ((h[10] & 7) + 1);
    }
    let sub_blocks = |src: &mut dyn Bytes, mut p: u64| -> Option<u64> {
        for _ in 0..1_000_000 {
            let n = *src.read(p, 1).first()? as u64;
            p += 1 + n;
            if n == 0 {
                return Some(p);
            }
        }
        None
    };
    for _ in 0..100_000 {
        let b = *src.read(p, 1).first()?;
        match b {
            0x3B => return Some(Hit { len: p + 1 - at, complete: true, kind: "gif", ext: "gif", label: "GIF image", detail: dims }),
            0x21 => p = sub_blocks(src, p + 2)?,
            0x2C => {
                let d = src.read(p, 10);
                let mut q = p + 10;
                if *d.get(9)? & 0x80 != 0 {
                    q += 3 << ((d[9] & 7) + 1);
                }
                p = sub_blocks(src, q + 1)?;
            }
            _ => return None,
        }
    }
    None
}

fn bmp(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 30);
    let size = le32(&h, 2)?;
    let data = le32(&h, 10)?;
    let dib = le32(&h, 14)?;
    if le32(&h, 6)? != 0 || ![12, 40, 52, 56, 108, 124].contains(&dib) || data < 14 + dib || data >= size || size > 64 << 20 || size < 64 {
        return None;
    }
    let (w, hh) = if dib == 12 { (le16(&h, 18)?, le16(&h, 20)?) } else { (le32(&h, 18)?, le32(&h, 22)?) };
    let planes = if dib == 12 { le16(&h, 22)? } else { le16(&h, 26)? };
    if planes != 1 || w == 0 || w > 65_535 {
        return None;
    }
    Some(Hit { len: size, complete: true, kind: "bmp", ext: "bmp", label: "BMP image", detail: format!("{} x {}", w, hh as i32 as i64 & 0xFFFF_FFFF) })
}

fn pdf(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const MAX: u64 = 256 << 20;
    let h = src.read(at, 8);
    if !(h.starts_with(b"%PDF-1.") || h.starts_with(b"%PDF-2.")) {
        return None;
    }
    let version = String::from_utf8_lossy(&h[5..h.len().min(8)]).to_string();
    let mut p = at;
    let mut end = None;
    // %%EOF ends the file unless an incremental update follows.
    while let Some(e) = src.find(p, at + MAX, b"%%EOF") {
        let mut stop = e + 5;
        let after = src.read(stop, 2);
        stop += after.iter().take_while(|c| **c == b'\r' || **c == b'\n').count() as u64;
        end = Some(stop);
        let next = src.read(stop, 1024);
        let more = next.windows(3).any(|w| w == b"obj") || next.windows(4).any(|w| w == b"xref");
        if !more {
            break;
        }
        p = stop;
    }
    let end = end?;
    Some(Hit { len: end - at, complete: true, kind: "pdf", ext: "pdf", label: "PDF document", detail: format!("PDF {}", version) })
}

fn zip(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const MAX: u64 = 512 << 20;
    let h = src.read(at, 30);
    let (version, method, nlen) = (le16(&h, 4)?, le16(&h, 8)?, le16(&h, 26)?);
    if version > 63 || !matches!(method, 0 | 8 | 9 | 12 | 14 | 93 | 95 | 99) || nlen == 0 || nlen > 1024 {
        return None;
    }
    let mut p = at;
    // The end record whose central directory offset points back at the
    // archive start belongs to this archive.
    while let Some(e) = src.find(p, at + MAX, b"PK\x05\x06") {
        let r = src.read(e, 22);
        let (entries, cd_size, cd_off, comment) = (le16(&r, 10)?, le32(&r, 12)?, le32(&r, 16)?, le16(&r, 20)?);
        if at + cd_off + cd_size == e || cd_off == 0xFFFF_FFFF {
            let names = zip_names(src, at + cd_off, entries.min(4096));
            let (kind, ext, label) = office_kind(&names, src, at);
            return Some(Hit { len: e + 22 + comment - at, complete: true, kind, ext, label, detail: format!("{} entries", entries) });
        }
        p = e + 4;
    }
    None
}

fn zip_names(src: &mut dyn Bytes, mut p: u64, n: u64) -> Vec<String> {
    let mut out = vec![];
    for _ in 0..n {
        let c = src.read(p, 46);
        if c.get(0..4) != Some(b"PK\x01\x02") {
            break;
        }
        let (nl, xl, cl) = (le16(&c, 28).unwrap_or(0), le16(&c, 30).unwrap_or(0), le16(&c, 32).unwrap_or(0));
        out.push(String::from_utf8_lossy(&src.read(p + 46, nl as usize)).into_owned());
        p += 46 + nl + xl + cl;
    }
    out
}

fn office_kind(names: &[String], src: &mut dyn Bytes, at: u64) -> (&'static str, &'static str, &'static str) {
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n));
    let prefix = |n: &str| names.iter().any(|x| x.to_ascii_lowercase().starts_with(n));
    if has("word/document.xml") {
        ("docx", "docx", "Word document")
    } else if has("xl/workbook.xml") {
        ("xlsx", "xlsx", "Excel workbook")
    } else if has("ppt/presentation.xml") {
        ("pptx", "pptx", "PowerPoint presentation")
    } else if has("mimetype") {
        let m = src.read(at + 38, 64);
        let s = String::from_utf8_lossy(&m);
        if s.contains("opendocument.text") {
            ("odt", "odt", "OpenDocument text")
        } else if s.contains("opendocument.spreadsheet") {
            ("ods", "ods", "OpenDocument spreadsheet")
        } else if s.contains("opendocument.presentation") {
            ("odp", "odp", "OpenDocument presentation")
        } else if s.contains("epub") {
            ("epub", "epub", "EPUB book")
        } else {
            ("zip", "zip", "ZIP archive")
        }
    } else if has("AndroidManifest.xml") {
        ("apk", "apk", "Android package")
    } else if has("META-INF/MANIFEST.MF") || prefix("meta-inf/") && names.iter().any(|n| n.ends_with(".class")) {
        ("jar", "jar", "Java archive")
    } else {
        ("zip", "zip", "ZIP archive")
    }
}

fn ole(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 512);
    let shift = le16(&h, 30)?;
    if !(shift == 9 || shift == 12) || le16(&h, 28)? != 0xFFFE {
        return None;
    }
    let ss = 1u64 << shift;
    let mut fat_sectors: Vec<u64> = (0..109).filter_map(|i| le32(&h, 76 + 4 * i)).filter(|&s| s < 0xFFFF_FFFA).collect();
    let mut difat = le32(&h, 68)?;
    let mut guard = 0;
    while difat < 0xFFFF_FFFA && guard < 1000 {
        let s = src.read(at + (difat + 1) * ss, ss as usize);
        let per = (ss / 4 - 1) as usize;
        fat_sectors.extend((0..per).filter_map(|i| le32(&s, 4 * i)).filter(|&x| x < 0xFFFF_FFFA));
        difat = le32(&s, 4 * per).unwrap_or(0xFFFF_FFFE);
        guard += 1;
    }
    if fat_sectors.is_empty() || fat_sectors.len() > 100_000 {
        return None;
    }
    // The highest sector the FAT uses ends the file.
    let mut last = 0u64;
    for (k, &fs) in fat_sectors.iter().enumerate() {
        let s = src.read(at + (fs + 1) * ss, ss as usize);
        if s.len() < ss as usize {
            return None;
        }
        for i in 0..(ss / 4) as usize {
            if le32(&s, 4 * i)? != 0xFFFF_FFFF {
                last = last.max(k as u64 * (ss / 4) + i as u64);
            }
        }
        last = last.max(fs);
    }
    let len = (last + 2) * ss;
    if len > 512 << 20 {
        return None;
    }
    let data = src.read(at, len as usize);
    let names: Vec<String> = kokino_artifacts::cfb::streams(&data, 1).map(|v| v.into_iter().map(|s| s.name).collect()).unwrap_or_default();
    let has = |n: &str| names.iter().any(|x| x.eq_ignore_ascii_case(n) || x.to_ascii_lowercase().ends_with(&format!("/{}", n.to_ascii_lowercase())));
    let (kind, ext, label) = if has("WordDocument") {
        ("doc", "doc", "Word 97-2003 document")
    } else if has("Workbook") || has("Book") {
        ("xls", "xls", "Excel 97-2003 workbook")
    } else if has("PowerPoint Document") {
        ("ppt", "ppt", "PowerPoint 97-2003 presentation")
    } else if names.iter().any(|n| n.starts_with("__substg1.0_")) {
        ("msg", "msg", "Outlook message")
    } else if has("DestList") {
        ("jumplist", "automaticDestinations-ms", "Jump List")
    } else {
        ("ole", "ole", "OLE compound file")
    };
    Some(Hit { len, complete: true, kind, ext, label, detail: format!("{} streams", names.len()) })
}

fn sqlite(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 100);
    let ps = match be16(&h, 16)? {
        1 => 65_536,
        v if v >= 512 && v.is_power_of_two() => v,
        _ => return None,
    };
    let pages = be32(&h, 28)?;
    // The in-header page count is valid only when "version-valid-for"
    // matches the change counter (SQLite 3.7.0+).
    let valid = be32(&h, 92)? == be32(&h, 24)? && pages > 0;
    if !valid || pages * ps > 1 << 30 {
        return None;
    }
    Some(Hit { len: pages * ps, complete: true, kind: "sqlite", ext: "sqlite", label: "SQLite database", detail: format!("{} pages of {} bytes", pages, ps) })
}

fn pe(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 64);
    let lfanew = le32(&h, 60)?;
    if !(64..4096).contains(&lfanew) {
        return None;
    }
    let p = src.read(at + lfanew, 24 + 240);
    if p.get(0..4) != Some(b"PE\0\0") {
        return None;
    }
    let machine = le16(&p, 4)?;
    let nsec = le16(&p, 6)?;
    let opt = le16(&p, 20)?;
    let chars = le16(&p, 22)?;
    if nsec == 0 || nsec > 96 || opt < 96 {
        return None;
    }
    let magic = le16(&p, 24)?;
    let dd = match magic {
        0x10B => 24 + 96,
        0x20B => 24 + 112,
        _ => return None,
    };
    let subsystem = le16(&p, 24 + 68)?;
    // Certificate table (data directory 4) is a file offset, after the sections.
    let (cert_off, cert_len) = (le32(&p, dd + 32).unwrap_or(0), le32(&p, dd + 36).unwrap_or(0));
    let st = src.read(at + lfanew + 24 + opt, 40 * nsec as usize);
    let mut end = lfanew + 24 + opt + 40 * nsec;
    for i in 0..nsec as usize {
        let (size, ptr) = (le32(&st, 40 * i + 16)?, le32(&st, 40 * i + 20)?);
        if size > 0 {
            end = end.max(ptr + size);
        }
    }
    if cert_len > 0 && cert_off >= end && cert_off - end < 1 << 20 {
        end = cert_off + cert_len;
    }
    if end > 256 << 20 {
        return None;
    }
    let (kind, ext, label) = if chars & 0x2000 != 0 {
        ("dll", "dll", "Windows DLL")
    } else if subsystem == 1 {
        ("sys", "sys", "Windows driver")
    } else {
        ("exe", "exe", "Windows executable")
    };
    let arch = match machine {
        0x14C => "x86",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x1C4 => "ARM",
        _ => "other CPU",
    };
    Some(Hit { len: end, complete: true, kind, ext, label, detail: format!("{}{}", arch, if cert_len > 0 { ", signed" } else { "" }) })
}

fn gzip(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const MAX: u64 = 256 << 20;
    let h = src.read(at, 10);
    let flags = *h.get(3)?;
    if flags & 0xE0 != 0 || h.len() < 10 {
        return None;
    }
    let mut p = at + 10;
    if flags & 4 != 0 {
        p += 2 + le16(&src.read(p, 2), 0)?;
    }
    for bit in [8u8, 16] {
        if flags & bit != 0 {
            p = src.find(p, p + 4096, b"\0")? + 1;
        }
    }
    if flags & 2 != 0 {
        p += 2;
    }
    let mut d = flate2::Decompress::new(false);
    let mut out = vec![0u8; 1 << 16];
    let mut q = p;
    loop {
        let chunk = src.read(q, 1 << 16);
        if chunk.is_empty() || q - at > MAX {
            return None;
        }
        let before = d.total_in();
        let st = d.decompress(&chunk, &mut out, flate2::FlushDecompress::None).ok()?;
        q += d.total_in() - before;
        match st {
            flate2::Status::StreamEnd => break,
            _ if d.total_in() == before && d.total_out() == 0 => return None,
            _ => {}
        }
    }
    let size = le32(&src.read(q + 4, 4), 0).unwrap_or(0);
    Some(Hit { len: q + 8 - at, complete: true, kind: "gzip", ext: "gz", label: "GZIP archive", detail: format!("{} bytes uncompressed (mod 4 GiB)", size) })
}

fn sevenzip(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 32);
    let (off, size) = (le64(&h, 12)?, le64(&h, 20)?);
    let len = 32u64.checked_add(off)?.checked_add(size)?;
    if size == 0 || size > 64 << 20 || len > 4 << 30 {
        return None;
    }
    Some(Hit { len, complete: true, kind: "7z", ext: "7z", label: "7-Zip archive", detail: String::new() })
}

fn riff(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 12);
    let size = le32(&h, 4)?;
    let (kind, ext, label) = match h.get(8..12)? {
        b"WAVE" => ("wav", "wav", "WAV audio"),
        b"AVI " => ("avi", "avi", "AVI video"),
        b"WEBP" => ("webp", "webp", "WebP image"),
        _ => return None,
    };
    if size < 4 || size > 2 << 30 {
        return None;
    }
    Some(Hit { len: 8 + size + (size & 1), complete: true, kind, ext, label, detail: String::new() })
}

fn mp4(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    const TOP: &[&[u8]] = &[b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"pnot", b"udta", b"sidx", b"moof", b"mfra", b"styp", b"pdin", b"prft", b"emsg"];
    let brand = String::from_utf8_lossy(&src.read(at + 8, 4)).trim().to_string();
    let mut p = at;
    let (mut moov, mut mdat) = (false, false);
    for _ in 0..10_000 {
        let b = src.read(p, 16);
        if b.len() < 8 || !TOP.contains(&&b[4..8]) {
            break;
        }
        let mut size = be32(&b, 0)?;
        if size == 1 {
            size = u64::from_be_bytes(b.get(8..16)?.try_into().ok()?);
        }
        if size < 8 || size > 8 << 30 {
            break;
        }
        moov |= &b[4..8] == b"moov";
        mdat |= &b[4..8] == b"mdat";
        p += size;
    }
    if p == at {
        return None;
    }
    let mov = brand == "qt";
    Some(Hit { len: p - at, complete: moov && mdat, kind: if mov { "mov" } else { "mp4" }, ext: if mov { "mov" } else { "mp4" }, label: if mov { "QuickTime video" } else { "MP4 video" }, detail: format!("brand {}", brand) })
}

/// A whole Internet Explorer index.dat: its size is in the header.
fn index_dat(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let h = src.read(at, 0x30);
    let size = le32(&h, 0x1c)?;
    if !(0x4000..=256 << 20).contains(&size) || size % 0x1000 != 0 || le32(&h, 0x24)? == 0 {
        return None;
    }
    let d = src.read(at, size as usize);
    let complete = d.len() as u64 == size;
    let ix = kokino_artifacts::iecache::parse(&d).ok()?;
    let urls = ix.records.iter().filter(|r| r.kind != kokino_artifacts::iecache::Kind::Redirect).count();
    Some(Hit { len: d.len() as u64, complete, kind: "index-dat", ext: "dat", label: "Internet Explorer index.dat", detail: format!("{} records{}", urls, if ix.unlisted > 0 { format!(", {} of them deleted", ix.unlisted) } else { String::new() }) })
}

/// A 64 KiB event log chunk: often all that survives of a cleared or
/// deleted log. Its records are counted with the EVTX reader.
fn evtx_chunk(src: &mut dyn Bytes, at: u64) -> Option<Hit> {
    let c = src.read(at, 65_536);
    if c.len() < 65_536 {
        return None;
    }
    let mut file = vec![0u8; 4096];
    file[0..8].copy_from_slice(b"ElfFile\0");
    file[42..44].copy_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&c);
    let mut channels: Vec<String> = vec![];
    let info = kokino_artifacts::evtx::parse(&file, &mut |e| {
        if !channels.contains(&e.channel) && channels.len() < 4 {
            channels.push(e.channel);
        }
    })
    .ok()?;
    if info.records == 0 {
        return None;
    }
    let iso = |t: u64| if t == 0 { String::new() } else { kokino_core::time::filetime_to_iso(t).chars().take(16).collect() };
    Some(Hit {
        len: 65_536,
        complete: true,
        kind: "evtx-chunk",
        ext: "evtx-chunk",
        label: "Event log chunk",
        detail: format!("{} records, {} to {}{}", info.records, iso(info.oldest), iso(info.newest), if channels.is_empty() { String::new() } else { format!(", {}", channels.join(", ")) }),
    })
}

/// Free space to carve: (space, offset, length, region label, file system
/// index). Space None: image offsets; Some(v): offsets in decrypted volume v.
fn regions(ev: &Evidence, analysis: &Analysis) -> Vec<(Option<usize>, u64, u64, String, Option<usize>)> {
    let mut out = vec![];
    // Shadow copies are left out: their free space is the live volume's, or
    // blocks the stores keep, both carved through the volume itself.
    for (fi, fsa) in analysis.filesystems.iter().enumerate().filter(|(_, f)| f.volume.shadow.is_none()) {
        let Ok(mut r) = volume_reader(ev, &fsa.volume) else { continue };
        let Ok(fs) = crate::fs::Fs::open(&mut r, &fsa.volume) else { continue };
        let decrypted = fsa.volume.bitlocker.is_some();
        for (start, len) in fs.free_runs(&mut r).unwrap_or_default() {
            if decrypted {
                out.push((Some(fsa.volume.index), start, len, format!("Volume {} free clusters (decrypted)", fsa.volume.index), Some(fi)));
            } else {
                out.push((None, fsa.volume.start + start, len, format!("Volume {} free clusters", fsa.volume.index), Some(fi)));
            }
        }
    }
    let parsed: std::collections::HashSet<usize> = analysis.filesystems.iter().map(|f| f.volume.index).collect();
    // Encrypted volumes that are read decrypted: their ciphertext holds nothing to carve.
    let unlocked: std::collections::HashSet<usize> = analysis.volumes.iter().filter_map(|v| v.bitlocker.as_ref().map(|b| b.of_volume)).collect();
    for v in analysis.volumes.iter().filter(|v| !v.is_virtual()) {
        match v.kind {
            VolumeKind::Unallocated => out.push((None, v.start, v.length, "Outside partitions".into(), None)),
            _ if v.fs == FsKind::BitLocker && unlocked.contains(&v.index) => {}
            _ if !parsed.contains(&v.index) => out.push((None, v.start, v.length, format!("Volume {} ({}, not parsed)", v.index, v.fs_label), None)),
            _ => {}
        }
    }
    out.sort_by_key(|r| (r.0, r.1));
    out
}

pub fn carve(ev: &Evidence, analysis: &Analysis, progress: Progress) -> anyhow::Result<CarveResult> {
    let regs = regions(ev, analysis);
    let total: u64 = regs.iter().map(|r| r.2).sum();
    let open = |space: Option<usize>| -> anyhow::Result<Img<BlockCache<Box<dyn ReadSeek>>>> {
        let (r, size) = space_reader(ev, &analysis.volumes, space)?;
        Ok(Img { r: BlockCache::new(r)?, size })
    };
    let mut cur_space = None;
    let mut src = open(None)?;
    // Deleted files whose data still starts where something is carved.
    let mut deleted_at: HashMap<(Option<usize>, u64), String> = HashMap::new();
    for fsa in analysis.filesystems.iter().filter(|f| f.volume.shadow.is_none()) {
        for f in fsa.files.iter().filter(|f| f.e.deleted && !f.e.is_dir) {
            if let Some(o) = f.e.data_offset() {
                let key = if fsa.volume.bitlocker.is_some() { (Some(fsa.volume.index), o) } else { (None, fsa.volume.start + o) };
                deleted_at.insert(key, f.e.path.clone());
            }
        }
    }
    let mut res = CarveResult { schema: CARVE_SCHEMA, tool_version: kokino_core::TOOL_VERSION.into(), regions: regs.len() as u64, ..Default::default() };
    let mut done = 0u64;
    for (space, start, len, label, fi) in &regs {
        if *space != cur_space {
            src = open(*space)?;
            cur_space = *space;
        }
        let end = start + len;
        let mut p = start.div_ceil(SECTOR) * SECTOR;
        while p < end {
            // Scan a window for any header first byte at sector boundaries.
            let n = ((end - p) as usize).min(WINDOW);
            let win = src.read(p, n);
            if win.is_empty() {
                break;
            }
            let mut next = p + win.len() as u64;
            scan_records(&mut src, p, &win, label, *fi, *space, &mut res);
            let mut i = 0usize;
            while i < win.len() {
                let b = &win[i..];
                let candidate = CARVERS.iter().any(|(m, _)| b.starts_with(&m[..m.len().min(b.len()).min(4)])) || b.get(4..8) == Some(b"ftyp");
                if candidate {
                    let at = p + i as u64;
                    let found = identify(&mut src, at);
                    if b.starts_with(&[0xFF, 0xD8, 0xFF]) && found.as_ref().is_none_or(|h| h.kind == "jpeg") {
                        if let Some((first, second, second_len, dims)) = jpeg_two(&mut src, at) {
                            let id = res.files.len() as u32;
                            let mut note = format!("joined from two pieces: {} bytes here, {} bytes from offset {}", first, second_len, second);
                            if let Some(path) = deleted_at.get(&(*space, at)) {
                                note = format!("{}; same location as deleted file {}", note, path);
                            }
                            res.files.push(Carved {
                                id,
                                offset: at,
                                len: first + second_len,
                                kind: "jpeg".into(),
                                ext: "jpg".into(),
                                label: "JPEG image".into(),
                                complete: true,
                                detail: dims,
                                note,
                                region: label.clone(),
                                fi: *fi,
                                beyond_region: at + first > end || second + second_len > end,
                                space: *space,
                                gap: Some((at + first, second - (at + first))),
                                ..Default::default()
                            });
                            if res.files.len() >= MAX_FILES {
                                res.truncated = true;
                                break;
                            }
                            // The first piece is skipped; the second is not
                            // scanned past either (it has no header of its own).
                            let after = (at + first).div_ceil(SECTOR) * SECTOR;
                            if after >= p + win.len() as u64 {
                                next = after;
                                break;
                            }
                            i = (after - p) as usize;
                            continue;
                        }
                    }
                    if let Some(h) = found {
                        if h.len > 0 {
                            let id = res.files.len() as u32;
                            let mut note = String::new();
                            if let Some(path) = deleted_at.get(&(*space, at)) {
                                note = format!("same location as deleted file {}", path);
                            }
                            let beyond = at + h.len > end;
                            res.files.push(Carved {
                                id,
                                offset: at,
                                len: h.len,
                                kind: h.kind.into(),
                                ext: h.ext.into(),
                                label: h.label.into(),
                                complete: h.complete,
                                detail: h.detail,
                                note,
                                region: label.clone(),
                                fi: *fi,
                                beyond_region: beyond,
                                space: *space,
                                ..Default::default()
                            });
                            if res.files.len() >= MAX_FILES {
                                res.truncated = true;
                                break;
                            }
                            // Continue after the carved file (headers inside it, such as
                            // thumbnails in a JPEG, are part of it).
                            let after = (at + h.len).div_ceil(SECTOR) * SECTOR;
                            if after >= p + win.len() as u64 {
                                next = after;
                                break;
                            }
                            i = (after - p) as usize;
                            continue;
                        }
                    }
                }
                i += SECTOR as usize;
            }
            if res.truncated {
                break;
            }
            // A carved file that runs past this window is skipped by the file
            // scan, but may hold records (a carved index.dat does).
            let mut q = p + win.len() as u64;
            while q < next.min(end) && !res.records_truncated {
                let b = src.read(q, ((next.min(end) - q) as usize).min(WINDOW));
                if b.is_empty() {
                    break;
                }
                scan_records(&mut src, q, &b, label, *fi, *space, &mut res);
                q += b.len() as u64;
            }
            done += next.min(end) - p;
            if !progress("Carving unallocated space", done.min(total), total) {
                anyhow::bail!("carving cancelled");
            }
            p = next;
        }
        if res.truncated {
            break;
        }
    }
    // Records that lie inside a carved index.dat.
    let dats: Vec<(Option<usize>, u64, u64, u32)> = res.files.iter().filter(|f| f.kind == "index-dat").map(|f| (f.space, f.offset, f.offset + f.len, f.id)).collect();
    for rec in &mut res.records {
        rec.in_file = dats.iter().find(|(s, a, b, _)| *s == rec.space && (*a..*b).contains(&rec.offset)).map(|d| d.3);
    }
    // Hashes of the carved bytes.
    let n = res.files.len() as u64;
    for (k, f) in res.files.iter_mut().enumerate() {
        if k % 64 == 0 && !progress("Hashing carved files", k as u64, n) {
            anyhow::bail!("carving cancelled");
        }
        let (rd, _) = carved_reader(ev, &analysis.volumes, f)?;
        let (h, _) = kokino_core::hashing::hash_reader(rd, |_| true)?;
        f.md5 = h.md5;
        f.sha256 = h.sha256;
    }
    res.scanned_bytes = total;
    res.carved_at = kokino_core::time::now_iso();
    Ok(res)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A real baseline JPEG (grayscale, 8x8 blocks with DC only), small but
    /// decodable by any viewer.
    pub fn jpeg_sample(w: usize, h: usize) -> Vec<u8> {
        // Standard luminance DC/AC Huffman tables (ITU T.81 K.3).
        let dc_bits = [0u8, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
        let dc_vals: Vec<u8> = (0..12).collect();
        let mut o = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0];
        o.extend_from_slice(&[0xFF, 0xDB, 0, 67, 0]);
        o.extend(std::iter::repeat(1u8).take(64));
        o.extend_from_slice(&[0xFF, 0xC0, 0, 11, 8, (h >> 8) as u8, h as u8, (w >> 8) as u8, w as u8, 1, 1, 0x11, 0]);
        o.extend_from_slice(&[0xFF, 0xC4, 0, (3 + 16 + 12) as u8, 0x00]);
        o.extend_from_slice(&dc_bits);
        o.extend_from_slice(&dc_vals);
        // AC table with only EOB (0x00), code length 1.
        let mut ac = vec![0xFF, 0xC4, 0, 3 + 16 + 1, 0x10, 1];
        ac.extend_from_slice(&[0; 15]);
        ac.push(0x00);
        o.extend_from_slice(&ac);
        o.extend_from_slice(&[0xFF, 0xDA, 0, 8, 1, 1, 0x00, 0, 63, 0]);
        // DC codes for the standard table, by category.
        let dc_code = |cat: usize| -> (u32, u32) {
            let lens = [2u32, 3, 3, 3, 3, 3, 4, 5, 6, 7, 8, 9];
            let codes = [0b00u32, 0b010, 0b011, 0b100, 0b101, 0b110, 0b1110, 0b11110, 0b111110, 0b1111110, 0b11111110, 0b111111110];
            (codes[cat], lens[cat])
        };
        struct Bits {
            acc: u64,
            n: u32,
            out: Vec<u8>,
        }
        impl Bits {
            fn put(&mut self, v: u32, n: u32) {
                self.acc = (self.acc << n) | v as u64;
                self.n += n;
                while self.n >= 8 {
                    let b = (self.acc >> (self.n - 8)) as u8;
                    self.out.push(b);
                    if b == 0xFF {
                        self.out.push(0); // byte stuffing
                    }
                    self.n -= 8;
                }
            }
        }
        let mut bw = Bits { acc: 0, n: 0, out: vec![] };
        let mut prev = 0i32;
        for by in 0..h / 8 {
            for bx in 0..w / 8 {
                let level = ((bx * 37 + by * 53) % 200) as i32 - 100; // pattern of gray blocks
                let diff = level - prev;
                prev = level;
                let mag = diff.unsigned_abs();
                let cat = 32 - mag.leading_zeros() as usize;
                let (c, l) = dc_code(cat);
                bw.put(c, l);
                if cat > 0 {
                    let v = if diff < 0 { (diff - 1) as u32 & ((1 << cat) - 1) } else { diff as u32 };
                    bw.put(v, cat as u32);
                }
                bw.put(0, 1); // EOB
            }
        }
        if bw.n > 0 {
            let pad = 8 - bw.n;
            bw.put((1 << pad) - 1, pad);
        }
        o.extend_from_slice(&bw.out);
        o.extend_from_slice(&[0xFF, 0xD9]);
        o
    }

    pub fn png_sample() -> Vec<u8> {
        let (w, h) = (16u32, 12u32);
        let mut raw = vec![];
        for y in 0..h {
            raw.push(0);
            for x in 0..w {
                raw.extend_from_slice(&[(x * 16) as u8, (y * 20) as u8, 160]);
            }
        }
        let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
        z.write_all(&raw).unwrap();
        let idat = z.finish().unwrap();
        let chunk = |ty: &[u8], data: &[u8]| -> Vec<u8> {
            let mut c = (data.len() as u32).to_be_bytes().to_vec();
            c.extend_from_slice(ty);
            c.extend_from_slice(data);
            let mut crc = flate2::Crc::new();
            crc.update(ty);
            crc.update(data);
            c.extend_from_slice(&crc.sum().to_be_bytes());
            c
        };
        let mut ihdr = w.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&h.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        [b"\x89PNG\r\n\x1a\n".to_vec(), chunk(b"IHDR", &ihdr), chunk(b"IDAT", &idat), chunk(b"IEND", &[])].concat()
    }

    fn one(data: &[u8]) -> Option<Hit> {
        let mut padded = data.to_vec();
        padded.extend_from_slice(&[0x5A; 4096]); // whatever follows on disk
        let mut s: &[u8] = &padded;
        identify(&mut s, 0)
    }

    #[test]
    fn formats_end_where_they_end() {
        let j = jpeg_sample(64, 48);
        let h = one(&j).unwrap();
        assert_eq!((h.kind, h.len, h.complete, h.detail.as_str()), ("jpeg", j.len() as u64, true, "64 x 48"));
        let p = png_sample();
        let h = one(&p).unwrap();
        assert_eq!((h.kind, h.len, h.detail.as_str()), ("png", p.len() as u64, "16 x 12"));
        let pdf = crate::doctext::tests::pdf();
        let h = one(&pdf).unwrap();
        assert_eq!((h.kind, h.len), ("pdf", pdf.len() as u64));
        let docx = crate::doctext::tests::zip(&[("[Content_Types].xml", b"<Types/>", true), ("word/document.xml", b"<w:p>x</w:p>", true)], None);
        let h = one(&docx).unwrap();
        assert_eq!((h.kind, h.len, h.detail.as_str()), ("docx", docx.len() as u64, "2 entries"));
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gz.write_all(&vec![7u8; 100_000]).unwrap();
        let gz = gz.finish().unwrap();
        assert_eq!(one(&gz).unwrap().len, gz.len() as u64);
    }

    #[test]
    fn lookalikes_are_rejected() {
        assert!(one(b"MZ\x90\0 just text").is_none());
        assert!(one(b"PK\x03\x04\x14\0\0\0\x08\0 no end record anywhere").is_none());
        assert!(one(b"BM\x10\0\0\0 nonsense").is_none());
        assert!(one(b"\xFF\xD8\xFF\xE0\0\x10JFIF\0 then garbage without image data").is_none());
        assert!(one(b"SQLite format 3\0\x10\0\x01\x01").is_none());
    }

    /// Ground truth from scripts/fixture_carve.py, placed by
    /// make_win_fixture.py in free clusters, a deleted file and the
    /// unpartitioned tail.
    #[test]
    fn carves_fixture_disk() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-win.img");
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let r = carve(&ev, &a, &mut |_, _, _| true).unwrap();
        let got: Vec<(&str, u64, bool)> = r.files.iter().map(|f| (f.kind.as_str(), f.len, f.complete)).collect();
        let want = [
            ("png", 720, true),
            ("jpeg", 237, true),
            ("docx", 346, true),
            ("sqlite", 2048, true),
            ("gif", 43, true),
            ("bmp", 198, true),
            ("pdf", 460, true),
            ("doc", 8192, true),
            ("exe", 2048, true),
            ("gzip", 76, true),
            ("7z", 117, true),
            ("wav", 844, true),
            ("mp4", 452, true),
            ("evtx-chunk", 65_536, true),
            ("index-dat", 20_480, true),
            ("jpeg", 512, false), // cut off by the end of the disk
        ];
        assert_eq!(got, want);
        let png = &r.files[0];
        assert_eq!(png.note, "same location as deleted file /Users/alice/Pictures/chart.png");
        let evtx = r.files.iter().find(|f| f.kind == "evtx-chunk").unwrap();
        assert!(evtx.detail.starts_with("14 records") && evtx.detail.ends_with("Security"));
        assert!(r.files.iter().all(|f| f.offset % 512 == 0 && f.md5.len() == 32 && f.sha256.len() == 64 && !f.beyond_region));
        assert_eq!(r.files.iter().filter(|f| f.region == "Outside partitions").count(), 12);
        // Internet Explorer records: one inside the deleted index.dat, two loose.
        let dat = r.files.iter().find(|f| f.kind == "index-dat").unwrap();
        assert_eq!(dat.detail, "1 records");
        let recs: Vec<(&str, &str, &str, Option<u32>)> = r.records.iter().map(|x| (x.what.as_str(), x.user.as_str(), x.url.as_str(), x.in_file)).collect();
        assert_eq!(recs, [("history", "bob", "http://gone.test/page.html", Some(dat.id)), ("daily history", "bob", "http://forum.test/thread", None), ("cache", "", "http://forum.test/avatar.gif", None)]);
        assert_eq!(r.records[0].title, "Gone");
        assert_eq!(r.records[2].file, "avatar[1].gif");
        assert!(r.records.iter().all(|x| x.offset % 128 == 0 && x.region == "Outside partitions"));
        // The hash is of exactly the carved bytes.
        let mut b = vec![0u8; png.len as usize];
        read_at(&mut ev.reader().unwrap(), png.offset, &mut b).unwrap();
        let (h, _) = kokino_core::hashing::hash_reader(&b[..], |_| true).unwrap();
        assert_eq!(h.sha256, png.sha256);

        // Carved documents are decoded into the text index.
        use crate::textindex::{build, search, Mode, Scope};
        let dir = std::env::temp_dir().join(format!("kokino-carve-idx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("idx.sqlite");
        let st = build(&ev, &a, Some(&r), &out, &mut |_, _, _| true).unwrap();
        assert_eq!(st.carved_documents, 3); // docx, pdf, gzip
        let kw = |q: &str| search(&out, &a, &Mode::Keyword(q.into()), Scope::Unallocated, None, 50, 10_000).unwrap().hits;
        let pdf = r.files.iter().find(|f| f.kind == "pdf").unwrap().id;
        assert!(kw("offshore account").iter().any(|h| h.source == "carved" && h.carved == Some(pdf) && h.image_offset.is_none()));
        let docx = r.files.iter().find(|f| f.kind == "docx").unwrap().id;
        assert!(kw("wire instructions").iter().any(|h| h.carved == Some(docx) && h.part.as_deref() == Some("word/document.xml")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// camera.jpg split at 64 KiB by a sector of text and two of zeros, as a
    /// file system that ran out of contiguous space would leave it.
    #[test]
    fn joins_a_jpeg_in_two_pieces() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/photo");
        let Ok(cam) = std::fs::read(dir.join("camera.jpg")) else { return };
        let other = std::fs::read(dir.join("edited.jpg")).unwrap();
        let j = crate::photo::jpeg::parse(&cam).unwrap();
        assert!(crate::photo::jpeg::scan_fits(&cam, &j), "the whole picture fits");
        let at = 65_536usize;
        let first = 65_536usize;
        let mut gap = b"Meeting notes, lab.test, room 2. Nothing to see here. ".repeat(10)[..512].to_vec();
        gap.extend(vec![0u8; 1024]);
        let build = |second: &[u8]| {
            let mut d = vec![0u8; at];
            d.extend(&cam[..first]);
            d.extend(&gap);
            d.extend(second);
            d.extend(vec![0u8; 8192]);
            d
        };
        let disk = build(&cam[first..]);
        let mut src: &[u8] = &disk;
        let (f, second, second_len, dims) = jpeg_two(&mut src, at as u64).expect("joined");
        assert_eq!((f, second, second_len), (first as u64, (at + first + gap.len()) as u64, (cam.len() - first) as u64));
        assert_eq!(dims, format!("{} x {}", j.width, j.height));
        // Read back through the pieces: the original file.
        let c = Carved { offset: at as u64, len: cam.len() as u64, gap: Some(((at + first) as u64, gap.len() as u64)), ..Default::default() };
        assert_eq!(c.pieces(), vec![(at as u64, first as u64), (second, second_len)]);
        let mut r = CarvedReader { r: Box::new(std::io::Cursor::new(disk.clone())), pieces: c.pieces(), len: c.len, pos: 0 };
        let mut back = vec![];
        r.read_to_end(&mut back).unwrap();
        assert_eq!(back, cam);
        // Whole: left to the ordinary walk.
        let mut whole = vec![0u8; at];
        whole.extend(&cam);
        whole.extend(vec![0u8; 4096]);
        let mut src: &[u8] = &whole;
        assert!(jpeg_two(&mut src, at as u64).is_none());
        // A "second piece" from another picture does not fit.
        let skip = other.len() - (cam.len() - first);
        let wrong = build(&other[skip..]);
        let mut src: &[u8] = &wrong;
        assert!(jpeg_two(&mut src, at as u64).is_none());
    }

    #[test]
    fn truncated_jpeg_is_kept_as_incomplete() {
        let j = jpeg_sample(64, 48);
        let cut = &j[..j.len() - 40];
        let mut s: &[u8] = cut;
        let h = identify(&mut s, 0).unwrap();
        assert!(!h.complete);
        assert_eq!(h.len, cut.len() as u64);
    }

    /// The decrypted free space of a BitLocker volume is carved: the
    /// fixture is testfs1-win encrypted, so carving it unlocked finds what
    /// carving testfs1-win finds, at the same offsets, with the same hashes.
    #[test]
    fn carves_decrypted_bitlocker_volume() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let (Ok(bek), true) = (std::fs::read(dir.join("bitlocker-xts.BEK")), dir.join("testfs1-win").exists()) else { return };
        let plain_ev = Evidence::open(dir.join("testfs1-win")).unwrap();
        let plain = carve(&plain_ev, &crate::analyze(&plain_ev, &mut |_, _, _| true).unwrap(), &mut |_, _, _| true).unwrap();
        let (ev, res) = kokino_image::unlock_bitlocker(Evidence::open(dir.join("bitlocker-xts.img")).unwrap(), &kokino_image::bde::Secret::StartupKey(&bek));
        assert!(res[0].2.is_ok());
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        assert_eq!(a.filesystems.len(), 1);
        assert_eq!(a.filesystems[0].files.len(), crate::analyze(&plain_ev, &mut |_, _, _| true).unwrap().filesystems[0].files.len());
        let enc = carve(&ev, &a, &mut |_, _, _| true).unwrap();
        assert_eq!(plain.files.len(), 4);
        let key = |f: &Carved| (f.offset, f.len, f.kind.clone(), f.sha256.clone(), f.note.clone());
        assert_eq!(enc.files.iter().map(key).collect::<Vec<_>>(), plain.files.iter().map(key).collect::<Vec<_>>());
        assert!(enc.files.iter().all(|f| f.space == Some(1) && f.region.contains("decrypted")));
        assert_eq!(enc.records.iter().map(|r| (r.offset, r.url.clone(), r.in_file)).collect::<Vec<_>>(), plain.records.iter().map(|r| (r.offset, r.url.clone(), r.in_file)).collect::<Vec<_>>());
        // Read back through the space they were carved from.
        let f = &enc.files[0];
        let d = read_carved(&ev, &a.volumes, f.space, f.offset, f.len).unwrap();
        assert_eq!(kokino_core::hashing::hash_reader(&d[..], |_| true).unwrap().0.sha256, f.sha256);
    }
}
