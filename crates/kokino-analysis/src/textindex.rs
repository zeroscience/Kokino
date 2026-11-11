//! Full-text index over file content, deleted files and unallocated space.
//!
//! Text is extracted the way `strings` does it, in two encodings: UTF-8
//! (which covers ASCII) and UTF-16LE (how Windows stores most text). Runs of
//! at least `MIN_CHARS` printable characters are packed into chunks of about
//! `CHUNK_TEXT` bytes and stored in a SQLite FTS5 table. Every chunk keeps a
//! map from its text positions back to the source byte offsets, so a hit can
//! be shown at its exact place in the file and in the image.
//!
//! Sources, per NTFS volume:
//! - every data stream (main and alternate) of live and deleted files,
//!   up to `MAX_STREAM_BYTES` each; deleted content is read as long as the
//!   record still describes it;
//! - every cluster marked free in $Bitmap (unallocated space).
//!
//! And on the disk: space outside any partition (also "unallocated", with
//! image offsets) and volumes whose file system is not parsed yet, read raw.
//!
//! Deleted files whose clusters are free are found twice, once as the file
//! and once as unallocated space.
//!
//! Files that are ZIP (DOCX, XLSX, PPTX, ODF, ...), GZIP or PDF containers
//! are also decoded (see `doctext`) and their text is indexed as "parts" of
//! the file ("word/document.xml", "page 3"). Decoded text has no single
//! place in the image, so those hits carry no image offset.

use crate::{volume_reader, Analysis, Progress};
use kokino_image::{read_at, Evidence, VolumeKind};
use kokino_ntfs::Extent;
use regex::{Regex, RegexBuilder};
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// 2: adds decoded document text (`chunks.part`, `SRC_DOC`).
pub const INDEX_SCHEMA: u32 = 2;
/// Shortest run of printable characters that is indexed.
pub const MIN_CHARS: usize = 4;
/// Streams longer than this are indexed up to this size only.
pub const MAX_STREAM_BYTES: u64 = 512 << 20;
/// Containers up to this size are decoded for document text.
pub const MAX_DOC_BYTES: u64 = 256 << 20;
const READ: usize = 1 << 20;
const CHUNK_TEXT: usize = 64 * 1024;
/// MFT records below this are NTFS metadata ($MFT, $LogFile, $Bitmap...).
const FIRST_USER_RECORD: u64 = 16;

const SRC_FILE: i64 = 0;
const SRC_UNALLOC: i64 = 1;
/// A volume read as raw bytes because its file system is not parsed.
const SRC_RAW: i64 = 2;
/// Text decoded from inside a file (Office, ZIP, PDF...); `part` names where.
const SRC_DOC: i64 = 3;
/// Text decoded from a carved file; `file` holds the carved file id.
const SRC_CARVED: i64 = 4;
/// Carved kinds whose text `doctext` can decode.
const CARVED_DOCS: &[&str] = &["pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "zip", "jar", "gzip"];
/// `fi` of chunks that belong to the disk rather than a parsed volume;
/// their offsets are image offsets.
const DISK: i64 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Enc {
    Utf8,
    Utf16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// Byte offset of the first character in the source.
    pub offset: u64,
    pub enc: Enc,
    pub text: String,
}

/// Characters accepted in UTF-16LE runs. Restricted to Latin, Greek and
/// Cyrillic plus common punctuation, because random binary read as UTF-16
/// otherwise turns into long runs of CJK "text".
fn utf16_ok(u: u16) -> bool {
    let c = u as u32;
    let printable = |c: u32| char::from_u32(c).map(|ch| !ch.is_control() || ch == '\t').unwrap_or(false);
    (c < 0x0250 || (0x0370..=0x052F).contains(&c) || (0x2010..=0x206F).contains(&c) || c == 0x20AC) && printable(c)
}

/// Finds string runs in `buf` (which starts at source offset `base`).
///
/// When `at_end` is false, runs still open at the end of the buffer are not
/// returned; the second value is the buffer position to continue reading
/// from so that they are seen whole next time.
pub fn extract(buf: &[u8], base: u64, at_end: bool) -> (Vec<Run>, usize) {
    let n = buf.len();
    let mut runs = vec![];
    let mut resume = n;

    // UTF-8 (and ASCII)
    let mut start: Option<usize> = None;
    let mut text = String::new();
    let mut chars = 0usize;
    let mut i = 0;
    while i < n {
        let b = buf[i];
        let (len, ch) = if b < 0x80 {
            (1, if (0x20..0x7f).contains(&b) || b == b'\t' { Some(b as char) } else { None })
        } else {
            let want = match b {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF4 => 4,
                _ => 0,
            };
            if want > 0 && i + want <= n {
                match std::str::from_utf8(&buf[i..i + want]) {
                    Ok(s) => (want, s.chars().next().filter(|c| !c.is_control())),
                    Err(_) => (1, None),
                }
            } else if want > 0 && !at_end {
                // A character split by the end of the buffer: continue next read.
                resume = resume.min(start.unwrap_or(i));
                start = None;
                break;
            } else {
                (1, None)
            }
        };
        match ch {
            Some(c) => {
                if start.is_none() {
                    start = Some(i);
                }
                text.push(c);
                chars += 1;
            }
            None => {
                if let Some(s) = start.take() {
                    if chars >= MIN_CHARS {
                        runs.push(Run { offset: base + s as u64, enc: Enc::Utf8, text: std::mem::take(&mut text) });
                    }
                }
                text.clear();
                chars = 0;
            }
        }
        i += len;
    }
    if let Some(s) = start {
        if at_end {
            if chars >= MIN_CHARS {
                runs.push(Run { offset: base + s as u64, enc: Enc::Utf8, text });
            }
        } else {
            resume = resume.min(s);
        }
    }

    // UTF-16LE, both byte alignments
    for parity in 0..2 {
        let mut start: Option<usize> = None;
        let mut text = String::new();
        let mut chars = 0usize;
        let mut i = parity;
        while i + 1 < n {
            let u = u16::from_le_bytes([buf[i], buf[i + 1]]);
            if utf16_ok(u) {
                if start.is_none() {
                    start = Some(i);
                }
                text.push(char::from_u32(u as u32).unwrap_or('?'));
                chars += 1;
            } else {
                if let Some(s) = start.take() {
                    // Pure ASCII-range runs are only kept when they really
                    // are UTF-16 (zero high bytes), not two ASCII bytes
                    // glued into one code unit.
                    if chars >= MIN_CHARS {
                        runs.push(Run { offset: base + s as u64, enc: Enc::Utf16, text: std::mem::take(&mut text) });
                    }
                }
                text.clear();
                chars = 0;
            }
            i += 2;
        }
        if let Some(s) = start {
            if at_end {
                if chars >= MIN_CHARS {
                    runs.push(Run { offset: base + s as u64, enc: Enc::Utf16, text });
                }
            } else {
                resume = resume.min(s);
            }
        }
    }
    runs.retain(|r| r.enc == Enc::Utf8 || plausible_utf16(&r.text));
    runs.sort_by_key(|r| r.offset);
    (runs, resume)
}

/// UTF-16 runs made of code units in 0x0100..0x024F are almost always two
/// ASCII bytes read as one unit; real text has mostly zero high bytes or
/// Greek/Cyrillic letters.
fn plausible_utf16(s: &str) -> bool {
    let total = s.chars().count().max(1);
    let good = s.chars().filter(|c| (*c as u32) < 0x0100 || (0x0370..=0x052F).contains(&(*c as u32))).count();
    good * 10 >= total * 9
}

/// Reads a source sequentially and returns all runs, carrying open runs
/// across read boundaries. `read(offset, buf)` fills from source offset.
fn scan_source(
    len: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> anyhow::Result<usize>,
    mut on_runs: impl FnMut(Vec<Run>) -> anyhow::Result<()>,
    mut on_progress: impl FnMut(u64) -> bool,
) -> anyhow::Result<()> {
    let mut pos = 0u64;
    let mut buf = vec![0u8; READ];
    // Ends of runs emitted from the previous buffer: a run that started
    // before the resume point is re-read in part and must not come back as
    // a second, shorter run.
    let mut prev_ends: std::collections::HashSet<(Enc, u64)> = Default::default();
    let end_of = |r: &Run| r.offset + if r.enc == Enc::Utf8 { r.text.len() as u64 } else { 2 * r.text.chars().count() as u64 };
    while pos < len {
        let want = ((len - pos) as usize).min(READ);
        let got = read(pos, &mut buf[..want])?;
        if got == 0 {
            break;
        }
        let at_end = pos + got as u64 >= len || got < want;
        let (runs, resume) = extract(&buf[..got], pos, at_end);
        // A single run filling the whole buffer is emitted as is, otherwise
        // the loop would never get past it.
        let (runs, step) = if resume == 0 { (extract(&buf[..got], pos, true).0, got) } else { (runs, resume) };
        let cut = pos + step as u64;
        // Runs starting at or after the resume point are found again whole
        // in the next buffer.
        let keep: Vec<Run> = runs.into_iter().filter(|r| (step == got || r.offset < cut) && !prev_ends.contains(&(r.enc, end_of(r)))).collect();
        prev_ends = keep.iter().map(|r| (r.enc, end_of(r))).collect();
        on_runs(keep)?;
        pos += step as u64;
        if !on_progress(step as u64) {
            anyhow::bail!("indexing cancelled");
        }
        if at_end {
            break;
        }
    }
    Ok(())
}

struct Chunker<'a> {
    tx: &'a rusqlite::Transaction<'a>,
    fi: i64,
    src: i64,
    file: i64,
    stream: String,
    part: String,
    text: String,
    map: Vec<u8>,
    chunks: u64,
}

impl<'a> Chunker<'a> {
    fn new(tx: &'a rusqlite::Transaction<'a>, fi: i64, src: i64, file: i64, stream: &str) -> Self {
        Chunker { tx, fi, src, file, stream: stream.to_string(), part: String::new(), text: String::new(), map: vec![], chunks: 0 }
    }

    fn push(&mut self, runs: Vec<Run>) -> anyhow::Result<()> {
        for r in runs {
            if !self.text.is_empty() && self.text.len() + r.text.len() > CHUNK_TEXT {
                self.flush()?;
            }
            self.map.extend_from_slice(&(self.text.len() as u32).to_le_bytes());
            self.map.extend_from_slice(&r.offset.to_le_bytes());
            self.map.push(if r.enc == Enc::Utf8 { 1 } else { 2 });
            self.text.push_str(&r.text);
            self.text.push('\n');
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.text.is_empty() {
            return Ok(());
        }
        self.tx.execute(
            "INSERT INTO chunks(fi, src, file, stream, part, map) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![self.fi, self.src, self.file, self.stream, self.part, self.map],
        )?;
        let id = self.tx.last_insert_rowid();
        self.tx.execute("INSERT INTO fts(rowid, text) VALUES (?1, ?2)", params![id, self.text])?;
        self.text.clear();
        self.map.clear();
        self.chunks += 1;
        Ok(())
    }
}

/// Text map entry: (text position, source offset, encoding).
fn decode_map(b: &[u8]) -> Vec<(usize, u64, Enc)> {
    b.chunks_exact(13)
        .map(|c| {
            let tp = u32::from_le_bytes(c[0..4].try_into().unwrap()) as usize;
            let off = u64::from_le_bytes(c[4..12].try_into().unwrap());
            (tp, off, if c[12] == 2 { Enc::Utf16 } else { Enc::Utf8 })
        })
        .collect()
}

/// Source offset of the character at text position `pos`, and its run.
fn locate(map: &[(usize, u64, Enc)], text: &str, pos: usize) -> Option<(u64, Enc, usize)> {
    let i = map.partition_point(|m| m.0 <= pos).checked_sub(1)?;
    let (tp, off, enc) = map[i];
    let rel = match enc {
        Enc::Utf8 => (pos - tp) as u64,
        Enc::Utf16 => 2 * text.get(tp..pos)?.chars().count() as u64,
    };
    Some((off + rel, enc, tp))
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct IndexStats {
    pub schema: u32,
    pub tool_version: String,
    pub built_at: String,
    pub streams: u64,
    pub deleted_streams: u64,
    pub file_bytes: u64,
    pub unalloc_bytes: u64,
    /// Space outside partitions plus volumes read raw.
    pub disk_bytes: u64,
    pub chunks: u64,
    /// Streams cut at MAX_STREAM_BYTES.
    pub truncated_streams: u64,
    /// Streams whose content could not be read (reused or damaged records).
    pub unreadable_streams: u64,
    /// Files decoded as documents (ZIP/Office/ODF, GZIP, PDF) with text found.
    #[serde(default)]
    pub documents: u64,
    #[serde(default)]
    pub document_parts: u64,
    /// What could not be decoded (encrypted, limits reached...), first 200.
    #[serde(default)]
    pub document_notes: Vec<String>,
    /// Carved files whose text was decoded.
    #[serde(default)]
    pub carved_documents: u64,
    pub min_chars: usize,
    pub max_stream_bytes: u64,
}

/// Builds the index for every analyzed NTFS volume into `out` (written to a
/// temporary file first and renamed when complete).
/// The text of every message in a PST or OST, each a part ("Inbox, message
/// 3"), with document attachments opened like any other content.
fn pst_text<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, e: &kokino_ntfs::FsEntry) -> crate::doctext::Extracted {
    let mut x = crate::doctext::Extracted::default();
    let mut p = match crate::pst::Pst::open(crate::fs::stream(fs, r, e), e.size) {
        Ok(p) => p,
        Err(err) => {
            x.notes.push(format!("PST: {:#}", err));
            return x;
        }
    };
    let folders: std::collections::HashMap<u32, String> = p.folders().into_iter().map(|f| (f.nid, f.path)).collect();
    let mut left: usize = 512 << 20;
    for (k, nid) in p.message_ids().into_iter().enumerate() {
        if left == 0 {
            x.notes.push("PST: text limit reached; later messages are not indexed".into());
            break;
        }
        let Ok(eml) = p.eml(nid) else { continue };
        let folder = p.nodes.get(&nid).and_then(|n| folders.get(&n.parent)).cloned().unwrap_or_default();
        let label = format!("{}{}message {}", folder, if folder.is_empty() { "" } else { ", " }, k + 1);
        let m = crate::mail::parse(&eml);
        let head: Vec<String> = ["Date", "From", "To", "Cc", "Subject"].iter().map(|h| format!("{}: {}", h, crate::mail::decode_words(&m.header(h)))).collect();
        let mut text = head.join("\n");
        text.push('\n');
        text.push_str(&m.text);
        if !m.attachments.is_empty() {
            text.push_str(&format!("\nAttachments: {}", m.attachments.iter().map(|(a, _)| a.name.clone()).collect::<Vec<_>>().join(", ")));
        }
        left = left.saturating_sub(text.len());
        x.parts.push(crate::doctext::Part { name: label.clone(), text });
        for (a, bytes) in m.attachments {
            let inner = crate::doctext::extract(&bytes);
            for ip in inner.parts {
                left = left.saturating_sub(ip.text.len());
                x.parts.push(crate::doctext::Part { name: format!("{}/{}/{}", label, a.name, ip.name), text: ip.text });
            }
        }
    }
    x
}

pub fn build(ev: &Evidence, analysis: &Analysis, carved: Option<&crate::carve::CarveResult>, out: &Path, progress: Progress) -> anyhow::Result<IndexStats> {
    let tmp = out.with_extension("sqlite.part");
    let _ = std::fs::remove_file(&tmp);
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut db = Connection::open(&tmp)?;
    db.execute_batch(
        "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;
         CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
         CREATE TABLE chunks(id INTEGER PRIMARY KEY, fi INTEGER NOT NULL, src INTEGER NOT NULL, file INTEGER NOT NULL, stream TEXT NOT NULL, part TEXT NOT NULL DEFAULT '', map BLOB NOT NULL);
         CREATE TABLE extents(fi INTEGER NOT NULL, file INTEGER NOT NULL, stream TEXT NOT NULL, ext TEXT NOT NULL, PRIMARY KEY(fi, file, stream));
         CREATE VIRTUAL TABLE fts USING fts5(text, tokenize = 'unicode61 remove_diacritics 2');",
    )?;
    let mut st = IndexStats {
        schema: INDEX_SCHEMA,
        tool_version: kokino_core::TOOL_VERSION.to_string(),
        min_chars: MIN_CHARS,
        max_stream_bytes: MAX_STREAM_BYTES,
        ..Default::default()
    };

    let tx = db.transaction()?;
    for (fi, fsa) in analysis.filesystems.iter().enumerate() {
        let mut r = volume_reader(ev, &fsa.volume)?;
        let fs = crate::fs::Fs::open(&mut r, &fsa.volume)?;
        let free = fs.free_runs(&mut r).unwrap_or_default();
        let streams: Vec<(usize, String, u64)> = fsa
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.e.is_dir && (!fs.is_ntfs() || f.e.record >= FIRST_USER_RECORD) && !f.e.path.starts_with("/$Extend"))
            .flat_map(|(i, f)| f.e.streams.iter().filter(|s| s.size > 0).map(move |s| (i, s.name.clone(), s.size)))
            .collect();
        let total: u64 = streams.iter().map(|s| s.2.min(MAX_STREAM_BYTES)).sum::<u64>() + free.iter().map(|f| f.1).sum::<u64>();
        let stage = format!("Volume {}: text index", fsa.volume.index);
        let mut done = 0u64;
        let mut tick = |n: u64| {
            done += n;
            progress(&stage, done.min(total), total)
        };
        if !tick(0) {
            anyhow::bail!("indexing cancelled");
        }

        for (idx, name, size) in streams {
            let f = &fsa.files[idx];
            let e = &f.e;
            let len = size.min(MAX_STREAM_BYTES);
            if size > MAX_STREAM_BYTES {
                st.truncated_streams += 1;
            }
            if let Ok(ext) = fs.extents(&mut r, e, &name) {
                tx.execute(
                    "INSERT OR REPLACE INTO extents(fi, file, stream, ext) VALUES (?1, ?2, ?3, ?4)",
                    params![fi as i64, idx as i64, name, serde_json::to_string(&ext)?],
                )?;
            }
            let mut ch = Chunker::new(&tx, fi as i64, SRC_FILE, idx as i64, &name);
            let mut read_any = false;
            let res = scan_source(
                len,
                |off, buf| {
                    let b = fs.read(&mut r, e, &name, off, buf.len())?;
                    buf[..b.len()].copy_from_slice(&b);
                    read_any |= !b.is_empty();
                    Ok(b.len())
                },
                |runs| ch.push(runs),
                &mut tick,
            );
            match res {
                Ok(()) => {}
                Err(e) if e.to_string().contains("cancelled") => return Err(e),
                Err(_) => st.unreadable_streams += 1,
            }
            ch.flush()?;
            st.chunks += ch.chunks;
            // Outlook PST and OST: read in place whatever their size, one
            // message at a time.
            let pst = read_any && name.is_empty() && crate::pst::is_pst(&fs.read(&mut r, e, "", 0, 16).unwrap_or_default());
            if read_any && (len <= MAX_DOC_BYTES || pst) {
                // Mail is recognized by its first header lines, so read a little more.
                let head = fs.read(&mut r, e, &name, 0, 2048.min(len as usize)).unwrap_or_default();
                if pst || crate::doctext::detect(&head).is_some() {
                    let data = if pst { Ok(vec![]) } else { fs.read(&mut r, e, &name, 0, len as usize) };
                    if let Ok(data) = data {
                        let x = if pst { pst_text(&fs, &mut r, e) } else { crate::doctext::extract(&data) };
                        if !x.parts.is_empty() {
                            st.documents += 1;
                        }
                        for p in x.parts {
                            let mut ch = Chunker::new(&tx, fi as i64, SRC_DOC, idx as i64, &name);
                            ch.part = p.name;
                            let mut off = 0u64;
                            let runs = p
                                .text
                                .split('\n')
                                .map(|line| {
                                    let r = Run { offset: off, enc: Enc::Utf8, text: line.to_string() };
                                    off += line.len() as u64 + 1;
                                    r
                                })
                                .filter(|r| !r.text.trim().is_empty())
                                .collect();
                            ch.push(runs)?;
                            ch.flush()?;
                            st.chunks += ch.chunks;
                            st.document_parts += 1;
                        }
                        for n in x.notes {
                            if st.document_notes.len() < 200 {
                                st.document_notes.push(format!("{}: {}", f.e.path, n));
                            }
                        }
                    }
                }
            }
            if read_any {
                st.streams += 1;
                st.file_bytes += len;
                if f.e.deleted {
                    st.deleted_streams += 1;
                }
            }
        }

        for (start, len) in free {
            let mut ch = Chunker::new(&tx, fi as i64, SRC_UNALLOC, -1, "");
            scan_source(
                len,
                |off, buf| {
                    r.seek(SeekFrom::Start(start + off))?;
                    let mut got = 0;
                    while got < buf.len() {
                        let n = r.read(&mut buf[got..])?;
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                    Ok(got)
                },
                // Unallocated offsets are volume offsets.
                |runs| ch.push(runs.into_iter().map(|mut x| { x.offset += start; x }).collect()),
                &mut tick,
            )?;
            ch.flush()?;
            st.chunks += ch.chunks;
            st.unalloc_bytes += len;
        }
    }

    // Disk level: gaps between partitions, and volumes not parsed as a file system.
    let parsed: std::collections::HashSet<usize> = analysis.filesystems.iter().map(|f| f.volume.index).collect();
    // Encrypted volumes read decrypted: their ciphertext holds no text.
    let unlocked: std::collections::HashSet<usize> = analysis.volumes.iter().filter_map(|v| v.bitlocker.as_ref().map(|b| b.of_volume)).collect();
    let raw: Vec<(i64, u64, u64)> = analysis
        .volumes
        .iter()
        .filter(|v| !v.is_virtual() && !unlocked.contains(&v.index))
        .filter_map(|v| match v.kind {
            VolumeKind::Unallocated => Some((SRC_UNALLOC, v.start, v.length)),
            _ if !parsed.contains(&v.index) => Some((SRC_RAW, v.start, v.length)),
            _ => None,
        })
        .collect();
    let total: u64 = raw.iter().map(|r| r.2).sum();
    let mut done = 0u64;
    let mut r = ev.reader()?;
    for (src, start, len) in raw {
        let mut ch = Chunker::new(&tx, DISK, src, -1, "");
        scan_source(
            len,
            |off, buf| Ok(read_at(&mut r, start + off, buf)?),
            |runs| ch.push(runs.into_iter().map(|mut x| { x.offset += start; x }).collect()),
            |n| {
                done += n;
                progress("Disk: space outside parsed volumes", done.min(total), total)
            },
        )?;
        ch.flush()?;
        st.chunks += ch.chunks;
        st.disk_bytes += len;
    }

    // Text inside carved documents: their raw strings are already in the
    // unallocated space above, but compressed text needs decoding.
    if let Some(c) = carved {
        let docs: Vec<&crate::carve::Carved> = c.files.iter().filter(|f| CARVED_DOCS.contains(&f.kind.as_str()) && f.len <= MAX_DOC_BYTES).collect();
        let n = docs.len() as u64;
        for (k, f) in docs.into_iter().enumerate() {
            progress("Text in carved documents", k as u64, n);
            let Ok(data) = crate::carve::read_carved_file(ev, &analysis.volumes, f) else { continue };
            let x = crate::doctext::extract(&data);
            if x.parts.is_empty() {
                continue;
            }
            st.carved_documents += 1;
            for p in x.parts {
                let mut ch = Chunker::new(&tx, DISK, SRC_CARVED, f.id as i64, "");
                ch.part = if p.name.is_empty() { f.label.clone() } else { p.name };
                let mut off = 0u64;
                let runs = p
                    .text
                    .split('\n')
                    .map(|line| {
                        let r = Run { offset: off, enc: Enc::Utf8, text: line.to_string() };
                        off += line.len() as u64 + 1;
                        r
                    })
                    .filter(|r| !r.text.trim().is_empty())
                    .collect();
                ch.push(runs)?;
                ch.flush()?;
                st.chunks += ch.chunks;
            }
        }
    }

    st.built_at = kokino_core::time::now_iso();
    tx.execute("INSERT INTO meta(k, v) VALUES ('stats', ?1)", params![serde_json::to_string(&st)?])?;
    tx.commit()?;
    progress("Optimizing text index", 0, 1);
    db.execute_batch("INSERT INTO fts(fts) VALUES ('optimize');")?;
    drop(db);
    std::fs::rename(&tmp, out)?;
    Ok(st)
}

/// Stats of an existing index, or None when there is none (or it is from an
/// older, incompatible index schema).
pub fn stats(path: &Path) -> Option<IndexStats> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let s: String = db.query_row("SELECT v FROM meta WHERE k = 'stats'", [], |r| r.get(0)).ok()?;
    serde_json::from_str::<IndexStats>(&s).ok().filter(|s| s.schema == INDEX_SCHEMA)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    All,
    /// Live (allocated) files only.
    Files,
    Deleted,
    Unallocated,
}

#[derive(Debug, Clone)]
pub enum Mode {
    /// Words and "quoted phrases", optional AND / OR / NOT, prefix*.
    Keyword(String),
    Regex { pattern: String, case_sensitive: bool },
    Preset(&'static Preset),
}

#[derive(Debug)]
pub struct Preset {
    pub id: &'static str,
    pub label: &'static str,
    pub pattern: &'static str,
    /// Extra check on a match (checksums), to cut false positives.
    pub check: Option<fn(&str) -> bool>,
}

fn luhn(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&d.len()) || d.iter().all(|x| *x == d[0]) {
        return false;
    }
    let sum: u32 = d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x }).sum();
    sum % 10 == 0
}

fn iban(s: &str) -> bool {
    let c: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&c.len()) {
        return false;
    }
    let moved = format!("{}{}", &c[4..], &c[..4]);
    let mut rem = 0u32;
    for ch in moved.chars() {
        let v = match ch.to_digit(36) {
            Some(v) => v,
            None => return false,
        };
        for digit in v.to_string().chars() {
            rem = (rem * 10 + digit.to_digit(10).unwrap()) % 97;
        }
    }
    rem == 1
}

pub static PRESETS: &[Preset] = &[
    Preset { id: "email", label: "Email addresses", pattern: r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}", check: None },
    Preset { id: "url", label: "URLs", pattern: r#"(?i)\b(?:https?|ftp)://[^\s"'<>]{3,2000}"#, check: None },
    Preset { id: "ipv4", label: "IPv4 addresses", pattern: r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b", check: None },
    Preset { id: "card", label: "Payment card numbers (Luhn-checked)", pattern: r"\b\d(?:[ -]?\d){12,18}\b", check: Some(luhn) },
    Preset { id: "iban", label: "IBANs (checksum-verified)", pattern: r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", check: Some(iban) },
    Preset { id: "btc", label: "Bitcoin addresses", pattern: r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", check: None },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    /// Parsed volume, or None for disk-level space (gaps, raw volumes).
    pub fi: Option<usize>,
    /// "file", "unallocated" or "raw".
    pub source: &'static str,
    pub file: Option<usize>,
    pub stream: String,
    /// Inside a decoded document: the part ("word/document.xml", "page 2").
    pub part: Option<String>,
    /// Id of the carved file the text was decoded from.
    pub carved: Option<u32>,
    /// Offset in the stream (files) or in the volume (unallocated).
    pub offset: u64,
    /// Absolute offset in the image, when it can be mapped.
    pub image_offset: Option<u64>,
    pub enc: Enc,
    pub matched: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub hits: Vec<Hit>,
    /// More hits exist than were returned (limit or time budget reached).
    pub truncated: bool,
    pub chunks_scanned: u64,
    pub elapsed_ms: u64,
}

/// Turns user input into a safe FTS5 query plus a regex that highlights it.
/// Bare tokens become quoted phrases, so input like `alice@example.com` or
/// `C:\Users` is valid; AND / OR / NOT and a trailing * are kept.
pub fn keyword_query(input: &str) -> anyhow::Result<(String, Regex)> {
    let mut fts = vec![];
    let mut hl = vec![];
    let mut negate = false;
    let mut chars = input.chars().peekable();
    let mut tokens: Vec<(String, bool)> = vec![];
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' {
            chars.next();
            let s: String = chars.by_ref().take_while(|c| *c != '"').collect();
            tokens.push((s, true));
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '"' {
                    break;
                }
                s.push(c);
                chars.next();
            }
            tokens.push((s, false));
        }
    }
    for (tok, quoted) in tokens {
        if !quoted && matches!(tok.as_str(), "AND" | "OR" | "NOT") {
            negate = tok == "NOT";
            fts.push(tok);
            continue;
        }
        let prefix = !quoted && tok.ends_with('*') && tok.len() > 1;
        let body = tok.trim_end_matches('*');
        let words: Vec<&str> = body.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        if words.is_empty() {
            continue;
        }
        fts.push(format!("\"{}\"{}", words.join(" "), if prefix { "*" } else { "" }));
        if !negate {
            let mut re = words.iter().map(|w| regex::escape(w)).collect::<Vec<_>>().join(r"[^\p{L}\p{N}]+");
            if prefix {
                re.push_str(r"[\p{L}\p{N}]*");
            }
            hl.push(re);
        }
        negate = false;
    }
    while matches!(fts.last().map(|s| s.as_str()), Some("AND" | "OR" | "NOT")) {
        fts.pop();
    }
    if fts.is_empty() || hl.is_empty() {
        anyhow::bail!("enter at least one word to search for");
    }
    let re = RegexBuilder::new(&format!("(?:{})", hl.join("|"))).case_insensitive(true).build()?;
    Ok((fts.join(" "), re))
}

/// Match positions in a chunk. For keyword searches, matches separated only
/// by a few spaces or punctuation marks on the same line become one hit, so
/// `confidential findings` is one match rather than two.
fn match_spans(re: &Regex, text: &str, check: Option<fn(&str) -> bool>, merge: bool) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = vec![];
    for m in re.find_iter(text) {
        if check.map(|c| !c(m.as_str())).unwrap_or(false) {
            continue;
        }
        if merge {
            if let Some(last) = out.last_mut() {
                let gap = &text[last.1..m.start()];
                if gap.len() <= 3 && !gap.contains('\n') && gap.chars().all(|c| !c.is_alphanumeric()) {
                    last.1 = m.end();
                    continue;
                }
            }
        }
        out.push((m.start(), m.end()));
    }
    out
}

fn context(text: &str, start: usize, end: usize) -> (String, String) {
    // Stay inside the run (runs are separated by '\n') and at most 80 chars.
    let line_start = text[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[end..].find('\n').map(|i| end + i).unwrap_or(text.len());
    let before: String = text[line_start..start].chars().rev().take(80).collect::<Vec<_>>().into_iter().rev().collect();
    let after: String = text[end..line_end].chars().take(80).collect();
    (before, after)
}

/// Runs a search. `deleted(fi, file)` tells whether a file row is deleted;
/// `extents(fi, file, stream)` maps stream offsets for image offsets.
pub fn search(path: &Path, analysis: &Analysis, mode: &Mode, scope: Scope, fi: Option<usize>, limit: usize, budget_ms: u64) -> anyhow::Result<SearchResult> {
    let started = std::time::Instant::now();
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (re, check, fts) = match mode {
        Mode::Keyword(q) => {
            let (fts, re) = keyword_query(q)?;
            (re, None, Some(fts))
        }
        Mode::Regex { pattern, case_sensitive } => {
            let re = RegexBuilder::new(pattern).case_insensitive(!case_sensitive).size_limit(16 << 20).build()?;
            (re, None, None)
        }
        Mode::Preset(p) => (Regex::new(p.pattern)?, p.check, None),
    };

    let mut sql = String::from("SELECT c.id, c.fi, c.src, c.file, c.stream, c.map, f.text, c.part FROM fts f JOIN chunks c ON c.id = f.rowid WHERE 1");
    if fts.is_some() {
        sql.push_str(" AND fts MATCH ?1");
    }
    match scope {
        Scope::Unallocated => sql.push_str(" AND c.src IN (1, 4)"),
        Scope::Files | Scope::Deleted => sql.push_str(" AND c.src IN (0, 3)"),
        Scope::All => {}
    }
    if let Some(fi) = fi {
        sql.push_str(&format!(" AND c.fi = {}", fi as i64));
    }
    sql.push_str(" ORDER BY c.id");
    let mut stmt = db.prepare(&sql)?;
    let mut rows = match &fts {
        Some(q) => stmt.query(params![q]),
        None => stmt.query([]),
    }
    .map_err(|e| anyhow::anyhow!("invalid search: {}", e))?;

    let mut ext_stmt = db.prepare("SELECT ext FROM extents WHERE fi = ?1 AND file = ?2 AND stream = ?3")?;
    let mut ext_cache: std::collections::HashMap<(usize, usize, String), Vec<Extent>> = Default::default();
    let mut hits = vec![];
    let mut truncated = false;
    let mut scanned = 0u64;
    while let Some(row) = rows.next().map_err(|e| anyhow::anyhow!("invalid search: {}", e))? {
        if hits.len() >= limit || started.elapsed().as_millis() as u64 > budget_ms {
            truncated = true;
            break;
        }
        scanned += 1;
        let cfi: i64 = row.get(1)?;
        let src: i64 = row.get(2)?;
        let file: i64 = row.get(3)?;
        let stream: String = row.get(4)?;
        let map = decode_map(&row.get::<_, Vec<u8>>(5)?);
        let text: String = row.get(6)?;
        let part: String = row.get(7)?;
        let fsa = if cfi == DISK { None } else { analysis.filesystems.get(cfi as usize) };
        let cfi = cfi as usize;
        let carved_id = (src == SRC_CARVED).then_some(file as u32);
        let file = (file >= 0 && src != SRC_CARVED).then_some(file as usize);
        if let (Some(f), Some(fsa)) = (file, fsa) {
            let deleted = fsa.files.get(f).map(|r| r.e.deleted).unwrap_or(false);
            if (scope == Scope::Deleted && !deleted) || (scope == Scope::Files && deleted) {
                continue;
            }
        }
        let spans = match_spans(&re, &text, check, fts.is_some());
        for (ms, me) in spans {
            let Some((offset, enc, _)) = locate(&map, &text, ms) else { continue };
            let image_offset = match (file, fsa) {
                _ if src == SRC_DOC || src == SRC_CARVED => None,
                (_, None) => Some(offset),
                // A shadow copy's or a decrypted volume's bytes are not in the image as shown.
                (_, Some(fsa)) if fsa.volume.is_virtual() => None,
                (None, Some(fsa)) => Some(fsa.volume.start + offset),
                (Some(f), Some(fsa)) => {
                    let key = (cfi, f, stream.clone());
                    if !ext_cache.contains_key(&key) {
                        let ext: Vec<Extent> = ext_stmt
                            .query_row(params![cfi as i64, f as i64, stream], |r| r.get::<_, String>(0))
                            .ok()
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default();
                        ext_cache.insert(key.clone(), ext);
                    }
                    kokino_ntfs::map_offset(&ext_cache[&key], offset).map(|v| v + fsa.volume.start)
                }
            };
            let (before, after) = context(&text, ms, me);
            hits.push(Hit {
                fi: fsa.map(|_| cfi),
                source: match src {
                    SRC_UNALLOC => "unallocated",
                    SRC_RAW => "raw",
                    SRC_CARVED => "carved",
                    _ => "file",
                },
                carved: carved_id,
                file,
                stream: stream.clone(),
                part: (!part.is_empty()).then(|| part.clone()),
                offset,
                image_offset,
                enc,
                matched: text[ms..me].to_string(),
                before,
                after,
            });
            if hits.len() >= limit {
                truncated = true;
                break;
            }
        }
    }
    Ok(SearchResult { hits, truncated, chunks_scanned: scanned, elapsed_ms: started.elapsed().as_millis() as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_utf8_and_utf16_with_offsets() {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(b"hello world\x00\x01");
        let utf16: Vec<u8> = "Lozinka123".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        b.push(0xFF); // odd alignment for the UTF-16 run
        b.extend_from_slice(&utf16);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice("\u{0421}\u{043A}\u{043E}\u{043F}\u{0458}\u{0435}".as_bytes());
        b.push(0);
        let (runs, resume) = extract(&b, 100, true);
        assert_eq!(resume, b.len());
        let find = |t: &str| runs.iter().find(|r| r.text == t).unwrap_or_else(|| panic!("{} not in {:?}", t, runs));
        assert_eq!(find("hello world").offset, 108);
        let u = find("Lozinka123");
        assert_eq!((u.offset, u.enc), (100 + 8 + 13 + 1, Enc::Utf16));
        assert_eq!(find("\u{0421}\u{043A}\u{043E}\u{043F}\u{0458}\u{0435}").enc, Enc::Utf8);
        // ASCII bytes glued as UTF-16 code units must not show up as text.
        assert!(runs.iter().all(|r| r.enc == Enc::Utf8 || r.text == "Lozinka123"), "{:?}", runs);
    }

    #[test]
    fn open_runs_resume_across_reads() {
        let data = b"\x00\x00first-part-of-a-long-string";
        let (runs, resume) = extract(data, 0, false);
        assert!(runs.is_empty());
        assert_eq!(resume, 2);
    }

    #[test]
    fn strings_across_read_boundaries_are_found_once() {
        let mut data = vec![0u8; 3 * READ];
        let words: Vec<(usize, Vec<u8>)> = vec![
            (100, b"plain".to_vec()),
            (READ - 5, b"straddles-the-first-boundary".to_vec()),
            (2 * READ - 7, "Granica".encode_utf16().flat_map(|u| u.to_le_bytes()).collect()),
            (2 * READ + 40, "\u{0416}ivot".as_bytes().to_vec()),
        ];
        for (o, w) in &words {
            data[*o..*o + w.len()].copy_from_slice(w);
        }
        let mut found = vec![];
        scan_source(
            data.len() as u64,
            |off, buf| {
                let o = off as usize;
                let n = buf.len().min(data.len() - o);
                buf[..n].copy_from_slice(&data[o..o + n]);
                Ok(n)
            },
            |runs| {
                found.extend(runs);
                Ok(())
            },
            |_| true,
        )
        .unwrap();
        let texts: Vec<(&str, u64)> = found.iter().map(|r| (r.text.as_str(), r.offset)).collect();
        assert_eq!(
            texts,
            vec![("plain", 100), ("straddles-the-first-boundary", (READ - 5) as u64), ("Granica", (2 * READ - 7) as u64), ("\u{0416}ivot", (2 * READ + 40) as u64)]
        );
    }

    #[test]
    fn keyword_queries_are_sanitized() {
        let (q, re) = keyword_query("alice@example.com AND secr*").unwrap();
        assert_eq!(q, "\"alice example com\" AND \"secr\"*");
        assert!(re.is_match("mail ALICE@Example.COM now"));
        assert!(re.is_match("secret"));
        let (q, _) = keyword_query(r#""wipe disk" NOT benign C:\Users"#).unwrap();
        assert_eq!(q, "\"wipe disk\" NOT \"benign\" \"C Users\"");
        assert!(keyword_query("AND OR").is_err());
    }

    #[test]
    fn checksums() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(!luhn("0000000000000000"));
        assert!(iban("MK07 2501 2000 0058 984"));
        assert!(iban("GB82WEST12345698765432"));
        assert!(!iban("GB82WEST12345698765433"));
    }

    /// Plants markers in a free NTFS cluster (UTF-8 and UTF-16) and in the
    /// space after the partition, indexes the copy and checks every hit's
    /// image offset against the image bytes.
    #[test]
    fn indexes_files_unallocated_and_disk_gaps() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-af.img");
        if !src.exists() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("kokino-textindex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = std::fs::read(&src).unwrap();

        let ev = Evidence::open(&src).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let fsa = &a.filesystems[0];
        let mut r = volume_reader(&ev, &fsa.volume).unwrap();
        let ntfs = kokino_ntfs::open_ntfs(&mut r).unwrap();
        let free = kokino_ntfs::free_runs(&ntfs, &mut r).unwrap();
        let run = free.iter().find(|f| f.1 >= 8192).copied().expect("a free run");
        let at1 = (fsa.volume.start + run.0) as usize;
        let m1 = b"KOKINO-UNALLOC-MARKER-7731";
        bytes[at1..at1 + m1.len()].copy_from_slice(m1);
        let at2 = at1 + 4096;
        let m2: Vec<u8> = "Tajna lozinka Vodno".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes[at2..at2 + m2.len()].copy_from_slice(&m2);
        let gap = a.volumes.iter().find(|v| v.kind == VolumeKind::Unallocated && v.start > fsa.volume.start).expect("disk tail");
        let at3 = (gap.start + 512) as usize;
        let m3 = b"outside-any-partition-4242";
        bytes[at3..at3 + m3.len()].copy_from_slice(m3);
        let img = dir.join("disk.img");
        std::fs::write(&img, &bytes).unwrap();

        let ev = Evidence::open(&img).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let out = dir.join("idx.sqlite");
        let st = build(&ev, &a, None, &out, &mut |_, _, _| true).unwrap();
        assert!(st.streams > 0 && st.unalloc_bytes > 0 && st.disk_bytes > 0, "{:?}", st);
        assert_eq!(stats(&out).unwrap().chunks, st.chunks);

        let kw = |q: &str, scope| search(&out, &a, &Mode::Keyword(q.into()), scope, None, 200, 10_000).unwrap();
        let at = |o: Option<u64>, n: usize| bytes[o.unwrap() as usize..o.unwrap() as usize + n].to_vec();

        // Live file: the planted Chrome History holds the search for wiping tools.
        let h = kw("permanently delete", Scope::Files);
        let hit = h.hits.iter().find(|h| h.file.map(|f| a.filesystems[0].files[f].e.name == "History").unwrap_or(false)).expect("History hit");
        assert_eq!(hit.source, "file");
        let utf8: Vec<_> = h.hits.iter().filter(|h| h.enc == Enc::Utf8 && h.image_offset.is_some()).collect();
        assert!(!utf8.is_empty());
        for h in utf8 {
            assert_eq!(at(h.image_offset, h.matched.len()).to_ascii_lowercase(), h.matched.as_bytes().to_ascii_lowercase());
        }
        assert!(kw("permanently delete", Scope::Unallocated).hits.iter().all(|h| h.source == "unallocated"));
        assert!(kw("permanently delete", Scope::Deleted).hits.iter().all(|h| a.filesystems[0].files[h.file.unwrap()].e.deleted));

        // Unallocated clusters, UTF-8 and UTF-16.
        let h = kw("KOKINO-UNALLOC-MARKER-7731", Scope::Unallocated);
        assert_eq!(h.hits.len(), 1);
        assert_eq!((h.hits[0].fi, h.hits[0].image_offset), (Some(0), Some(at1 as u64)));
        let h = kw("lozinka", Scope::All);
        assert_eq!(h.hits.len(), 1, "{:?}", h.hits);
        assert_eq!((h.hits[0].enc, h.hits[0].image_offset), (Enc::Utf16, Some((at2 + 2 * "Tajna ".len()) as u64)));
        assert_eq!(h.hits[0].before, "Tajna ");

        // Outside the partition.
        let h = kw("outside-any-partition-4242", Scope::Unallocated);
        assert_eq!(h.hits.len(), 1);
        assert_eq!((h.hits[0].fi, h.hits[0].image_offset), (None, Some(at3 as u64)));

        // Regex and presets.
        let h = search(&out, &a, &Mode::Regex { pattern: r"MARKER-\d{4}".into(), case_sensitive: true }, Scope::All, None, 10, 10_000).unwrap();
        assert_eq!(h.hits.len(), 1);
        assert_eq!(at(h.hits[0].image_offset, 11), b"MARKER-7731");
        let urls = search(&out, &a, &Mode::Preset(preset("url").unwrap()), Scope::All, None, 500, 10_000).unwrap();
        assert!(urls.hits.iter().any(|h| h.matched.contains("sysinternals")));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// disk-fat.img (scripts/make_fat_fixture.py): FAT32 and exFAT partitions.
    /// Both are analyzed, the deleted file's text is found through the
    /// file system and every hit maps back to the image bytes.
    #[test]
    fn indexes_fat_and_exfat_volumes() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-fat.img");
        if !src.exists() {
            return;
        }
        let bytes = std::fs::read(&src).unwrap();
        let ev = Evidence::open(&src).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        assert!(a.errors.is_empty(), "{:?}", a.errors);
        let kinds: Vec<&str> = a.filesystems.iter().map(|f| f.info.version.as_str()).collect();
        assert_eq!(kinds, ["FAT32", "exFAT"]);
        for fsa in &a.filesystems {
            let jpg = fsa.files.iter().find(|f| f.e.name == "IMG_0001.JPG").unwrap();
            assert_eq!(jpg.sig.as_deref(), Some("jpeg"));
            assert!(fsa.files.iter().any(|f| f.e.deleted && f.e.path == "/Old keys.txt"));
        }

        let dir = std::env::temp_dir().join(format!("kokino-fatindex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("idx.sqlite");
        let st = build(&ev, &a, None, &out, &mut |_, _, _| true).unwrap();
        assert!(st.streams > 0 && st.unalloc_bytes > 0, "{:?}", st);
        let kw = |q: &str, scope| search(&out, &a, &Mode::Keyword(q.into()), scope, None, 200, 10_000).unwrap();
        let h = kw("4242-1717", Scope::Deleted);
        let files: Vec<(usize, &str)> = h.hits.iter().map(|h| (h.fi.unwrap(), a.filesystems[h.fi.unwrap()].files[h.file.unwrap()].e.path.as_str())).collect();
        assert_eq!(files, [(0, "/Old keys.txt"), (1, "/Old keys.txt")], "{:?}", h.hits);
        // The fragmented file: a phrase in the second run maps to the right image bytes.
        let h = kw("\"external drive\"", Scope::Files);
        assert!(h.hits.len() >= 2);
        for hit in &h.hits {
            let o = hit.image_offset.unwrap() as usize;
            assert_eq!(&bytes[o..o + hit.matched.len()], hit.matched.as_bytes());
        }
        assert!(h.hits.iter().any(|h| h.offset >= 8 * 512), "second fragment not reached");

        let c = crate::carve::carve(&ev, &a, &mut |_, _, _| true).unwrap();
        assert!(c.scanned_bytes > 0 && c.regions >= 2, "free clusters of both volumes are carved");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Plants a ZIP (holding a DOCX and a text note) over one file and a PDF
    /// over another, through their real on-disk extents, then searches the
    /// decoded text.
    #[test]
    fn indexes_text_inside_documents() {
        use crate::doctext::tests::{pdf, zip};
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-af.img");
        if !src.exists() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("kokino-docindex-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = std::fs::read(&src).unwrap();
        let ev = Evidence::open(&src).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let fsa = &a.filesystems[0];
        let mut r = volume_reader(&ev, &fsa.volume).unwrap();
        let ntfs = kokino_ntfs::open_ntfs(&mut r).unwrap();
        let mut plant = |suffix: &str, make: &dyn Fn(usize) -> Vec<u8>| {
            let f = fsa.files.iter().find(|f| f.e.path.ends_with(suffix)).unwrap();
            let data = make(f.e.size as usize);
            assert_eq!(data.len() as u64, f.e.size);
            let ext = kokino_ntfs::stream_extents(&ntfs, &mut r, f.e.record, "").unwrap();
            for (i, b) in data.iter().enumerate() {
                let v = kokino_ntfs::map_offset(&ext, i as u64).unwrap();
                bytes[(fsa.volume.start + v) as usize] = *b;
            }
        };
        let docx = zip(&[("word/document.xml", b"<w:p><w:r><w:t>Kokino quarterly </w:t></w:r><w:r><w:t>confidential findings</w:t></w:r></w:p>", true)], None);
        plant("Edge/User Data/Default/History", &|n| zip(&[("report.docx", &docx, true), ("notes.txt", b"Meet at Vodno at nine", true)], Some(n)));
        plant("/places.sqlite", &|n| {
            let mut p = pdf();
            p.resize(n, b' ');
            p
        });
        let img = dir.join("disk.img");
        std::fs::write(&img, &bytes).unwrap();

        let ev = Evidence::open(&img).unwrap();
        let a = crate::analyze(&ev, &mut |_, _, _| true).unwrap();
        let out = dir.join("idx.sqlite");
        let st = build(&ev, &a, None, &out, &mut |_, _, _| true).unwrap();
        assert_eq!(st.documents, 2, "{:?}", st);
        assert!(st.document_parts >= 4 && st.document_notes.is_empty(), "{:?}", st);

        let kw = |q: &str, scope| search(&out, &a, &Mode::Keyword(q.into()), scope, None, 50, 10_000).unwrap().hits;
        let path = |h: &Hit| a.filesystems[0].files[h.file.unwrap()].e.path.clone();
        let h = kw("confidential findings", Scope::All);
        assert_eq!(h.len(), 1, "{:?}", h);
        assert_eq!(h[0].part.as_deref(), Some("report.docx/word/document.xml"));
        assert!(path(&h[0]).ends_with("Edge/User Data/Default/History"));
        assert_eq!((h[0].image_offset, h[0].before.as_str(), h[0].source), (None, "Kokino quarterly ", "file"));
        assert_eq!(kw("vodno nine", Scope::Files)[0].part.as_deref(), Some("notes.txt"));
        assert!(kw("vodno nine", Scope::Deleted).is_empty());

        let h = kw("\"hello pdf world\"", Scope::All);
        assert_eq!((h.len(), h[0].part.as_deref()), (1, Some("page 1")));
        assert!(path(&h[0]).ends_with("/places.sqlite"));
        assert_eq!(kw("\u{0421}\u{043A}\u{043E}\u{043F}", Scope::All)[0].part.as_deref(), Some("page 1"));
        // The Info dictionary is not compressed: found both raw (with an image
        // offset) and decoded as document metadata.
        let h = kw("quarterly plan", Scope::All);
        assert!(h.iter().any(|x| x.part.is_none() && x.image_offset.is_some()), "{:?}", h);
        assert!(h.iter().any(|x| x.part.as_deref() == Some("metadata")), "{:?}", h);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn locate_maps_utf16_positions() {
        let text = "abcd\n\u{0412}\u{043E}\u{0434}\u{043D}\u{043E}\n";
        let map = vec![(0, 1000, Enc::Utf8), (5, 2000, Enc::Utf16)];
        assert_eq!(locate(&map, text, 2).unwrap().0, 1002);
        let pos = text.find("\u{043D}\u{043E}").unwrap();
        assert_eq!(locate(&map, text, pos).unwrap().0, 2006);
    }
}
