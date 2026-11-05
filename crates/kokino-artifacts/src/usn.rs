//! NTFS change journal ($Extend\$UsnJrnl, stream $J).
//!
//! Windows appends a record to the journal for every change to a file:
//! created, written, renamed (old and new name), attributes or times
//! changed, deleted, and so on. Each record holds the file's and its
//! folder's MFT references, the name at that moment, a timestamp and the
//! reasons accumulated since the file was opened; a record with the CLOSE
//! reason ends one round of changes. The journal keeps the most recent tens
//! of megabytes (older parts become sparse), so it covers days to weeks on
//! a busy system and much longer on a quiet one, and it keeps the names of
//! files long after their MFT records were reused.
//!
//! Record versions 2 and 3 are read (version 3 has 128-bit file IDs; on
//! NTFS the low 64 bits are the usual MFT reference). Version 4 records
//! (range tracking) carry no name and are skipped.

use crate::bin::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsnRecord {
    pub usn: u64,
    pub time: u64,
    /// MFT reference (record, sequence number).
    pub file: (u64, u16),
    pub parent: (u64, u16),
    pub reason: u32,
    pub attributes: u32,
    pub source_info: u32,
    pub name: String,
}

pub const DATA_OVERWRITE: u32 = 0x1;
pub const DATA_EXTEND: u32 = 0x2;
pub const DATA_TRUNCATION: u32 = 0x4;
pub const FILE_CREATE: u32 = 0x100;
pub const FILE_DELETE: u32 = 0x200;
pub const SECURITY_CHANGE: u32 = 0x800;
pub const RENAME_OLD_NAME: u32 = 0x1000;
pub const RENAME_NEW_NAME: u32 = 0x2000;
pub const BASIC_INFO_CHANGE: u32 = 0x8000;
pub const CLOSE: u32 = 0x8000_0000;

const REASONS: &[(u32, &str)] = &[
    (FILE_CREATE, "created"),
    (FILE_DELETE, "deleted"),
    (RENAME_NEW_NAME, "renamed"),
    (DATA_OVERWRITE, "data overwritten"),
    (DATA_EXTEND, "data extended"),
    (DATA_TRUNCATION, "data truncated"),
    (0x10, "stream overwritten"),
    (0x20, "stream extended"),
    (0x40, "stream truncated"),
    (0x400, "extended attributes changed"),
    (SECURITY_CHANGE, "permissions changed"),
    (0x4000, "indexing flag changed"),
    (BASIC_INFO_CHANGE, "attributes or times changed"),
    (0x10000, "hard link changed"),
    (0x20000, "compression changed"),
    (0x40000, "encryption changed"),
    (0x80000, "object ID changed"),
    (0x100000, "reparse point changed"),
    (0x200000, "stream added or removed"),
    (0x400000, "transacted change"),
    (0x800000, "integrity changed"),
];

/// The reasons in plain words, most telling first ("created, data
/// extended"). RENAME_OLD_NAME and CLOSE are left out: a rename is told by
/// its new name, and every round of changes ends with a close.
pub fn describe(reason: u32) -> String {
    let v: Vec<&str> = REASONS.iter().filter(|(b, _)| reason & b != 0).map(|(_, s)| *s).collect();
    if v.is_empty() {
        if reason & RENAME_OLD_NAME != 0 { "renamed".into() } else { "closed".into() }
    } else {
        v.join(", ")
    }
}

fn split_ref(v: u64) -> (u64, u16) {
    (v & 0xFFFF_FFFF_FFFF, (v >> 48) as u16)
}

/// Parses records from `buf`, calling `f` for each. Records start on 8-byte
/// boundaries; zeros (page padding, sparse space) and anything that is not
/// a plausible record are stepped over 8 bytes at a time. Returns how many
/// bytes were used: the rest is a record cut short by the end of `buf`.
pub fn parse(buf: &[u8], f: &mut dyn FnMut(UsnRecord)) -> usize {
    let mut p = 0;
    while p + 8 <= buf.len() {
        let len = u32_at(buf, p).unwrap_or(0) as usize;
        let major = u16_at(buf, p + 4).unwrap_or(0);
        if len < 0x40 || len % 8 != 0 || len > 0x1_0000 || !(2..=3).contains(&major) {
            p += 8;
            continue;
        }
        if p + len > buf.len() {
            return p;
        }
        match record(&buf[p..p + len], major) {
            Some(r) => {
                f(r);
                p += len;
            }
            None => p += 8,
        }
    }
    p.min(buf.len())
}

fn record(d: &[u8], major: u16) -> Option<UsnRecord> {
    // (file ref, parent ref, usn, time, reason, source, attributes, name length, name offset)
    let (fr, pr, at) = if major == 2 { (8, 16, 24) } else { (8, 24, 40) };
    let file = split_ref(u64_at(d, fr)?);
    let parent = split_ref(u64_at(d, pr)?);
    let usn = u64_at(d, at)?;
    let time = u64_at(d, at + 8)?;
    let reason = u32_at(d, at + 16)?;
    let source_info = u32_at(d, at + 20)?;
    let attributes = u32_at(d, at + 28)?;
    let nlen = u16_at(d, at + 32)? as usize;
    let noff = u16_at(d, at + 34)? as usize;
    if plausible(time) == 0 || reason == 0 || nlen == 0 || nlen % 2 != 0 || noff < at + 36 || noff + nlen > d.len() {
        return None;
    }
    let units: Vec<u16> = d[noff..noff + nlen].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let name = String::from_utf16(&units).ok()?;
    if name.chars().any(|c| c < ' ') {
        return None;
    }
    Some(UsnRecord { usn, time, file, parent, reason, attributes, source_info, name })
}

/// The journal's $Max stream: its size limits and identity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalMax {
    pub max_size: u64,
    pub allocation_delta: u64,
    /// The journal's ID, which is the FILETIME it was created.
    pub journal_id: u64,
    pub lowest_valid_usn: u64,
}

pub fn parse_max(d: &[u8]) -> Option<JournalMax> {
    Some(JournalMax { max_size: u64_at(d, 0)?, allocation_delta: u64_at(d, 8)?, journal_id: u64_at(d, 16)?, lowest_valid_usn: u64_at(d, 24)? })
}

/// One round of changes to a file, from its first record to the CLOSE that
/// ended it, with the reasons combined.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    /// Time of the last record (the close).
    pub t: u64,
    /// Time of the first record, when earlier.
    pub first: u64,
    pub usn: u64,
    pub record: u64,
    pub seq: u16,
    pub parent: u64,
    pub parent_seq: u16,
    pub name: String,
    /// Name and folder before a rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<(String, u64, u16)>,
    pub reasons: u32,
    pub attributes: u32,
}

/// Groups records into changes as they come, oldest first.
#[derive(Default)]
pub struct Grouper {
    open: HashMap<(u64, u16), Change>,
    pub done: Vec<Change>,
    pub records: u64,
    pub first: u64,
    pub last: u64,
    /// Folder names seen in the journal: (record, seq) -> (name, parent).
    pub folders: HashMap<(u64, u16), (String, (u64, u16))>,
}

impl Grouper {
    pub fn push(&mut self, r: UsnRecord) {
        self.records += 1;
        if self.first == 0 || r.time < self.first {
            self.first = r.time;
        }
        self.last = self.last.max(r.time);
        if r.attributes & 0x10 != 0 && r.reason & RENAME_OLD_NAME == 0 {
            self.folders.insert(r.file, (r.name.clone(), r.parent));
        }
        let c = self.open.entry(r.file).or_insert_with(|| Change { first: r.time, record: r.file.0, seq: r.file.1, ..Default::default() });
        if r.reason & RENAME_OLD_NAME != 0 && c.old.is_none() {
            c.old = Some((r.name.clone(), r.parent.0, r.parent.1));
        }
        c.t = r.time;
        c.usn = r.usn;
        c.name = r.name;
        c.parent = r.parent.0;
        c.parent_seq = r.parent.1;
        c.reasons |= r.reason & !CLOSE;
        c.attributes = r.attributes;
        if r.reason & CLOSE != 0 {
            let mut c = self.open.remove(&r.file).unwrap_or_default();
            if c.first == c.t {
                c.first = 0;
            }
            self.done.push(c);
        }
    }

    /// Changes not yet closed when the journal ends are kept as they are.
    pub fn finish(mut self) -> (Vec<Change>, HashMap<(u64, u16), (String, (u64, u16))>) {
        let mut rest: Vec<Change> = self.open.into_values().collect();
        rest.sort_by_key(|c| c.usn);
        for mut c in rest {
            if c.first == c.t {
                c.first = 0;
            }
            self.done.push(c);
        }
        (self.done, self.folders)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const T: u64 = 134_000_000_000_000_000;

    /// A version 2 record as Windows writes it.
    pub fn v2(usn: u64, file: (u64, u16), parent: (u64, u16), t: u64, reason: u32, attrs: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let len = (0x3C + units.len() * 2 + 7) & !7;
        let mut d = vec![0u8; len];
        d[0..4].copy_from_slice(&(len as u32).to_le_bytes());
        d[4..6].copy_from_slice(&2u16.to_le_bytes());
        d[8..16].copy_from_slice(&(file.0 | (file.1 as u64) << 48).to_le_bytes());
        d[16..24].copy_from_slice(&(parent.0 | (parent.1 as u64) << 48).to_le_bytes());
        d[24..32].copy_from_slice(&usn.to_le_bytes());
        d[32..40].copy_from_slice(&t.to_le_bytes());
        d[40..44].copy_from_slice(&reason.to_le_bytes());
        d[52..56].copy_from_slice(&attrs.to_le_bytes());
        d[56..58].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
        d[58..60].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, u) in units.iter().enumerate() {
            d[0x3C + i * 2..0x3E + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        d
    }

    #[test]
    fn records_and_changes() {
        let dir = (40, 2);
        let s = 10_000_000;
        let mut j = vec![0u8; 64]; // sparse start
        j.extend(v2(100, (50, 1), dir, T, FILE_CREATE, 0x20, "New Text Document.txt"));
        j.extend(v2(200, (50, 1), dir, T, FILE_CREATE | DATA_EXTEND, 0x20, "New Text Document.txt"));
        j.extend(v2(300, (50, 1), dir, T + s, FILE_CREATE | DATA_EXTEND | CLOSE, 0x20, "New Text Document.txt"));
        j.extend(v2(400, (50, 1), dir, T + 2 * s, RENAME_OLD_NAME, 0x20, "New Text Document.txt"));
        j.extend(v2(500, (50, 1), dir, T + 2 * s, RENAME_NEW_NAME, 0x20, "plan.txt"));
        j.extend(v2(600, (50, 1), dir, T + 2 * s, RENAME_NEW_NAME | CLOSE, 0x20, "plan.txt"));
        j.extend(vec![0u8; 24]); // page padding
        j.extend(v2(700, (51, 4), dir, T + 3 * s, FILE_CREATE | CLOSE, 0x10, "Secret"));
        j.extend(v2(800, (50, 1), dir, T + 4 * s, FILE_DELETE | CLOSE, 0x20, "plan.txt"));
        // V3 record with 128-bit IDs
        let mut v3 = vec![0u8; 0x58];
        v3[0..4].copy_from_slice(&0x58u32.to_le_bytes());
        v3[4..6].copy_from_slice(&3u16.to_le_bytes());
        v3[8..16].copy_from_slice(&(52u64 | 1 << 48).to_le_bytes());
        v3[24..32].copy_from_slice(&(51u64 | 4 << 48).to_le_bytes());
        v3[40..48].copy_from_slice(&900u64.to_le_bytes());
        v3[48..56].copy_from_slice(&(T + 5 * s).to_le_bytes());
        v3[56..60].copy_from_slice(&(FILE_CREATE | CLOSE).to_le_bytes());
        v3[72..74].copy_from_slice(&6u16.to_le_bytes());
        v3[74..76].copy_from_slice(&0x4Cu16.to_le_bytes());
        for (i, u) in "a.7z".encode_utf16().take(3).enumerate() {
            v3[0x4C + i * 2..0x4E + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        j.extend(v3);
        let cut = v2(1000, (53, 1), dir, T, FILE_CREATE, 0, "cut-short.txt");
        j.extend(&cut[..30]);

        let mut g = Grouper::default();
        let used = parse(&j, &mut |r| g.push(r));
        assert_eq!(used, j.len() - 30, "a record cut short is left for the next buffer");
        assert_eq!(g.records, 9);
        let (ch, folders) = g.finish();
        let got: Vec<(&str, String)> = ch.iter().map(|c| (c.name.as_str(), describe(c.reasons))).collect();
        assert_eq!(got, vec![
            ("New Text Document.txt", "created, data extended".to_string()),
            ("plan.txt", "renamed".to_string()),
            ("Secret", "created".to_string()),
            ("plan.txt", "deleted".to_string()),
            ("a.7", "created".to_string()),
        ]);
        assert_eq!((ch[0].first, ch[0].t), (T, T + s));
        assert_eq!(ch[1].old.as_ref().unwrap().0, "New Text Document.txt");
        assert_eq!((ch[4].record, ch[4].seq, ch[4].parent, ch[4].parent_seq), (52, 1, 51, 4));
        assert_eq!(folders.get(&(51, 4)).unwrap().0, "Secret");
        assert_eq!(parse_max(&[1u8; 32]).unwrap().journal_id, 0x0101_0101_0101_0101);
    }

    #[test]
    fn junk_never_panics() {
        let mut junk: Vec<u8> = (0..20000u32).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
        for i in (0..junk.len() - 8).step_by(512) {
            junk[i..i + 4].copy_from_slice(&0x60u32.to_le_bytes());
            junk[i + 4] = 2;
            junk[i + 5] = 0;
        }
        let mut n = 0;
        parse(&junk, &mut |_| n += 1);
        assert!(n < 5);
    }
}
