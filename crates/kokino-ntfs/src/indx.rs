//! Names left in NTFS folder indexes ($I30).
//!
//! A folder lists its children in a B+ tree of index entries, each holding a
//! copy of the child's $FILE_NAME (name, parent, four timestamps, sizes).
//! Large folders keep the tree in INDX records in $INDEX_ALLOCATION. When an
//! entry is removed (file deleted, renamed or moved, or the tree rebalanced)
//! the entries after it move up and the record's used size shrinks, but the
//! bytes past the used size are not cleared: that slack keeps old entries
//! until the space is written again. They often outlive the file's MFT
//! record, which Windows reuses quickly.
//!
//! Entries in slack can be cut short or partly overwritten, so they are
//! found by their $FILE_NAME alone, with strict checks: the parent reference
//! must be the folder itself (record and sequence number), all four
//! timestamps plausible and the name valid. The index entry header in front
//! (which holds the child's own MFT reference) is used only when it lies in
//! the slack as well.
//!
//! $LogFile, the NTFS transaction log, records every change to a folder
//! index with the entry itself, so names of files created and deleted
//! since the log last wrapped are there too; it is searched the same way,
//! for $FILE_NAMEs whose parent is a known folder.

use crate::Times;

/// One name recovered from an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexName {
    /// MFT reference of the child (record, sequence number), when the index
    /// entry header survived.
    pub file: Option<(u64, u16)>,
    pub name: String,
    /// $FILE_NAME namespace: 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS.
    pub namespace: u8,
    pub times: Times,
    pub alloc_size: u64,
    pub size: u64,
    /// File attribute flags from the $FILE_NAME (0x10000000 is a folder).
    pub flags: u32,
    /// Offset of the index entry (or of the $FILE_NAME when the header is
    /// not trusted) in the scanned buffer.
    pub offset: usize,
    /// The folder the $FILE_NAME names as parent.
    pub parent: (u64, u16),
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Slack of a folder's INDX record.
    Slack,
    /// Used part of a deleted folder's index.
    DeletedFolder,
    LogFile,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Slack => "$I30 slack",
            Source::DeletedFolder => "$I30 of a deleted folder",
            Source::LogFile => "$LogFile",
        }
    }
}

impl IndexName {
    pub fn is_dir(&self) -> bool {
        self.flags & 0x1000_0000 != 0
    }
}

/// FILETIMEs from 1980 to about 2100.
const T_MIN: u64 = 119_600_064_000_000_000;
const T_MAX: u64 = 159_000_000_000_000_000;

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

fn split_ref(v: u64) -> (u64, u16) {
    (v & 0xFFFF_FFFF_FFFF, (v >> 48) as u16)
}

/// Applies the update sequence fixups of one INDX record (or $LogFile page,
/// `sig`) in place: the last two bytes of every 512-byte sector were
/// swapped for a check value when the record was written. Returns the
/// record size, or None when `rec` does not start with a usable record.
pub fn fixup(rec: &mut [u8], sig: &[u8; 4]) -> Option<usize> {
    if rec.get(..4)? != sig {
        return None;
    }
    let usa = u16_at(rec, 4)? as usize;
    let count = u16_at(rec, 6)? as usize;
    if count < 2 || count > 129 {
        return None;
    }
    let size = (count - 1) * 512;
    if size > rec.len() || usa + count * 2 > size {
        return None;
    }
    for i in 1..count {
        let at = i * 512 - 2;
        let (a, b) = (rec[usa + i * 2], rec[usa + i * 2 + 1]);
        rec[at] = a;
        rec[at + 1] = b;
    }
    Some(size)
}

/// Every $FILE_NAME between `from` and `to` in `d` whose parent passes
/// `parent_ok`. Index entry headers before `trust` are not read (they may
/// belong to the entry that overwrote this one).
pub fn carve_names(d: &[u8], from: usize, to: usize, trust: usize, parent_ok: &dyn Fn((u64, u16)) -> bool, source: Source, out: &mut Vec<IndexName>) {
    let to = to.min(d.len());
    let mut p = (from + 7) & !7;
    while p + 66 <= to {
        let Some(name) = file_name_at(d, p, to, parent_ok) else {
            p += 8;
            continue;
        };
        let (parent, n, ns, times, alloc, size, flags) = name;
        let file = if p >= 16 && p - 16 >= trust {
            let (rec, seq) = split_ref(u64_at(d, p - 16).unwrap_or(0));
            let len = u16_at(d, p - 8).unwrap_or(0) as usize;
            let klen = u16_at(d, p - 6).unwrap_or(0) as usize;
            // An index entry's lengths cover at least this $FILE_NAME.
            (rec != 0 && len >= 16 + klen && klen >= 66 + 2 * n.encode_utf16().count() && len <= 4096).then_some((rec, seq))
        } else {
            None
        };
        let offset = if file.is_some() { p - 16 } else { p };
        out.push(IndexName { file, name: n, namespace: ns, times, alloc_size: alloc, size, flags, offset, parent, source });
        let used = 66 + 2 * d[p + 64] as usize;
        p += (used + 7) & !7;
    }
}

type Parsed = ((u64, u16), String, u8, Times, u64, u64, u32);

fn file_name_at(d: &[u8], p: usize, end: usize, parent_ok: &dyn Fn((u64, u16)) -> bool) -> Option<Parsed> {
    let parent = split_ref(u64_at(d, p)?);
    if !parent_ok(parent) {
        return None;
    }
    let t = |o| u64_at(d, p + o).unwrap_or(0);
    let times = Times { created: t(8), modified: t(16), mft_modified: t(24), accessed: t(32) };
    if ![times.created, times.modified, times.mft_modified, times.accessed].iter().all(|x| (T_MIN..T_MAX).contains(x)) {
        return None;
    }
    let (alloc, size) = (t(40), t(48));
    if size > 1 << 48 || alloc > 1 << 48 {
        return None;
    }
    let flags = u32_at(d, p + 56)?;
    let len = d[p + 64] as usize;
    let ns = d[p + 65];
    if len == 0 || ns > 3 || p + 66 + len * 2 > end {
        return None;
    }
    let units: Vec<u16> = (0..len).map(|i| u16_at(d, p + 66 + i * 2).unwrap_or(0)).collect();
    let name = String::from_utf16(&units).ok()?;
    if name == "." || name == ".." || name.chars().any(|c| c < ' ' || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\u{FFFD}' | '\u{FFFF}')) {
        return None;
    }
    Some((parent, name, ns, times, alloc, size, flags))
}

/// Names in a folder's $INDEX_ALLOCATION bytes: the slack of every INDX
/// record, and for a deleted folder (`whole`) its used entries too.
pub fn scan_allocation(data: &mut [u8], dir: (u64, u16), whole: bool) -> Vec<IndexName> {
    let mut out = vec![];
    let mut p = 0;
    while p + 512 <= data.len() {
        let Some(size) = fixup(&mut data[p..], b"INDX") else {
            p += 512;
            continue;
        };
        let rec = &data[p..p + size];
        let hdr = 0x18;
        let first = hdr + u32_at(rec, hdr).unwrap_or(0) as usize;
        let used = hdr + u32_at(rec, hdr + 4).unwrap_or(0) as usize;
        let alloc = (hdr + u32_at(rec, hdr + 8).unwrap_or(0) as usize).min(size);
        if first < 0x28 || first > used || used > alloc {
            p += 512;
            continue;
        }
        let mut found = vec![];
        let is_dir = |x| x == dir;
        if whole {
            carve_names(rec, first, used, first, &is_dir, Source::DeletedFolder, &mut found);
        }
        carve_names(rec, used, alloc, used, &is_dir, Source::Slack, &mut found);
        for mut f in found {
            f.offset += p;
            out.push(f);
        }
        p += size;
    }
    out
}

/// Names in a deleted folder's $INDEX_ROOT value (small folders keep their
/// whole index in the MFT record).
pub fn scan_root(value: &[u8], dir: (u64, u16)) -> Vec<IndexName> {
    let mut out = vec![];
    let hdr = 0x10;
    let first = hdr + u32_at(value, hdr).unwrap_or(0) as usize;
    let alloc = hdr + u32_at(value, hdr + 8).unwrap_or(0) as usize;
    if first >= 0x20 {
        carve_names(value, first, alloc.min(value.len()), first, &|x| x == dir, Source::DeletedFolder, &mut out);
    }
    out
}

/// Names in $LogFile: every log record page (RCRD) after its fixups,
/// searched for $FILE_NAMEs whose parent passes `parent_ok`. A name split
/// over two pages is missed.
pub fn scan_logfile(data: &mut [u8], parent_ok: &dyn Fn((u64, u16)) -> bool) -> Vec<IndexName> {
    let mut out = vec![];
    let mut p = 0;
    while p + 512 <= data.len() {
        let Some(size) = fixup(&mut data[p..], b"RCRD") else {
            p += 512;
            continue;
        };
        let mut found = vec![];
        carve_names(&data[p..p + size], 0x40, size, 0x40, parent_ok, Source::LogFile, &mut found);
        for mut f in found {
            f.offset += p;
            out.push(f);
        }
        p += size;
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const T: u64 = 134_000_000_000_000_000; // 2025

    /// An index entry for `name` under folder `dir`, pointing at `file`.
    pub fn entry(file: (u64, u16), dir: (u64, u16), name: &str, size: u64) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let klen = 66 + units.len() * 2;
        let len = (16 + klen + 7) & !7;
        let mut e = vec![0u8; len];
        e[0..8].copy_from_slice(&(file.0 | (file.1 as u64) << 48).to_le_bytes());
        e[8..10].copy_from_slice(&(len as u16).to_le_bytes());
        e[10..12].copy_from_slice(&(klen as u16).to_le_bytes());
        let f = &mut e[16..];
        f[0..8].copy_from_slice(&(dir.0 | (dir.1 as u64) << 48).to_le_bytes());
        for i in 0..4 {
            f[8 + i * 8..16 + i * 8].copy_from_slice(&(T + i as u64 * 10_000_000).to_le_bytes());
        }
        f[40..48].copy_from_slice(&((size + 4095) & !4095).to_le_bytes());
        f[48..56].copy_from_slice(&size.to_le_bytes());
        f[56..60].copy_from_slice(&0x20u32.to_le_bytes());
        f[64] = units.len() as u8;
        f[65] = 1;
        for (i, u) in units.iter().enumerate() {
            f[66 + i * 2..68 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    /// A 4 KiB INDX record holding `live` entries, with `stale` entries left
    /// after the used size, fixups applied as Windows writes them.
    pub fn indx(live: &[Vec<u8>], stale: &[Vec<u8>]) -> Vec<u8> {
        let mut r = vec![0u8; 4096];
        r[0..4].copy_from_slice(b"INDX");
        r[4..6].copy_from_slice(&0x28u16.to_le_bytes());
        r[6..8].copy_from_slice(&9u16.to_le_bytes());
        let first = 0x40usize;
        let mut p = first;
        for e in live {
            r[p..p + e.len()].copy_from_slice(e);
            p += e.len();
        }
        // end-of-node entry
        r[p + 8..p + 10].copy_from_slice(&16u16.to_le_bytes());
        r[p + 12] = 2;
        p += 16;
        let used = p;
        for e in stale {
            r[p..p + e.len()].copy_from_slice(e);
            p += e.len();
        }
        r[0x18..0x1C].copy_from_slice(&((first - 0x18) as u32).to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&((used - 0x18) as u32).to_le_bytes());
        r[0x20..0x24].copy_from_slice(&((4096 - 0x18) as u32).to_le_bytes());
        r[0x28..0x2A].copy_from_slice(&7u16.to_le_bytes());
        for i in 1..9 {
            let at = i * 512 - 2;
            let (a, b) = (r[at], r[at + 1]);
            r[0x28 + i * 2] = a;
            r[0x29 + i * 2] = b;
            r[at] = 7;
            r[at + 1] = 0;
        }
        r
    }

    #[test]
    fn slack_names() {
        let dir = (40, 3);
        let live = vec![entry((41, 1), dir, "keep.txt", 10)];
        let stale = vec![entry((42, 1), dir, "gone report.docx", 20_000), entry((43, 2), (99, 1), "other folder.txt", 5), entry((44, 1), dir, "second.bin", 7)];
        let mut d = indx(&live, &stale);
        d.extend(vec![0u8; 512]);
        let names = scan_allocation(&mut d, dir, false);
        let got: Vec<(&str, Option<(u64, u16)>, u64)> = names.iter().map(|n| (n.name.as_str(), n.file, n.size)).collect();
        assert_eq!(got, vec![("gone report.docx", Some((42, 1)), 20_000), ("second.bin", Some((44, 1)), 7)]);
        assert!(names.iter().all(|n| n.source == Source::Slack && n.parent == dir && n.times.created == T && n.times.accessed == T + 30_000_000));
        // A deleted folder: its used entries count too.
        let mut d = indx(&live, &stale);
        let names = scan_allocation(&mut d, dir, true);
        assert_eq!(names.len(), 3);
        assert!(names[0].source == Source::DeletedFolder && names[0].name == "keep.txt");
    }

    #[test]
    fn overwritten_header_and_junk() {
        let dir = (40, 3);
        let mut e = entry((42, 1), dir, "half.txt", 1);
        // The slack begins inside this entry: its header is not trusted.
        let mut d = vec![0xAAu8; 8];
        d.append(&mut e);
        let mut out = vec![];
        carve_names(&d, 8 + 16, d.len(), 8 + 16, &|x| x == dir, Source::Slack, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].file, out[0].name.as_str(), out[0].offset), (None, "half.txt", 24));
        // Bad times, bad names and truncation are refused.
        for bad in [0usize, 1, 2] {
            let mut e = entry((42, 1), dir, "x:y", 1);
            if bad == 1 {
                e = entry((42, 1), dir, "ok", 1);
                e[16 + 8..16 + 16].copy_from_slice(&5u64.to_le_bytes());
            }
            if bad == 2 {
                e = entry((42, 1), dir, "a-long-name.txt", 1);
                e.truncate(16 + 70);
            }
            let mut out = vec![];
            carve_names(&e, 0, e.len(), 0, &|x| x == dir, Source::Slack, &mut out);
            assert!(out.is_empty(), "case {}", bad);
        }
        // Fuzz-style input never panics.
        let mut junk: Vec<u8> = (0..9000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        junk[0..4].copy_from_slice(b"INDX");
        let _ = scan_allocation(&mut junk, dir, true);
        let _ = scan_root(&junk, dir);
        junk[0..4].copy_from_slice(b"RCRD");
        let _ = scan_logfile(&mut junk, &|_| true);
    }

    #[test]
    fn logfile_names() {
        // A log page with an index entry in a redo record.
        let dir = (5, 5);
        let mut page = vec![0u8; 4096];
        page[0..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&0x28u16.to_le_bytes());
        page[6..8].copy_from_slice(&9u16.to_le_bytes());
        let e = entry((65, 1), dir, "Albireo.txt", 1024);
        page[0x100..0x100 + e.len()].copy_from_slice(&e);
        page[0x28..0x2A].copy_from_slice(&3u16.to_le_bytes());
        for i in 1..9 {
            let at = i * 512 - 2;
            page[0x28 + i * 2] = page[at];
            page[0x29 + i * 2] = page[at + 1];
            page[at] = 3;
            page[at + 1] = 0;
        }
        let known = |x: (u64, u16)| x == dir;
        let names = scan_logfile(&mut page, &known);
        assert_eq!(names.len(), 1);
        assert_eq!((names[0].name.as_str(), names[0].file, names[0].source, names[0].offset), ("Albireo.txt", Some((65, 1)), Source::LogFile, 0x100));
    }
}
