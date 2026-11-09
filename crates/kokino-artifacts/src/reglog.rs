//! Registry transaction logs (.LOG1, .LOG2, and .LOG on Windows XP).
//!
//! Windows writes changes to a hive's log first and to the hive later. A
//! hive whose two sequence numbers differ was not cleanly saved, and the
//! newest changes are only in its logs. Applying them in memory gives the
//! hive as Windows would have seen it; the evidence is never changed.
//!
//! Two formats:
//!
//! - Windows 8.1 and later: log entries (`HvLE`), each with a sequence
//!   number, the hive's new size, a list of dirty pages and the pages
//!   themselves, protected by two Marvin32 checksums. Entries are applied
//!   in sequence order starting at the hive's secondary sequence number,
//!   taken from both logs, and the replay stops at the first damaged or
//!   missing entry.
//! - Windows XP to 8: a `DIRT` bitmap of dirty 512-byte sectors followed by
//!   those sectors, valid when the log's base block is intact and matches
//!   the hive's primary sequence number.
//!
//! A log whose base block checksum is wrong is not used. When nothing can
//! be applied the caller keeps the hive as it is and says why.

use crate::bin::*;

const BASE: usize = 4096;
/// Hives larger than this are not grown by a log.
const MAX_HIVE: usize = 2 << 30;
const MARVIN_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    /// "new" (Windows 8.1+) or "old" (XP to 8).
    pub format: &'static str,
    /// Log entries (new format) or logs (old format) applied.
    pub applied: u32,
    /// Which logs were used, e.g. ["LOG1", "LOG2"].
    pub from: Vec<String>,
    /// Pages written into the hive.
    pub pages: u32,
    pub last_sequence: u32,
    /// Why the replay stopped early, if it did.
    pub stopped: Option<String>,
}

/// Marvin32, the checksum of new-format log entries. The registry keeps
/// the whole 64-bit state (high word first), not the usual 32-bit result.
pub fn marvin32(seed: u64, data: &[u8]) -> u64 {
    let (mut lo, mut hi) = (seed as u32, (seed >> 32) as u32);
    let block = |lo: &mut u32, hi: &mut u32| {
        *hi ^= *lo;
        *lo = lo.rotate_left(20).wrapping_add(*hi);
        *hi = hi.rotate_left(9) ^ *lo;
        *lo = lo.rotate_left(27).wrapping_add(*hi);
        *hi = hi.rotate_left(19);
    };
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        lo = lo.wrapping_add(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        block(&mut lo, &mut hi);
    }
    let r = chunks.remainder();
    let tail = match r.len() {
        0 => 0x80,
        1 => 0x8000 | r[0] as u32,
        2 => 0x80_0000 | r[0] as u32 | (r[1] as u32) << 8,
        _ => 0x8000_0000 | r[0] as u32 | (r[1] as u32) << 8 | (r[2] as u32) << 16,
    };
    lo = lo.wrapping_add(tail);
    block(&mut lo, &mut hi);
    block(&mut lo, &mut hi);
    (hi as u64) << 32 | lo as u64
}

/// The base block checksum (XOR of its first 127 dwords).
pub fn base_checksum(b: &[u8]) -> Option<u32> {
    let mut x = 0u32;
    for i in 0..127 {
        x ^= u32_at(b, 4 * i)?;
    }
    Some(match x {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        x => x,
    })
}

fn base_ok(b: &[u8]) -> bool {
    b.get(0..4) == Some(b"regf") && base_checksum(b).is_some_and(|c| u32_at(b, 508) == Some(c))
}

/// Whether the hive needs its logs (its sequence numbers differ).
pub fn dirty(hive: &[u8]) -> bool {
    u32_at(hive, 4) != u32_at(hive, 8)
}

struct Entry<'a> {
    seq: u32,
    bins: u32,
    pages: Vec<(u32, &'a [u8])>,
    log: usize,
}

/// Valid new-format entries of one log.
fn entries(log: &[u8], which: usize) -> (Vec<Entry<'_>>, Option<String>) {
    let mut out = vec![];
    let mut p = 512usize;
    while p + 40 <= log.len() && slice(log, p, 4) == Some(b"HvLE") {
        let size = u32_at(log, p + 4).unwrap_or(0) as usize;
        if size < 40 || size % 512 != 0 || p + size > log.len() {
            return (out, Some(format!("entry at offset {} has a bad size", p)));
        }
        let e = &log[p..p + size];
        let h1 = u64_at(e, 24).unwrap_or(0);
        let h2 = u64_at(e, 32).unwrap_or(0);
        if marvin32(MARVIN_SEED, &e[40..]) != h1 || marvin32(MARVIN_SEED, &e[..32]) != h2 {
            return (out, Some(format!("entry at offset {} fails its checksum", p)));
        }
        let seq = u32_at(e, 12).unwrap_or(0);
        let bins = u32_at(e, 16).unwrap_or(0);
        let n = u32_at(e, 20).unwrap_or(0) as usize;
        let mut data = 40 + 8 * n;
        let mut pages = vec![];
        for i in 0..n {
            let off = u32_at(e, 40 + 8 * i).unwrap_or(0);
            let len = u32_at(e, 44 + 8 * i).unwrap_or(0) as usize;
            let Some(bytes) = e.get(data..data.saturating_add(len)) else { return (out, Some(format!("entry at offset {} is cut off", p))) };
            pages.push((off, bytes));
            data += len;
        }
        out.push(Entry { seq, bins, pages, log: which });
        p += size;
    }
    (out, None)
}

/// Applies the logs to a copy of the hive. `Ok(None)`: the hive is clean.
pub fn recover(hive: &[u8], log1: Option<&[u8]>, log2: Option<&[u8]>) -> anyhow::Result<Option<(Vec<u8>, Recovery)>> {
    if hive.get(0..4) != Some(b"regf") || hive.len() < BASE {
        anyhow::bail!("not a registry hive");
    }
    if !dirty(hive) {
        return Ok(None);
    }
    let seq1 = u32_at(hive, 4).unwrap_or(0);
    let seq2 = u32_at(hive, 8).unwrap_or(0);
    let logs: Vec<(usize, &[u8])> = [log1, log2].iter().enumerate().filter_map(|(i, l)| l.filter(|l| l.len() >= 512).map(|l| (i, l))).collect();
    if logs.is_empty() {
        anyhow::bail!("the hive was not cleanly saved and its .LOG1/.LOG2 files are missing or empty");
    }
    let name = |i: usize| format!("LOG{}", i + 1);
    let mut problems = vec![];
    // New format.
    let mut all: Vec<Entry> = vec![];
    let mut new_format = false;
    for (i, l) in &logs {
        if slice(l, 512, 4) == Some(b"HvLE") {
            new_format = true;
            if !base_ok(l) {
                problems.push(format!("{}: base block damaged", name(*i)));
                continue;
            }
            let (es, problem) = entries(l, *i);
            if let Some(pr) = problem {
                problems.push(format!("{}: {}", name(*i), pr));
            }
            all.extend(es);
        }
    }
    if new_format {
        let mut data = hive.to_vec();
        let mut r = Recovery { format: "new", ..Default::default() };
        let mut want = seq2;
        loop {
            // The same sequence number in both logs: the later log wins.
            let Some(e) = all.iter().filter(|e| e.seq == want).max_by_key(|e| e.log) else { break };
            let size = BASE + e.bins as usize;
            if size > MAX_HIVE {
                problems.push(format!("entry {} would grow the hive to {} bytes", want, size));
                break;
            }
            data.resize(size, 0);
            for (off, bytes) in &e.pages {
                let at = BASE + *off as usize;
                if let Some(dst) = data.get_mut(at..at + bytes.len()) {
                    dst.copy_from_slice(bytes);
                    r.pages += 1;
                }
            }
            r.applied += 1;
            r.last_sequence = want;
            let l = name(e.log);
            if !r.from.contains(&l) {
                r.from.push(l);
            }
            want = want.wrapping_add(1);
            // The base block of the log the entry came from: root cell and size.
            if let Some((_, lb)) = logs.iter().find(|(i, _)| *i == e.log) {
                data[36..40].copy_from_slice(&lb[36..40]);
            }
            data[40..44].copy_from_slice(&e.bins.to_le_bytes());
        }
        if r.applied == 0 {
            anyhow::bail!("no usable log entry (the hive needs entries from sequence number {}){}", seq2, if problems.is_empty() { String::new() } else { format!(": {}", problems.join("; ")) });
        }
        if !problems.is_empty() {
            r.stopped = Some(problems.join("; "));
        }
        let next = r.last_sequence.wrapping_add(1);
        data[4..8].copy_from_slice(&next.to_le_bytes());
        data[8..12].copy_from_slice(&next.to_le_bytes());
        return Ok(Some((data, r)));
    }
    // Old format: one log holds the dirty sectors.
    for (i, l) in &logs {
        if slice(l, 512, 4) != Some(b"DIRT") {
            problems.push(format!("{}: not a log Kokino knows", name(*i)));
            continue;
        }
        if !base_ok(l) {
            problems.push(format!("{}: base block damaged", name(*i)));
            continue;
        }
        let (ls1, ls2) = (u32_at(l, 4).unwrap_or(0), u32_at(l, 8).unwrap_or(1));
        if ls1 != ls2 || ls1 != seq1 {
            problems.push(format!("{}: written for another state of the hive (log {}/{}, hive {}/{})", name(*i), ls1, ls2, seq1, seq2));
            continue;
        }
        let length = u32_at(l, 40).unwrap_or(0) as usize;
        if length == 0 || BASE + length > MAX_HIVE {
            problems.push(format!("{}: bad hive size", name(*i)));
            continue;
        }
        let sectors = length / 512;
        let bitmap = &l.get(516..516 + sectors.div_ceil(8)).unwrap_or(&[]);
        if bitmap.len() < sectors.div_ceil(8) {
            problems.push(format!("{}: dirty map cut off", name(*i)));
            continue;
        }
        let mut src = (516 + bitmap.len()).div_ceil(512) * 512;
        let mut data = hive.to_vec();
        data.resize(BASE + length, 0);
        let mut r = Recovery { format: "old", from: vec![name(*i)], ..Default::default() };
        let mut ok = true;
        for s in 0..sectors {
            if bitmap[s / 8] >> (s % 8) & 1 == 0 {
                continue;
            }
            let Some(sec) = l.get(src..src + 512) else {
                ok = false;
                break;
            };
            data[BASE + s * 512..BASE + s * 512 + 512].copy_from_slice(sec);
            r.pages += 1;
            src += 512;
        }
        if !ok {
            problems.push(format!("{}: dirty sectors cut off", name(*i)));
            continue;
        }
        data[36..40].copy_from_slice(&l[36..40]);
        data[40..44].copy_from_slice(&(length as u32).to_le_bytes());
        data[8..12].copy_from_slice(&seq1.to_le_bytes());
        r.applied = 1;
        r.last_sequence = seq1;
        return Ok(Some((data, r)));
    }
    anyhow::bail!("no usable log: {}", problems.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_block(seq1: u32, seq2: u32, length: u32, ftype: u32) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..4].copy_from_slice(b"regf");
        b[4..8].copy_from_slice(&seq1.to_le_bytes());
        b[8..12].copy_from_slice(&seq2.to_le_bytes());
        b[28..32].copy_from_slice(&ftype.to_le_bytes());
        b[36..40].copy_from_slice(&32u32.to_le_bytes());
        b[40..44].copy_from_slice(&length.to_le_bytes());
        let c = base_checksum(&b).unwrap();
        b[508..512].copy_from_slice(&c.to_le_bytes());
        b
    }

    fn entry(seq: u32, bins: u32, pages: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![];
        for (off, d) in pages {
            body.extend_from_slice(&off.to_le_bytes());
            body.extend_from_slice(&(d.len() as u32).to_le_bytes());
        }
        for (_, d) in pages {
            body.extend_from_slice(d);
        }
        let size = (40 + body.len()).div_ceil(512) * 512;
        let mut e = vec![0u8; size];
        e[0..4].copy_from_slice(b"HvLE");
        e[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        e[12..16].copy_from_slice(&seq.to_le_bytes());
        e[16..20].copy_from_slice(&bins.to_le_bytes());
        e[20..24].copy_from_slice(&(pages.len() as u32).to_le_bytes());
        e[40..40 + body.len()].copy_from_slice(&body);
        let h1 = marvin32(MARVIN_SEED, &e[40..]);
        e[24..32].copy_from_slice(&h1.to_le_bytes());
        let h2 = marvin32(MARVIN_SEED, &e[..32]);
        e[32..40].copy_from_slice(&h2.to_le_bytes());
        e
    }

    #[test]
    fn new_format_entries_in_order_across_logs() {
        let mut hive = base_block(3, 2, 4096, 0);
        hive.resize(BASE + 4096, 0);
        let log1 = [base_block(2, 2, 4096, 6), entry(2, 4096, &[(0, vec![0xA1; 4096])])].concat();
        let log2 = [base_block(3, 3, 8192, 6), entry(3, 8192, &[(4096, vec![0xB2; 512])]), entry(4, 8192, &[(512, vec![0xC3; 512])])].concat();
        let (d, r) = recover(&hive, Some(&log1), Some(&log2)).unwrap().unwrap();
        assert_eq!((r.applied, r.last_sequence, r.from.clone(), r.pages), (3, 4, vec!["LOG1".to_string(), "LOG2".to_string()], 3));
        assert_eq!(d.len(), BASE + 8192);
        assert_eq!((d[BASE], d[BASE + 512], d[BASE + 4096]), (0xA1, 0xC3, 0xB2));
        assert_eq!((u32_at(&d, 4), u32_at(&d, 8)), (Some(5), Some(5)));
        // Starting later: LOG1's older entry is not used.
        let mut h2 = hive.clone();
        h2[4..8].copy_from_slice(&4u32.to_le_bytes());
        h2[8..12].copy_from_slice(&3u32.to_le_bytes());
        let (_, r) = recover(&h2, Some(&log1), Some(&log2)).unwrap().unwrap();
        assert_eq!((r.applied, r.from.clone()), (2, vec!["LOG2".to_string()]));
        // A damaged entry stops the replay; one that is needed first fails it.
        let mut bad = log1.clone();
        bad[512 + 100] ^= 1;
        assert!(recover(&hive, Some(&bad), Some(&log2)).is_err());
        let mut bad2 = log2.clone();
        let second = 512 + entry(3, 8192, &[(4096, vec![0xB2; 512])]).len();
        bad2[second + 60] ^= 1;
        let (_, r) = recover(&hive, Some(&log1), Some(&bad2)).unwrap().unwrap();
        assert_eq!(r.applied, 2);
        assert!(r.stopped.unwrap().contains("checksum"));
        // A clean hive needs nothing.
        assert!(recover(&base_block(7, 7, 0, 0).into_iter().chain(vec![0u8; 4096 - 512]).collect::<Vec<_>>(), None, None).unwrap().is_none());
    }

    #[test]
    fn old_format_dirty_sectors() {
        let mut hive = base_block(5, 4, 2048, 0);
        hive.resize(BASE + 2048, 0x11);
        let mut log = base_block(5, 5, 2048, 1);
        log.extend_from_slice(b"DIRT");
        log.push(0b0000_0101); // sectors 0 and 2
        log.resize(1024, 0);
        log.extend(vec![0x22; 512]);
        log.extend(vec![0x33; 512]);
        let (d, r) = recover(&hive, Some(&log), None).unwrap().unwrap();
        assert_eq!((r.format, r.pages), ("old", 2));
        assert_eq!((d[BASE], d[BASE + 512], d[BASE + 1024], d[BASE + 1536]), (0x22, 0x11, 0x33, 0x11));
        // Written for another state of the hive: not used.
        let mut other = log.clone();
        other[4..8].copy_from_slice(&9u32.to_le_bytes());
        other[8..12].copy_from_slice(&9u32.to_le_bytes());
        let c = base_checksum(&other).unwrap();
        other[508..512].copy_from_slice(&c.to_le_bytes());
        assert!(recover(&hive, Some(&other), None).is_err());
        assert!(recover(&hive, None, None).is_err());
    }
}
