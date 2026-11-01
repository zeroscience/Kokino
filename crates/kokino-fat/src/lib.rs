//! FAT12, FAT16, FAT32 and exFAT reader.
//!
//! Walks the whole directory tree, live and deleted entries alike, and
//! returns the same `FsEntry` records as the NTFS walker so every view
//! (explorer, timeline, search, carving, artifacts) works unchanged.
//!
//! Deleted files: FAT clears the cluster chain on delete (and replaces the
//! first character of the short name with 0xE5), so content is recovered on
//! the standard assumption that the file's clusters were contiguous. When
//! any of those clusters is in use again, the entry says so: the content may
//! belong to another file. Long file names of deleted files are kept when
//! their checksum still matches the short entry.
//!
//! Times: FAT stores local time with no time zone; they are shown as
//! stored. exFAT stores a UTC offset, which is applied when present.

#![forbid(unsafe_code)]

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

/// Root directory record id; real entries start at FIRST_RECORD so the
/// analysis never mistakes them for NTFS metadata files.
pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
/// `attributes` bit set when a stream is read as contiguous clusters (exFAT
/// NoFatChain, or a deleted file whose chain is gone).
pub const CONTIGUOUS: u32 = 1 << 31;
const MAX_ENTRIES: usize = 5_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Fat12 => "FAT12",
            Kind::Fat16 => "FAT16",
            Kind::Fat32 => "FAT32",
            Kind::ExFat => "exFAT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FatVolume {
    pub kind: Kind,
    pub sector: u64,
    pub cluster: u64,
    pub fat_offset: u64,
    pub fat_bytes: u64,
    pub data_offset: u64,
    pub clusters: u64,
    /// FAT12/16: fixed root directory region (offset, bytes).
    pub root_region: Option<(u64, u64)>,
    pub root_cluster: u64,
    pub size: u64,
    pub serial: String,
    pub label: String,
    pub dirty: bool,
    /// The first FAT, decoded: next cluster per cluster number.
    pub fat: Vec<u32>,
    /// exFAT allocation bitmap (bit per cluster from 2); FAT uses `fat`.
    bitmap: Option<Vec<u8>>,
}

/// Up to `n` bytes at `off`; fewer at the end. Memory grows with the bytes
/// actually read, not with `n` (which often comes from the boot sector).
fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = Vec::with_capacity(n.min(1 << 20));
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}
fn u16_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
fn u32_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<FatVolume> {
    let b = rd(r, 0, 512)?;
    if b.len() < 512 {
        anyhow::bail!("volume too small");
    }
    if &b[3..11] == b"EXFAT   " {
        return open_exfat(r, &b, size);
    }
    let bps = u16_at(&b, 11);
    let spc = b[13] as u64;
    let rsvd = u16_at(&b, 14);
    let nfats = b[16] as u64;
    let root_ents = u16_at(&b, 17);
    let tot = if u16_at(&b, 19) != 0 { u16_at(&b, 19) } else { u32_at(&b, 32) };
    let fatsz = if u16_at(&b, 22) != 0 { u16_at(&b, 22) } else { u32_at(&b, 36) };
    if !(bps == 512 || bps == 1024 || bps == 2048 || bps == 4096) || spc == 0 || !spc.is_power_of_two() || nfats == 0 || fatsz == 0 || rsvd == 0 {
        anyhow::bail!("not a FAT boot sector");
    }
    let root_secs = (root_ents * 32).div_ceil(bps);
    let data_sec = rsvd + nfats * fatsz + root_secs;
    let clusters = tot.saturating_sub(data_sec) / spc;
    // FAT32 is told by its boot sector layout (no 16-bit FAT size, no fixed
    // root directory), as Linux and most tools do; FAT12 versus FAT16 by the
    // cluster count (Microsoft's rule).
    let kind = if u16_at(&b, 22) == 0 && root_ents == 0 {
        Kind::Fat32
    } else if clusters < 4085 {
        Kind::Fat12
    } else {
        Kind::Fat16
    };
    let (serial_off, label_off) = if kind == Kind::Fat32 { (67, 71) } else { (39, 43) };
    let serial = u32_at(&b, serial_off);
    let mut v = FatVolume {
        kind,
        sector: bps,
        cluster: bps * spc,
        fat_offset: rsvd * bps,
        fat_bytes: fatsz * bps,
        data_offset: data_sec * bps,
        clusters,
        root_region: (kind != Kind::Fat32).then_some(((rsvd + nfats * fatsz) * bps, root_secs * bps)),
        root_cluster: if kind == Kind::Fat32 { u32_at(&b, 44) } else { 0 },
        size: (tot * bps).min(size.max(tot * bps)),
        serial: format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF),
        label: String::from_utf8_lossy(&b[label_off..label_off + 11]).trim().to_string(),
        dirty: false,
        fat: vec![],
        bitmap: None,
    };
    let raw = rd(r, v.fat_offset, v.fat_bytes.min(512 << 20) as usize)?;
    // No more clusters than the FAT read from the image describes: the
    // header's sector count alone could claim billions.
    let entries = match kind {
        Kind::Fat12 => raw.len() * 2 / 3,
        Kind::Fat16 => raw.len() / 2,
        _ => raw.len() / 4,
    };
    v.clusters = clusters.min(entries.saturating_sub(2) as u64);
    let n = (v.clusters + 2) as usize;
    v.fat = (0..n)
        .map(|c| match kind {
            Kind::Fat12 => {
                let o = c + c / 2;
                let w = u16_at(&raw, o) as u32;
                if c % 2 == 0 { w & 0xFFF } else { w >> 4 }
            }
            Kind::Fat16 => u16_at(&raw, 2 * c) as u32,
            _ => u32_at(&raw, 4 * c) as u32 & 0x0FFF_FFFF,
        })
        .collect();
    // Clean-shutdown bit in FAT[1] (FAT16 bit 15, FAT32 bit 27): cleared = dirty.
    v.dirty = match kind {
        Kind::Fat16 => u16_at(&raw, 2) & 0x8000 == 0,
        Kind::Fat32 => u32_at(&raw, 4) & 0x0800_0000 == 0,
        _ => false,
    };
    Ok(v)
}

fn open_exfat<R: Read + Seek>(r: &mut R, b: &[u8], size: u64) -> anyhow::Result<FatVolume> {
    // The specification allows 512-byte to 4 KiB sectors and clusters up to 32 MiB.
    if !(9..=12).contains(&b[108]) || b[108] as u32 + b[109] as u32 > 25 {
        anyhow::bail!("not an exFAT boot sector (sector or cluster size out of range)");
    }
    let bps = 1u64 << b[108];
    let spc = 1u64 << b[109];
    let fat_off = u32_at(b, 80) * bps;
    let fat_len = u32_at(b, 84) * bps;
    let heap = u32_at(b, 88) * bps;
    let clusters = u32_at(b, 92);
    let serial = u32_at(b, 100);
    let mut v = FatVolume {
        kind: Kind::ExFat,
        sector: bps,
        cluster: bps * spc,
        fat_offset: fat_off,
        fat_bytes: fat_len,
        data_offset: heap,
        clusters,
        root_region: None,
        root_cluster: u32_at(b, 96),
        size: u64_at(b, 72).saturating_mul(bps).min(size.max(1)),
        serial: format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF),
        label: String::new(),
        dirty: u16_at(b, 106) & 2 != 0,
        fat: vec![],
        bitmap: None,
    };
    let raw = rd(r, fat_off, fat_len.min(512 << 20) as usize)?;
    v.clusters = clusters.min((raw.len() / 4).saturating_sub(2) as u64);
    v.fat = (0..(v.clusters + 2) as usize).map(|c| u32_at(&raw, 4 * c) as u32).collect();
    // Root directory: allocation bitmap and volume label.
    let root = v.chain_bytes(r, v.root_cluster, None, false)?;
    for e in root.chunks_exact(32) {
        match e[0] {
            0x81 if v.bitmap.is_none() => {
                let (c, len) = (u32_at(e, 20), u64_at(e, 24));
                v.bitmap = Some(v.chain_bytes(r, c, Some(len), false)?);
            }
            0x83 => {
                let n = (e[1] as usize).min(11);
                v.label = utf16(&e[2..2 + 2 * n]);
            }
            0x00 => break,
            _ => {}
        }
    }
    Ok(v)
}

fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0 && u != 0xFFFF).collect();
    String::from_utf16_lossy(&w)
}

impl FatVolume {
    fn eoc(&self, v: u32) -> bool {
        match self.kind {
            Kind::Fat12 => v >= 0xFF8,
            Kind::Fat16 => v >= 0xFFF8,
            Kind::Fat32 => v >= 0x0FFF_FFF8,
            Kind::ExFat => v >= 0xFFFF_FFF8,
        }
    }

    fn valid(&self, c: u64) -> bool {
        c >= 2 && c < self.clusters + 2
    }

    pub fn cluster_offset(&self, c: u64) -> u64 {
        self.data_offset.saturating_add(c.saturating_sub(2).saturating_mul(self.cluster))
    }

    /// exFAT only: the FAT chain from `start` has exactly the clusters a file
    /// of `size` bytes needs, ends with the end-of-chain mark, does not loop,
    /// and every cluster is free in the bitmap. Then it is the deleted file's
    /// own chain, left in place.
    fn intact_chain(&self, start: u64, size: u64) -> bool {
        if self.kind != Kind::ExFat || self.bitmap.is_none() || size == 0 || !self.valid(start) {
            return false;
        }
        let want = size.div_ceil(self.cluster);
        let mut c = start;
        let mut seen = HashSet::new();
        for i in 0..want {
            if !self.valid(c) || self.allocated(c) || !seen.insert(c) {
                return false;
            }
            let next = self.fat.get(c as usize).copied().unwrap_or(0);
            if i + 1 == want {
                return self.eoc(next);
            }
            c = next as u64;
        }
        false
    }

    /// Cluster is in use (FAT entry non-zero, or exFAT bitmap bit set).
    pub fn allocated(&self, c: u64) -> bool {
        if let Some(bm) = &self.bitmap {
            let i = (c - 2) as usize;
            return bm.get(i / 8).map(|b| b >> (i % 8) & 1 == 1).unwrap_or(true);
        }
        self.fat.get(c as usize).map(|&x| x != 0).unwrap_or(true)
    }

    /// Clusters of a stream: the FAT chain, or `n` contiguous clusters.
    pub fn clusters_of(&self, start: u64, len: Option<u64>, contiguous: bool) -> Vec<u64> {
        if !self.valid(start) {
            return vec![];
        }
        let want = len.map(|l| l.div_ceil(self.cluster).max(1));
        if contiguous {
            let n = want.unwrap_or(1).min(self.clusters + 2 - start);
            return (start..start + n).collect();
        }
        let mut out = vec![start];
        let mut seen = HashSet::from([start]);
        let mut c = start;
        loop {
            if want.map(|w| out.len() as u64 >= w).unwrap_or(false) {
                break;
            }
            let next = self.fat.get(c as usize).copied().unwrap_or(0) as u64;
            if self.eoc(next as u32) || !self.valid(next) || !seen.insert(next) {
                break;
            }
            out.push(next);
            c = next;
        }
        out
    }

    fn chain_bytes<R: Read + Seek>(&self, r: &mut R, start: u64, len: Option<u64>, contiguous: bool) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![];
        for c in self.clusters_of(start, len, contiguous) {
            out.extend(rd(r, self.cluster_offset(c), self.cluster as usize)?);
            if out.len() > 256 << 20 {
                break;
            }
        }
        if let Some(l) = len {
            out.truncate(l as usize);
        }
        Ok(out)
    }

    /// Where a file's bytes live, as volume extents (runs of contiguous clusters).
    pub fn extents(&self, e: &FsEntry) -> Vec<Extent> {
        let Some(first) = e.streams.first().and_then(|s| s.first_offset) else { return vec![] };
        if first < self.data_offset || e.size == 0 {
            return vec![];
        }
        let start = (first - self.data_offset) / self.cluster + 2;
        let cs = self.clusters_of(start, Some(e.size), e.attributes & CONTIGUOUS != 0);
        let mut out: Vec<Extent> = vec![];
        for (i, c) in cs.iter().enumerate() {
            let off = i as u64 * self.cluster;
            let vol = self.cluster_offset(*c);
            match out.last_mut() {
                Some(x) if x.vol.map(|v| v + x.len) == Some(vol) => x.len += self.cluster,
                _ => out.push(Extent { offset: off, len: self.cluster, vol: Some(vol) }),
            }
        }
        out
    }

    /// Up to `len` bytes of a file from `offset`.
    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= e.size {
            return Ok(vec![]);
        }
        let want = (len as u64).min(e.size - offset) as usize;
        let mut out = Vec::with_capacity(want);
        for x in self.extents(e) {
            if out.len() >= want {
                break;
            }
            let pos = offset + out.len() as u64;
            if pos >= x.offset + x.len || pos < x.offset {
                continue;
            }
            let within = pos - x.offset;
            let n = ((x.len - within) as usize).min(want - out.len());
            out.extend(rd(r, x.vol.unwrap() + within, n)?);
        }
        Ok(out)
    }

    /// Unallocated cluster runs: (volume byte offset, length).
    pub fn free_runs(&self) -> Vec<(u64, u64)> {
        let mut out = vec![];
        let mut start: Option<u64> = None;
        for c in 2..self.clusters + 2 {
            match (self.allocated(c), start) {
                (false, None) => start = Some(c),
                (true, Some(s)) => {
                    out.push((self.cluster_offset(s), (c - s) * self.cluster));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            out.push((self.cluster_offset(s), (self.clusters + 2 - s) * self.cluster));
        }
        out
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: self.serial.clone(),
            version: self.kind.label().into(),
            cluster_size: self.cluster as u32,
            sector_size: self.sector as u16,
            record_size: 32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: self.fat_offset,
            dirty: self.dirty,
        }
    }
}

/// FAT date/time (local, no zone) to FILETIME; 0 when unset or invalid.
fn dos_time(date: u64, time: u64, tenth: u64) -> u64 {
    if date == 0 {
        return 0;
    }
    let (y, mo, d) = (1980 + (date >> 9), (date >> 5) & 15, date & 31);
    let (h, mi, s) = (time >> 11, (time >> 5) & 63, (time & 31) * 2);
    if !(1..=12).contains(&mo) || d == 0 || h > 23 || mi > 59 || s > 59 {
        return 0;
    }
    let Some(dt) = chrono::NaiveDate::from_ymd_opt(y as i32, mo as u32, d as u32).and_then(|x| x.and_hms_opt(h as u32, mi as u32, s as u32)) else { return 0 };
    kokino_core::time::datetime_to_filetime(dt.and_utc()) + tenth.min(199) * 100_000
}

/// exFAT timestamp with 10 ms increment and UTC offset byte.
fn exfat_time(ts: u64, ms10: u64, utc: u8) -> u64 {
    let t = dos_time(ts >> 16, ts & 0xFFFF, ms10);
    if t == 0 || utc & 0x80 == 0 {
        return t;
    }
    let quarters = ((utc << 1) as i8 >> 1) as i64; // 7-bit signed, 15-minute steps
    (t as i64 - quarters * 15 * 60 * 10_000_000).max(0) as u64
}

fn lfn_checksum(short: &[u8]) -> u8 {
    short.iter().fold(0u8, |s, &c| ((s & 1) << 7).wrapping_add(s >> 1).wrapping_add(c))
}

/// 8.3 name; `case` is the NTRes byte (0x08 lowercase base, 0x10 lowercase
/// extension), which Windows uses instead of a long name for e.g. "keys.txt".
fn short_name_case(n: &[u8], deleted: bool, case: u8) -> String {
    let s = short_name(n, deleted);
    match s.split_once('.') {
        Some((b, e)) => format!("{}.{}", if case & 0x08 != 0 { b.to_lowercase() } else { b.to_string() }, if case & 0x10 != 0 { e.to_lowercase() } else { e.to_string() }),
        None => if case & 0x08 != 0 { s.to_lowercase() } else { s },
    }
}

fn short_name(n: &[u8], deleted: bool) -> String {
    let mut base: Vec<u8> = n[..8].to_vec();
    if deleted {
        base[0] = b'?';
    } else if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let to_s = |b: &[u8]| b.iter().map(|&c| if c.is_ascii() { c as char } else { char::from_u32(c as u32).unwrap_or('?') }).collect::<String>().trim_end().to_string();
    let (b, e) = (to_s(&base), to_s(&n[8..11]));
    if e.is_empty() { b } else { format!("{}.{}", b, e) }
}

/// A directory still to walk: (record, path, its clusters with offsets, deleted).
type DirWork = (u64, String, Vec<(u64, Vec<u8>)>, bool);

pub struct FatScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
}

struct Walker<'a, R: Read + Seek> {
    v: &'a FatVolume,
    r: &'a mut R,
    out: Vec<FsEntry>,
    next: u64,
    seen_dirs: HashSet<u64>,
}

/// Walks the tree from the root. `progress(done, total)` may return false.
pub fn scan<R: Read + Seek>(v: &FatVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<FatScan> {
    let root = FsEntry {
        record: ROOT_RECORD,
        seq: 0,
        parent: ROOT_RECORD,
        parent_seq: 0,
        name: ".".into(),
        dos_name: None,
        path: "/".into(),
        is_dir: true,
        deleted: false,
        orphan: false,
        size: 0,
        alloc_size: 0,
        resident: false,
        attributes: 0x10,
        hard_links: 1,
        usn: None,
        si: None,
        fname: None,
        streams: vec![],
        has_reparse: false,
        record_offset: v.root_region.map(|x| x.0).unwrap_or_else(|| v.cluster_offset(v.root_cluster.max(2))),
        error: None,
    };
    let mut w = Walker { v, r, out: vec![root], next: FIRST_RECORD, seen_dirs: HashSet::new() };
    let root_data = match v.root_region {
        Some((off, len)) => vec![(off, rd(w.r, off, len as usize)?)],
        None => w.dir_clusters(v.root_cluster, false),
    };
    let mut queue: Vec<DirWork> = vec![(ROOT_RECORD, String::new(), root_data, false)];
    let mut dirs = 0u64;
    while let Some((parent, path, data, parent_deleted)) = queue.pop() {
        dirs += 1;
        if dirs.is_multiple_of(64) && !progress(w.out.len() as u64, w.out.len() as u64 + queue.len() as u64) {
            anyhow::bail!("scan cancelled");
        }
        let found = if v.kind == Kind::ExFat { w.exfat_dir(parent, &path, &data, parent_deleted) } else { w.fat_dir(parent, &path, &data, parent_deleted) };
        queue.extend(found);
        if w.out.len() > MAX_ENTRIES {
            break;
        }
    }
    progress(w.out.len() as u64, w.out.len() as u64);
    // Deleted files claiming the same clusters (a deleted file overwritten
    // by another one deleted later, or a contiguous guess running into
    // another file).
    let mut ranges = vec![];
    for (i, e) in w.out.iter().enumerate().filter(|(_, e)| e.deleted && !e.is_dir && e.size > 0) {
        for x in v.extents(e) {
            if let Some(vol) = x.vol {
                ranges.push((i, vol, vol + x.len.min(e.size.saturating_sub(x.offset))));
            }
        }
        if ranges.len() > 1 << 22 {
            break;
        }
    }
    kokino_ntfs::note_shared_space(&mut w.out, ranges);
    let info = v.info(w.out.len() as u64);
    Ok(FatScan { info, entries: w.out })
}

impl<'a, R: Read + Seek> Walker<'a, R> {
    /// Directory clusters with their volume offsets (deleted directories:
    /// first cluster only, the chain is gone).
    fn dir_clusters(&mut self, start: u64, deleted: bool) -> Vec<(u64, Vec<u8>)> {
        if !self.v.valid(start) || !self.seen_dirs.insert(start) {
            return vec![];
        }
        let cs = if deleted { vec![start] } else { self.v.clusters_of(start, None, false) };
        cs.into_iter().take(65_536).filter_map(|c| rd(self.r, self.v.cluster_offset(c), self.v.cluster as usize).ok().map(|b| (self.v.cluster_offset(c), b))).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn push(&mut self, parent: u64, path: &str, name: String, dos: Option<String>, is_dir: bool, deleted: bool, size: u64, start: u64, attrs: u32, times: Times, entry_off: u64, contiguous: bool) -> u64 {
        let rec = self.next;
        self.next += 1;
        let first_offset = (self.v.valid(start) && (size > 0 || is_dir)).then(|| self.v.cluster_offset(start));
        let mut error = None;
        let mut attributes = attrs;
        // FAT12/16/32 zero a deleted file's chain, so its clusters are taken
        // as contiguous. exFAT keeps allocation in a bitmap and often leaves
        // the chain: it is followed when it is fully intact.
        let contiguous = contiguous || (deleted && !is_dir && !self.v.intact_chain(start, size));
        if contiguous {
            attributes |= CONTIGUOUS;
        }
        if deleted && size > 0 && self.v.valid(start) {
            let reused = self.v.clusters_of(start, Some(size), contiguous).into_iter().filter(|&c| self.v.allocated(c)).count();
            if reused > 0 {
                error = Some(format!("{} of its clusters are in use again: recovered content may belong to another file", reused));
            }
        }
        self.out.push(FsEntry {
            record: rec,
            seq: 0,
            parent,
            parent_seq: 0,
            path: format!("{}/{}", path, name),
            name,
            dos_name: dos,
            is_dir,
            deleted,
            orphan: false,
            size: if is_dir { 0 } else { size },
            alloc_size: size.div_ceil(self.v.cluster).saturating_mul(self.v.cluster),
            resident: false,
            attributes,
            hard_links: 1,
            usn: None,
            si: Some(times),
            fname: None,
            streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset }] },
            has_reparse: false,
            record_offset: entry_off,
            error,
        });
        rec
    }

    fn fat_dir(&mut self, parent: u64, path: &str, data: &[(u64, Vec<u8>)], parent_deleted: bool) -> Vec<DirWork> {
        let mut sub = vec![];
        let mut lfn: Vec<(u8, u8, String)> = vec![]; // (ord, checksum, part)
        'clusters: for (base, buf) in data {
            for (i, e) in buf.chunks_exact(32).enumerate() {
                let off = base + 32 * i as u64;
                if e[0] == 0x00 {
                    break 'clusters;
                }
                let deleted = e[0] == 0xE5 || parent_deleted;
                let attr = e[11];
                if attr == 0x0F {
                    let part = utf16(&[&e[1..11], &e[14..26], &e[28..32]].concat());
                    lfn.push((e[0], e[13], part));
                    continue;
                }
                let pending = std::mem::take(&mut lfn);
                if attr & 0x08 != 0 || e[..11] == *b".          " || e[..11] == *b"..         " {
                    continue;
                }
                let mut sum = lfn_checksum(&e[..11]);
                // A deleted short entry lost its first byte, so its checksum no
                // longer matches the long-name parts before it. The checksum is
                // a bijection of that byte: find the one that makes the parts
                // directly in front match, which restores the long name.
                if e[0] == 0xE5 {
                    if let Some(&(_, want, _)) = pending.last() {
                        let mut s = e[..11].to_vec();
                        if (0x20..0x7F).any(|c| {
                            s[0] = c;
                            lfn_checksum(&s) == want
                        }) {
                            sum = want;
                        }
                    }
                }
                let parts: Vec<&(u8, u8, String)> = pending.iter().filter(|p| p.1 == sum).collect();
                // Parts are stored last first; deleted ones lost their order byte, so use position.
                let long: String = parts.iter().rev().map(|p| p.2.as_str()).collect();
                let short = short_name_case(&e[..11], e[0] == 0xE5, e[12]);
                let (name, dos) = if long.is_empty() { (short, None) } else { (long, Some(short)) };
                let start = (u16_at(e, 20) << 16 | u16_at(e, 26)) & if self.v.kind == Kind::Fat32 { 0x0FFF_FFFF } else { 0xFFFF };
                let size = u32_at(e, 28);
                let is_dir = attr & 0x10 != 0;
                let times = Times {
                    created: dos_time(u16_at(e, 16), u16_at(e, 14), e[13] as u64),
                    modified: dos_time(u16_at(e, 24), u16_at(e, 22), 0),
                    accessed: dos_time(u16_at(e, 18), 0, 0),
                    mft_modified: 0,
                };
                let rec = self.push(parent, path, name.clone(), dos, is_dir, deleted, size, start, attr as u32 & 0x3F, times, off, false);
                if is_dir {
                    let d = self.dir_clusters(start, deleted);
                    if !d.is_empty() {
                        sub.push((rec, format!("{}/{}", path, name), d, deleted));
                    }
                }
            }
        }
        sub
    }

    fn exfat_dir(&mut self, parent: u64, path: &str, data: &[(u64, Vec<u8>)], parent_deleted: bool) -> Vec<DirWork> {
        let mut sub = vec![];
        let entries: Vec<(u64, &[u8])> = data.iter().flat_map(|(base, b)| b.chunks_exact(32).enumerate().map(move |(i, e)| (base + 32 * i as u64, e))).collect();
        let mut i = 0;
        while i < entries.len() {
            let (off, e) = entries[i];
            if e[0] == 0x00 {
                break;
            }
            // File directory entry (0x85 live, 0x05 deleted) starts a set.
            if e[0] & 0x7F != 0x05 {
                i += 1;
                continue;
            }
            let deleted = e[0] & 0x80 == 0 || parent_deleted;
            let secondary = e[1] as usize;
            let attr = u16_at(e, 4) as u32;
            let times = Times {
                created: exfat_time(u32_at(e, 8), e[20] as u64, e[22]),
                modified: exfat_time(u32_at(e, 12), e[21] as u64, e[23]),
                accessed: exfat_time(u32_at(e, 16), 0, e[24]),
                mft_modified: 0,
            };
            let (mut name, mut size, mut start, mut nofat, mut name_len) = (String::new(), 0u64, 0u64, false, 0usize);
            for k in 1..=secondary.min(18) {
                let Some(&(_, s)) = entries.get(i + k) else { break };
                match s[0] & 0x7F {
                    0x40 => {
                        nofat = s[1] & 2 != 0;
                        name_len = s[3] as usize;
                        size = u64_at(s, 24);
                        start = u32_at(s, 20);
                    }
                    0x41 => name.push_str(&utf16(&s[2..32])),
                    _ => {}
                }
            }
            let name: String = name.chars().take(name_len.max(1)).collect();
            i += 1 + secondary;
            if name.is_empty() {
                continue;
            }
            let is_dir = attr & 0x10 != 0;
            let rec = self.push(parent, path, name.clone(), None, is_dir, deleted, size, start, attr & 0x3F, times, off, nofat);
            if is_dir {
                let d = if nofat || deleted {
                    let cs = self.v.clusters_of(start, Some(size.max(self.v.cluster)), true);
                    if !self.v.valid(start) || !self.seen_dirs.insert(start) {
                        vec![]
                    } else {
                        cs.into_iter().filter_map(|c| rd(self.r, self.v.cluster_offset(c), self.v.cluster as usize).ok().map(|b| (self.v.cluster_offset(c), b))).collect()
                    }
                } else {
                    self.dir_clusters(start, false)
                };
                if !d.is_empty() {
                    sub.push((rec, format!("{}/{}", path, name), d, deleted));
                }
            }
        }
        sub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<std::fs::File> {
        std::fs::File::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)).ok()
    }

    #[test]
    fn helpers() {
        // 2026-10-20 09:45:30.5 local
        let d = ((2026 - 1980) << 9) | (10 << 5) | 20;
        let t = (9 << 11) | (45 << 5) | 15;
        let ft = dos_time(d, t, 50);
        assert_eq!(kokino_core::time::filetime_to_iso(ft), "2026-10-20T09:45:30.5000000Z");
        // exFAT with UTC+2 (8 quarter hours): stored local 09:45 is 07:45 UTC
        let ts = (d << 16) | t;
        assert_eq!(kokino_core::time::filetime_to_iso(exfat_time(ts, 0, 0x80 | 8)), "2026-10-20T07:45:30.0000000Z");
        assert_eq!(lfn_checksum(b"NIGHTJ~1DOC"), lfn_checksum(b"NIGHTJ~1DOC"));
        assert_eq!(short_name(b"\xE5ELETE  TXT", true), "?ELETE.TXT");
        assert_eq!(short_name(b"README  TXT", false), "README.TXT");
        assert_eq!(short_name_case(b"KEYS    TXT", false, 0x18), "keys.txt");
    }

    fn check(name: &str, kind: Kind) -> Option<FatScan> {
        let mut f = fixture(name)?;
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        assert_eq!(v.kind, kind, "{}", name);
        assert!(["KOKINO FAT1", "KOKINO FAT2", "KOKINO FAT3", "KokinoExFAT"].contains(&v.label.as_str()), "{}", v.label);
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let notes = by("/Projects/Nightjar plan (final).txt");
        assert!(!notes.deleted);
        assert_eq!(v.read(&mut f, notes, 0, notes.size as usize).unwrap(), b"Move the archive to the external drive.\n".repeat(200));
        // Fragmented on purpose: the FAT chain must be followed.
        assert!(v.extents(notes).len() > 1, "{:?}", v.extents(notes));
        let gone = s.entries.iter().find(|e| e.deleted && e.name.ends_with("keys.txt")).unwrap_or_else(|| panic!("deleted keys.txt missing in {}", name));
        assert_eq!(v.read(&mut f, gone, 0, 100).unwrap(), b"vault: 4242-1717\n");
        assert!(gone.error.is_none());
        let reused = s.entries.iter().find(|e| e.deleted && e.name.contains("overwritten")).unwrap();
        assert!(reused.error.as_deref().unwrap_or("").contains("in use again"), "{:?}", reused);
        assert!(s.entries.iter().any(|e| e.is_dir && e.path == "/Projects/Photos"));
        // A file inside a deleted directory is deleted too and still readable.
        let trip = by("/Trip/itinerary.txt");
        assert!(trip.deleted && by("/Trip").deleted);
        assert_eq!(v.read(&mut f, trip, 0, 100).unwrap(), b"Day 1: ferry to the island. Day 2: back by noon.
");
        assert_eq!(gone.path, "/Old keys.txt");
        let free: u64 = v.free_runs().iter().map(|r| r.1).sum();
        assert!(free > 0);
        Some(s)
    }

    #[test]
    fn fat12_fat16_fat32_exfat_fixtures() {
        for (name, kind) in [("fat12.img", Kind::Fat12), ("fat16.img", Kind::Fat16), ("fat32.img", Kind::Fat32), ("exfat.img", Kind::ExFat)] {
            check(name, kind);
        }
    }
}
