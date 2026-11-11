//! UDF (Universal Disk Format, ECMA-167 / OSTA UDF 1.02 to 2.60): DVDs,
//! Blu-ray discs, packet-written and UDF-formatted media.
//!
//! Reads the anchor, the volume descriptor sequence, the partition maps,
//! the file set, then every file entry (FE and EFE) with short, long and
//! embedded allocation descriptors. Directory entries marked deleted stay
//! in UDF directories until the space is reused: they are listed as
//! deleted with whatever their file entry still says.
//!
//! Partition maps: physical; sparable (DVD-RW, CD-RW: packets moved to a
//! spare area are read from there, through the sparing table); virtual
//! (CD-R and DVD-R written incrementally: blocks are numbered through the
//! VAT, the virtual allocation table recorded at the end of the last
//! session, in the UDF 1.50 and 2.00 layouts); and the metadata partition
//! of UDF 2.50 and later. Every session of a write-once disc ends with its
//! own VAT: the older ones still describe the disc as it was, so files
//! that a later session removed are listed as deleted, from the session
//! that still had them.

use crate::{civil_ft, le16, le32, le64, rd, ROOT_RECORD};
use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta};
use std::collections::HashSet;
use std::io::{Read, Seek};

const FIRST_RECORD: u64 = 100;
const MAX_ENTRIES: usize = 2_000_000;
const MAX_DIR_BYTES: u64 = 64 << 20;
const MAX_ADS: usize = 1 << 16;

/// A partition as the logical volume maps it.
#[derive(Debug, Clone)]
enum Map {
    /// Logical block n is sector `start + n`.
    Physical { start: u64, len: u64 },
    /// UDF 2.50+: blocks are offsets into the metadata file, which lives
    /// in the physical partition `phys` (index into the map table).
    Metadata { phys: usize, extents: Vec<(u64, u64)> },
    /// Like physical, but packets listed in the sparing table (original
    /// block, sorted) were moved to the spare sector given.
    Sparable { start: u64, len: u64, packet: u64, table: Vec<(u64, u64)> },
    /// Block n is VAT entry n, a block of the physical map `phys`.
    Virtual { phys: usize, vat: Vec<u32> },
    Unsupported(String),
}

const MAX_VAT_ENTRIES: usize = 1 << 22;
const MAX_SPARING_ENTRIES: usize = 1 << 16;

#[derive(Clone)]
pub struct UdfVolume {
    pub block: u64,
    pub label: String,
    pub revision: String,
    pub size: u64,
    maps: Vec<Map>,
    root: (u64, u16),
    pub notes: Vec<String>,
    pub created: u64,
    /// The file set descriptor: (block, partition reference).
    fsd: (u64, usize),
    /// The virtual map, and the VATs of earlier sessions (sector, table),
    /// newest first.
    virt: Option<usize>,
    old_vats: Vec<(u64, Vec<u32>)>,
}

/// How much of a disc is searched for the VATs of earlier sessions.
const MAX_VAT_SEARCH: u64 = 8 << 30;
const MAX_OLD_VATS: usize = 64;

fn tag(b: &[u8]) -> u16 {
    le16(b, 0) as u16
}

/// OSTA CS0 d-string: compression id 8 (8-bit) or 16 (UTF-16BE).
fn dstring(b: &[u8]) -> String {
    match b.first() {
        Some(8) => b[1..].iter().map(|&c| c as char).collect::<String>().trim_end_matches('\0').to_string(),
        Some(16) => {
            let w: Vec<u16> = b[1..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&w).trim_end_matches('\0').to_string()
        }
        _ => String::new(),
    }
}

/// A fixed-length d-string field: the last byte holds the used length.
fn dfield(b: &[u8]) -> String {
    let n = b.last().copied().unwrap_or(0) as usize;
    dstring(&b[..n.min(b.len().saturating_sub(1))])
}

/// ECMA-167 timestamp (12 bytes).
fn timestamp(b: &[u8]) -> u64 {
    if b.len() < 12 {
        return 0;
    }
    let tz = le16(b, 0) as u16;
    let year = le16(b, 2) as i32;
    if year == 0 {
        return 0;
    }
    let offset = if tz >> 12 == 1 {
        let m = (tz & 0x0FFF) as i16;
        let m = if m & 0x0800 != 0 { m | !0x0FFF } else { m };
        if m == -2047 { 0 } else { m as i32 }
    } else {
        0
    };
    let nanos = b[9] as u64 * 10_000_000 + b[10] as u64 * 100_000 + b[11] as u64 * 1000;
    civil_ft(year, b[4] as u32, b[5] as u32, b[6] as u32, b[7] as u32, b[8] as u32, nanos, offset)
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<UdfVolume> {
    // Anchor at sector 256 (2048-byte sectors; 512-byte media also exist).
    let mut found = None;
    for bs in [2048u64, 512, 4096] {
        for at in [256u64, (size / bs).saturating_sub(256), (size / bs).saturating_sub(1)] {
            let a = rd(r, at.saturating_mul(bs), 512)?;
            if a.len() >= 32 && tag(&a) == 2 && le32(&a, 12) == at {
                found = Some((bs, a));
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }
    let (block, avdp) = found.ok_or_else(|| anyhow::anyhow!("no UDF anchor volume descriptor"))?;
    let (vds_len, vds_loc) = (le32(&avdp, 16), le32(&avdp, 20));
    let vds = rd(r, vds_loc * block, vds_len.min(64 * block) as usize)?;
    let mut parts: Vec<(u64, u64, u64)> = vec![]; // number, start, length
    let mut lvd: Option<Vec<u8>> = None;
    let mut label = String::new();
    let mut created = 0;
    for d in vds.chunks(block as usize) {
        // A descriptor cut short at the end of the image ends the sequence.
        if d.len() < 512 {
            break;
        }
        match tag(d) {
            1 => {
                label = dfield(&d[24..56]);
                created = timestamp(&d[376..388]);
            }
            5 => parts.push((le16(d, 22), le32(d, 188), le32(d, 192))),
            6 => lvd = Some(d.to_vec()),
            8 => break,
            _ => {}
        }
    }
    let lvd = lvd.ok_or_else(|| anyhow::anyhow!("UDF logical volume descriptor missing"))?;
    let lblock = le32(&lvd, 212);
    if lblock != block {
        anyhow::bail!("UDF logical block size {} differs from the sector size {}", lblock, block);
    }
    let lv_label = dfield(&lvd[84..212]);
    let revision = {
        let d = &lvd[216..248]; // domain identifier: "*OSTA UDF Compliant" + revision
        let rev = le16(d, 24);
        if rev > 0 { format!("{}.{:02x}", rev >> 8, rev & 0xFF) } else { String::new() }
    };
    let fsd_ad = &lvd[248..264];
    let nmaps = le32(&lvd, 268) as usize;
    let mut maps = vec![];
    let mut notes: Vec<String> = vec![];
    // Virtual maps: (map index, partition number).
    let mut virtual_pn: Vec<(usize, u64)> = vec![];
    let mut p = 440usize;
    for _ in 0..nmaps.min(16) {
        let Some(m) = lvd.get(p..) else { break };
        let (ty, len) = (m.first().copied().unwrap_or(0), m.get(1).copied().unwrap_or(0) as usize);
        if len < 6 {
            break;
        }
        let pnum = le16(m, 4);
        let phys = parts.iter().find(|x| x.0 == pnum).map(|x| (x.1, x.2));
        match (ty, phys) {
            (1, Some((start, len))) => maps.push(Map::Physical { start, len }),
            (2, _) => {
                let id = String::from_utf8_lossy(m.get(5..28).unwrap_or(&[])).trim_end_matches('\0').to_string();
                let pn = le16(m, 38);
                let phys_of = |pn: u64| parts.iter().find(|x| x.0 == pn).map(|x| (x.1, x.2));
                if id.contains("Sparable") {
                    match phys_of(pn) {
                        Some((start, plen)) => {
                            let packet = le16(m, 40).max(1);
                            let ntables = (m.get(42).copied().unwrap_or(0) as usize).min(4);
                            let tsize = le32(m, 44).min(MAX_SPARING_ENTRIES as u64 * 8 + 56);
                            let mut table = None;
                            for k in 0..ntables {
                                let loc = le32(m, 48 + 4 * k);
                                let Ok(t) = rd(r, loc.saturating_mul(block), tsize.max(56) as usize) else { continue };
                                if t.len() < 56 || !String::from_utf8_lossy(&t[17..40]).contains("Sparing Table") {
                                    continue;
                                }
                                let n = (le16(&t, 48) as usize).min(MAX_SPARING_ENTRIES);
                                let mut e: Vec<(u64, u64)> = (0..n).filter_map(|i| t.get(56 + 8 * i..64 + 8 * i)).map(|c| (le32(c, 0), le32(c, 4))).filter(|&(o, _)| o < 0xFFFF_FFF0).collect();
                                e.sort_unstable();
                                table = Some(e);
                                break;
                            }
                            if table.is_none() && ntables > 0 {
                                notes.push("UDF sparable partition: no sparing table could be read; blocks moved to the spare area are read from their original place".to_string());
                            }
                            maps.push(Map::Sparable { start, len: plen, packet, table: table.unwrap_or_default() });
                        }
                        None => maps.push(Map::Unsupported(id)),
                    }
                } else if id.contains("Virtual") {
                    maps.push(Map::Virtual { phys: usize::MAX, vat: vec![] });
                    virtual_pn.push((maps.len() - 1, pn));
                } else if id.contains("Metadata") {
                    let pn = le16(m, 38);
                    let file = le32(m, 40);
                    let phys_idx = maps.iter().position(|x| matches!(x, Map::Physical { .. } | Map::Sparable { .. })).unwrap_or(0);
                    let _ = pn;
                    maps.push(Map::Metadata { phys: phys_idx, extents: vec![(file, u64::MAX)] });
                } else {
                    maps.push(Map::Unsupported(id));
                }
            }
            _ => maps.push(Map::Unsupported(format!("partition map type {}", ty))),
        }
        p += len;
    }
    let mut v = UdfVolume {
        block,
        label: if lv_label.is_empty() { label } else { lv_label },
        revision,
        size,
        maps,
        root: (0, 0),
        notes,
        created,
        fsd: (le32(fsd_ad, 4), le16(fsd_ad, 8) as usize),
        virt: None,
        old_vats: vec![],
    };
    // Virtual partitions: the VAT is recorded last, so it is looked for from
    // the end of the image back.
    for (mi, pn) in virtual_pn {
        let phys = (0..v.maps.len()).find(|&i| i != mi && matches!(v.maps[i], Map::Physical { .. }) && parts.iter().any(|x| x.0 == pn)).unwrap_or(0);
        match find_vat(&v, r, phys) {
            Some((at, vat)) => {
                v.maps[mi] = Map::Virtual { phys, vat };
                v.virt = Some(mi);
                v.old_vats = older_vats(&v, r, phys, at);
            }
            None => v.maps[mi] = Map::Unsupported("*UDF Virtual Partition (no VAT found)".into()),
        }
    }
    // Metadata partition: its blocks are the metadata file's content.
    for i in 0..v.maps.len() {
        if let Map::Metadata { phys, extents } = v.maps[i].clone() {
            let fe_lbn = extents[0].0;
            let fe = v.block_read(r, phys, fe_lbn)?;
            let (ads, _, _) = alloc_descs(&fe);
            let ext: Vec<(u64, u64)> = ads.iter().map(|a| (a.lbn, a.len)).collect();
            v.maps[i] = Map::Metadata { phys, extents: ext };
        }
    }
    for m in &v.maps {
        if let Map::Unsupported(id) = m {
            v.notes.push(format!("UDF partition \"{}\" is not read yet (files in it are missing)", id));
        }
    }
    // File set descriptor, then the root directory's ICB.
    let fsd = v.block_read(r, le16(fsd_ad, 8) as usize, le32(fsd_ad, 4))?;
    if tag(&fsd) != 256 {
        anyhow::bail!("UDF file set descriptor not found");
    }
    v.root = (le32(&fsd, 404), le16(&fsd, 408) as u16);
    Ok(v)
}

/// The VAT of the last session: the VAT file entry nearest the end of the
/// image. Returns its sector and its entries.
fn find_vat<R: Read + Seek>(v: &UdfVolume, r: &mut R, phys: usize) -> Option<(u64, Vec<u32>)> {
    let last = (v.size / v.block).checked_sub(1)?;
    for back in 0..256u64 {
        let Some(at) = last.checked_sub(back) else { break };
        if let Some(vat) = vat_at(v, r, phys, at) {
            return Some((at, vat));
        }
    }
    None
}

/// VATs of earlier sessions: VAT file entries (type 248) before the
/// current one, newest first.
fn older_vats<R: Read + Seek>(v: &UdfVolume, r: &mut R, phys: usize, current: u64) -> Vec<(u64, Vec<u32>)> {
    let mut out = vec![];
    let bs = v.block as usize;
    let end = current.min(MAX_VAT_SEARCH / v.block);
    let chunk = ((1u64 << 20) / v.block).max(1);
    let mut s = 0u64;
    while s < end {
        let n = chunk.min(end - s);
        let Ok(buf) = rd(r, s * v.block, (n * v.block) as usize) else { break };
        for (i, b) in buf.chunks_exact(bs).enumerate() {
            if matches!(tag(b), 261 | 266) && b.get(27) == Some(&248) {
                if let Some(vat) = vat_at(v, r, phys, s + i as u64) {
                    out.push((s + i as u64, vat));
                }
            }
        }
        if buf.len() < (n * v.block) as usize {
            break;
        }
        s += n;
    }
    out.reverse();
    out.truncate(MAX_OLD_VATS);
    out
}

/// The VAT whose file entry is at sector `at`: a file entry whose file type
/// is 248 (UDF 2.00 and later), or whose data ends with "*UDF Virtual Alloc
/// Tbl" (UDF 1.50). Its entries are blocks of the physical map `phys`.
fn vat_at<R: Read + Seek>(v: &UdfVolume, r: &mut R, phys: usize, at: u64) -> Option<Vec<u32>> {
    {
        let fe = rd(r, at * v.block, v.block as usize).ok()?;
        if fe.len() < 176 || !matches!(tag(&fe), 261 | 266) {
            return None;
        }
        let ftype = fe[27];
        let (exts, size) = v.map_file(r, at * v.block, phys);
        if size < 4 || size > MAX_VAT_ENTRIES as u64 * 4 + 4096 {
            return None;
        }
        let mut d = vec![];
        for x in exts {
            let n = x.len.min(size - d.len() as u64) as usize;
            match x.vol {
                Some(o) => d.extend(rd(r, o, n).ok()?),
                None => d.resize(d.len() + n, 0),
            }
            if d.len() as u64 >= size {
                break;
            }
        }
        // An embedded VAT: the data is in the entry itself.
        if d.is_empty() {
            if let (_, _, Some(e)) = alloc_descs(&fe) {
                d = e;
            }
        }
        let entries: &[u8] = if ftype == 248 {
            let hd = le16(&d, 0) as usize;
            if hd < 152 || hd > d.len() {
                return None;
            }
            &d[hd..]
        } else if d.len() >= 36 && d[d.len() - 36..].windows(22).any(|w| w == b"*UDF Virtual Alloc Tbl") {
            &d[..d.len() - 36]
        } else {
            return None;
        };
        Some(entries.chunks_exact(4).take(MAX_VAT_ENTRIES).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
    }
}

/// One allocation descriptor, resolved to a partition reference.
#[derive(Debug, Clone, Copy)]
struct Ad {
    len: u64,
    lbn: u64,
    part: u16,
    /// 0 recorded, 1 allocated not recorded (zeros), 2 not allocated.
    kind: u8,
}

/// Allocation descriptors of a file entry, its info length, and the
/// embedded data when the file lives in its entry.
fn alloc_descs(fe: &[u8]) -> (Vec<Ad>, u64, Option<Vec<u8>>) {
    let efe = tag(fe) == 266;
    let (l_ea, l_ad, base) = if efe { (le32(fe, 208), le32(fe, 212), 216usize) } else { (le32(fe, 168), le32(fe, 172), 176usize) };
    let size = le64(fe, 56);
    let start = base.saturating_add(l_ea as usize);
    let Some(area) = fe.get(start..start.saturating_add(l_ad as usize)) else { return (vec![], size, None) };
    let flags = le16(fe, 34);
    let mut out = vec![];
    match flags & 7 {
        0 => {
            for c in area.chunks_exact(8).take(MAX_ADS) {
                let l = le32(c, 0);
                if l & 0x3FFF_FFFF == 0 {
                    break;
                }
                out.push(Ad { len: l & 0x3FFF_FFFF, lbn: le32(c, 4), part: u16::MAX, kind: (l >> 30) as u8 });
            }
        }
        1 => {
            for c in area.chunks_exact(16).take(MAX_ADS) {
                let l = le32(c, 0);
                if l & 0x3FFF_FFFF == 0 {
                    break;
                }
                out.push(Ad { len: l & 0x3FFF_FFFF, lbn: le32(c, 4), part: le16(c, 8) as u16, kind: (l >> 30) as u8 });
            }
        }
        3 => return (vec![], size, Some(area.to_vec())),
        _ => {}
    }
    (out, size, None)
}

impl UdfVolume {
    /// Volume byte offset of logical block `lbn` of partition `part`.
    fn locate(&self, part: usize, lbn: u64) -> Option<u64> {
        match self.maps.get(part)? {
            Map::Physical { start, len } => (lbn < *len).then(|| (start + lbn) * self.block),
            Map::Metadata { phys, extents } => {
                let mut off = lbn * self.block;
                for &(e_lbn, e_len) in extents {
                    if off < e_len {
                        return self.locate(*phys, e_lbn + off / self.block).map(|o| o + off % self.block);
                    }
                    off -= e_len;
                }
                None
            }
            Map::Sparable { start, len, packet, table } => {
                if lbn >= *len {
                    return None;
                }
                let first = lbn - lbn % packet;
                match table.binary_search_by_key(&first, |x| x.0) {
                    Ok(i) => Some((table[i].1 + (lbn - first)) * self.block),
                    Err(_) => Some((start + lbn) * self.block),
                }
            }
            Map::Virtual { phys, vat } => {
                let p = *vat.get(usize::try_from(lbn).ok()?)?;
                // A virtual map pointing at itself cannot be resolved.
                if p == u32::MAX || matches!(self.maps.get(*phys), Some(Map::Virtual { .. })) {
                    return None;
                }
                self.locate(*phys, p as u64)
            }
            Map::Unsupported(_) => None,
        }
    }

    fn block_read<R: Read + Seek>(&self, r: &mut R, part: usize, lbn: u64) -> anyhow::Result<Vec<u8>> {
        let off = self.locate(part, lbn).ok_or_else(|| anyhow::anyhow!("block {} outside partition {}", lbn, part))?;
        Ok(rd(r, off, self.block as usize)?)
    }

    /// File extents as volume byte runs. `fe_off` is where the file entry is.
    fn map_file<R: Read + Seek>(&self, r: &mut R, fe_off: u64, part: usize) -> (Vec<Extent>, u64) {
        let Ok(fe) = rd(r, fe_off, self.block as usize) else { return (vec![], 0) };
        let (ads, size, embedded) = alloc_descs(&fe);
        if embedded.is_some() {
            let efe = tag(&fe) == 266;
            let base = if efe { 216 } else { 176 } + if efe { le32(&fe, 208) } else { le32(&fe, 168) };
            return (vec![Extent { offset: 0, len: size, vol: Some(fe_off + base) }], size);
        }
        let mut out = vec![];
        let mut logical = 0u64;
        for a in ads {
            let p = if a.part == u16::MAX { part } else { a.part as usize };
            let vol = if a.kind == 0 { self.locate(p, a.lbn) } else { None };
            out.push(Extent { offset: logical, len: a.len, vol });
            logical += a.len;
        }
        (out, size)
    }

    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> Vec<Extent> {
        if e.is_dir || e.size == 0 {
            return vec![];
        }
        self.map_file(r, e.record_offset, (e.attributes >> 24 & 0xF) as usize).0
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= e.size {
            return Ok(vec![]);
        }
        let want = (len as u64).min(e.size - offset) as usize;
        let end = offset + want as u64;
        let mut out = vec![0u8; want];
        for x in self.extents(r, e) {
            let (s, t) = (x.offset.max(offset), (x.offset + x.len).min(end));
            if s >= t {
                continue;
            }
            if let Some(v) = x.vol {
                let b = rd(r, v + (s - x.offset), (t - s) as usize)?;
                let at = (s - offset) as usize;
                out[at..at + b.len()].copy_from_slice(&b);
            }
        }
        Ok(out)
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: kokino_core::time::filetime_to_iso(self.created),
            version: if self.revision.is_empty() { "UDF".into() } else { format!("UDF {}", self.revision) },
            cluster_size: self.block as u32,
            sector_size: self.block as u16,
            record_size: self.block as u32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: 256 * self.block,
            dirty: false,
        }
    }
}

pub struct UdfScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    pub notes: Vec<String>,
}

/// `attributes` bits 24..28: the partition reference of the file entry.
fn part_bits(p: usize) -> u32 {
    ((p as u32) & 0xF) << 24
}

pub fn scan<R: Read + Seek>(v: &UdfVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<UdfScan> {
    let mut out = vec![];
    let root_off = v.locate(v.root.1 as usize, v.root.0).ok_or_else(|| anyhow::anyhow!("UDF root directory outside its partition"))?;
    let root_fe = rd(r, root_off, v.block as usize)?;
    out.push(file_entry(&root_fe, ROOT_RECORD, ROOT_RECORD, "/".into(), ".".into(), root_off, v.root.1 as usize, true, false, None));
    let mut next = FIRST_RECORD;
    let deleted_count = walk(v, r, (ROOT_RECORD, String::new(), root_off, v.root.1 as usize), &mut next, &mut out, &mut progress, None)?;
    let mut notes = v.notes.clone();
    // Earlier sessions: their trees, through their own VATs; what the
    // current tree no longer has is listed as deleted.
    let mut from_sessions = 0usize;
    if let Some(mi) = v.virt {
        let now: HashSet<String> = out.iter().map(|e| e.path.to_lowercase()).collect();
        for (k, (at, vat)) in v.old_vats.iter().enumerate() {
            let mut ov = v.clone();
            if let Map::Virtual { phys, .. } = v.maps[mi] {
                ov.maps[mi] = Map::Virtual { phys, vat: vat.clone() };
            }
            let Ok(fsd) = ov.block_read(r, ov.fsd.1, ov.fsd.0) else { continue };
            if tag(&fsd) != 256 {
                continue;
            }
            let (rl, rp) = (le32(&fsd, 404), le16(&fsd, 408) as usize);
            let Some(ro) = ov.locate(rp, rl) else { continue };
            let mut old = vec![];
            let label = format!("session {} before the last (VAT at sector {})", k + 1, at);
            let _ = walk(&ov, r, (ROOT_RECORD, String::new(), ro, rp), &mut 0, &mut old, &mut |_, _| true, Some(&label));
            // Parents by path, so a name under a folder that is gone hangs off it.
            let mut by_path: std::collections::HashMap<String, u64> = out.iter().map(|e| (e.path.to_lowercase(), e.record)).collect();
            for mut e in old {
                let key = e.path.to_lowercase();
                if now.contains(&key) || by_path.contains_key(&key) {
                    continue;
                }
                let parent_path = e.path.rsplit_once('/').map(|x| x.0).filter(|p| !p.is_empty()).unwrap_or("/").to_lowercase();
                e.parent = by_path.get(&parent_path).copied().unwrap_or(ROOT_RECORD);
                e.record = next;
                next += 1;
                e.deleted = true;
                by_path.insert(key, e.record);
                from_sessions += 1;
                out.push(e);
                if out.len() > MAX_ENTRIES {
                    break;
                }
            }
        }
    }
    progress(out.len() as u64, out.len() as u64);
    if deleted_count > 0 {
        notes.push(format!(
            "{} deleted UDF directory {} still {} a name; content is shown when the file entry it points to is intact, which cannot be guaranteed.",
            deleted_count,
            if deleted_count == 1 { "entry" } else { "entries" },
            if deleted_count == 1 { "holds" } else { "hold" }
        ));
    }
    if from_sessions > 0 {
        notes.push(format!("{} file(s) and folder(s) are only in earlier sessions of this disc (found through their VATs): a later session removed them.", from_sessions));
    }
    let info = v.info(out.len() as u64);
    Ok(UdfScan { info, entries: out, notes })
}

/// Walks a directory tree from `start` (record, path, file entry offset,
/// partition), adding entries to `out`. `session`: the earlier session the
/// tree is from, noted on each entry. Returns the deleted names seen.
#[allow(clippy::type_complexity)]
fn walk<R: Read + Seek>(v: &UdfVolume, r: &mut R, start: (u64, String, u64, usize), next: &mut u64, out: &mut Vec<FsEntry>, progress: &mut dyn FnMut(u64, u64) -> bool, session: Option<&str>) -> anyhow::Result<u64> {
    let mut seen = HashSet::from([start.2]);
    let mut queue = vec![(start.0, start.1, start.2, start.3, false)];
    let mut deleted_count = 0u64;
    let base = out.len();
    while let Some((parent, path, fe_off, part, parent_deleted)) = queue.pop() {
        if out.len() % 4096 == 0 && !progress(out.len() as u64, out.len() as u64 + queue.len() as u64) {
            anyhow::bail!("scan cancelled");
        }
        let (exts, size) = v.map_file(r, fe_off, part);
        let mut data = vec![];
        for x in exts {
            if data.len() as u64 >= size.min(MAX_DIR_BYTES) {
                break;
            }
            let n = x.len.min(size.min(MAX_DIR_BYTES) - data.len() as u64) as usize;
            match x.vol {
                Some(o) => data.extend(rd(r, o, n)?),
                None => data.resize(data.len() + n, 0),
            }
        }
        let mut pos = 0usize;
        while pos + 38 <= data.len() {
            let f = &data[pos..];
            if tag(f) != 257 {
                // Directory data is a run of FIDs; anything else ends it.
                break;
            }
            let (ch, l_fi, l_iu) = (f[18], f[19] as usize, le16(f, 36) as usize);
            let total = (38 + l_iu + l_fi + 3) & !3;
            if pos + total > data.len() {
                break;
            }
            pos += total;
            if ch & 8 != 0 {
                continue; // parent entry
            }
            let name = dstring(&f[38 + l_iu..38 + l_iu + l_fi]).replace('/', "_");
            if name.is_empty() {
                continue;
            }
            let deleted = ch & 4 != 0 || parent_deleted;
            let icb = &f[20..36];
            let (lbn, ipart) = (le32(icb, 4), le16(icb, 8) as usize);
            let child_path = if path.is_empty() { name.clone() } else { format!("{}/{}", path, name) };
            let Some(child_off) = v.locate(ipart, lbn) else { continue };
            let fe = rd(r, child_off, v.block as usize)?;
            let is_dir_fid = ch & 2 != 0;
            let fe_ok = matches!(tag(&fe), 261 | 266);
            let record = *next;
            *next += 1;
            if deleted {
                deleted_count += 1;
            }
            let note = if let Some(s) = session {
                Some(format!("only in an earlier session of the disc ({}); the current session no longer lists it", s))
            } else if deleted && !fe_ok {
                Some("deleted entry: its file entry has been reused or cleared, so only the name is left".to_string())
            } else if deleted {
                Some("deleted entry still in its directory; the file entry it points to may since belong to another file".to_string())
            } else {
                None
            };
            let mut e = if fe_ok {
                file_entry(&fe, record, parent, format!("/{}", child_path), name, child_off, ipart, is_dir_fid, deleted, note)
            } else {
                let mut e = file_entry(&[0u8; 256], record, parent, format!("/{}", child_path), name, child_off, ipart, is_dir_fid, deleted, note);
                e.size = 0;
                e.streams.iter_mut().for_each(|s| {
                    s.size = 0;
                    s.first_offset = None;
                });
                e
            };
            // Deleted folders are walked too: their hierarchy is still worth reading.
            if e.is_dir && fe_ok && seen.insert(child_off) {
                queue.push((record, child_path, child_off, ipart, deleted));
            }
            e.attributes |= part_bits(ipart);
            // Where the content starts, for the hex view.
            if !e.is_dir && e.size > 0 {
                let first = v.map_file(r, child_off, ipart).0.iter().find_map(|x| x.vol);
                if let Some(s) = e.streams.first_mut() {
                    s.first_offset = first;
                }
            }
            out.push(e);
            if out.len() - base > MAX_ENTRIES {
                return Ok(deleted_count);
            }
        }
    }
    Ok(deleted_count)
}

#[allow(clippy::too_many_arguments)]
fn file_entry(fe: &[u8], record: u64, parent: u64, path: String, name: String, off: u64, part: usize, dir_hint: bool, deleted: bool, note: Option<String>) -> FsEntry {
    // An entry cut short at the end of the image reads as zeros past it.
    let mut padded = fe.to_vec();
    padded.resize(padded.len().max(256), 0);
    let fe = &padded[..];
    let efe = tag(fe) == 266;
    let ftype = fe.get(27).copied().unwrap_or(0); // icbtag file type
    let is_dir = ftype == 4 || (ftype == 0 && dir_hint);
    let size = le64(fe, 56);
    let (access, modify, create, attr) = if efe {
        (timestamp(&fe[80..92]), timestamp(&fe[92..104]), timestamp(&fe[104..116]), timestamp(&fe[116..128]))
    } else {
        (timestamp(&fe[72..84]), timestamp(&fe[84..96]), 0, timestamp(&fe[96..108]))
    };
    let (uid, gid, perm, links) = (le32(fe, 36), le32(fe, 40), le32(fe, 44), le16(fe, 48));
    // UDF permissions: other, group, owner in 5-bit groups (r, w, x, chattr, delete).
    let rwx = |shift: u32| -> u32 {
        let g = (perm >> shift) as u32;
        (g & 4 != 0) as u32 * 4 + (g & 2 != 0) as u32 * 2 + (g & 1 != 0) as u32
    };
    let mode = if is_dir { 0o040000 } else if ftype == 12 { 0o120000 } else { 0o100000 } | rwx(10) << 6 | rwx(5) << 3 | rwx(0);
    FsEntry {
        record,
        seq: 0,
        parent,
        parent_seq: 0,
        name,
        dos_name: None,
        path,
        is_dir,
        deleted,
        orphan: false,
        size: if is_dir { 0 } else { size },
        alloc_size: size,
        resident: alloc_descs(fe).2.is_some(),
        attributes: if is_dir { 0x10 } else { 0x01 } | part_bits(part),
        hard_links: links as u16,
        usn: None,
        si: Some(Times { created: create, modified: modify, accessed: access, mft_modified: attr }),
        fname: None,
        streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset: None }] },
        has_reparse: false,
        record_offset: off,
        error: note,
        unix: Some(UnixMeta { inode: le64(fe, if efe { 200 } else { 160 }), mode, uid: uid as u32, gid: gid as u32, deleted_time: 0, inode_offset: off, journal_seq: None, link_target: None }),
        name_only: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udf_bridge_disc() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/iso-udf.iso");
        let Ok(mut f) = std::fs::File::open(&p) else { return };
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        assert_eq!(v.label, "KOKINO_DISC");
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let report = by("/docs/report.txt");
        assert_eq!(v.read(&mut f, report, 0, 9000).unwrap(), (b"Quarterly report line, lab.test internal.\n".repeat(220))[..9000].to_vec());
        assert_eq!(v.read(&mut f, by("/docs/a/b/c/d/e/f/g/h/deep.txt"), 0, 100).unwrap(), b"nine levels down\n");
        assert_eq!(v.read(&mut f, by("/Unicode name - Skopje Ohrid.txt"), 0, 100).unwrap(), b"names test\n");
        assert!(by("/README.TXT").si.unwrap().modified > 0);
        // A directory entry marked deleted: listed, content still readable.
        let gone = by("/deleted-in-udf.txt");
        assert!(gone.deleted);
        assert_eq!(v.read(&mut f, gone, 0, 100).unwrap(), b"deleted from the UDF directory (test data)\n");
        assert_eq!(s.entries.iter().filter(|e| e.deleted).count(), 1);
    }

    fn fixture(name: &str) -> Option<(std::fs::File, u64)> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
        let f = std::fs::File::open(&p).ok()?;
        let size = f.metadata().ok()?.len();
        Some((f, size))
    }

    /// scripts/make_udf_fixture.py: the packet holding moved.txt was moved
    /// to the spare area; its old place holds a stale copy.
    #[test]
    fn sparable_partition() {
        let Some((mut f, size)) = fixture("udf-sparable.img") else { return };
        let v = open(&mut f, size).unwrap();
        assert!(v.notes.is_empty(), "{:?}", v.notes);
        assert_eq!(v.label, "KOKINO_DVDRW");
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} missing", p));
        assert_eq!(v.read(&mut f, by("/moved.txt"), 0, 100).unwrap(), b"This block was moved to the spare area (test data).
");
        assert_eq!(v.read(&mut f, by("/docs/report.txt"), 0, 5000).unwrap(), (b"Quarterly report line, lab.test internal.
".repeat(120))[..5000].to_vec());
        assert_eq!(v.read(&mut f, by("/README.TXT"), 0, 100).unwrap(), b"Kokino UDF test disc. Invented data.
");
        // Where the hex view shows it: the spare packet (sector 320 + 6).
        assert_eq!(by("/moved.txt").streams[0].first_offset, Some(326 * 2048));
    }

    /// scripts/make_udf_fixture.py: everything but file data is in the
    /// virtual partition, found through the VAT in the last sector.
    #[test]
    fn virtual_partition_through_the_vat() {
        let Some((mut f, size)) = fixture("udf-vat.img") else { return };
        let v = open(&mut f, size).unwrap();
        assert!(v.notes.is_empty(), "{:?}", v.notes);
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let paths: Vec<&str> = s.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths.len(), 6, "{:?}", paths);
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} missing in {:?}", p, paths));
        assert_eq!(v.read(&mut f, by("/session.txt"), 0, 100).unwrap(), b"Written in the last session of a CD-R (test data).
");
        assert_eq!(v.read(&mut f, by("/docs/report.txt"), 0, 5000).unwrap().len(), 5000);
        assert!(by("/docs").is_dir);
        assert!(s.entries.iter().filter(|e| e.path != "/draft-old.txt").all(|e| !e.deleted));
        // Removed by the last session; the earlier session's VAT still has it.
        let draft = by("/draft-old.txt");
        assert!(draft.deleted && draft.error.as_deref().unwrap_or("").starts_with("only in an earlier session of the disc (session 1 before the last"), "{:?}", draft.error);
        assert_eq!(v.read(&mut f, draft, 0, 100).unwrap(), b"Early draft, removed in the second session (test data).\n");
        assert!(s.notes.iter().any(|n| n.starts_with("1 file(s) and folder(s) are only in earlier sessions")), "{:?}", s.notes);
        // Without the last session's VAT (a session never closed), the disc
        // reads as the earlier session left it.
        let mut cut = vec![0u8; size as usize - 2048];
        use std::io::{Read as _, Seek as _};
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.read_exact(&mut cut).unwrap();
        let mut c = std::io::Cursor::new(cut.clone());
        let v1 = open(&mut c, cut.len() as u64).unwrap();
        let s1 = scan(&v1, &mut c, |_, _| true).unwrap();
        let p1: Vec<&str> = s1.entries.iter().filter(|e| !e.deleted).map(|e| e.path.as_str()).collect();
        assert!(p1.contains(&"/draft-old.txt") && !p1.contains(&"/session.txt"), "{:?}", p1);
        // With no VAT at all, the virtual partition cannot be read, and says so.
        let mut none = cut.clone();
        for k in [37usize, 38] {
            none[(300 + k) * 2048..(301 + k) * 2048].fill(0);
        }
        let mut c = std::io::Cursor::new(none.clone());
        match open(&mut c, none.len() as u64) {
            Ok(v) => assert!(v.notes.iter().any(|n| n.contains("no VAT found")), "{:?}", v.notes),
            Err(e) => assert!(e.to_string().contains("outside"), "{}", e),
        }
    }
}
