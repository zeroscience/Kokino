//! UDF (Universal Disk Format, ECMA-167 / OSTA UDF 1.02 to 2.60): DVDs,
//! Blu-ray discs, packet-written and UDF-formatted media.
//!
//! Reads the anchor, the volume descriptor sequence, the partition maps
//! (physical, and the metadata partition of UDF 2.50 and later), the file
//! set, then every file entry (FE and EFE) with short, long and embedded
//! allocation descriptors. Directory entries marked deleted stay in UDF
//! directories until the space is reused: they are listed as deleted with
//! whatever their file entry still says.
//!
//! Not read yet: virtual partitions (VAT, CD-R written incrementally) and
//! sparable partitions (sparing tables of DVD-RW); such discs are reported.

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
    Unsupported(String),
}

pub struct UdfVolume {
    pub block: u64,
    pub label: String,
    pub revision: String,
    pub size: u64,
    maps: Vec<Map>,
    root: (u64, u16),
    pub notes: Vec<String>,
    pub created: u64,
}

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
                let id = String::from_utf8_lossy(&m[5..28]).trim_end_matches('\0').to_string();
                if id.contains("Metadata") {
                    let pn = le16(m, 38);
                    let file = le32(m, 40);
                    let phys_idx = maps.iter().position(|x| matches!(x, Map::Physical { .. })).unwrap_or(0);
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
        notes: vec![],
        created,
    };
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
    let mut seen = HashSet::from([root_off]);
    let mut queue = vec![(ROOT_RECORD, String::new(), root_off, v.root.1 as usize, false)];
    let mut deleted_count = 0u64;
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
            let record = next;
            next += 1;
            if deleted {
                deleted_count += 1;
            }
            let note = if deleted && !fe_ok {
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
            if e.is_dir && fe_ok && seen.insert(child_off) && !deleted {
                queue.push((record, child_path, child_off, ipart, deleted));
            }
            // Directory hierarchy of a deleted folder is still worth reading.
            else if e.is_dir && fe_ok && deleted && seen.insert(child_off) {
                queue.push((record, child_path, child_off, ipart, true));
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
            if out.len() > MAX_ENTRIES {
                break;
            }
        }
    }
    progress(out.len() as u64, out.len() as u64);
    let mut notes = v.notes.clone();
    if deleted_count > 0 {
        notes.push(format!(
            "{} deleted UDF directory {} still {} a name; content is shown when the file entry it points to is intact, which cannot be guaranteed.",
            deleted_count,
            if deleted_count == 1 { "entry" } else { "entries" },
            if deleted_count == 1 { "holds" } else { "hold" }
        ));
    }
    let info = v.info(out.len() as u64);
    Ok(UdfScan { info, entries: out, notes })
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
}
