//! APFS (Apple File System).
//!
//! Finds the newest valid container superblock in the checkpoint area
//! (Fletcher-64 checked), resolves virtual objects through the container
//! and volume object maps, and walks each volume's file-system tree:
//! inodes, directory records, file extents, extended attributes (including
//! decmpfs compression and resource forks). A container with several
//! volumes shows each as a top-level folder.
//!
//! Deleted files: APFS never overwrites metadata in place (copy-on-write),
//! so older file-system tree nodes stay in free blocks until reused. Kokino
//! reads every checksummed leaf node of a file-system tree in the container
//! and lists directory entries and inodes the current trees no longer
//! have, with the content their old extent records point to.
//!
//! Not read yet: encrypted volumes (FileVault; reported), snapshots,
//! sealed system volumes' integrity data, Fusion drives.

use crate::decmpfs;
use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;

pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
const MAX_NODES: usize = 4 << 20;
const MAX_RECORDS: usize = 20_000_000;
const MAX_DEPTH: u16 = 16;
const ROOT_DIR: u64 = 2;

fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = Vec::with_capacity(n.min(1 << 20));
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}
fn le16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

/// Nanoseconds since 1970 to FILETIME.
fn ns_ft(ns: u64) -> u64 {
    if ns == 0 {
        return 0;
    }
    ns / 100 + 116_444_736_000_000_000
}

/// The Fletcher-64 checksum of an APFS object (over everything after its
/// first 8 bytes).
pub fn fletcher64(b: &[u8]) -> u64 {
    let (mut s1, mut s2) = (0u64, 0u64);
    for w in b[8..].chunks_exact(4) {
        s1 = (s1 + u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64) % 0xFFFF_FFFF;
        s2 = (s2 + s1) % 0xFFFF_FFFF;
    }
    let c1 = 0xFFFF_FFFF - ((s1 + s2) % 0xFFFF_FFFF);
    let c2 = 0xFFFF_FFFF - ((s1 + c1) % 0xFFFF_FFFF);
    c2 << 32 | c1
}

fn valid(b: &[u8]) -> bool {
    b.len() >= 64 && le64(b, 0) == fletcher64(b) && b.iter().any(|&x| x != 0)
}

/// One record of the file-system tree.
#[derive(Debug, Clone)]
struct Rec {
    key: Vec<u8>,
    val: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct Inode {
    #[allow(dead_code)]
    parent: u64,
    private_id: u64,
    times: Times,
    nlink: u64,
    owner: u32,
    group: u32,
    mode: u32,
    flags: u32,
    size: u64,
    name: String,
}

/// An extended attribute's value: embedded, or (data stream id, size).
type XattrVal = Result<Vec<u8>, (u64, u64)>;

#[derive(Debug, Default)]
struct Index {
    inodes: HashMap<u64, Inode>,
    /// (parent, name, file id)
    drecs: Vec<(u64, String, u64)>,
    /// dstream id -> (logical, length, physical block)
    extents: HashMap<u64, Vec<(u64, u64, u64)>>,
    /// inode -> (name, embedded data, or the dstream id of the data)
    xattrs: HashMap<u64, Vec<(String, XattrVal)>>,
}

pub struct Volume {
    pub name: String,
    pub uuid: String,
    pub role: u64,
    pub encrypted: bool,
    pub case_insensitive: bool,
    pub files: u64,
    pub dirs: u64,
    pub formatted_by: String,
    pub last_modified: u64,
    omap_tree: u64,
    xid: u64,
    root_tree: u64,
    hashed: bool,
    index: OnceLock<Index>,
}

pub struct ApfsContainer {
    pub block: u64,
    pub blocks: u64,
    pub xid: u64,
    pub uuid: String,
    pub volumes: Vec<Volume>,
    pub size: u64,
    pub notes: Vec<String>,
    /// Records from every file-system tree leaf in the container, old ones
    /// included (for deleted files); filled by `scan` or on first need.
    old: OnceLock<Index>,
}

fn uuid_text(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    let h: Vec<String> = b[..16].iter().map(|x| format!("{:02X}", x)).collect();
    format!("{}-{}-{}-{}-{}", h[0..4].concat(), h[4..6].concat(), h[6..8].concat(), h[8..10].concat(), h[10..16].concat())
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<ApfsContainer> {
    let b0 = rd(r, 0, 4096)?;
    if b0.get(32..36) != Some(b"NXSB") {
        anyhow::bail!("not an APFS container");
    }
    let block = le32(&b0, 36);
    if !(4096..=65536).contains(&block) || !block.is_power_of_two() {
        anyhow::bail!("APFS block size out of range");
    }
    // The newest valid superblock in the checkpoint descriptor area.
    let mut best = if valid(&rd(r, 0, block as usize)?) { Some(rd(r, 0, block as usize)?) } else { None };
    let (desc_blocks, desc_base) = (le32(&b0, 104) & 0x7FFF_FFFF, le64(&b0, 112));
    if le32(&b0, 104) & 0x8000_0000 == 0 {
        for i in 0..desc_blocks.min(65536) {
            let b = rd(r, desc_base.saturating_add(i).saturating_mul(block), block as usize)?;
            if b.len() == block as usize && b.get(32..36) == Some(b"NXSB") && valid(&b) && best.as_ref().is_none_or(|x| le64(&b, 16) > le64(x, 16)) {
                best = Some(b);
            }
        }
    }
    let sb = best.ok_or_else(|| anyhow::anyhow!("no valid APFS container superblock"))?;
    let mut c = ApfsContainer {
        block,
        blocks: le64(&sb, 40),
        xid: le64(&sb, 16),
        uuid: uuid_text(&sb[72..88]),
        volumes: vec![],
        size: (le64(&sb, 40).saturating_mul(block)).min(size.max(block)),
        notes: vec![],
        old: OnceLock::new(),
    };
    let omap = c.object(r, le64(&sb, 160))?;
    let omap_tree = le64(&omap, 48);
    for i in 0..le32(&sb, 180).min(100) as usize {
        let oid = le64(&sb, 184 + 8 * i);
        if oid == 0 {
            continue;
        }
        let Some(paddr) = c.omap_lookup(r, omap_tree, oid, c.xid)? else {
            c.notes.push(format!("volume object {} not found in the container object map", oid));
            continue;
        };
        let v = c.object(r, paddr)?;
        if v.get(32..36) != Some(b"APSB") {
            continue;
        }
        let incompat = le64(&v, 56);
        let vomap = c.object(r, le64(&v, 128))?;
        let fby = cstr(&v[272..304]);
        let vol = Volume {
            name: cstr(&v[704..960]),
            uuid: uuid_text(&v[240..256]),
            role: le16(&v, 964),
            encrypted: le64(&v, 264) & 1 == 0,
            case_insensitive: incompat & 1 != 0,
            files: le64(&v, 184),
            dirs: le64(&v, 192),
            formatted_by: fby,
            last_modified: ns_ft(le64(&v, 256)),
            omap_tree: le64(&vomap, 48),
            xid: le64(&v, 16),
            root_tree: le64(&v, 136),
            hashed: incompat & (1 | 8) != 0,
            index: OnceLock::new(),
        };
        if vol.encrypted {
            c.notes.push(format!("APFS volume \"{}\" is encrypted (FileVault): its files cannot be read without the password or recovery key, which Kokino does not support yet", vol.name));
        }
        c.volumes.push(vol);
    }
    if c.volumes.is_empty() {
        anyhow::bail!("APFS container has no readable volume");
    }
    Ok(c)
}

impl ApfsContainer {
    fn object<R: Read + Seek>(&self, r: &mut R, paddr: u64) -> anyhow::Result<Vec<u8>> {
        if paddr == 0 || paddr >= self.blocks {
            anyhow::bail!("object address {} outside the container", paddr);
        }
        let b = rd(r, paddr.saturating_mul(self.block), self.block as usize)?;
        if b.len() < self.block as usize || !valid(&b) {
            anyhow::bail!("object at block {} fails its checksum", paddr);
        }
        Ok(b)
    }

    /// Physical address of virtual object `oid` at transaction `xid` or before.
    fn omap_lookup<R: Read + Seek>(&self, r: &mut R, tree: u64, oid: u64, xid: u64) -> anyhow::Result<Option<u64>> {
        let mut node = tree;
        for _ in 0..MAX_DEPTH {
            let n = self.object(r, node)?;
            let recs = node_records(&n, true, self.block as usize);
            let leaf = le16(&n, 32) & 2 != 0;
            // The last key <= (oid, xid).
            let mut pick: Option<&Rec> = None;
            for rec in &recs {
                let (k_oid, k_xid) = (le64(&rec.key, 0), le64(&rec.key, 8));
                if (k_oid, k_xid) <= (oid, xid) {
                    pick = Some(rec);
                } else {
                    break;
                }
            }
            let Some(p) = pick else { return Ok(None) };
            if leaf {
                return Ok((le64(&p.key, 0) == oid).then(|| le64(&p.val, 8)));
            }
            node = le64(&p.val, 0);
        }
        Ok(None)
    }

    /// Every record of a volume's file-system tree.
    fn fs_records<R: Read + Seek>(&self, r: &mut R, v: &Volume) -> anyhow::Result<Vec<Rec>> {
        let mut out = vec![];
        let root = self.omap_lookup(r, v.omap_tree, v.root_tree, v.xid)?.ok_or_else(|| anyhow::anyhow!("file-system tree root not in the volume object map"))?;
        let mut stack = vec![(root, MAX_DEPTH)];
        let mut seen = HashSet::new();
        while let Some((paddr, depth)) = stack.pop() {
            if depth == 0 || !seen.insert(paddr) || seen.len() > MAX_NODES {
                continue;
            }
            let Ok(n) = self.object(r, paddr) else { continue };
            let recs = node_records(&n, false, self.block as usize);
            if le16(&n, 32) & 2 != 0 {
                out.extend(recs);
                if out.len() > MAX_RECORDS {
                    break;
                }
            } else {
                // Children are virtual objects of the volume.
                for rec in recs.iter().rev() {
                    if let Ok(Some(p)) = self.omap_lookup(r, v.omap_tree, le64(&rec.val, 0), v.xid) {
                        stack.push((p, depth - 1));
                    }
                }
            }
        }
        Ok(out)
    }

    fn index<'a, R: Read + Seek>(&self, r: &mut R, v: &'a Volume) -> &'a Index {
        v.index.get_or_init(|| {
            let recs = if v.encrypted { vec![] } else { self.fs_records(r, v).unwrap_or_default() };
            build_index(&recs, v.hashed)
        })
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        let names: Vec<String> = self.volumes.iter().map(|v| v.name.clone()).collect();
        NtfsVolumeInfo {
            label: names.join(", "),
            serial: self.uuid.clone(),
            version: format!("APFS, {} volume{}", self.volumes.len(), if self.volumes.len() == 1 { "" } else { "s" }),
            cluster_size: self.block as u32,
            sector_size: 512,
            record_size: self.block as u32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: 0,
            dirty: false,
        }
    }

    /// The volume and inode of an entry (`attributes` bits 24..28 hold the volume).
    fn locate(&self, e: &FsEntry) -> Option<(usize, u64)> {
        let vi = (e.attributes >> 24 & 0xF) as usize;
        Some((vi, e.unix.as_ref()?.inode))
    }

    fn dstream<R: Read + Seek>(&self, r: &mut R, v: &Volume, id: u64, size: u64) -> Vec<Extent> {
        let idx = self.index(r, v);
        let mut out = vec![];
        for &(logical, len, phys) in idx.extents.get(&id).map(|x| x.as_slice()).unwrap_or(&[]) {
            if logical >= size {
                break;
            }
            out.push(Extent { offset: logical, len: len.min(size - logical), vol: (phys != 0).then_some(phys.saturating_mul(self.block)) });
        }
        out
    }

    fn read_runs<R: Read + Seek>(&self, r: &mut R, runs: &[Extent], size: u64, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= size {
            return Ok(vec![]);
        }
        let want = (len as u64).min(size - offset) as usize;
        let end = offset + want as u64;
        let mut out = vec![0u8; want];
        for x in runs {
            let (s, t) = (x.offset.max(offset), x.offset.saturating_add(x.len).min(end));
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

    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> Vec<Extent> {
        let Some((vi, inode)) = self.locate(e) else { return vec![] };
        let Some(v) = self.volumes.get(vi) else { return vec![] };
        if e.attributes & COMPRESSED != 0 {
            return vec![];
        }
        let private = self.index(r, v).inodes.get(&inode).map(|i| i.private_id).unwrap_or(e.record_offset);
        self.dstream(r, v, private, e.size)
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if e.deleted {
            // Old extent records of its data stream (`record_offset`).
            let old = self.old.get_or_init(|| old_records(self, r, &mut |_, _| true).unwrap_or_default());
            let runs: Vec<Extent> = old.extents.get(&e.record_offset).map(|x| x.iter().filter(|x| x.0 < e.size).map(|&(l, n, p)| Extent { offset: l, len: n.min(e.size - l), vol: (p != 0).then_some(p.saturating_mul(self.block)) }).collect()).unwrap_or_default();
            return self.read_runs(r, &runs, e.size, offset, len);
        }
        let (vi, inode) = self.locate(e).ok_or_else(|| anyhow::anyhow!("not an APFS entry"))?;
        let v = self.volumes.get(vi).ok_or_else(|| anyhow::anyhow!("no such volume"))?;
        if e.attributes & COMPRESSED != 0 {
            let x = self.xattr(r, v, inode, decmpfs::XATTR).ok_or_else(|| anyhow::anyhow!("compression attribute missing"))?;
            let rsrc = self.xattr(r, v, inode, decmpfs::RSRC);
            let all = decmpfs::decompress(&x, rsrc.as_deref())?;
            return Ok(all.get(offset as usize..).map(|b| b[..b.len().min(len)].to_vec()).unwrap_or_default());
        }
        let runs = self.extents(r, e);
        self.read_runs(r, &runs, e.size, offset, len)
    }

    fn xattr<R: Read + Seek>(&self, r: &mut R, v: &Volume, inode: u64, name: &str) -> Option<Vec<u8>> {
        let idx = self.index(r, v);
        let (_, val) = idx.xattrs.get(&inode)?.iter().find(|(n, _)| n == name)?.clone();
        match val {
            Ok(d) => Some(d),
            Err((id, size)) => {
                let runs = self.dstream(r, v, id, size);
                self.read_runs(r, &runs, size, 0, size.min(decmpfs::MAX_SIZE) as usize).ok()
            }
        }
    }

    /// Extended attributes (name, value) of an inode on volume `vi`.
    pub fn xattrs_of<R: Read + Seek>(&self, r: &mut R, vi: usize, inode: u64) -> Vec<(String, Vec<u8>)> {
        let Some(v) = self.volumes.get(vi) else { return vec![] };
        let names: Vec<String> = self.index(r, v).xattrs.get(&inode).map(|x| x.iter().map(|(n, _)| n.clone()).collect()).unwrap_or_default();
        names.into_iter().filter_map(|n| self.xattr(r, v, inode, &n).map(|d| (n, d))).collect()
    }
}

/// `attributes` bit: content is compressed (decmpfs).
pub const COMPRESSED: u32 = 1 << 30;

/// Records of a B-tree node. `fixed`: object-map nodes (16-byte keys,
/// 16-byte values, or 8-byte child addresses in index nodes).
fn node_records(n: &[u8], fixed: bool, block: usize) -> Vec<Rec> {
    let flags = le16(n, 32);
    let nkeys = le32(n, 36) as usize;
    let (toc_off, toc_len) = (le16(n, 40) as usize, le16(n, 42) as usize);
    let toc = 56 + toc_off;
    let keys = toc + toc_len;
    let vals_end = if flags & 1 != 0 { block.saturating_sub(40) } else { block };
    let leaf = flags & 2 != 0;
    let fixed = fixed || flags & 4 != 0;
    let mut out = vec![];
    for i in 0..nkeys.min(4096) {
        let (k, kl, v, vl) = if fixed {
            let e = toc + 4 * i;
            (le16(n, e) as usize, 16usize, le16(n, e + 2) as usize, if leaf { 16 } else { 8 })
        } else {
            let e = toc + 8 * i;
            (le16(n, e) as usize, le16(n, e + 2) as usize, le16(n, e + 4) as usize, le16(n, e + 6) as usize)
        };
        let (Some(key), Some(vs)) = (n.get(keys + k..keys + k + kl), vals_end.checked_sub(v)) else { continue };
        let Some(val) = n.get(vs..vs + vl) else { continue };
        out.push(Rec { key: key.to_vec(), val: val.to_vec() });
    }
    out
}

fn build_index(recs: &[Rec], hashed: bool) -> Index {
    let mut idx = Index::default();
    for rec in recs {
        let hdr = le64(&rec.key, 0);
        let (oid, ty) = (hdr & 0x0FFF_FFFF_FFFF_FFFF, hdr >> 60);
        let v = &rec.val;
        match ty {
            3 => {
                let mut ino = Inode {
                    parent: le64(v, 0),
                    private_id: le64(v, 8),
                    times: Times { created: ns_ft(le64(v, 16)), modified: ns_ft(le64(v, 24)), mft_modified: ns_ft(le64(v, 32)), accessed: ns_ft(le64(v, 40)) },
                    nlink: le32(v, 56),
                    flags: le32(v, 68) as u32,
                    owner: le32(v, 72) as u32,
                    group: le32(v, 76) as u32,
                    mode: le16(v, 80) as u32,
                    ..Default::default()
                };
                // Extended fields: name and data stream.
                for (t, d) in xfields(v.get(92..).unwrap_or(&[])) {
                    match t {
                        4 => ino.name = cstr(d),
                        8 => ino.size = le64(d, 0),
                        _ => {}
                    }
                }
                idx.inodes.insert(oid, ino);
            }
            9 => {
                let name = if hashed {
                    let nl = (le32(&rec.key, 8) & 0x3FF) as usize;
                    cstr(rec.key.get(12..12 + nl).unwrap_or(&[]))
                } else {
                    let nl = le16(&rec.key, 8) as usize;
                    cstr(rec.key.get(10..10 + nl).unwrap_or(&[]))
                };
                idx.drecs.push((oid, name, le64(v, 0)));
            }
            8 => {
                let len = le64(v, 0) & 0x00FF_FFFF_FFFF_FFFF;
                idx.extents.entry(oid).or_default().push((le64(&rec.key, 8), len, le64(v, 8)));
            }
            4 => {
                let nl = le16(&rec.key, 8) as usize;
                let name = cstr(rec.key.get(10..10 + nl).unwrap_or(&[]));
                let (flags, dl) = (le16(v, 0), le16(v, 2) as usize);
                let data = v.get(4..4 + dl).unwrap_or(&[]);
                let val = if flags & 1 != 0 { Err((le64(data, 0), le64(data, 8))) } else { Ok(data.to_vec()) };
                idx.xattrs.entry(oid).or_default().push((name, val));
            }
            _ => {}
        }
    }
    for list in idx.extents.values_mut() {
        list.sort_unstable();
        list.dedup();
    }
    idx
}

/// Extended fields of an inode or directory record: (type, data).
fn xfields(b: &[u8]) -> Vec<(u8, &[u8])> {
    let n = le16(b, 0) as usize;
    let mut out = vec![];
    let mut data = 4 + 4 * n;
    for i in 0..n.min(64) {
        let (t, size) = (b.get(4 + 4 * i).copied().unwrap_or(0), le16(b, 6 + 4 * i) as usize);
        if let Some(d) = b.get(data..data + size) {
            out.push((t, d));
        }
        data += (size + 7) & !7;
    }
    out
}

pub struct ApfsScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    pub notes: Vec<String>,
}

pub fn scan<R: Read + Seek>(c: &ApfsContainer, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<ApfsScan> {
    let mut out = vec![dir_entry(ROOT_RECORD, ROOT_RECORD, "/".into(), ".".into())];
    let mut next = FIRST_RECORD;
    let mut notes = c.notes.clone();
    let multi = c.volumes.len() > 1;
    // Old leaf nodes of file-system trees, for deleted entries.
    if c.old.get().is_none() {
        let found = old_records(c, r, &mut progress)?;
        let _ = c.old.set(found);
    }
    let old = c.old.get().unwrap();
    for (vi, v) in c.volumes.iter().enumerate() {
        if v.encrypted {
            continue;
        }
        let idx = c.index(r, v);
        let base_rec = if multi {
            let rec = next;
            next += 1;
            out.push(dir_entry(rec, ROOT_RECORD, format!("/{}", v.name), v.name.clone()));
            rec
        } else {
            ROOT_RECORD
        };
        let base_path = if multi { format!("/{}", v.name) } else { String::new() };
        let mut children: BTreeMap<u64, Vec<(&str, u64)>> = BTreeMap::new();
        for (parent, name, id) in &idx.drecs {
            children.entry(*parent).or_default().push((name.as_str(), *id));
        }
        let mut stack = vec![(ROOT_DIR, base_rec, base_path.clone())];
        let mut seen = HashSet::new();
        while let Some((dir, rec, path)) = stack.pop() {
            if !seen.insert(dir) {
                continue;
            }
            for (name, id) in children.get(&dir).cloned().unwrap_or_default() {
                let p = format!("{}/{}", path, name.replace('/', ":"));
                let record = next;
                next += 1;
                let ino = idx.inodes.get(&id).cloned().unwrap_or_default();
                let e = file_entry(c, r, v, vi, &ino, id, record, rec, p.clone(), name.to_string(), false);
                if e.is_dir {
                    stack.push((id, record, p));
                }
                out.push(e);
            }
            if out.len() % 4096 == 0 && !progress(out.len() as u64, out.len() as u64) {
                anyhow::bail!("scan cancelled");
            }
        }
        // Deleted: directory records and inodes only older nodes have.
        let live_names: HashSet<(u64, &str)> = idx.drecs.iter().map(|(p, n, _)| (*p, n.as_str())).collect();
        let mut found = 0;
        let mut path_of: HashMap<u64, (u64, String)> = HashMap::new();
        for e in out.iter().filter(|e| e.is_dir) {
            if let Some(u) = &e.unix {
                path_of.insert(u.inode, (e.record, e.path.clone()));
            }
        }
        path_of.insert(ROOT_DIR, (base_rec, base_path.clone()));
        let mut done = HashSet::new();
        for (parent, name, id) in &old.drecs {
            if live_names.contains(&(*parent, name.as_str())) || idx.inodes.contains_key(id) || !done.insert((*parent, name.clone())) {
                continue;
            }
            let Some(ino) = old.inodes.get(id) else { continue };
            let (prec, ppath, orphan) = match path_of.get(parent) {
                Some((r2, p)) => (*r2, p.clone(), false),
                None => (ROOT_RECORD, format!("{}/{}", base_path, kokino_ntfs::ORPHAN_ROOT), true),
            };
            let record = next;
            next += 1;
            let mut e = file_entry(c, r, v, vi, ino, *id, record, prec, format!("{}/{}", ppath, name), name.clone(), true);
            e.orphan = orphan;
            e.error = Some("found in an older copy of the file-system tree (APFS writes changes to new blocks); its content is read from the extents that copy names, which may since have been reused".into());
            // Content of old files comes from old extent records.
            if !e.is_dir {
                if let Some(s) = e.streams.first_mut() {
                    s.first_offset = old.extents.get(&ino.private_id).and_then(|x| x.first()).map(|x| x.2.saturating_mul(c.block));
                }
                e.record_offset = ino.private_id;
            }
            out.push(e);
            found += 1;
        }
        if found > 0 {
            notes.push(format!("{} deleted file(s) and folder(s) on \"{}\" found in older copies of its file-system tree.", found, v.name));
        }
    }
    progress(out.len() as u64, out.len() as u64);
    let info = c.info(out.len() as u64);
    Ok(ApfsScan { info, entries: out, notes })
}

/// Every checksummed leaf node of a file-system tree anywhere in the
/// container, older ones included.
fn old_records<R: Read + Seek>(c: &ApfsContainer, r: &mut R, progress: &mut impl FnMut(u64, u64) -> bool) -> anyhow::Result<Index> {
    let mut recs = vec![];
    let chunk = 256u64;
    let mut b = 0u64;
    while b < c.blocks {
        let n = chunk.min(c.blocks - b);
        let buf = rd(r, b.saturating_mul(c.block), (n * c.block) as usize)?;
        for blk in buf.chunks_exact(c.block as usize) {
            // B-tree root (type 2) or node (type 3) of a file-system tree
            // (subtype 0x0E), leaf.
            if matches!(le32(blk, 24) & 0xFFFF, 2 | 3) && le32(blk, 28) == 0x0E && le16(blk, 32) & 2 != 0 && valid(blk) {
                recs.extend(node_records(blk, false, c.block as usize));
            }
        }
        b += n;
        if (b / chunk).is_multiple_of(64) && !progress(b, c.blocks) {
            anyhow::bail!("scan cancelled");
        }
        if recs.len() > MAX_RECORDS {
            break;
        }
    }
    Ok(build_index(&recs, true))
}

fn dir_entry(record: u64, parent: u64, path: String, name: String) -> FsEntry {
    FsEntry {
        record,
        seq: 0,
        parent,
        parent_seq: 0,
        name,
        dos_name: None,
        path,
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
        record_offset: 0,
        error: None,
        unix: None,
        name_only: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn file_entry<R: Read + Seek>(c: &ApfsContainer, r: &mut R, v: &Volume, vi: usize, ino: &Inode, id: u64, record: u64, parent: u64, path: String, name: String, deleted: bool) -> FsEntry {
    let is_dir = ino.mode & 0o170000 == 0o040000;
    let idx = c.index(r, v);
    let compressed = !is_dir && ino.flags & 0x20 != 0 && !deleted;
    // The compression header may be inline or in its own data stream.
    let size = if compressed { c.xattr(r, v, id, decmpfs::XATTR).and_then(|a| decmpfs::header(&a).map(|h| h.1)).unwrap_or(ino.size) } else { ino.size };
    let first = if is_dir || compressed { None } else { idx.extents.get(&ino.private_id).and_then(|x| x.first()).map(|x| x.2.saturating_mul(c.block)) };
    let link_target = (ino.mode & 0o170000 == 0o120000)
        .then(|| idx.xattrs.get(&id).and_then(|x| x.iter().find(|(n, _)| n == "com.apple.fs.symlink")).and_then(|(_, val)| val.as_ref().ok().map(|d| cstr(d))))
        .flatten();
    let quarantine = idx.xattrs.get(&id).is_some_and(|x| x.iter().any(|(n, _)| n == "com.apple.quarantine"));
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
        alloc_size: size.div_ceil(c.block).saturating_mul(c.block),
        resident: false,
        attributes: if is_dir { 0x10 } else { 0 } | if compressed { COMPRESSED | 0x800 } else { 0 } | if quarantine { 1 << 29 } else { 0 } | ((vi as u32) & 0xF) << 24,
        hard_links: if is_dir { 1 } else { ino.nlink.max(1) as u16 },
        usn: None,
        si: Some(ino.times),
        fname: None,
        streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset: first }] },
        has_reparse: false,
        record_offset: 0,
        error: None,
        unix: Some(UnixMeta { inode: id, mode: ino.mode, uid: ino.owner, gid: ino.group, deleted_time: 0, inode_offset: 0, journal_seq: None, link_target }),
        name_only: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum() {
        // An all-zero block with a correct Fletcher-64 is still rejected as empty.
        let b = vec![0u8; 4096];
        assert!(!valid(&b));
    }

    #[test]
    fn apfs_fixture() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/apfs.img");
        let Ok(mut f) = std::fs::File::open(&p) else { return };
        // GPT: the APFS partition starts at LBA 40 (20 KiB in).
        let gpt = rd(&mut f, 1024, 128).unwrap();
        let start = le64(&gpt, 32) * 512;
        let len = (le64(&gpt, 40) + 1) * 512 - start;
        let mut part = kokino_core_sub(f, start, len);
        let c = open(&mut part, len).unwrap();
        assert_eq!(c.volumes.len(), 1);
        assert_eq!(c.volumes[0].name, "KOKINO_APFS");
        let s = scan(&c, &mut part, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let read = |r: &mut Sub, e: &FsEntry| c.read(r, e, 0, e.size as usize).unwrap();
        assert_eq!(read(&mut part, by("/Documents/report.txt")), (b"Quarterly report line, lab.test internal.\n".repeat(220))[..9000].to_vec());
        assert_eq!(read(&mut part, by("/Documents/deep/a/b/c/notes.txt")), b"deep note\n");
        assert_eq!(read(&mut part, by("/Documents/hello-link.txt")), b"Hello from the Kokino macOS test volume.\n");
        assert_eq!(by("/hello.txt").unix.as_ref().unwrap().inode, 16);
        assert_eq!(by("/hello.txt").hard_links, 2);
        let comp = by("/compressed.txt");
        assert_eq!(comp.size, 64000);
        assert_eq!(read(&mut part, comp), b"compressible line for decmpfs, lab.test\n".repeat(1600));
        assert_eq!(by("/link").unix.as_ref().unwrap().link_target.as_deref(), Some("Documents/report.txt"));
        assert_eq!(kokino_core::time::filetime_to_iso(by("/hello.txt").si.unwrap().modified), "2026-10-20T08:06:30.0000000Z");
        let xa = c.xattrs_of(&mut part, 0, 16);
        assert!(xa.iter().any(|(n, v)| n == "com.apple.quarantine" && v.starts_with(b"0083;")));
        let gone = s.entries.iter().find(|e| e.name == "secret.txt").expect("deleted secret.txt");
        assert!(gone.deleted);
        assert_eq!(read(&mut part, gone), b"SECRET: meet at the lab.test office, 10:00 (test data)\n");
    }

    type Sub = SubFile;
    pub struct SubFile {
        f: std::fs::File,
        start: u64,
        len: u64,
        pos: u64,
    }
    fn kokino_core_sub(f: std::fs::File, start: u64, len: u64) -> SubFile {
        SubFile { f, start, len, pos: 0 }
    }
    impl Read for SubFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.len {
                return Ok(0);
            }
            let n = ((self.len - self.pos) as usize).min(buf.len());
            self.f.seek(SeekFrom::Start(self.start + self.pos))?;
            let got = self.f.read(&mut buf[..n])?;
            self.pos += got as u64;
            Ok(got)
        }
    }
    impl Seek for SubFile {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            self.pos = match p {
                SeekFrom::Start(x) => x,
                SeekFrom::End(d) => (self.len as i64 + d) as u64,
                SeekFrom::Current(d) => (self.pos as i64 + d) as u64,
            };
            Ok(self.pos)
        }
    }
}
