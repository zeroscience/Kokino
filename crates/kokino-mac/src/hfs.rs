//! HFS+ and HFSX (Mac OS Extended).
//!
//! Walks the catalog B-tree from its leaf chain, follows the extents
//! overflow file for fragmented forks, reads extended attributes from the
//! attributes B-tree, resolves hard links through the private "iNode"
//! files, and decompresses decmpfs files. Deleted files: HFS+ removes a
//! catalog record by compacting its node, so old records survive only in
//! copies of catalog nodes, most often in the journal and in catalog nodes
//! no longer in use. Kokino reads every such copy and lists the files the
//! live catalog no longer has, with the content their extents point to and
//! a warning when those blocks are allocated again.
//!
//! Times: seconds since 1904-01-01 UTC (the volume creation date alone is
//! local time).

use crate::decmpfs;
use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
const MAX_ENTRIES: usize = 5_000_000;
const MAX_BTREE: u64 = 1 << 30;
/// Seconds from 1904-01-01 to 1970-01-01.
const HFS_EPOCH: i64 = 2_082_844_800;

pub(crate) fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = Vec::with_capacity(n.min(1 << 20));
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}
fn be16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_be_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
fn be32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn be64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_be_bytes(x.try_into().unwrap())).unwrap_or(0)
}

fn hfs_time(t: u64) -> u64 {
    if t == 0 {
        return 0;
    }
    ((t as i64 - HFS_EPOCH) as i128 * 10_000_000 + 116_444_736_000_000_000).clamp(0, u64::MAX as i128) as u64
}

/// A fork: logical size and its extents (start block, block count).
#[derive(Debug, Clone, Default)]
pub struct Fork {
    pub size: u64,
    pub extents: Vec<(u64, u64)>,
}

fn fork(b: &[u8], o: usize) -> Fork {
    let mut f = Fork { size: be64(b, o), extents: vec![] };
    for i in 0..8 {
        let (s, n) = (be32(b, o + 16 + 8 * i), be32(b, o + 20 + 8 * i));
        if n == 0 {
            break;
        }
        f.extents.push((s, n));
    }
    f
}

pub struct HfsVolume {
    pub block: u64,
    pub blocks: u64,
    pub hfsx: bool,
    pub journaled: bool,
    pub dirty: bool,
    pub created: u64,
    pub modified: u64,
    pub label: String,
    pub uuid: String,
    pub size: u64,
    catalog: Fork,
    alloc: Fork,
    journal: Option<(u64, u64)>,
    /// (file id, fork type 0 data / 0xFF resource) -> extents past the first eight.
    overflow: HashMap<(u64, u8), Vec<(u64, u64)>>,
    /// file id -> (name, inline data or a fork).
    xattrs: HashMap<u64, Vec<(String, XattrData)>>,
    node_size: u64,
}

#[derive(Debug, Clone)]
pub enum XattrData {
    Inline(Vec<u8>),
    Fork(Fork),
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<HfsVolume> {
    let vh = rd(r, 1024, 512)?;
    if vh.len() < 512 {
        anyhow::bail!("volume too small for an HFS+ header");
    }
    let sig = &vh.get(0..2).unwrap_or(&[]);
    if *sig != b"H+" && *sig != b"HX" {
        anyhow::bail!("not an HFS+ volume header");
    }
    let block = be32(&vh, 40);
    let blocks = be32(&vh, 44);
    if !(512..=1 << 20).contains(&block) || !block.is_power_of_two() || blocks == 0 {
        anyhow::bail!("HFS+ block size out of range");
    }
    let attrs = be32(&vh, 4);
    let fi = &vh[80..112];
    let uuid: String = fi[24..32].iter().map(|b| format!("{:02X}", b)).collect();
    let mut v = HfsVolume {
        block,
        blocks,
        hfsx: *sig == b"HX",
        journaled: attrs & 0x2000 != 0,
        dirty: attrs & 0x100 == 0,
        created: hfs_time(be32(&vh, 16)),
        modified: hfs_time(be32(&vh, 20)),
        label: String::new(),
        uuid,
        size: (blocks * block).min(size.max(block)),
        catalog: fork(&vh, 272),
        alloc: fork(&vh, 112),
        journal: None,
        overflow: HashMap::new(),
        xattrs: HashMap::new(),
        node_size: 4096,
    };
    if v.journaled {
        let jib = rd(r, be32(&vh, 12) * block, 512)?;
        let (off, len) = (be64(&jib, 36), be64(&jib, 44));
        if off > 0 && len > 0 && off < v.size {
            v.journal = Some((off, len.min(v.size - off)));
        }
    }
    // Extents overflow file: extents past the eighth of any fork.
    let ext = fork(&vh, 192);
    for rec in leaf_records(r, &v, &ext)? {
        let (key, data) = rec;
        if key.len() >= 12 {
            let (ftype, id, _start) = (key[2], be32(&key, 4), be32(&key, 8));
            let list = v.overflow.entry((id, ftype)).or_default();
            for i in 0..8 {
                let (s, n) = (be32(&data, 8 * i), be32(&data, 8 * i + 4));
                if n == 0 {
                    break;
                }
                list.push((s, n));
            }
        }
    }
    // Attributes file: extended attributes.
    let attr_fork = fork(&vh, 352);
    if attr_fork.size > 0 {
        for (key, data) in leaf_records(r, &v, &attr_fork)? {
            if key.len() < 14 {
                continue;
            }
            let id = be32(&key, 4);
            let nlen = be16(&key, 12) as usize;
            let name = utf16(key.get(14..14 + 2 * nlen).unwrap_or(&[]));
            let val = match be32(&data, 0) {
                0x10 => {
                    let n = be32(&data, 12) as usize;
                    XattrData::Inline(data.get(16..16 + n).unwrap_or(&[]).to_vec())
                }
                0x20 => XattrData::Fork(fork(&data, 8)),
                _ => continue,
            };
            v.xattrs.entry(id).or_default().push((name, val));
        }
    }
    // Volume name: the root folder's record sits under parent 1 with it as its name.
    v.node_size = header_node(r, &v, &v.catalog.clone())?.map(|h| be16(&h, 32)).unwrap_or(4096);
    for (key, data) in leaf_records(r, &v, &v.catalog.clone())? {
        if be32(&key, 2) == 1 && be16(&data, 0) == 1 {
            v.label = utf16(key.get(8..8 + 2 * be16(&key, 6) as usize).unwrap_or(&[]));
            break;
        }
    }
    Ok(v)
}

fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&w)
}

impl HfsVolume {
    /// Byte runs of a fork (with its overflow extents) on the volume.
    pub fn fork_runs(&self, f: &Fork, id: u64, ftype: u8) -> Vec<Extent> {
        let mut out = vec![];
        let mut logical = 0u64;
        let extra = self.overflow.get(&(id, ftype)).cloned().unwrap_or_default();
        for (s, n) in f.extents.iter().chain(extra.iter()) {
            if logical >= f.size || *s >= self.blocks {
                break;
            }
            let len = (n * self.block).min(f.size - logical);
            out.push(Extent { offset: logical, len, vol: Some(s * self.block) });
            logical += n * self.block;
        }
        out
    }

    fn read_fork<R: Read + Seek>(&self, r: &mut R, f: &Fork, id: u64, ftype: u8, max: u64) -> std::io::Result<Vec<u8>> {
        let mut out = vec![];
        for x in self.fork_runs(f, id, ftype) {
            if out.len() as u64 >= max {
                break;
            }
            out.extend(rd(r, x.vol.unwrap(), x.len.min(max - out.len() as u64) as usize)?);
        }
        Ok(out)
    }

    fn xattr<R: Read + Seek>(&self, r: &mut R, id: u64, name: &str) -> Option<Vec<u8>> {
        let (_, v) = self.xattrs.get(&id)?.iter().find(|(n, _)| n == name)?;
        match v {
            XattrData::Inline(d) => Some(d.clone()),
            XattrData::Fork(f) => self.read_fork(r, f, id, 0, 64 << 20).ok(),
        }
    }

    /// Block is in use according to the allocation file.
    pub fn allocated<R: Read + Seek>(&self, r: &mut R, b: u64) -> bool {
        let byte = b / 8;
        let Some(x) = self.fork_runs(&self.alloc, 6, 0).into_iter().find(|x| byte >= x.offset && byte < x.offset + x.len) else { return true };
        rd(r, x.vol.unwrap() + byte - x.offset, 1).ok().and_then(|v| v.first().copied()).map(|v| v & (0x80 >> (b % 8)) != 0).unwrap_or(true)
    }

    pub fn free_runs<R: Read + Seek>(&self, r: &mut R) -> Vec<(u64, u64)> {
        let Ok(bm) = self.read_fork(r, &self.alloc, 6, 0, 512 << 20) else { return vec![] };
        let mut out = vec![];
        let mut start: Option<u64> = None;
        for b in 0..self.blocks.min(bm.len() as u64 * 8) {
            let used = bm[(b / 8) as usize] & (0x80 >> (b % 8)) != 0;
            match (used, start) {
                (false, None) => start = Some(b),
                (true, Some(s)) => {
                    out.push((s * self.block, (b - s) * self.block));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = start {
            out.push((s * self.block, (self.blocks - s) * self.block));
        }
        out
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: self.uuid.clone(),
            version: format!("{}{}", if self.hfsx { "HFSX (case-sensitive)" } else { "HFS+" }, if self.journaled { ", journaled" } else { "" }),
            cluster_size: self.block as u32,
            sector_size: 512,
            record_size: self.node_size as u32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: self.catalog.extents.first().map(|e| e.0 * self.block).unwrap_or(0),
            dirty: self.dirty,
        }
    }

    /// The file's content: its data fork, or decompressed when it uses
    /// HFS compression. `record_offset` is where its catalog record is.
    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= e.size {
            return Ok(vec![]);
        }
        let want = (len as u64).min(e.size - offset) as usize;
        let rec = rd(r, e.record_offset, 248)?;
        let id = be32(&rec, 8);
        if e.attributes & COMPRESSED != 0 {
            let attr = self.xattr(r, id, decmpfs::XATTR).ok_or_else(|| anyhow::anyhow!("compression attribute missing"))?;
            let rsrc = fork(&rec, 168);
            let rdata = if rsrc.size > 0 { Some(self.read_fork(r, &rsrc, id, 0xFF, decmpfs::MAX_SIZE)?) } else { None };
            let all = decmpfs::decompress(&attr, rdata.as_deref())?;
            return Ok(all.get(offset as usize..).map(|x| x[..x.len().min(want)].to_vec()).unwrap_or_default());
        }
        let data = fork(&rec, 88);
        let mut out = Vec::with_capacity(want);
        for x in self.fork_runs(&data, id, 0) {
            let pos = offset + out.len() as u64;
            if out.len() >= want || pos >= x.offset + x.len || pos < x.offset {
                continue;
            }
            let n = ((x.offset + x.len - pos) as usize).min(want - out.len());
            out.extend(rd(r, x.vol.unwrap() + (pos - x.offset), n)?);
        }
        Ok(out)
    }

    /// The resource fork ("rsrc" stream).
    pub fn read_rsrc<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let rec = rd(r, e.record_offset, 248)?;
        let f = fork(&rec, 168);
        let all = self.read_fork(r, &f, be32(&rec, 8), 0xFF, (offset + len as u64).min(f.size))?;
        Ok(all.get(offset as usize..).map(|x| x.to_vec()).unwrap_or_default())
    }

    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> Vec<Extent> {
        if e.attributes & COMPRESSED != 0 {
            return vec![];
        }
        let Ok(rec) = rd(r, e.record_offset, 248) else { return vec![] };
        self.fork_runs(&fork(&rec, 88), be32(&rec, 8), 0)
    }
}

/// `attributes` bit: content is HFS-compressed (decmpfs).
pub const COMPRESSED: u32 = 1 << 30;

fn header_node<R: Read + Seek>(r: &mut R, v: &HfsVolume, f: &Fork) -> anyhow::Result<Option<Vec<u8>>> {
    let first = rd(r, f.extents.first().map(|e| e.0 * v.block).unwrap_or(0), 512)?;
    if first.len() < 46 || first[8] != 1 {
        return Ok(None);
    }
    let node_size = be16(&first, 32);
    Ok(Some(first).filter(|_| (512..=32768).contains(&node_size)))
}

/// Every record in the leaf chain of a B-tree file: (key, data).
fn leaf_records<R: Read + Seek>(r: &mut R, v: &HfsVolume, f: &Fork) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let Some(h) = header_node(r, v, f)? else { return Ok(vec![]) };
    let node_size = be16(&h, 32);
    let file = v.read_fork(r, f, 0, 0, f.size.min(MAX_BTREE))?;
    let mut out = vec![];
    let mut node = be32(&h, 24); // first leaf
    let mut seen = HashSet::new();
    while node != 0 && seen.insert(node) {
        let Some(n) = file.get((node * node_size) as usize..((node + 1) * node_size) as usize) else { break };
        if n[8] != 0xFF {
            break;
        }
        out.extend(node_records(n).into_iter().map(|(_, k, d)| (k.to_vec(), d.to_vec())));
        node = be32(n, 0);
    }
    Ok(out)
}

/// Records of one node: (offset in node, key, data). Keys are prefixed by a
/// 16-bit length; data starts at the next even offset.
fn node_records(n: &[u8]) -> Vec<(usize, &[u8], &[u8])> {
    let ns = n.len();
    let count = be16(n, 10) as usize;
    let mut out = vec![];
    // Offsets are stored from the end of the node, one more than records.
    for i in 0..count.min((ns / 2).saturating_sub(1)) {
        let start = be16(n, ns - 2 * (i + 1)) as usize;
        let end = be16(n, ns - 2 * (i + 2)) as usize;
        if start < 14 || end <= start || end > ns {
            continue;
        }
        let rec = &n[start..end];
        let kl = be16(rec, 0) as usize + 2;
        let ds = kl + (kl & 1);
        if ds > rec.len() {
            continue;
        }
        out.push((start, &rec[..kl.min(rec.len())], &rec[ds..]));
    }
    out
}

pub struct HfsScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    pub notes: Vec<String>,
}

/// A catalog record found somewhere: where, its parent and name, and the
/// record bytes (folder or file).
#[derive(Clone)]
struct Cat {
    off: u64,
    parent: u64,
    name: String,
    data: Vec<u8>,
}

const PRIVATE_FILES: &str = "\0\0\0\0HFS+ Private Data";
const PRIVATE_DIRS: &str = ".HFS+ Private Directory Data\r";

pub fn scan<R: Read + Seek>(v: &HfsVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<HfsScan> {
    let h = header_node(r, v, &v.catalog)?.ok_or_else(|| anyhow::anyhow!("catalog header node missing"))?;
    let ns = be16(&h, 32);
    let runs = v.fork_runs(&v.catalog, 4, 0);
    let file = v.read_fork(r, &v.catalog, 4, 0, v.catalog.size.min(MAX_BTREE))?;
    let vol_off = |logical: u64| runs.iter().find(|x| logical >= x.offset && logical < x.offset + x.len).map(|x| x.vol.unwrap() + logical - x.offset);
    // Live records: the leaf chain.
    let mut live: Vec<Cat> = vec![];
    let mut node = be32(&h, 24);
    let mut seen_nodes = HashSet::new();
    while node != 0 && seen_nodes.insert(node) {
        let Some(n) = file.get((node * ns) as usize..((node + 1) * ns) as usize) else { break };
        if n[8] != 0xFF {
            break;
        }
        for (o, k, d) in node_records(n) {
            let t = be16(d, 0);
            if t == 1 || t == 2 {
                let off = vol_off(node * ns + o as u64 + k.len() as u64 + (k.len() & 1) as u64).unwrap_or(0);
                live.push(Cat { off, parent: be32(k, 2), name: utf16(k.get(8..8 + 2 * be16(k, 6) as usize).unwrap_or(&[])), data: d.to_vec() });
            }
        }
        node = be32(n, 0);
        if live.len() > MAX_ENTRIES {
            break;
        }
    }
    progress(live.len() as u64, live.len() as u64 * 2);
    let live_ids: HashSet<u64> = live.iter().map(|c| be32(&c.data, 8)).collect();
    // Older copies of catalog leaf nodes: unused nodes of the catalog file
    // and copies in the journal.
    let mut old: Vec<Cat> = vec![];
    let scan_nodes = |buf: &[u8], base: Option<u64>, step: usize, old: &mut Vec<Cat>| {
        let mut p = 0usize;
        while p + ns as usize <= buf.len() {
            let n = &buf[p..p + ns as usize];
            // A leaf node whose first record starts right after the descriptor.
            if n[8] == 0xFF && n[9] == 1 && be16(n, ns as usize - 2) == 14 && be16(n, 10) > 0 {
                for (o, k, d) in node_records(n) {
                    let t = be16(d, 0);
                    if t != 2 || d.len() < 248 {
                        continue;
                    }
                    let id = be32(d, 8);
                    if live_ids.contains(&id) || old.iter().any(|c| be32(&c.data, 8) == id) {
                        continue;
                    }
                    let off = match base {
                        Some(b) => b + (p + o + k.len() + (k.len() & 1)) as u64,
                        None => vol_off((p + o + k.len() + (k.len() & 1)) as u64).unwrap_or(0),
                    };
                    old.push(Cat { off, parent: be32(k, 2), name: utf16(k.get(8..8 + 2 * be16(k, 6) as usize).unwrap_or(&[])), data: d.to_vec() });
                }
                p += ns as usize;
            } else {
                p += step;
            }
        }
    };
    scan_nodes(&file, None, ns as usize, &mut old);
    if let Some((joff, jlen)) = v.journal {
        let j = rd(r, joff, jlen.min(256 << 20) as usize)?;
        scan_nodes(&j, Some(joff), 512, &mut old);
    }
    // Build the tree.
    let mut out = vec![];
    let root = live.iter().find(|c| be32(&c.data, 8) == 2 && be16(&c.data, 0) == 1).cloned();
    out.push(entry(v, r, root.as_ref(), ROOT_RECORD, ROOT_RECORD, "/".into(), ".".into(), false));
    let mut path_of: HashMap<u64, (u64, String)> = HashMap::from([(2, (ROOT_RECORD, String::new()))]);
    let mut by_parent: HashMap<u64, Vec<&Cat>> = HashMap::new();
    for c in &live {
        by_parent.entry(c.parent).or_default().push(c);
    }
    // Hard link targets: iNode<n> in the private folder.
    let private = live.iter().find(|c| c.parent == 2 && c.name == PRIVATE_FILES).map(|c| be32(&c.data, 8));
    let inodes: HashMap<u64, &Cat> = live.iter().filter(|c| Some(c.parent) == private && c.name.starts_with("iNode")).filter_map(|c| c.name[5..].parse().ok().map(|n| (n, c))).collect();
    let mut next = FIRST_RECORD;
    let mut queue = vec![2u64];
    let mut walked = HashSet::new();
    while let Some(dir) = queue.pop() {
        if !walked.insert(dir) {
            continue;
        }
        let (rec, path) = path_of.get(&dir).cloned().unwrap_or((ROOT_RECORD, String::new()));
        for c in by_parent.get(&dir).cloned().unwrap_or_default() {
            let display = match c.name.as_str() {
                PRIVATE_FILES => "[HFS+ Private Data]".to_string(),
                PRIVATE_DIRS => "[HFS+ Private Directory Data]".to_string(),
                n => n.replace('/', ":"),
            };
            let p = if path.is_empty() { display.clone() } else { format!("{}/{}", path, display) };
            let record = next;
            next += 1;
            // A hard link points at its iNode file for content and times.
            let target = if be16(&c.data, 0) == 2 && &c.data[48..56] == b"hlnkhfs+" { inodes.get(&be32(&c.data, 44)).copied() } else { None };
            let mut e = entry(v, r, Some(target.unwrap_or(c)), record, rec, format!("/{}", p), display, false);
            if let Some(t) = target {
                // The iNode file's BSD "special" field counts its links.
                e.hard_links = be32(&t.data, 44).max(2) as u16;
            }
            if be16(&c.data, 0) == 1 {
                path_of.insert(be32(&c.data, 8), (record, p));
                queue.push(be32(&c.data, 8));
            }
            out.push(e);
            if out.len() > MAX_ENTRIES {
                break;
            }
        }
        if out.len() % 4096 == 0 && !progress(out.len() as u64, live.len() as u64 * 2) {
            anyhow::bail!("scan cancelled");
        }
    }
    // Deleted files from older node copies.
    let mut notes = vec![];
    let mut reused = 0;
    for c in &old {
        let (parent_rec, parent_path, orphan) = match path_of.get(&c.parent) {
            Some((rec, p)) => (*rec, p.clone(), false),
            None => (ROOT_RECORD, kokino_ntfs::ORPHAN_ROOT.to_string(), true),
        };
        let name = c.name.replace('/', ":");
        let p = if parent_path.is_empty() { format!("/{}", name) } else if orphan { format!("{}/{}", parent_path, name) } else { format!("/{}/{}", parent_path, name) };
        let record = next;
        next += 1;
        let mut e = entry(v, r, Some(c), record, parent_rec, p, name, true);
        e.orphan = orphan;
        let used = v.fork_runs(&fork(&c.data, 88), be32(&c.data, 8), 0).iter().flat_map(|x| (x.vol.unwrap() / v.block)..(x.vol.unwrap() + x.len).div_ceil(v.block)).filter(|&b| v.allocated(r, b)).count();
        e.error = Some(if used > 0 {
            reused += 1;
            format!("catalog record found in an old copy of a catalog node (journal or unused node); {} of its blocks are in use again, so the content may belong to another file", used)
        } else {
            "catalog record found in an old copy of a catalog node (journal or unused node); its blocks are free".to_string()
        });
        out.push(e);
    }
    if !old.is_empty() {
        notes.push(format!(
            "{} deleted file(s) found in old copies of catalog nodes (the journal and unused nodes){}.",
            old.len(),
            if reused > 0 { format!("; {} of them have blocks in use again", reused) } else { String::new() }
        ));
    }
    progress(out.len() as u64, out.len() as u64);
    let info = v.info(out.len() as u64);
    Ok(HfsScan { info, entries: out, notes })
}

#[allow(clippy::too_many_arguments)]
fn entry<R: Read + Seek>(v: &HfsVolume, r: &mut R, c: Option<&Cat>, record: u64, parent: u64, path: String, name: String, deleted: bool) -> FsEntry {
    let empty = Cat { off: 0, parent: 0, name: String::new(), data: vec![0; 248] };
    let c = c.unwrap_or(&empty);
    let mut d = c.data.clone();
    d.resize(248, 0);
    let is_dir = be16(&d, 0) == 1;
    let id = be32(&d, 8);
    let mode = be16(&d, 32 + 10) as u32;
    let (uid, gid) = (be32(&d, 32) as u32, be32(&d, 36) as u32);
    let times = Times { created: hfs_time(be32(&d, 12)), modified: hfs_time(be32(&d, 16)), accessed: hfs_time(be32(&d, 24)), mft_modified: hfs_time(be32(&d, 20)) };
    let data = fork(&d, 88);
    let compressed = !is_dir && v.xattrs.get(&id).is_some_and(|x| x.iter().any(|(n, _)| n == decmpfs::XATTR));
    let size = if is_dir {
        0
    } else if compressed {
        v.xattrs.get(&id).and_then(|x| x.iter().find(|(n, _)| n == decmpfs::XATTR)).and_then(|(_, a)| if let XattrData::Inline(a) = a { decmpfs::header(a).map(|h| h.1) } else { None }).unwrap_or(0)
    } else {
        data.size
    };
    let first = if is_dir || compressed { None } else { v.fork_runs(&data, id, 0).first().and_then(|x| x.vol) };
    let link_target = (mode & 0o170000 == 0o120000).then(|| v.read_fork(r, &data, id, 0, 4096).ok().map(|b| String::from_utf8_lossy(&b).into_owned())).flatten();
    let mut streams = vec![];
    if !is_dir {
        streams.push(Stream { name: String::new(), size, resident: false, first_offset: first });
        let rsrc = fork(&d, 168);
        if rsrc.size > 0 && !compressed {
            streams.push(Stream { name: "rsrc".into(), size: rsrc.size, resident: false, first_offset: v.fork_runs(&rsrc, id, 0xFF).first().and_then(|x| x.vol) });
        }
    }
    let xattr_names: Vec<String> = v.xattrs.get(&id).map(|x| x.iter().map(|(n, _)| n.clone()).collect()).unwrap_or_default();
    let quarantine = xattr_names.iter().any(|n| n == "com.apple.quarantine");
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
        size,
        alloc_size: data.extents.iter().map(|e| e.1 * v.block).sum(),
        resident: false,
        attributes: if is_dir { 0x10 } else { 0 } | if compressed { COMPRESSED | 0x800 } else { 0 } | if quarantine { 1 << 29 } else { 0 },
        hard_links: 1,
        usn: None,
        si: Some(times),
        fname: None,
        streams,
        has_reparse: false,
        record_offset: c.off,
        error: None,
        unix: (c.off != 0 || record == ROOT_RECORD).then_some(UnixMeta {
            inode: id,
            mode: if mode == 0 { if is_dir { 0o040755 } else { 0o100644 } } else { mode },
            uid,
            gid,
            deleted_time: 0,
            inode_offset: c.off,
            journal_seq: None,
            link_target,
        }),
    }
}

impl HfsVolume {
    /// Extended attribute names and values of a file, for the details view.
    pub fn xattrs_of<R: Read + Seek>(&self, r: &mut R, id: u64) -> Vec<(String, Vec<u8>)> {
        let names: Vec<String> = self.xattrs.get(&id).map(|x| x.iter().map(|(n, _)| n.clone()).collect()).unwrap_or_default();
        names.into_iter().filter_map(|n| self.xattr(r, id, &n).map(|v| (n, v))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hfsplus_fixture() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/hfsplus.img");
        let Ok(mut f) = std::fs::File::open(&p) else { return };
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        assert_eq!(v.label, "KOKINO_HFS");
        assert!(v.journaled);
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let read = |f: &mut std::fs::File, e: &FsEntry| v.read(f, e, 0, e.size as usize).unwrap();
        assert_eq!(read(&mut f, by("/Documents/report.txt")), (b"Quarterly report line, lab.test internal.\n".repeat(220))[..9000].to_vec());
        assert_eq!(read(&mut f, by("/Documents/deep/a/b/c/notes.txt")), b"deep note\n");
        // Hard link: the content of iNode20.
        let link = by("/Documents/hello-link.txt");
        assert_eq!(read(&mut f, link), b"Hello from the Kokino macOS test volume.\n");
        assert_eq!(link.unix.as_ref().unwrap().inode, 20);
        assert_eq!(read(&mut f, by("/hello.txt")), b"Hello from the Kokino macOS test volume.\n");
        // HFS compression (LZVN, inline).
        let c = by("/compressed.txt");
        assert_eq!(c.size, 64000);
        assert_eq!(read(&mut f, c), b"compressible line for decmpfs, lab.test\n".repeat(1600));
        assert_eq!(by("/link").unix.as_ref().unwrap().link_target.as_deref(), Some("Documents/report.txt"));
        // Times as macOS reported them (manifest): hello.txt modified 08:06:30 UTC.
        assert_eq!(kokino_core::time::filetime_to_iso(by("/hello.txt").si.unwrap().modified), "2026-10-20T08:06:30.0000000Z");
        // Extended attributes, including the quarantine flag.
        let xa = v.xattrs_of(&mut f, 20);
        assert!(xa.iter().any(|(n, val)| n == "com.apple.quarantine" && val.starts_with(b"0083;")), "{:?}", xa.iter().map(|x| &x.0).collect::<Vec<_>>());
        // Unicode name (stored decomposed on HFS+).
        assert!(s.entries.iter().any(|e| e.name.starts_with("Cafe\u{301}") || e.name.starts_with("Caf\u{e9}")));
        // The deleted file, from an old catalog node copy.
        let gone = s.entries.iter().find(|e| e.name == "secret.txt").expect("deleted secret.txt");
        assert!(gone.deleted);
        assert_eq!(read(&mut f, gone), b"SECRET: meet at the lab.test office, 10:00 (test data)\n");
    }
}
