//! XFS reader (format versions 4 and 5).
//!
//! Walks the directory tree from the root inode and returns the same
//! `FsEntry` records as the other file systems, so every view works
//! unchanged. Owner, mode and inode number go in `FsEntry::unix`.
//!
//! Layout: the volume is split into allocation groups (AGs). Inode and block
//! numbers carry the AG number in their high bits. Each AG starts with a
//! copy of the superblock, the free-space header (AGF, with a B+tree of free
//! extents) and the inode header (AGI, with a B+tree of inode chunks).
//! Files map their content with an extent list in the inode, or a B+tree of
//! extents when the list does not fit. Folders are kept in the inode
//! (short form) when small, otherwise in directory blocks.
//!
//! Deleted files:
//! - Names: removing an entry from a directory block turns it into a free
//!   region. Only the first four bytes (the high half of the inode number)
//!   are overwritten; the low half, the name and the file type stay until
//!   the space is reused. In a short-form folder the entries after it move
//!   down; older kernels may leave the last one removed past the end.
//! - Inodes: older kernels set the mode, size and extent count to zero but
//!   leave the extent records in the inode (what xfs_undelete relies on);
//!   the size is lost, so content runs to the end of the file's last block.
//!   Recent kernels (6.19 checked) clear the whole freed inode, and the
//!   leftovers of short-form folders. The inode change time is the time of
//!   deletion.
//! - Inodes no name points to are listed under $OrphanFiles.
//!
//! Times are UTC with nanoseconds, the creation time from version 5 on and
//! dates past 2038 with the bigtime feature; the inode change time is
//! reported as `mft_modified` (entry modified).

#![forbid(unsafe_code)]

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta, ORPHAN_ROOT};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Mutex, OnceLock};

/// Root directory record id; real entries start at FIRST_RECORD.
pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
const MAX_ENTRIES: usize = 5_000_000;
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Extent B+tree blocks read to map one file.
const MAX_MAP_BLOCKS: usize = 1 << 16;
const MAX_EXTENTS: usize = 1 << 20;
/// Inode B+tree and free-space B+tree blocks read per volume.
const MAX_TREE_BLOCKS: usize = 1 << 20;
/// Inodes read when looking for orphans.
const MAX_INODE_BYTES: u64 = 2 << 30;
/// Directory data blocks lie below this byte offset in the folder; the
/// hash index and free-space index of large folders lie above it.
const DIR_LEAF_OFFSET: u64 = 32 << 30;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

const FMT_LOCAL: u8 = 1;
const FMT_EXTENTS: u8 = 2;
const FMT_BTREE: u8 = 3;
const DIFLAG_REALTIME: u16 = 0x1;
const DIFLAG2_BIGTIME: u64 = 0x8;
const DIFLAG2_NREXT64: u64 = 0x10;

fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
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
    b.get(o..o + 8).map(|x| u64::from_be_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]])).unwrap_or(0)
}
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
}
fn uuid(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    if h.len() != 32 {
        return h;
    }
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Unix seconds and nanoseconds to FILETIME; 0 stays 0 (unset).
fn unix_ft(secs: i64, nsec: u64) -> u64 {
    if secs == 0 && nsec == 0 {
        return 0;
    }
    let nsec = if nsec > 999_999_999 { 0 } else { nsec };
    let t = (secs as i128 + 11_644_473_600) * 10_000_000 + (nsec / 100) as i128;
    t.clamp(0, u64::MAX as i128) as u64
}

fn plausible_name(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7F) && b != b"." && b != b".."
}

fn name_str(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace(['/', '\0'], "_")
}

/// Directory entry file type to the file-type bits of a mode.
fn ftype_mode(ft: u8) -> u32 {
    match ft {
        1 => S_IFREG,
        2 => S_IFDIR,
        3 => 0o020000,
        4 => 0o060000,
        5 => 0o010000,
        6 => 0o140000,
        7 => S_IFLNK,
        _ => 0,
    }
}

pub struct XfsVolume {
    /// Format version: 4 or 5.
    pub version: u8,
    pub block: u64,
    pub blocks: u64,
    pub agblocks: u64,
    pub agcount: u64,
    pub inode_size: u64,
    pub sector: u64,
    /// Directory block size (one or more file-system blocks).
    pub dir_block: u64,
    pub root_ino: u64,
    pub label: String,
    pub uuid: String,
    /// Inodes allocated and free, and free blocks, as the superblock counts them.
    pub icount: u64,
    pub ifree: u64,
    pub free_blocks: u64,
    pub size: u64,
    /// Feature names for the volume summary (ftype, sparse inodes, bigtime...).
    pub features: Vec<&'static str>,
    agblklog: u32,
    inopblog: u32,
    ftype: bool,
    sparse: bool,
    realtime: bool,
    /// Metadata inodes (quota files, realtime bitmap and summary): not orphans.
    meta_inodes: Vec<u64>,
    free: OnceLock<Vec<(u64, u64)>>,
    /// Last file mapped: (inode offset, its extents).
    map_cache: Mutex<Option<(u64, Vec<Extent>)>>,
}

/// One inode, decoded.
#[derive(Debug, Clone)]
pub struct Inode {
    pub raw: Vec<u8>,
    pub mode: u32,
    pub version: u8,
    pub format: u8,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub nblocks: u64,
    pub nextents: u64,
    pub forkoff: usize,
    pub flags: u16,
    pub generation: u32,
    pub times: Times,
    /// Inode number the inode records for itself (version 3), else 0.
    pub number: u64,
}

impl Inode {
    fn parse(raw: Vec<u8>) -> Option<Inode> {
        if raw.len() < 100 || &raw[0..2] != b"IN" || !(1..=3).contains(&raw[4]) {
            return None;
        }
        let version = raw[4];
        if version == 3 && raw.len() < 176 {
            return None;
        }
        let flags2 = if version == 3 { be64(&raw, 120) } else { 0 };
        let bigtime = flags2 & DIFLAG2_BIGTIME != 0;
        let ts = |o: usize| -> u64 {
            if bigtime {
                let ns = be64(&raw, o);
                if ns == 0 {
                    return 0;
                }
                unix_ft((ns / 1_000_000_000) as i64 - (1i64 << 31), ns % 1_000_000_000)
            } else {
                unix_ft(be32(&raw, o) as u32 as i32 as i64, be32(&raw, o + 4))
            }
        };
        let times = Times { accessed: ts(32), modified: ts(40), mft_modified: ts(48), created: if version == 3 { ts(144) } else { 0 } };
        Some(Inode {
            mode: be16(&raw, 2) as u32,
            version,
            format: raw[5],
            uid: be32(&raw, 8) as u32,
            gid: be32(&raw, 12) as u32,
            links: if version == 1 { be16(&raw, 6) as u32 } else { be32(&raw, 16) as u32 },
            size: be64(&raw, 56),
            nblocks: be64(&raw, 64),
            nextents: if flags2 & DIFLAG2_NREXT64 != 0 { be64(&raw, 24) } else { be32(&raw, 76) },
            forkoff: raw[82] as usize,
            flags: be16(&raw, 90) as u16,
            generation: be32(&raw, 92) as u32,
            times,
            number: if version == 3 { be64(&raw, 152) } else { 0 },
            raw,
        })
    }

    fn core(&self) -> usize {
        if self.version == 3 {
            176
        } else {
            100
        }
    }
    /// The data fork: from the end of the core to the attribute fork.
    fn fork(&self) -> &[u8] {
        let c = self.core();
        let end = if self.forkoff > 0 { c + self.forkoff * 8 } else { self.raw.len() };
        self.raw.get(c..end.min(self.raw.len())).unwrap_or(&[])
    }
    fn kind(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == S_IFDIR
    }
    /// In use (a deleted inode has mode 0).
    pub fn live(&self) -> bool {
        self.mode != 0
    }
    /// Freed by a deletion: mode 0, but it was used (the change time is set).
    fn freed(&self) -> bool {
        self.mode == 0 && self.times.mft_modified != 0
    }
}

/// One packed extent record: (file block, volume block number, blocks, unwritten).
fn unpack(b: &[u8]) -> (u64, u64, u64, bool) {
    let hi = be64(b, 0);
    let lo = be64(b, 8);
    ((hi >> 9) & ((1 << 54) - 1), ((hi & 0x1FF) << 43) | (lo >> 21), lo & 0x1F_FFFF, hi >> 63 == 1)
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<XfsVolume> {
    let sb = rd(r, 0, 512)?;
    if sb.len() < 264 || &sb[0..4] != b"XFSB" {
        anyhow::bail!("not an XFS superblock");
    }
    let block = be32(&sb, 4);
    let sector = be16(&sb, 102);
    let inode_size = be16(&sb, 104);
    let inopb = be16(&sb, 106);
    let (blocklog, inodelog, inopblog, agblklog) = (sb[120] as u32, sb[122] as u32, sb[123] as u32, sb[124] as u32);
    if !(9..=16).contains(&blocklog) || block != 1 << blocklog {
        anyhow::bail!("XFS block size out of range");
    }
    if !sector.is_power_of_two() || !(512..=32768).contains(&sector) {
        anyhow::bail!("XFS sector size out of range");
    }
    if !(8..=11).contains(&inodelog) || inopblog > 8 || inode_size != 1 << inodelog || inode_size > block || inopb != block / inode_size || inopb != 1 << inopblog {
        anyhow::bail!("XFS inode size out of range");
    }
    let agblocks = be32(&sb, 84);
    let agcount = be32(&sb, 88);
    let blocks = be64(&sb, 8);
    if !(1..=31).contains(&agblklog) || agblocks == 0 || agblocks > 1 << agblklog || agcount == 0 || agcount > 1 << 24 || blocks == 0 || blocks > agcount * agblocks {
        anyhow::bail!("XFS allocation groups out of range");
    }
    if agblklog + inopblog > 32 + 31 {
        anyhow::bail!("XFS inode numbers out of range");
    }
    let versionnum = be16(&sb, 100);
    let version = (versionnum & 0xF) as u8;
    if !(4..=5).contains(&version) {
        anyhow::bail!("XFS format version {} not supported", version);
    }
    let dirblklog = sb[192] as u32;
    if dirblklog > 6 || block << dirblklog > 65536 {
        anyhow::bail!("XFS directory block size out of range");
    }
    let features2 = be32(&sb, 200);
    let incompat = if version == 5 { be32(&sb, 216) } else { 0 };
    let ftype = if version == 5 { incompat & 1 != 0 } else { features2 & 0x200 != 0 };
    let sparse = incompat & 2 != 0;
    let mut features = vec![];
    if ftype {
        features.push("file types in folders");
    }
    if sparse {
        features.push("sparse inodes");
    }
    if incompat & 8 != 0 {
        features.push("bigtime (dates to 2486)");
    }
    if incompat & 0x20 != 0 {
        features.push("64-bit extent counts");
    }
    if version == 5 && be32(&sb, 212) & 2 != 0 {
        features.push("reverse mapping");
    }
    if version == 5 && be32(&sb, 212) & 4 != 0 {
        features.push("reflink");
    }
    let rblocks = be64(&sb, 16);
    let mut meta_at = vec![64usize, 72, 160, 168];
    if version == 5 {
        meta_at.push(232);
    }
    let meta_inodes: Vec<u64> = meta_at.into_iter().map(|o| be64(&sb, o)).filter(|&n| n != 0 && n != u64::MAX).collect();
    Ok(XfsVolume {
        version,
        block,
        blocks,
        agblocks,
        agcount,
        inode_size,
        sector,
        dir_block: block << dirblklog,
        root_ino: be64(&sb, 56),
        label: cstr(&sb[108..120]),
        uuid: uuid(&sb[32..48]),
        icount: be64(&sb, 128),
        ifree: be64(&sb, 136),
        free_blocks: be64(&sb, 144),
        size,
        features,
        agblklog,
        inopblog,
        ftype,
        sparse,
        realtime: rblocks > 0,
        meta_inodes,
        free: OnceLock::new(),
        map_cache: Mutex::new(None),
    })
}

impl XfsVolume {
    /// Volume byte offset of AG block `agbno` of group `ag`.
    fn ag_byte(&self, ag: u64, agbno: u64) -> Option<u64> {
        (ag < self.agcount && agbno < self.agblocks).then(|| (ag * self.agblocks + agbno) * self.block)
    }
    /// Volume byte offset of a file-system block number (AG in the high bits).
    fn fsb_byte(&self, fsb: u64) -> Option<u64> {
        self.ag_byte(fsb >> self.agblklog, fsb & ((1 << self.agblklog) - 1))
    }

    /// Volume byte offset of inode `n`.
    pub fn inode_offset(&self, n: u64) -> Option<u64> {
        let bits = self.agblklog + self.inopblog;
        let ag = n.checked_shr(bits).unwrap_or(0);
        let agino = n & ((1u64 << bits) - 1);
        let off = self.ag_byte(ag, agino >> self.inopblog)? + (agino & ((1 << self.inopblog) - 1)) * self.inode_size;
        (off + self.inode_size <= self.size).then_some(off)
    }

    fn inode_at<R: Read + Seek>(&self, r: &mut R, off: u64) -> anyhow::Result<Inode> {
        let raw = rd(r, off, self.inode_size as usize)?;
        Inode::parse(raw).ok_or_else(|| anyhow::anyhow!("not an XFS inode at {}", off))
    }

    pub fn inode<R: Read + Seek>(&self, r: &mut R, n: u64) -> anyhow::Result<Inode> {
        let off = self.inode_offset(n).ok_or_else(|| anyhow::anyhow!("inode {} out of range", n))?;
        self.inode_at(r, off)
    }

    /// Extent records to volume extents, sorted, overlaps dropped.
    fn to_extents(&self, recs: Vec<(u64, u64, u64, bool)>) -> Vec<Extent> {
        let mut out: Vec<Extent> = vec![];
        let max_off = 1u64 << 54;
        for (off, fsb, n, unwritten) in recs {
            if n == 0 || off >= max_off / self.block.max(1) {
                continue;
            }
            let vol = if unwritten { None } else { self.fsb_byte(fsb) };
            if !unwritten && vol.is_none() {
                continue;
            }
            out.push(Extent { offset: off * self.block, len: n * self.block, vol });
        }
        out.sort_by_key(|x| x.offset);
        let mut kept: Vec<Extent> = Vec::with_capacity(out.len());
        for x in out {
            if kept.last().is_some_and(|p| p.offset + p.len > x.offset) {
                continue;
            }
            kept.push(x);
        }
        kept
    }

    /// Extent records of a B+tree-mapped fork whose root sits in `root`.
    fn btree_records<R: Read + Seek>(&self, r: &mut R, root: &[u8]) -> Vec<(u64, u64, u64, bool)> {
        let level = be16(root, 0);
        let numrecs = be16(root, 2) as usize;
        let maxrecs = root.len().saturating_sub(4) / 16;
        if level == 0 || level > 9 || numrecs > maxrecs {
            return vec![];
        }
        let ptrs = 4 + maxrecs * 8;
        let mut queue: VecDeque<(u64, u64)> = (0..numrecs).map(|i| (be64(root, ptrs + i * 8), level - 1)).collect();
        let (hdr, magic) = if self.version == 5 { (72usize, b"BMA3") } else { (24usize, b"BMAP") };
        let bs = self.block as usize;
        let mut out = vec![];
        let mut read = 0usize;
        let mut seen = HashSet::new();
        while let Some((fsb, want_level)) = queue.pop_front() {
            read += 1;
            if read > MAX_MAP_BLOCKS || out.len() > MAX_EXTENTS || !seen.insert(fsb) {
                break;
            }
            let Some(at) = self.fsb_byte(fsb) else { continue };
            let Ok(b) = rd(r, at, bs) else { continue };
            if b.len() < bs || &b[0..4] != magic || be16(&b, 4) != want_level {
                continue;
            }
            let n = be16(&b, 6) as usize;
            let maxr = (bs - hdr) / 16;
            if n > maxr {
                continue;
            }
            if want_level == 0 {
                for i in 0..n {
                    out.push(unpack(&b[hdr + i * 16..hdr + i * 16 + 16]));
                }
            } else {
                let p = hdr + maxr * 8;
                for i in 0..n {
                    queue.push_back((be64(&b, p + i * 8), want_level - 1));
                }
            }
        }
        out
    }

    /// Where a live inode's bytes live, as volume extents.
    pub fn map<R: Read + Seek>(&self, r: &mut R, ino: &Inode, inode_off: u64) -> Vec<Extent> {
        if ino.flags & DIFLAG_REALTIME != 0 {
            return vec![];
        }
        let fork = ino.fork();
        let x = match ino.format {
            FMT_LOCAL => return if ino.size > 0 { vec![Extent { offset: 0, len: ino.size.min(fork.len() as u64), vol: Some(inode_off + ino.core() as u64) }] } else { vec![] },
            FMT_EXTENTS => {
                let n = (ino.nextents as usize).min(fork.len() / 16);
                self.to_extents((0..n).map(|i| unpack(&fork[i * 16..i * 16 + 16])).collect())
            }
            FMT_BTREE => {
                let recs = self.btree_records(r, fork);
                self.to_extents(recs)
            }
            _ => vec![],
        };
        // Version 5 symbolic links kept in blocks start each block with a
        // 56-byte header ("XSLM"); the target follows.
        if ino.kind() == S_IFLNK && self.version == 5 {
            let mut out = vec![];
            let mut at = 0u64;
            for e in &x {
                let Some(v) = e.vol else { continue };
                for k in 0..e.len / self.block {
                    out.push(Extent { offset: at, len: self.block - 56, vol: Some(v + k * self.block + 56) });
                    at += self.block - 56;
                }
            }
            return out;
        }
        x
    }

    /// The extent records a deleted inode still holds: XFS clears the count
    /// but not the records. Each record must point inside the volume; the
    /// file must start at block 0.
    fn deleted_map(&self, ino: &Inode) -> Vec<Extent> {
        let c = ino.core();
        let mut recs = vec![];
        let mut p = c;
        while p + 16 <= ino.raw.len() && recs.len() < 64 {
            let b = &ino.raw[p..p + 16];
            if b.iter().all(|&x| x == 0) {
                break;
            }
            let (off, fsb, n, unwritten) = unpack(b);
            let ag = fsb >> self.agblklog;
            let agbno = fsb & ((1 << self.agblklog) - 1);
            if unwritten || n == 0 || ag >= self.agcount || agbno + n > self.agblocks || (ag * self.agblocks + agbno + n) > self.blocks || off > 1 << 40 {
                break;
            }
            recs.push((off, fsb, n, false));
            p += 16;
        }
        let x = self.to_extents(recs);
        if x.first().is_some_and(|e| e.offset == 0) {
            x
        } else {
            vec![]
        }
    }

    /// The inode an entry's content is read through.
    fn content_inode<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> anyhow::Result<(Inode, u64)> {
        let u = e.unix.as_ref().ok_or_else(|| anyhow::anyhow!("not an XFS entry"))?;
        Ok((self.inode_at(r, u.inode_offset)?, u.inode_offset))
    }

    /// Where a file's bytes live, as volume extents.
    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> anyhow::Result<Vec<Extent>> {
        let Some(u) = e.unix.as_ref() else { return Ok(vec![]) };
        if e.size == 0 && !e.is_dir {
            return Ok(vec![]);
        }
        if let Ok(c) = self.map_cache.lock() {
            if let Some((off, x)) = c.as_ref() {
                if *off == u.inode_offset {
                    return Ok(x.clone());
                }
            }
        }
        let (ino, off) = self.content_inode(r, e)?;
        let x = if ino.live() { self.map(r, &ino, off) } else { self.deleted_map(&ino) };
        if let Ok(mut c) = self.map_cache.lock() {
            *c = Some((off, x.clone()));
        }
        Ok(x)
    }

    /// Up to `len` bytes of a file from `offset`; holes read as zeros.
    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= e.size {
            return Ok(vec![]);
        }
        let map = self.extents(r, e)?;
        read_map(r, &map, e.size, offset, len)
    }

    /// Free extents from each AG's free-space B+tree (by block number), as
    /// volume (byte offset, length), sorted.
    fn free_list<R: Read + Seek>(&self, r: &mut R) -> &Vec<(u64, u64)> {
        self.free.get_or_init(|| {
            let mut out = vec![];
            let (hdr, magic) = if self.version == 5 { (56usize, b"AB3B") } else { (16usize, b"ABTB") };
            let bs = self.block as usize;
            let mut read = 0usize;
            for ag in 0..self.agcount {
                let Some(ag0) = self.ag_byte(ag, 0) else { break };
                let Ok(agf) = rd(r, ag0 + self.sector, 64) else { continue };
                if agf.len() < 64 || &agf[0..4] != b"XAGF" || be32(&agf, 8) != ag {
                    continue;
                }
                let ag_len = be32(&agf, 12).min(self.agblocks);
                let mut queue = VecDeque::from([(be32(&agf, 16), be32(&agf, 28).saturating_sub(1))]);
                let mut seen = HashSet::new();
                while let Some((bno, level)) = queue.pop_front() {
                    read += 1;
                    if read > MAX_TREE_BLOCKS {
                        break;
                    }
                    if !seen.insert(bno) || bno >= ag_len {
                        continue;
                    }
                    let Ok(b) = rd(r, ag0 + bno * self.block, bs) else { continue };
                    if b.len() < bs || &b[0..4] != magic || be16(&b, 4) != level {
                        continue;
                    }
                    let n = be16(&b, 6) as usize;
                    let maxr = (bs - hdr) / 8;
                    if n > maxr {
                        continue;
                    }
                    if level == 0 {
                        for i in 0..n {
                            let (s, c) = (be32(&b, hdr + i * 8), be32(&b, hdr + i * 8 + 4));
                            if c > 0 && s + c <= ag_len {
                                out.push(((ag * self.agblocks + s) * self.block, c * self.block));
                            }
                        }
                    } else {
                        let maxk = (bs - hdr) / 12;
                        for i in 0..n.min(maxk) {
                            queue.push_back((be32(&b, hdr + maxk * 8 + i * 4), level - 1));
                        }
                    }
                }
            }
            out.sort_unstable();
            out.dedup();
            out
        })
    }

    /// Block (linear number) is in use according to the free-space trees.
    pub fn allocated<R: Read + Seek>(&self, r: &mut R, linear: u64) -> bool {
        let at = linear * self.block;
        let f = self.free_list(r);
        let i = f.partition_point(|x| x.0 <= at);
        !(i > 0 && at < f[i - 1].0 + f[i - 1].1)
    }

    /// Unallocated block runs: (volume byte offset, length).
    pub fn free_runs<R: Read + Seek>(&self, r: &mut R) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = vec![];
        for &(s, l) in self.free_list(r) {
            let l = l.min(self.size.saturating_sub(s));
            if l == 0 {
                continue;
            }
            match out.last_mut() {
                Some(p) if p.0 + p.1 == s => p.1 += l,
                _ => out.push((s, l)),
            }
        }
        out
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: self.uuid.clone(),
            version: format!("XFS v{}", self.version),
            cluster_size: self.block as u32,
            sector_size: self.sector as u16,
            record_size: self.inode_size as u32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: self.inode_offset(self.root_ino).unwrap_or(0),
            dirty: false,
        }
    }

    /// Inode chunks of every AG from the inode B+trees: (first inode, free
    /// mask, hole mask). A set bit in the free mask is a free inode; a set
    /// hole-mask bit covers four inodes that were never allocated.
    fn chunks<R: Read + Seek>(&self, r: &mut R) -> Vec<(u64, u64, u16)> {
        let (hdr, magic) = if self.version == 5 { (56usize, b"IAB3") } else { (16usize, b"IABT") };
        let bs = self.block as usize;
        let mut out = vec![];
        let mut read = 0usize;
        let bits = self.agblklog + self.inopblog;
        for ag in 0..self.agcount {
            let Some(ag0) = self.ag_byte(ag, 0) else { break };
            let Ok(agi) = rd(r, ag0 + 2 * self.sector, 64) else { continue };
            if agi.len() < 64 || &agi[0..4] != b"XAGI" || be32(&agi, 8) != ag {
                continue;
            }
            let mut queue = VecDeque::from([(be32(&agi, 20), be32(&agi, 24).saturating_sub(1))]);
            let mut seen = HashSet::new();
            while let Some((bno, level)) = queue.pop_front() {
                read += 1;
                if read > MAX_TREE_BLOCKS {
                    break;
                }
                if !seen.insert(bno) || bno >= self.agblocks {
                    continue;
                }
                let Ok(b) = rd(r, ag0 + bno * self.block, bs) else { continue };
                if b.len() < bs || &b[0..4] != magic || be16(&b, 4) != level {
                    continue;
                }
                let n = be16(&b, 6) as usize;
                if level == 0 {
                    for i in 0..n.min((bs - hdr) / 16) {
                        let rec = &b[hdr + i * 16..hdr + i * 16 + 16];
                        let holes = if self.sparse { be16(rec, 4) as u16 } else { 0 };
                        out.push(((ag << bits) | be32(rec, 0), be64(rec, 8), holes));
                    }
                } else {
                    let maxk = (bs - hdr) / 8;
                    for i in 0..n.min(maxk) {
                        queue.push_back((be32(&b, hdr + maxk * 4 + i * 4), level - 1));
                    }
                }
            }
        }
        out
    }
}

/// Up to `len` bytes from `offset` of a file of `size` bytes mapped by `map`.
fn read_map<R: Read + Seek>(r: &mut R, map: &[Extent], size: u64, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
    if offset >= size {
        return Ok(vec![]);
    }
    let want = (len as u64).min(size - offset) as usize;
    let end = offset + want as u64;
    let mut out = vec![0u8; want];
    for x in map.iter() {
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

/// One name found in a folder: (name, inode, file type, deleted, inode
/// number complete). A deleted entry at the start of a free region kept
/// only the low 32 bits of its inode number.
type Found = (String, u64, u8, bool, bool);

pub struct XfsScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    /// Plain-language notes for the volume summary.
    pub notes: Vec<String>,
}

struct Walker<'a, R: Read + Seek> {
    v: &'a XfsVolume,
    r: &'a mut R,
    out: Vec<FsEntry>,
    next: u64,
    seen_dirs: HashSet<u64>,
    named: HashSet<u64>,
    recovered: u64,
    no_content: u64,
    reused: u64,
}

/// A directory still to walk: (record, path, inode number, inode offset, deleted).
type DirWork = (u64, String, u64, u64, bool);

/// Walks the tree from the root inode, then the inode chunks for orphans.
/// `progress(done, total)` may return false.
pub fn scan<R: Read + Seek>(v: &XfsVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<XfsScan> {
    let mut notes = vec![];
    let root_off = v.inode_offset(v.root_ino).ok_or_else(|| anyhow::anyhow!("XFS root inode out of range"))?;
    let root_ino = v.inode_at(r, root_off)?;
    if !root_ino.is_dir() {
        anyhow::bail!("XFS root inode is not a directory");
    }
    let mut named = HashSet::from([v.root_ino]);
    named.extend(v.meta_inodes.iter().copied());
    let mut w = Walker { v, r, out: vec![], next: FIRST_RECORD, seen_dirs: HashSet::new(), named, recovered: 0, no_content: 0, reused: 0 };
    let root = w.entry(ROOT_RECORD, ROOT_RECORD, "/".into(), ".".into(), v.root_ino, root_off, &root_ino, false, Some((root_ino.clone(), root_off)), 0, None);
    w.out.push(root);
    let mut queue: VecDeque<DirWork> = VecDeque::from([(ROOT_RECORD, String::new(), v.root_ino, root_off, false)]);
    w.seen_dirs.insert(v.root_ino);
    let mut dirs = 0u64;
    while let Some(d) = queue.pop_front() {
        dirs += 1;
        if dirs.is_multiple_of(64) && !progress(w.out.len() as u64, w.out.len() as u64 + queue.len() as u64) {
            anyhow::bail!("scan cancelled");
        }
        queue.extend(w.dir(d));
        if w.out.len() > MAX_ENTRIES {
            break;
        }
    }
    w.orphans(&mut progress, &mut notes)?;
    progress(w.out.len() as u64, w.out.len() as u64);

    // Deleted files whose blocks are in use again, or claimed twice.
    let mut ranges = vec![];
    for i in 0..w.out.len() {
        let e = &w.out[i];
        if !e.deleted || e.is_dir || e.size == 0 {
            continue;
        }
        let ext = v.extents(w.r, e).unwrap_or_default();
        let mut reused = 0u64;
        for x in &ext {
            let Some(vol) = x.vol else { continue };
            let len = x.len.min(e.size.saturating_sub(x.offset));
            ranges.push((i, vol, vol + len));
            for b in (vol / v.block)..(vol + len).div_ceil(v.block) {
                if v.allocated(w.r, b) {
                    reused += 1;
                }
            }
        }
        if reused > 0 {
            w.reused += 1;
            let msg = format!("{} of its blocks are in use again: recovered content may belong to another file", reused);
            w.out[i].error = Some(match w.out[i].error.take() {
                Some(m) => format!("{}; {}", m, msg),
                None => msg,
            });
        }
        if ranges.len() > 1 << 22 {
            break;
        }
    }
    kokino_ntfs::note_shared_space(&mut w.out, ranges);
    if w.reused > 0 {
        notes.push(format!("{} recovered deleted file(s) have blocks in use again: their content may belong to another file.", w.reused));
    }
    if !v.features.is_empty() {
        notes.push(format!("XFS version {} with {}.", v.version, v.features.join(", ")));
    }
    if w.recovered > 0 {
        notes.push(format!(
            "{} deleted file(s) were recovered through the extent records XFS leaves in a freed inode. XFS clears the size on delete, so their content runs to the end of the last block (trailing zeros or older data may follow the real end).",
            w.recovered
        ));
    }
    if w.no_content > 0 {
        notes.push(format!("{} deleted file(s) have no recoverable content: their inode no longer holds extent records (recent kernels clear a freed inode). File carving over free space may still find them.", w.no_content));
    }
    if v.realtime {
        notes.push("This XFS volume has a realtime section on a separate device; files kept there cannot be read from this image.".into());
    }
    let info = v.info(w.out.len() as u64);
    Ok(XfsScan { info, entries: w.out, notes })
}

impl<'a, R: Read + Seek> Walker<'a, R> {
    #[allow(clippy::too_many_arguments)]
    fn entry(&mut self, record: u64, parent: u64, path: String, name: String, n: u64, off: u64, ino: &Inode, deleted: bool, content: Option<(Inode, u64)>, ftype: u8, error: Option<String>) -> FsEntry {
        let mode = if ino.mode != 0 { ino.mode } else { ftype_mode(ftype) };
        let is_dir = mode & S_IFMT == S_IFDIR;
        let (size, map, resident) = match &content {
            Some((c, c_off)) if c.live() => {
                let map = if is_dir { vec![] } else { self.v.map(self.r, c, *c_off) };
                (if is_dir { 0 } else { c.size }, map, c.format == FMT_LOCAL)
            }
            Some((c, _)) => {
                let map = self.v.deleted_map(c);
                let end = map.last().map(|x| x.offset + x.len).unwrap_or(0);
                (if is_dir { 0 } else { end }, map, false)
            }
            None => (0, vec![], false),
        };
        let first_offset = if is_dir || size == 0 { None } else { map.iter().find_map(|x| x.vol) };
        let link_target = (mode & S_IFMT == S_IFLNK && size > 0 && size < 4096 && content.as_ref().is_some_and(|c| c.0.live())).then(|| String::from_utf8_lossy(&read_map(self.r, &map, size, 0, size as usize).unwrap_or_default()).into_owned());
        let c_off = content.as_ref().map(|c| c.1).unwrap_or(off);
        FsEntry {
            name_only: None,
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
            alloc_size: if ino.live() { ino.nblocks.saturating_mul(self.v.block) } else { size },
            resident,
            attributes: if is_dir { 0x10 } else { 0 },
            hard_links: ino.links.min(u16::MAX as u32) as u16,
            usn: None,
            si: Some(ino.times),
            fname: None,
            streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident, first_offset }] },
            has_reparse: false,
            record_offset: off,
            error,
            unix: Some(UnixMeta {
                inode: n,
                mode,
                uid: ino.uid,
                gid: ino.gid,
                // A freed inode's change time is the time it was freed.
                deleted_time: if ino.freed() { ino.times.mft_modified } else { 0 },
                inode_offset: c_off,
                journal_seq: None,
                link_target,
            }),
        }
    }

    /// Adds one name. Returns the directory to walk next, if it is one.
    fn name(&mut self, parent: u64, parent_path: &str, f: Found, parent_deleted: bool) -> Option<DirWork> {
        let (name, n, ftype, deleted_name, complete) = f;
        let path = format!("{}/{}", parent_path, name);
        let off = self.v.inode_offset(n);
        let ino = off.and_then(|o| self.v.inode_at(self.r, o).ok());
        // A deleted name kept only the low half of its inode number: taken
        // when the inode there was freed and (version 5) names itself.
        let ino = match (ino, deleted_name && !complete) {
            (Some(i), true) if !(i.freed() && (i.version < 3 || i.number == n)) => None,
            (i, _) => i,
        };
        let (Some(off), Some(ino)) = (off, ino) else {
            if !deleted_name {
                return None;
            }
            // The name is evidence even when its inode cannot be tied to it.
            let rec = self.next;
            self.next += 1;
            let blank = Inode::parse([b"IN".as_slice(), &[0, 0, 3], &[0; 171]].concat()).expect("blank inode");
            let msg = "the folder entry no longer leads to its inode (the inode was reused, or the high half of its number was overwritten)".to_string();
            let mut e = self.entry(rec, parent, path, name, n, 0, &blank, true, None, ftype, Some(msg));
            e.unix = None;
            e.si = None;
            self.out.push(e);
            return None;
        };
        let rec = self.next;
        let mut error = None;
        let deleted = deleted_name || parent_deleted || !ino.live();
        let content = if !deleted {
            Some((ino.clone(), off))
        } else if ino.live() {
            error = Some(format!("inode {} is in use again (the file was renamed, or the inode reused by another file); content not attributed to this name", n));
            None
        } else if ino.freed() && !self.v.deleted_map(&ino).is_empty() {
            if ftype != 2 {
                self.recovered += 1;
            }
            Some((ino.clone(), off))
        } else {
            None
        };
        if deleted && content.is_none() && error.is_none() && ftype != 2 {
            self.no_content += 1;
        }
        if deleted && content.as_ref().is_some_and(|c| !c.0.live()) && ftype != 2 {
            error = Some("size not kept (XFS clears it on delete): content read to the end of the file's last block".into());
        }
        self.next += 1;
        self.named.insert(n);
        let e = self.entry(rec, parent, path.clone(), name, n, off, &ino, deleted, content.clone(), ftype, error);
        let is_dir = e.is_dir;
        self.out.push(e);
        (is_dir && (content.is_some() || ino.freed()) && self.seen_dirs.insert(n)).then_some((rec, path, n, off, deleted))
    }

    fn dir(&mut self, (rec, path, n, off, deleted): DirWork) -> Vec<DirWork> {
        let Ok(ino) = self.v.inode_at(self.r, off) else { return vec![] };
        let mut found: Vec<Found> = vec![];
        if ino.live() && ino.format == FMT_LOCAL {
            self.short_form(ino.fork(), ino.size as usize, None, &mut found);
        } else if ino.live() {
            let map = self.v.map(self.r, &ino, off);
            self.dir_blocks(&map, n, &mut found);
        } else if ino.freed() {
            // A deleted folder: its blocks, if the extents survived, else the
            // short-form entries left in the inode (checked against the parent).
            let map = self.v.deleted_map(&ino);
            if !map.is_empty() {
                self.dir_blocks(&map, n, &mut found);
            }
            if found.is_empty() {
                let parent_rec = self.out.iter().find(|e| e.record == rec).map(|e| e.parent).unwrap_or(ROOT_RECORD);
                let parent_ino = self.out.iter().find(|e| e.record == parent_rec).and_then(|e| e.unix.as_ref().map(|u| u.inode));
                let fork = &ino.raw[ino.core()..];
                self.short_form(fork, fork.len(), parent_ino, &mut found);
                for f in found.iter_mut() {
                    f.3 = true;
                }
            }
        }
        let live: HashSet<(String, u64)> = found.iter().filter(|x| !x.3).map(|x| (x.0.clone(), x.1)).collect();
        let live_names: HashSet<String> = found.iter().filter(|x| !x.3).map(|x| x.0.clone()).collect();
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let mut sub = vec![];
        for f in found {
            if f.1 == n && !f.3 {
                continue;
            }
            // A deleted copy of a name the folder still has (a short-form
            // folder shifting entries down, a rename within the folder).
            if f.3 && (live.contains(&(f.0.clone(), f.1)) || (live_names.contains(&f.0) && !f.4) || !seen.insert((f.0.clone(), f.1))) {
                continue;
            }
            if let Some(d) = self.name(rec, &path, f, deleted) {
                sub.push(d);
            }
            if self.out.len() > MAX_ENTRIES {
                break;
            }
        }
        sub
    }

    /// A short-form folder: header (count, count of 8-byte numbers, parent),
    /// then entries (name length, offset tag, name, file type, inode number).
    /// `used` bytes are live; one entry may be left past them, removed.
    /// With `parent`, the bytes are a freed inode's leftovers and must name
    /// that parent.
    fn short_form(&self, fork: &[u8], used: usize, parent: Option<u64>, found: &mut Vec<Found>) {
        if fork.len() < 6 {
            return;
        }
        let count = fork[0] as usize;
        let i8 = fork[1] as usize;
        if i8 != 0 && i8 != count {
            return;
        }
        let w = if i8 > 0 { 8 } else { 4 };
        let num = |p: usize| if w == 8 { be64(fork, p) } else { be32(fork, p) };
        if parent.is_some_and(|p| num(2) != p) {
            return;
        }
        let ft = self.v.ftype as usize;
        let used = used.min(fork.len());
        let mut p = 2 + w;
        let mut k = 0usize;
        let mut last_tag = 0u64;
        loop {
            let live = k < count;
            let lim = if live { used } else { fork.len() };
            if p + 3 > lim {
                break;
            }
            let nl = fork[p] as usize;
            let end = p + 3 + nl + ft + w;
            if nl == 0 || end > lim {
                break;
            }
            let name = &fork[p + 3..p + 3 + nl];
            let tag = be16(fork, p + 1);
            let ftype = if ft == 1 { fork[p + 3 + nl] } else { 0 };
            let child = num(p + 3 + nl + ft);
            if !plausible_name(name) || ftype > 7 || child == 0 {
                break;
            }
            if !live {
                // Past the live entries: only an entry that still sorts after
                // the last live one (tags grow) and leads to a valid inode.
                if tag <= last_tag || self.v.inode_offset(child).is_none() {
                    break;
                }
            }
            last_tag = tag;
            found.push((name_str(name), child, ftype, !live || parent.is_some(), true));
            p = end;
            k += 1;
            if k > 255 {
                break;
            }
        }
    }

    /// Entries of a folder kept in directory blocks: every data block below
    /// the leaf offset, live entries and removed ones in the free regions.
    fn dir_blocks(&mut self, map: &[Extent], n: u64, found: &mut Vec<Found>) {
        let db = self.v.dir_block as usize;
        let mut total = 0u64;
        for x in map {
            if x.offset >= DIR_LEAF_OFFSET {
                break;
            }
            let Some(vol) = x.vol else { continue };
            let len = x.len.min(DIR_LEAF_OFFSET - x.offset).min(MAX_DIR_BYTES - total);
            if len == 0 {
                break;
            }
            total += len;
            let Ok(data) = rd(self.r, vol, len as usize) else { continue };
            for blk in data.chunks_exact(db) {
                self.data_block(blk, n, found);
            }
        }
    }

    fn data_block(&self, blk: &[u8], n: u64, found: &mut Vec<Found>) {
        let magic = &blk[0..4];
        let (hdr, single) = match magic {
            b"XD2B" => (16, true),
            b"XD2D" => (16, false),
            b"XDB3" => (64, true),
            b"XDD3" => (64, false),
            _ => return,
        };
        // Version 5 blocks name the folder they belong to.
        if hdr == 64 && be64(blk, 40) != n {
            return;
        }
        let end = if single {
            let count = be32(blk, blk.len() - 8) as usize;
            match blk.len().checked_sub(8 + count * 8) {
                Some(e) if e >= hdr => e,
                _ => return,
            }
        } else {
            blk.len()
        };
        let ft = self.v.ftype as usize;
        let mut p = hdr;
        while p + 8 <= end {
            if be16(blk, p) == 0xFFFF {
                let len = be16(blk, p + 2) as usize;
                if len < 8 || !len.is_multiple_of(8) || p + len > end {
                    return;
                }
                self.removed(blk, p, p + len, found);
                p += len;
                continue;
            }
            let nl = blk[p + 8] as usize;
            let size = (8 + 1 + nl + ft + 2).next_multiple_of(8);
            if nl == 0 || p + size > end || be16(blk, p + size - 2) != p as u64 {
                return;
            }
            let name = &blk[p + 9..p + 9 + nl];
            let ftype = if ft == 1 { blk[p + 9 + nl] } else { 0 };
            if name != b"." && name != b".." {
                found.push((name_str(name), be64(blk, p), ftype, false, true));
            }
            p += size;
        }
    }

    /// Removed entries inside the free region `s..end` of a directory block.
    /// Each sits at an 8-byte boundary and ends with a tag giving its own
    /// offset; at the region's start the high half of the inode number was
    /// overwritten by the free tag and length.
    fn removed(&self, blk: &[u8], s: usize, end: usize, found: &mut Vec<Found>) {
        let ft = self.v.ftype as usize;
        let mut p = s;
        while p + 16 <= end {
            let nl = blk[p + 8] as usize;
            let size = (8 + 1 + nl + ft + 2).next_multiple_of(8);
            // The region's own tag (its start) overwrites the tag of the entry
            // that ends where the region ends.
            let tag = be16(blk, p + size - 2);
            let ok = nl > 0 && p + size <= end && (tag == p as u64 || (p + size == end && tag == s as u64)) && plausible_name(&blk[p + 9..p + 9 + nl]) && (ft == 0 || (1..=7).contains(&blk[p + 9 + nl]));
            if ok {
                let complete = p != s;
                let child = if complete { be64(blk, p) } else { be32(blk, p + 4) };
                if child != 0 {
                    found.push((name_str(&blk[p + 9..p + 9 + nl]), child, if ft == 1 { blk[p + 9 + nl] } else { 0 }, true, complete));
                }
                p += size;
            } else {
                p += 8;
            }
        }
    }

    /// Inodes no name points to: files unlinked while still open, and freed
    /// inodes whose extent records survived. Orphaned directories are walked
    /// first, so the files inside a deleted folder keep their names.
    fn orphans(&mut self, progress: &mut impl FnMut(u64, u64) -> bool, notes: &mut Vec<String>) -> anyhow::Result<()> {
        let v = self.v;
        let chunks = v.chunks(self.r);
        let mut read = 0u64;
        let mut candidates: Vec<(u64, u64, bool)> = vec![];
        let per_block = 1u64 << v.inopblog;
        for (ci, &(first, free, holes)) in chunks.iter().enumerate() {
            if ci % 256 == 0 && !progress(self.out.len() as u64, self.out.len() as u64) {
                anyhow::bail!("scan cancelled");
            }
            if read + 64 * v.inode_size > MAX_INODE_BYTES {
                notes.push(format!("Only the first {} MiB of inodes were searched for orphaned inodes.", MAX_INODE_BYTES >> 20));
                break;
            }
            let mut k = 0u64;
            while k < 64 {
                // Read a block of inodes at a time.
                let Some(off) = v.inode_offset(first + k) else { break };
                let take = per_block.min(64 - k);
                if (0..take).all(|j| holes >> ((k + j) / 4) & 1 == 1) {
                    k += take;
                    continue;
                }
                let Ok(buf) = rd(self.r, off, (take * v.inode_size) as usize) else { break };
                read += buf.len() as u64;
                for (j, raw) in buf.chunks_exact(v.inode_size as usize).enumerate() {
                    let i = k + j as u64;
                    let num = first + i;
                    if holes >> (i / 4) & 1 == 1 || self.named.contains(&num) || candidates.len() >= MAX_ENTRIES {
                        continue;
                    }
                    let Some(ino) = Inode::parse(raw.to_vec()) else { continue };
                    let is_free = free >> i & 1 == 1;
                    let take_it = if is_free { ino.freed() && !v.deleted_map(&ino).is_empty() } else { ino.live() };
                    if take_it && (ino.version < 3 || ino.number == num) {
                        candidates.push((num, off + j as u64 * v.inode_size, ino.is_dir()));
                    }
                }
                k += take;
            }
        }
        // Directories first, lowest inode first (a parent is usually older).
        candidates.sort_by_key(|&(n, _, d)| (!d, n));
        for (n, off, _) in candidates {
            if self.named.contains(&n) {
                continue;
            }
            let Ok(ino) = v.inode_at(self.r, off) else { continue };
            let deleted = !ino.live();
            if deleted && !ino.is_dir() {
                self.recovered += 1;
            }
            let name = format!("inode-{}", n);
            let path = format!("{}/{}", ORPHAN_ROOT, name);
            let rec = self.next;
            self.next += 1;
            self.named.insert(n);
            let error = deleted.then(|| "size not kept (XFS clears it on delete): content read to the end of the file's last block".to_string());
            let mut e = self.entry(rec, ROOT_RECORD, path.clone(), name, n, off, &ino, deleted, Some((ino.clone(), off)), 0, error);
            e.orphan = true;
            let walk = (e.is_dir && self.seen_dirs.insert(n)).then_some((rec, path, n, off, deleted));
            self.out.push(e);
            if let Some(d) = walk {
                let mut queue = VecDeque::from([d]);
                while let Some(d) = queue.pop_front() {
                    queue.extend(self.dir(d));
                    if self.out.len() > MAX_ENTRIES {
                        break;
                    }
                }
            }
            if self.out.len() > MAX_ENTRIES {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
