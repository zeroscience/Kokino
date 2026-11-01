//! ext2, ext3 and ext4 reader.
//!
//! Walks the directory tree from the root inode and returns the same
//! `FsEntry` records as the NTFS and FAT walkers, so every view (explorer,
//! timeline, search, carving, artifacts) works unchanged. Owner, mode and
//! inode number go in `FsEntry::unix`.
//!
//! Deleted files:
//! - Names: removing a directory entry only grows the previous entry's
//!   record length over it, so the name and inode number stay in the slack
//!   until the space is reused. They are recovered with strict checks.
//! - Content: ext2 keeps a deleted inode's block pointers, so content is read
//!   as is. ext3 and ext4 zero the block map (and the size) on delete. Their
//!   journal often still holds an older copy of the inode-table block with
//!   the inode as it was before deletion; that copy is used when its
//!   generation matches. Otherwise only carving can bring the content back.
//! - Inodes that no name points to any more are listed under $OrphanFiles.
//!
//! Times are UTC seconds (ext4: plus nanoseconds and the creation time);
//! the inode change time is reported as `mft_modified` (entry modified).

#![forbid(unsafe_code)]

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta, ORPHAN_ROOT};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Mutex, OnceLock};

/// Root directory record id; real entries start at FIRST_RECORD, as on FAT.
pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
const ROOT_INODE: u64 = 2;
const JOURNAL_MAGIC: u32 = 0xC03B_3998;
const EXTENT_MAGIC: u16 = 0xF30A;
const MAX_ENTRIES: usize = 5_000_000;
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Extent-tree and indirect blocks read to map one file.
const MAX_MAP_BLOCKS: usize = 1 << 16;
const MAX_EXTENTS: usize = 1 << 20;
/// Inode tables read when looking for orphans.
const MAX_ITABLE_BYTES: u64 = 2 << 30;
const MAX_JOURNAL_BLOCKS: u64 = 1 << 20;
const MAX_JOURNAL_COPIES: usize = 4 << 20;
const MAX_BITMAP_BYTES: u64 = 512 << 20;

const COMPAT_HAS_JOURNAL: u32 = 0x4;
const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_RECOVER: u32 = 0x4;
const INCOMPAT_META_BG: u32 = 0x10;
const INCOMPAT_EXTENTS: u32 = 0x40;
const INCOMPAT_64BIT: u32 = 0x80;
const INCOMPAT_FLEX_BG: u32 = 0x200;
const RO_SPARSE_SUPER: u32 = 0x1;
const RO_HUGE_FILE: u32 = 0x8;
const RO_GDT_CSUM: u32 = 0x10;
const RO_DIR_NLINK: u32 = 0x20;
const RO_EXTRA_ISIZE: u32 = 0x40;
const RO_METADATA_CSUM: u32 = 0x400;

const FL_INDEX: u32 = 0x1000;
const FL_EXTENTS: u32 = 0x8_0000;
const FL_INLINE: u32 = 0x1000_0000;
const BG_INODE_UNINIT: u16 = 0x1;
const BG_BLOCK_UNINIT: u16 = 0x2;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

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
fn be32_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).trim().to_string()
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

#[derive(Debug, Clone, Copy)]
struct Group {
    block_bitmap: u64,
    inode_table: u64,
    flags: u16,
    itable_unused: u64,
}

pub struct ExtVolume {
    /// "ext2", "ext3" or "ext4".
    pub version: &'static str,
    pub block: u64,
    pub blocks: u64,
    pub first_data_block: u64,
    pub blocks_per_group: u64,
    pub inodes_per_group: u64,
    pub inodes: u64,
    pub inode_size: u64,
    pub first_ino: u64,
    pub label: String,
    pub uuid: String,
    pub last_mounted: String,
    /// FILETIMEs: file system created, last mounted, last written.
    pub created: u64,
    pub mount_time: u64,
    pub write_time: u64,
    pub dirty: bool,
    pub journal_inode: u64,
    /// Block groups per flex group (ext4 flex_bg), 1 otherwise.
    pub groups_per_flex: u64,
    pub size: u64,
    filetype: bool,
    uninit_bg: bool,
    groups: Vec<Group>,
    bitmap: OnceLock<Option<Vec<u8>>>,
    /// Last file mapped: (inode offset, its extents).
    map_cache: Mutex<Option<(u64, Vec<Extent>)>>,
}

/// One inode, decoded.
#[derive(Debug, Clone)]
pub struct Inode {
    pub raw: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub flags: u32,
    pub generation: u64,
    pub dtime: u64,
    pub blocks512: u64,
    pub times: Times,
}

impl Inode {
    fn parse(raw: Vec<u8>, huge: bool) -> Inode {
        let extra = if raw.len() > 130 { u16_at(&raw, 128) } else { 0 };
        let has = |need: u64| extra >= need && raw.len() as u64 >= 128 + need;
        let t = |lo: usize, ex: Option<usize>| -> u64 {
            let secs = u32_at(&raw, lo) as u32 as i32 as i64;
            match ex {
                Some(x) => {
                    let e = u32_at(&raw, x);
                    unix_ft(secs + (((e & 3) as i64) << 32), e >> 2)
                }
                None => unix_ft(secs, 0),
            }
        };
        let times = Times {
            accessed: t(8, has(16).then_some(140)),
            mft_modified: t(12, has(8).then_some(132)),
            modified: t(16, has(12).then_some(136)),
            created: if has(20) { t(144, has(24).then_some(148)) } else { 0 },
        };
        let flags = u32_at(&raw, 32) as u32;
        let mut blocks512 = u32_at(&raw, 28) | u16_at(&raw, 116) << 32;
        if huge && flags & 0x40000 != 0 {
            // HUGE_FILE: counted in file-system blocks; the caller scales.
            blocks512 |= 1 << 63;
        }
        Inode {
            mode: u16_at(&raw, 0) as u32,
            uid: (u16_at(&raw, 2) | u16_at(&raw, 120) << 16) as u32,
            gid: (u16_at(&raw, 24) | u16_at(&raw, 122) << 16) as u32,
            size: u32_at(&raw, 4) | u32_at(&raw, 108) << 32,
            links: u16_at(&raw, 26) as u16,
            flags,
            generation: u32_at(&raw, 100),
            dtime: u32_at(&raw, 20),
            blocks512,
            times,
            raw,
        }
    }

    fn kind(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == S_IFDIR
    }
    /// Still in use: linked and not deleted.
    pub fn live(&self) -> bool {
        self.mode != 0 && self.links > 0 && self.dtime == 0
    }
    /// The block map is empty (zeroed on delete by ext3/ext4).
    fn map_empty(&self) -> bool {
        let b = &self.raw[40..100.min(self.raw.len())];
        if self.flags & FL_EXTENTS != 0 {
            return u16_at(b, 2) == 0;
        }
        b.iter().all(|&x| x == 0)
    }
    /// Content stored in the inode itself (fast symlink or inline data).
    fn inline(&self) -> bool {
        if self.flags & FL_INLINE != 0 {
            return true;
        }
        // Fast symlink: no blocks of its own (an extended-attribute block
        // may still be counted in i_blocks).
        let own = self.blocks512 & !(1 << 63);
        self.kind() == S_IFLNK && self.flags & FL_EXTENTS == 0 && self.size < 60 && (own == 0 || (u32_at(&self.raw, 104) != 0 && own <= 128))
    }
}

fn dirty_flags(sb: &[u8]) -> bool {
    u16_at(sb, 58) & 1 == 0 || u32_at(sb, 96) as u32 & INCOMPAT_RECOVER != 0
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<ExtVolume> {
    let sb = rd(r, 1024, 1024)?;
    if sb.len() < 1024 || u16_at(&sb, 56) != 0xEF53 {
        anyhow::bail!("not an ext2/3/4 superblock");
    }
    let log = u32_at(&sb, 24);
    if log > 6 {
        anyhow::bail!("ext block size out of range");
    }
    let block = 1024u64 << log;
    let (compat, incompat, ro) = (u32_at(&sb, 92) as u32, u32_at(&sb, 96) as u32, u32_at(&sb, 100) as u32);
    let is64 = incompat & INCOMPAT_64BIT != 0;
    let blocks = u32_at(&sb, 4) | if is64 { u32_at(&sb, 0x150) << 32 } else { 0 };
    let first_data_block = u32_at(&sb, 20);
    let bpg = u32_at(&sb, 32);
    let ipg = u32_at(&sb, 40);
    let rev = u32_at(&sb, 76);
    let inode_size = if rev == 0 { 128 } else { u16_at(&sb, 88) };
    let first_ino = if rev == 0 { 11 } else { u32_at(&sb, 84).max(3) };
    let desc_size = if is64 { u16_at(&sb, 0xFE).max(32) } else { 32 };
    if bpg == 0 || bpg > 8 * block || ipg == 0 || ipg > 8 * block || blocks <= first_data_block || first_data_block > 1 {
        anyhow::bail!("ext superblock geometry out of range");
    }
    if inode_size < 128 || inode_size > block || !inode_size.is_power_of_two() || desc_size > block || !desc_size.is_power_of_two() {
        anyhow::bail!("ext inode or descriptor size out of range");
    }
    let ngroups = (blocks - first_data_block).div_ceil(bpg);
    if ngroups > 1 << 24 {
        anyhow::bail!("ext group count out of range");
    }
    let inodes = u32_at(&sb, 0).min(ngroups.saturating_mul(ipg));
    let sparse = ro & RO_SPARSE_SUPER != 0;
    let has_super = |g: u64| {
        if !sparse || g <= 1 {
            return true;
        }
        [3u64, 5, 7].iter().any(|&p| {
            let mut x = g;
            while x.is_multiple_of(p) {
                x /= p;
            }
            x == 1
        })
    };
    // Group descriptors: right after the superblock, or (meta_bg) one block
    // of them at the start of each meta group.
    let per_block = block / desc_size;
    let desc_blocks = ngroups.div_ceil(per_block);
    let first_meta_bg = if incompat & INCOMPAT_META_BG != 0 { u32_at(&sb, 0x104) } else { u64::MAX };
    let mut groups = Vec::with_capacity(ngroups.min(1 << 16) as usize);
    for i in 0..desc_blocks {
        let at = if i < first_meta_bg {
            first_data_block + 1 + i
        } else {
            let g = i * per_block;
            first_data_block + g * bpg + has_super(g) as u64
        };
        let b = if at < blocks { rd(r, at * block, block as usize)? } else { vec![] };
        // Descriptors past the end of the image cannot be read: the table
        // grows with what the image holds, not with what the header claims.
        if b.is_empty() {
            break;
        }
        for k in 0..per_block {
            if groups.len() as u64 >= ngroups {
                break;
            }
            let d = b.get((k * desc_size) as usize..((k + 1) * desc_size) as usize).unwrap_or(&[]);
            let hi = |o: usize| if desc_size >= 64 { u32_at(d, o) << 32 } else { 0 };
            let valid = |x: u64| if x != 0 && x < blocks { x } else { 0 };
            groups.push(Group {
                block_bitmap: valid(u32_at(d, 0) | hi(0x20)),
                inode_table: valid(u32_at(d, 8) | hi(0x28)),
                flags: u16_at(d, 0x12) as u16,
                itable_unused: u16_at(d, 0x1C) | if desc_size >= 64 { u16_at(d, 0x32) << 16 } else { 0 },
            });
        }
    }
    let version = if incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG) != 0 || ro & (RO_HUGE_FILE | RO_DIR_NLINK | RO_EXTRA_ISIZE | RO_METADATA_CSUM) != 0 {
        "ext4"
    } else if compat & COMPAT_HAS_JOURNAL != 0 {
        "ext3"
    } else {
        "ext2"
    };
    let u = &sb[104..120];
    let hex: String = u.iter().map(|b| format!("{:02x}", b)).collect();
    let uuid = format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32]);
    let vol_bytes = blocks.saturating_mul(block);
    Ok(ExtVolume {
        version,
        block,
        blocks,
        first_data_block,
        blocks_per_group: bpg,
        inodes_per_group: ipg,
        inodes,
        inode_size,
        first_ino,
        label: cstr(&sb[120..136]),
        uuid,
        last_mounted: cstr(&sb[136..200]),
        created: unix_ft(u32_at(&sb, 0x108) as i64, 0),
        mount_time: unix_ft(u32_at(&sb, 44) as i64, 0),
        write_time: unix_ft(u32_at(&sb, 48) as i64, 0),
        dirty: dirty_flags(&sb),
        journal_inode: if compat & COMPAT_HAS_JOURNAL != 0 { u32_at(&sb, 0xE0) } else { 0 },
        groups_per_flex: if incompat & INCOMPAT_FLEX_BG != 0 && sb[0x174] < 16 { 1 << sb[0x174] } else { 1 },
        size: if size == 0 { vol_bytes } else { vol_bytes.min(size) },
        filetype: incompat & INCOMPAT_FILETYPE != 0,
        uninit_bg: ro & (RO_GDT_CSUM | RO_METADATA_CSUM) != 0,
        groups,
        bitmap: OnceLock::new(),
        map_cache: Mutex::new(None),
    })
}

impl ExtVolume {
    /// Volume byte offset of inode `n` in its inode table.
    pub fn inode_offset(&self, n: u64) -> Option<u64> {
        if n == 0 || n > self.inodes {
            return None;
        }
        let g = self.groups.get(((n - 1) / self.inodes_per_group) as usize)?;
        if g.inode_table == 0 {
            return None;
        }
        Some(g.inode_table * self.block + (n - 1) % self.inodes_per_group * self.inode_size)
    }

    fn inode_at<R: Read + Seek>(&self, r: &mut R, off: u64) -> anyhow::Result<Inode> {
        let raw = rd(r, off, self.inode_size as usize)?;
        if raw.len() < 128 {
            anyhow::bail!("inode past the end of the volume");
        }
        let mut i = Inode::parse(raw, true);
        if i.blocks512 & (1 << 63) != 0 {
            i.blocks512 = (i.blocks512 & !(1 << 63)).saturating_mul(self.block / 512);
        }
        Ok(i)
    }

    pub fn inode<R: Read + Seek>(&self, r: &mut R, n: u64) -> anyhow::Result<Inode> {
        let off = self.inode_offset(n).ok_or_else(|| anyhow::anyhow!("inode {} out of range", n))?;
        self.inode_at(r, off)
    }

    /// Where an inode's bytes live: logical runs in file order. Runs with
    /// `vol: None` read as zeros (uninitialized extents); holes are absent.
    pub fn map<R: Read + Seek>(&self, r: &mut R, ino: &Inode, inode_off: u64) -> Vec<Extent> {
        if ino.inline() {
            return vec![Extent { offset: 0, len: ino.size.min(60), vol: Some(inode_off + 40) }];
        }
        let mut out = vec![];
        let mut budget = MAX_MAP_BLOCKS;
        let root = &ino.raw[40..100];
        if ino.flags & FL_EXTENTS != 0 {
            self.walk_extents(r, root, 5, &mut out, &mut budget);
            out.sort_by_key(|x: &Extent| x.offset);
        } else {
            // ext2 rmdir sets a directory's size to 0 but keeps its pointers.
            let want = if ino.size == 0 && ino.is_dir() { (ino.blocks512.saturating_mul(512) / self.block).clamp(1, 4096) } else { ino.size.div_ceil(self.block) };
            let mut logical = 0u64;
            for i in 0..12 {
                if logical >= want {
                    break;
                }
                self.add(&mut out, logical, u32_at(root, 4 * i));
                logical += 1;
            }
            for level in 1..=3u32 {
                if logical >= want {
                    break;
                }
                self.indirect(r, u32_at(root, 4 * (11 + level as usize)), level, &mut logical, want, &mut out, &mut budget);
            }
        }
        out
    }

    fn add(&self, out: &mut Vec<Extent>, logical: u64, p: u64) {
        if p == 0 || p >= self.blocks || out.len() >= MAX_EXTENTS {
            return;
        }
        let (off, vol) = (logical * self.block, p * self.block);
        match out.last_mut() {
            Some(x) if x.offset + x.len == off && x.vol.map(|v| v + x.len) == Some(vol) => x.len += self.block,
            _ => out.push(Extent { offset: off, len: self.block, vol: Some(vol) }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn indirect<R: Read + Seek>(&self, r: &mut R, ptr: u64, level: u32, logical: &mut u64, want: u64, out: &mut Vec<Extent>, budget: &mut usize) {
        let per = self.block / 4;
        let span = per.saturating_pow(level);
        if ptr == 0 || ptr >= self.blocks || *budget == 0 {
            *logical = logical.saturating_add(span);
            return;
        }
        *budget -= 1;
        let Ok(b) = rd(r, ptr * self.block, self.block as usize) else {
            *logical = logical.saturating_add(span);
            return;
        };
        for i in 0..per as usize {
            if *logical >= want {
                return;
            }
            let p = u32_at(&b, 4 * i);
            if level == 1 {
                self.add(out, *logical, p);
                *logical += 1;
            } else {
                self.indirect(r, p, level - 1, logical, want, out, budget);
            }
        }
    }

    fn walk_extents<R: Read + Seek>(&self, r: &mut R, node: &[u8], max_depth: u64, out: &mut Vec<Extent>, budget: &mut usize) {
        if node.len() < 12 || u16_at(node, 0) != EXTENT_MAGIC as u64 {
            return;
        }
        let depth = u16_at(node, 6);
        if depth > max_depth {
            return;
        }
        let n = (u16_at(node, 2) as usize).min((node.len() - 12) / 12);
        for i in 0..n {
            let e = &node[12 + 12 * i..24 + 12 * i];
            if depth == 0 {
                let lblk = u32_at(e, 0);
                let mut len = u16_at(e, 4);
                let uninit = len > 32768;
                if uninit {
                    len -= 32768;
                }
                let start = u16_at(e, 6) << 32 | u32_at(e, 8);
                if len == 0 || start.saturating_add(len) > self.blocks || out.len() >= MAX_EXTENTS {
                    continue;
                }
                let (off, l) = (lblk * self.block, len * self.block);
                let vol = (!uninit).then_some(start * self.block);
                match out.last_mut() {
                    Some(x) if vol.is_some() && x.offset + x.len == off && x.vol.map(|v| v + x.len) == vol => x.len += l,
                    _ => out.push(Extent { offset: off, len: l, vol }),
                }
            } else {
                let leaf = u32_at(e, 4) | u16_at(e, 8) << 32;
                if leaf == 0 || leaf >= self.blocks || *budget == 0 {
                    continue;
                }
                *budget -= 1;
                if let Ok(b) = rd(r, leaf * self.block, self.block as usize) {
                    self.walk_extents(r, &b, depth - 1, out, budget);
                }
            }
        }
    }

    /// The inode an entry's content is read through (see `UnixMeta::inode_offset`).
    fn content_inode<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> anyhow::Result<(Inode, u64)> {
        let u = e.unix.as_ref().ok_or_else(|| anyhow::anyhow!("not an ext entry"))?;
        Ok((self.inode_at(r, u.inode_offset)?, u.inode_offset))
    }

    /// Where a file's bytes live, as volume extents.
    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> anyhow::Result<Vec<Extent>> {
        let Some(u) = e.unix.as_ref() else { return Ok(vec![]) };
        if let Ok(c) = self.map_cache.lock() {
            if let Some((off, x)) = c.as_ref() {
                if *off == u.inode_offset {
                    return Ok(x.clone());
                }
            }
        }
        let (ino, off) = self.content_inode(r, e)?;
        let x = self.map(r, &ino, off);
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

    fn bitmap<R: Read + Seek>(&self, r: &mut R) -> Option<&Vec<u8>> {
        self.bitmap
            .get_or_init(|| {
                // Only groups whose blocks lie inside the image.
                let in_image = self.size.div_ceil(self.block).saturating_sub(self.first_data_block).div_ceil(self.blocks_per_group) as usize;
                let groups = &self.groups[..self.groups.len().min(in_image)];
                let bytes = groups.len() as u64 * self.blocks_per_group / 8;
                if bytes > MAX_BITMAP_BYTES {
                    return None;
                }
                let mut out = Vec::with_capacity(bytes as usize);
                for g in groups {
                    let n = (self.blocks_per_group / 8) as usize;
                    // Never-initialized groups have no bitmap on disk: all free.
                    let b = if (self.uninit_bg && g.flags & BG_BLOCK_UNINIT != 0) || g.block_bitmap == 0 { vec![0; n] } else { rd(r, g.block_bitmap * self.block, n).unwrap_or_default() };
                    out.extend_from_slice(&b);
                    out.resize(out.len() + n - b.len(), 0xFF);
                }
                Some(out)
            })
            .as_ref()
    }

    /// Block is in use according to the block bitmap (true when unknown).
    pub fn allocated<R: Read + Seek>(&self, r: &mut R, b: u64) -> bool {
        if b < self.first_data_block || b >= self.blocks {
            return true;
        }
        let i = b - self.first_data_block;
        self.bitmap(r).and_then(|bm| bm.get((i / 8) as usize)).map(|x| x >> (i % 8) & 1 == 1).unwrap_or(true)
    }

    /// Unallocated block runs: (volume byte offset, length).
    pub fn free_runs<R: Read + Seek>(&self, r: &mut R) -> Vec<(u64, u64)> {
        let Some(bm) = self.bitmap(r) else { return vec![] };
        let mut out = vec![];
        let mut start: Option<u64> = None;
        let total = (self.blocks - self.first_data_block).min(bm.len() as u64 * 8);
        let mut i = 0u64;
        while i < total {
            let byte = bm.get((i / 8) as usize).copied().unwrap_or(0xFF);
            if i.is_multiple_of(8) && (byte == 0xFF && start.is_none() || byte == 0 && start.is_some()) && i + 8 <= total {
                i += 8;
                continue;
            }
            let used = byte >> (i % 8) & 1 == 1;
            match (used, start) {
                (false, None) => start = Some(i),
                (true, Some(s)) => {
                    out.push(((s + self.first_data_block) * self.block, (i - s) * self.block));
                    start = None;
                }
                _ => {}
            }
            i += 1;
        }
        if let Some(s) = start {
            out.push(((s + self.first_data_block) * self.block, (total - s) * self.block));
        }
        out
    }

    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: self.uuid.clone(),
            version: self.version.into(),
            cluster_size: self.block as u32,
            sector_size: 512,
            record_size: self.inode_size as u32,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: self.groups.first().map(|g| g.inode_table * self.block).unwrap_or(0),
            dirty: self.dirty,
        }
    }

    /// Inode-table block ranges, sorted: [start, end).
    fn itable_ranges(&self) -> Vec<(u64, u64)> {
        let n = (self.inodes_per_group * self.inode_size).div_ceil(self.block);
        let mut v: Vec<(u64, u64)> = self.groups.iter().filter(|g| g.inode_table != 0).map(|g| (g.inode_table, g.inode_table + n)).collect();
        v.sort_unstable();
        v
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

/// Copies of inode-table blocks found in the journal: file-system block to
/// (transaction sequence, volume offset of the copy), newest first.
type JournalCopies = HashMap<u64, Vec<(u32, u64)>>;

fn journal_copies<R: Read + Seek>(v: &ExtVolume, r: &mut R) -> anyhow::Result<JournalCopies> {
    let mut out: JournalCopies = HashMap::new();
    if v.journal_inode == 0 {
        return Ok(out);
    }
    let ji = v.inode(r, v.journal_inode)?;
    let jo = v.inode_offset(v.journal_inode).unwrap_or(0);
    let map = v.map(r, &ji, jo);
    let at = |j: u64| -> Option<u64> {
        let off = j.checked_mul(v.block)?;
        let i = map.partition_point(|x| x.offset + x.len <= off);
        let x = map.get(i)?;
        (x.offset <= off).then(|| x.vol.map(|vol| vol + off - x.offset)).flatten()
    };
    let Some(sb_at) = at(0) else { return Ok(out) };
    let jsb = rd(r, sb_at, 1024)?;
    if be32_at(&jsb, 0) != JOURNAL_MAGIC as u64 || !(3..=4).contains(&be32_at(&jsb, 4)) || be32_at(&jsb, 12) != v.block {
        anyhow::bail!("journal superblock not recognized");
    }
    let maxlen = be32_at(&jsb, 16).min(ji.size / v.block).min(MAX_JOURNAL_BLOCKS);
    let first = be32_at(&jsb, 20).max(1);
    let incompat = if be32_at(&jsb, 4) == 4 { be32_at(&jsb, 0x28) } else { 0 };
    let (is64, csum2, csum3) = (incompat & 2 != 0, incompat & 8 != 0, incompat & 0x10 != 0);
    let tag_len = if csum3 { 16 } else { 8 + if csum2 { 2 } else { 0 } + if is64 { 4 } else { 0 } };
    let tail = if csum2 || csum3 { 4 } else { 0 };
    let tables = v.itable_ranges();
    let in_table = |b: u64| {
        let i = tables.partition_point(|x| x.1 <= b);
        tables.get(i).map(|x| x.0 <= b).unwrap_or(false)
    };
    let mut copies = 0usize;
    for j in first..maxlen {
        let Some(off) = at(j) else { continue };
        let b = rd(r, off, v.block as usize)?;
        if be32_at(&b, 0) != JOURNAL_MAGIC as u64 || be32_at(&b, 4) != 1 {
            continue;
        }
        let seq = be32_at(&b, 8) as u32;
        let mut p = 12usize;
        let mut data = j;
        while p + tag_len + tail <= b.len() {
            let t = &b[p..p + tag_len];
            let flags = if csum3 { be32_at(t, 4) } else { be32_at(t, 4) & 0xFFFF };
            let fsb = be32_at(t, 0) | if is64 { be32_at(t, 8) << 32 } else { 0 };
            data += 1;
            if data >= maxlen {
                data = first;
            }
            // Escaped blocks had their first four bytes replaced; the inode
            // copies are only used when that cannot matter.
            if flags & 1 == 0 && in_table(fsb) && copies < MAX_JOURNAL_COPIES {
                if let Some(d) = at(data) {
                    out.entry(fsb).or_default().push((seq, d));
                    copies += 1;
                }
            }
            p += tag_len + if flags & 2 == 0 { 16 } else { 0 };
            if flags & 8 != 0 {
                break;
            }
        }
    }
    for list in out.values_mut() {
        list.sort_by_key(|x| std::cmp::Reverse(x.0));
    }
    Ok(out)
}

pub struct ExtScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    /// Plain-language notes for the volume summary.
    pub notes: Vec<String>,
}

struct Walker<'a, R: Read + Seek> {
    v: &'a ExtVolume,
    r: &'a mut R,
    out: Vec<FsEntry>,
    next: u64,
    seen_dirs: HashSet<u64>,
    named: HashSet<u64>,
    journal: JournalCopies,
    from_journal: u64,
    no_content: u64,
    /// Deleted directories whose first block was found by search: inode to volume offset.
    found_dirs: HashMap<u64, u64>,
    dir_search_bytes: u64,
}

/// A directory still to walk: (record, path, inode number, inode offset, deleted).
type DirWork = (u64, String, u64, u64, bool);

/// Walks the tree from the root inode, then the inode tables for orphans.
/// `progress(done, total)` may return false.
pub fn scan<R: Read + Seek>(v: &ExtVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<ExtScan> {
    let mut notes = vec![];
    let journal = match journal_copies(v, r) {
        Ok(j) => j,
        Err(e) => {
            notes.push(format!("The ext journal could not be read ({}); deleted ext3/ext4 files cannot be recovered through it.", e));
            HashMap::new()
        }
    };
    let root_off = v.inode_offset(ROOT_INODE).ok_or_else(|| anyhow::anyhow!("root inode not found"))?;
    let root_ino = v.inode_at(r, root_off)?;
    if !root_ino.is_dir() {
        anyhow::bail!("ext root inode is not a directory");
    }
    let mut w = Walker { v, r, out: vec![], next: FIRST_RECORD, seen_dirs: HashSet::new(), named: HashSet::from([ROOT_INODE]), journal, from_journal: 0, no_content: 0, found_dirs: HashMap::new(), dir_search_bytes: 0 };
    let root = w.entry(ROOT_RECORD, ROOT_RECORD, "/".into(), ".".into(), ROOT_INODE, root_off, &root_ino, false, (root_ino.clone(), root_off, None), None);
    w.out.push(root);
    let mut queue: VecDeque<DirWork> = VecDeque::from([(ROOT_RECORD, String::new(), ROOT_INODE, root_off, false)]);
    w.seen_dirs.insert(ROOT_INODE);
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
    if w.from_journal > 0 {
        notes.push(format!("{} deleted file(s) were recovered through older copies of their inodes kept in the ext journal.", w.from_journal));
    }
    if w.no_content > 0 {
        notes.push(format!(
            "{} deleted file(s) have no recoverable content: ext3 and ext4 clear the block map when a file is deleted, and the journal held no older copy. File carving over unallocated space may still find them.",
            w.no_content
        ));
    }
    let info = v.info(w.out.len() as u64);
    Ok(ExtScan { info, entries: w.out, notes })
}

impl<'a, R: Read + Seek> Walker<'a, R> {
    /// The newest journal copy of inode `n` that is still the same file
    /// (same generation) and still had its block map.
    fn journal_inode(&mut self, n: u64, current: &Inode) -> Option<(Inode, u64, u32)> {
        let off = self.v.inode_offset(n)?;
        let blk = off / self.v.block;
        let within = off % self.v.block;
        let copies = self.journal.get(&blk)?.clone();
        for (seq, at) in copies {
            let Ok(old) = self.v.inode_at(self.r, at + within) else { continue };
            if old.live() && old.generation == current.generation && old.kind() == current.kind() && old.size > 0 && !old.map_empty() {
                return Some((old, at + within, seq));
            }
        }
        None
    }

    /// Looks for the first block of deleted directory `n` among the free
    /// blocks of its flex group: the block that starts with "." naming `n`
    /// and "..". Bounded per volume.
    fn find_dir_block(&mut self, n: u64) -> bool {
        const BUDGET: u64 = 2 << 30;
        if self.found_dirs.contains_key(&n) {
            return true;
        }
        let v = self.v;
        if self.dir_search_bytes >= BUDGET || n == 0 {
            return false;
        }
        let g = (n - 1) / v.inodes_per_group;
        let first_g = g - g % v.groups_per_flex;
        let start = v.first_data_block + first_g * v.blocks_per_group;
        let end = (start + v.groups_per_flex * v.blocks_per_group).min(v.blocks);
        let bs = v.block as usize;
        let chunk = (1u64 << 20) / v.block;
        let mut b = start;
        while b < end && self.dir_search_bytes < BUDGET {
            let n_blocks = chunk.min(end - b);
            let Ok(buf) = rd(self.r, b * v.block, (n_blocks * v.block) as usize) else { break };
            self.dir_search_bytes += buf.len() as u64;
            for (i, blk) in buf.chunks_exact(bs).enumerate() {
                if u32_at(blk, 0) == n && u16_at(blk, 4) == 12 && blk[6] == 1 && blk[8] == b'.' && blk[18] == 2 && blk[20] == b'.' && blk[21] == b'.' && !v.allocated(self.r, b + i as u64) {
                    self.found_dirs.insert(n, (b + i as u64) * v.block);
                    return true;
                }
            }
            if buf.len() < (n_blocks * v.block) as usize {
                break;
            }
            b += n_blocks;
        }
        false
    }

    /// The inode to read a deleted file's content through: its own when the
    /// block map survived (ext2), else a journal copy. None: nothing left.
    fn deleted_content(&mut self, n: u64, ino: &Inode, off: u64) -> Option<(Inode, u64, Option<u32>)> {
        if (ino.size > 0 || ino.is_dir()) && (!ino.map_empty() || ino.inline()) {
            return Some((ino.clone(), off, None));
        }
        if ino.is_dir() || matches!(ino.kind(), S_IFREG | S_IFLNK) || ino.mode == 0 {
            if let Some((old, at, seq)) = self.journal_inode(n, ino) {
                self.from_journal += 1;
                return Some((old, at, Some(seq)));
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn entry(&mut self, record: u64, parent: u64, path: String, name: String, n: u64, off: u64, ino: &Inode, deleted: bool, content: (Inode, u64, Option<u32>), error: Option<String>) -> FsEntry {
        let (c, c_off, seq) = content;
        let is_dir = ino.is_dir() || (ino.mode == 0 && c.is_dir());
        let size = if is_dir { 0 } else { c.size };
        let first_offset = if is_dir || size == 0 { None } else { self.v.map(self.r, &c, c_off).iter().find_map(|x| x.vol) };
        let link_target = (c.kind() == S_IFLNK && c.size > 0 && c.size < 4096).then(|| {
            let map = self.v.map(self.r, &c, c_off);
            String::from_utf8_lossy(&read_map(self.r, &map, c.size, 0, c.size as usize).unwrap_or_default()).into_owned()
        });
        let mode = if ino.mode != 0 { ino.mode } else { c.mode };
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
            alloc_size: c.blocks512.saturating_mul(512),
            resident: c.inline(),
            attributes: if is_dir { 0x10 } else { 0 },
            hard_links: ino.links,
            usn: None,
            si: Some(ino.times),
            fname: None,
            streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: c.inline(), first_offset }] },
            has_reparse: false,
            record_offset: off,
            error,
            unix: Some(UnixMeta {
                inode: n,
                mode,
                uid: ino.uid,
                gid: ino.gid,
                deleted_time: unix_ft(ino.dtime as i64, 0),
                inode_offset: c_off,
                journal_seq: seq,
                link_target,
            }),
        }
    }

    /// Adds one name. Returns the directory to walk next, if it is one.
    #[allow(clippy::too_many_arguments)]
    fn name(&mut self, parent: u64, parent_path: &str, name: String, n: u64, ftype: u8, deleted_name: bool, parent_deleted: bool) -> Option<DirWork> {
        if n == 0 {
            // A deleted name whose inode number was cleared (ext2): the name
            // is evidence, the content cannot be tied to it.
            let rec = self.next;
            self.next += 1;
            let blank = Inode::parse(vec![0; 128], false);
            let msg = "the directory entry no longer names its inode (ext2 clears it on delete); the content may be among the orphaned inodes ($OrphanFiles)".to_string();
            let mut e = self.entry(rec, parent, format!("{}/{}", parent_path, name), name, 0, 0, &blank, true, (blank.clone(), 0, None), Some(msg));
            e.unix = None;
            e.is_dir = ftype == 2;
            e.attributes = if e.is_dir { 0x10 } else { 0 };
            e.streams = if e.is_dir { vec![] } else { vec![Stream { name: String::new(), size: 0, resident: false, first_offset: None }] };
            e.si = None;
            self.out.push(e);
            return None;
        }
        let off = self.v.inode_offset(n)?;
        let ino = self.v.inode_at(self.r, off).ok()?;
        let rec = self.next;
        let path = format!("{}/{}", parent_path, name);
        let mut error = None;
        let deleted = deleted_name || parent_deleted || !ino.live();
        let content = if !deleted {
            Some((ino.clone(), off, None))
        } else if ino.live() {
            // The name is gone but its inode is in use: a rename, another
            // hard link, or the inode was reused for a new file.
            error = Some(format!("inode {} is in use again (the file was renamed, or the inode reused by another file); content not attributed to this name", n));
            None
        } else {
            self.deleted_content(n, &ino, off)
        };
        if deleted_name && ino.mode == 0 && content.is_none() && ftype == 0 {
            return None;
        }
        self.next += 1;
        self.named.insert(n);
        let mut content = content;
        if content.is_none() && error.is_none() && (ino.is_dir() || ftype == 2) && self.find_dir_block(n) {
            content = Some((ino.clone(), off, None));
            error = Some("folder entries read from its directory block, found by searching free blocks (the inode's block map was cleared)".into());
        }
        let has_content = content.is_some();
        if deleted && !has_content && error.is_none() && !ino.is_dir() && ftype != 2 {
            self.no_content += 1;
        }
        let c = content.clone().unwrap_or_else(|| (Inode { size: 0, ..ino.clone() }, off, None));
        let mut e = self.entry(rec, parent, path.clone(), name, n, off, &ino, deleted, c, error);
        if !has_content {
            // Keep the file type from the directory entry when the inode says nothing.
            e.is_dir = e.is_dir || (ino.mode == 0 && ftype == 2);
            e.streams.clear();
            e.size = 0;
            if let Some(u) = e.unix.as_mut() {
                u.inode_offset = off;
            }
            if !e.is_dir {
                e.streams.push(Stream { name: String::new(), size: 0, resident: false, first_offset: None });
            }
        }
        let is_dir = e.is_dir;
        let walk_off = e.unix.as_ref().map(|u| u.inode_offset).unwrap_or(off);
        self.out.push(e);
        (is_dir && has_content && self.seen_dirs.insert(n)).then_some((rec, path, n, walk_off, deleted))
    }

    fn dir(&mut self, (rec, path, n, off, deleted): DirWork) -> Vec<DirWork> {
        let Ok(ino) = self.v.inode_at(self.r, off) else { return vec![] };
        let indexed = ino.flags & FL_INDEX != 0;
        let mut data = vec![];
        for x in self.v.map(self.r, &ino, off) {
            if x.offset != data.len() as u64 && x.offset > data.len() as u64 {
                if x.offset > MAX_DIR_BYTES {
                    break;
                }
                data.resize(x.offset as usize, 0);
            }
            if data.len() as u64 >= MAX_DIR_BYTES {
                break;
            }
            let len = x.len.min(MAX_DIR_BYTES - data.len() as u64).min(ino.size.max(x.offset + x.len).saturating_sub(x.offset));
            match x.vol {
                Some(v) => data.extend(rd(self.r, v, len as usize).unwrap_or_default()),
                None => data.resize(data.len() + len as usize, 0),
            }
        }
        if data.iter().all(|&b| b == 0) {
            if let Some(&at) = self.found_dirs.get(&n) {
                data = rd(self.r, at, self.v.block as usize).unwrap_or_default();
            }
        }
        if ino.inline() {
            // Inline directories: 4-byte parent inode, then entries.
            data = data.get(4..).map(|d| d.to_vec()).unwrap_or_default();
        }
        let bs = if ino.inline() { data.len().max(1) } else { self.v.block as usize };
        let mut found = vec![];
        for (bi, blk) in data.chunks(bs).enumerate() {
            // htree interior blocks: one empty entry spanning the block.
            // (A leaf whose files were all deleted looks the same but keeps a name.)
            if indexed && bi > 0 && u32_at(blk, 0) == 0 && u16_at(blk, 4) as usize == blk.len() && blk.get(6) == Some(&0) {
                continue;
            }
            self.parse_block(blk, indexed && bi == 0, &mut found);
        }
        // An htree block split moves entries and leaves the old copies in
        // slack: a deleted name the folder still has (same inode) is stale.
        let live: HashSet<(String, u64)> = found.iter().filter(|x| !x.3).map(|x| (x.0.clone(), x.1)).collect();
        let mut seen: HashSet<(String, u64)> = HashSet::new();
        let mut sub = vec![];
        for (name, child, ftype, del) in found {
            if child == n && !del {
                continue;
            }
            if del && (live.contains(&(name.clone(), child)) || !seen.insert((name.clone(), child))) {
                continue;
            }
            if let Some(d) = self.name(rec, &path, name, child, ftype, del, deleted) {
                sub.push(d);
            }
            if self.out.len() > MAX_ENTRIES {
                break;
            }
        }
        sub
    }

    /// Entries of one directory block: (name, inode, file type, deleted).
    fn parse_block(&self, blk: &[u8], htree_root: bool, found: &mut Vec<(String, u64, u8, bool)>) {
        let mut pos = 0usize;
        let mut index = 0;
        while pos + 8 <= blk.len() {
            let n = u32_at(blk, pos);
            let rl = u16_at(blk, pos + 4) as usize;
            let (nl, ft) = if self.v.filetype { (blk[pos + 6] as usize, blk[pos + 7]) } else { (u16_at(blk, pos + 6) as usize, 0) };
            if rl < 8 || !rl.is_multiple_of(4) || pos + rl > blk.len() || 8 + nl > rl {
                return;
            }
            let name = &blk[pos + 8..pos + 8 + nl];
            if n != 0 && nl > 0 && name != b"." && name != b".." {
                found.push((name_str(name), n, ft, false));
            } else if n == 0 && nl > 0 && (1..=7).contains(&ft) && plausible_name(name) {
                // First entry of a block, deleted: the kernel only zeroed its inode.
                found.push((name_str(name), 0, ft, true));
            }
            // In an htree root, the ".." entry covers the index; no names there.
            let skip_slack = htree_root && index == 1;
            if !skip_slack {
                self.slack(blk, pos + ((8 + nl + 3) & !3).max(8), pos + rl, found);
            }
            pos += rl;
            index += 1;
        }
    }

    /// Removed entries left in the slack between `s` and `end`.
    fn slack(&self, blk: &[u8], s: usize, end: usize, found: &mut Vec<(String, u64, u8, bool)>) {
        let mut p = s;
        while p + 12 <= end {
            let n = u32_at(blk, p);
            let rl = u16_at(blk, p + 4) as usize;
            let (nl, ft) = if self.v.filetype { (blk[p + 6] as usize, blk[p + 7]) } else { (u16_at(blk, p + 6) as usize, 0) };
            // ext2 also zeroes the inode number of a removed entry; such a
            // name is kept when the file type byte still says what it was.
            let ok = (n >= 1 || (self.v.filetype && (1..=7).contains(&ft)))
                && n <= self.v.inodes
                && rl >= 12
                && rl.is_multiple_of(4)
                && p + rl <= end
                && nl >= 1
                && 8 + nl <= rl
                && ft <= 7
                && blk[p + 8..p + 8 + nl].iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7F)
                && &blk[p + 8..p + 8 + nl] != b"."
                && &blk[p + 8..p + 8 + nl] != b"..";
            if ok {
                found.push((name_str(&blk[p + 8..p + 8 + nl]), n, ft, true));
                p += (8 + nl + 3) & !3;
            } else {
                p += 4;
            }
        }
    }

    /// Inodes no name points to: deleted files whose names are gone, and
    /// files unlinked while still open. Orphaned directories are walked
    /// first, so the files inside a deleted folder keep their names.
    fn orphans(&mut self, progress: &mut impl FnMut(u64, u64) -> bool, notes: &mut Vec<String>) -> anyhow::Result<()> {
        let v = self.v;
        let mut read = 0u64;
        let mut candidates: Vec<(u64, u64, bool)> = vec![];
        for (gi, g) in v.groups.clone().iter().enumerate() {
            if gi % 64 == 0 && !progress(self.out.len() as u64, self.out.len() as u64) {
                anyhow::bail!("scan cancelled");
            }
            if g.inode_table == 0 || (v.uninit_bg && g.flags & BG_INODE_UNINIT != 0) {
                continue;
            }
            let count = if v.uninit_bg { v.inodes_per_group.saturating_sub(g.itable_unused) } else { v.inodes_per_group };
            let bytes = count * v.inode_size;
            if read + bytes > MAX_ITABLE_BYTES {
                notes.push(format!("Only the first {} MiB of inode tables were searched for orphaned inodes.", MAX_ITABLE_BYTES >> 20));
                break;
            }
            read += bytes;
            let table = rd(self.r, g.inode_table * v.block, bytes as usize)?;
            for (k, raw) in table.chunks_exact(v.inode_size as usize).enumerate() {
                let n = gi as u64 * v.inodes_per_group + k as u64 + 1;
                if n < v.first_ino || n > v.inodes || self.named.contains(&n) || u16_at(raw, 0) == 0 || candidates.len() >= MAX_ENTRIES {
                    continue;
                }
                let is_dir = u16_at(raw, 0) as u32 & S_IFMT == S_IFDIR;
                candidates.push((n, g.inode_table * v.block + k as u64 * v.inode_size, is_dir));
            }
        }
        // Directories first, lowest inode first (a parent is usually older).
        candidates.sort_by_key(|&(n, _, d)| (!d, n));
        for (n, off, _) in candidates {
            if self.named.contains(&n) {
                continue; // found inside an orphaned directory walked before
            }
            let Ok(ino) = v.inode_at(self.r, off) else { continue };
            // A never-used inode keeps mode 0; one with a mode but no
            // times at all is noise.
            if ino.times.modified == 0 && ino.times.mft_modified == 0 {
                continue;
            }
            let deleted = !ino.live();
            let content = if deleted { self.deleted_content(n, &ino, off) } else { Some((ino.clone(), off, None)) };
            if deleted && content.is_none() && !ino.is_dir() {
                self.no_content += 1;
            }
            let content = if content.is_none() && ino.is_dir() && self.find_dir_block(n) { Some((ino.clone(), off, None)) } else { content };
            let has_content = content.is_some();
            let c = content.unwrap_or_else(|| (Inode { size: 0, ..ino.clone() }, off, None));
            let name = format!("inode-{}", n);
            let path = format!("{}/{}", ORPHAN_ROOT, name);
            let rec = self.next;
            self.next += 1;
            self.named.insert(n);
            let mut e = self.entry(rec, ROOT_RECORD, path.clone(), name, n, off, &ino, deleted, c, None);
            e.orphan = true;
            let walk = (e.is_dir && has_content && self.seen_dirs.insert(n)).then(|| (rec, path, n, e.unix.as_ref().map(|u| u.inode_offset).unwrap_or(off), deleted));
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

fn plausible_name(b: &[u8]) -> bool {
    b.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7F) && b != b"." && b != b".."
}

fn name_str(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace(['/', '\0'], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<std::fs::File> {
        std::fs::File::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)).ok()
    }

    #[test]
    fn helpers() {
        // 2026-10-20 09:05:30 UTC
        assert_eq!(kokino_core::time::filetime_to_iso(unix_ft(1_792_487_130, 500_000_000)), "2026-10-20T09:05:30.5000000Z");
        assert_eq!(unix_ft(0, 0), 0);
        let u = UnixMeta { mode: 0o104755, ..Default::default() };
        assert_eq!(u.mode_string(), "-rwsr-xr-x");
        let u = UnixMeta { mode: 0o041777, ..Default::default() };
        assert_eq!(u.mode_string(), "drwxrwxrwt");
    }

    fn check(name: &str, version: &str) {
        let Some(mut f) = fixture(name) else { return };
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        assert_eq!(v.version, version);
        assert_eq!(v.label, version.to_uppercase());
        assert_eq!(v.last_mounted, "/mnt/evidence");
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let read = |f: &mut std::fs::File, e: &FsEntry| v.read(f, e, 0, e.size as usize).unwrap();

        assert_eq!(read(&mut f, by("/hello.txt")), b"Hello from Kokino's ext test volume.\n");
        assert_eq!(read(&mut f, by("/docs/hello-link.txt")), b"Hello from Kokino's ext test volume.\n");
        assert_eq!(by("/hello.txt").hard_links, 2);
        assert_eq!(read(&mut f, by("/docs/report.txt")), (b"Quarterly report line, lab.test internal.\n".repeat(72))[..3000].to_vec());
        assert_eq!(read(&mut f, by("/docs/notes/deep.txt")), b"deep note in /docs/notes\n");
        let big = by("/big.bin");
        let want: Vec<u8> = (0..40960u32).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(read(&mut f, big), want);
        // Partial reads across the fragment boundary.
        assert_eq!(v.read(&mut f, big, 19_000, 4_000).unwrap(), want[19_000..23_000].to_vec());
        if version == "ext4" {
            assert_eq!(v.extents(&mut f, big).unwrap().len(), 2);
        }
        let link = by("/link");
        assert_eq!(link.unix.as_ref().unwrap().link_target.as_deref(), Some("docs/report.txt"));
        assert_eq!(link.unix.as_ref().unwrap().mode_string(), "lrwxrwxrwx");

        let hello = by("/hello.txt");
        let u = hello.unix.as_ref().unwrap();
        assert_eq!((u.uid, u.gid, u.mode_string().as_str()), (1000, 1000, "-rw-r--r--"));
        let t = hello.si.unwrap();
        assert_eq!(kokino_core::time::filetime_to_iso(t.modified)[..19], *"2026-10-20T08:05:40");
        if version == "ext4" {
            assert_eq!(kokino_core::time::filetime_to_iso(t.modified), "2026-10-20T08:05:40.1234567Z");
            assert_eq!(kokino_core::time::filetime_to_iso(t.created), "2026-10-20T07:05:40.0000000Z");
        } else {
            assert_eq!(t.created, 0);
        }

        // Deleted: name from the slack; content from the inode (ext2) or
        // from the journal copy of the inode (ext3, ext4).
        let gone = by("/deleted-secret.txt");
        assert!(gone.deleted && !gone.orphan, "{:?}", gone);
        assert_ne!(gone.unix.as_ref().unwrap().deleted_time, 0);
        assert_eq!(read(&mut f, gone), b"SECRET: wire 1,200 EUR to account LAB-0001 (test data)\n");
        assert!(gone.error.is_none(), "{:?}", gone.error);
        assert_eq!(gone.unix.as_ref().unwrap().journal_seq, if version == "ext2" { None } else { Some(5) });
        let orphan = s.entries.iter().find(|e| e.orphan && e.name == "inode-20").expect("orphan inode 20");
        assert!(orphan.deleted);
        assert_eq!(read(&mut f, orphan), b"orphaned inode content, name long gone\n");
        assert_eq!(s.entries.iter().filter(|e| e.orphan).count(), 1, "{:?}", s.entries.iter().filter(|e| e.orphan).map(|e| &e.path).collect::<Vec<_>>());
        assert!(s.entries.iter().all(|e| !e.path.contains("..")));
        assert_eq!(s.entries.iter().filter(|e| !e.deleted && !e.is_dir).count(), 6);

        let free: u64 = v.free_runs(&mut f).iter().map(|r| r.1).sum();
        assert!(free > 3 << 20, "{}", free);
        // The deleted file's block is free, so it shows up in a free run.
        let sb = v.extents(&mut f, gone).unwrap()[0].vol.unwrap();
        assert!(v.free_runs(&mut f).iter().any(|r| r.0 <= sb && sb < r.0 + r.1));
    }

    #[test]
    fn ext2_ext3_ext4_fixtures() {
        check("ext2.img", "ext2");
        check("ext3.img", "ext3");
        check("ext4.img", "ext4");
    }

    #[test]
    fn rejects_garbage() {
        let mut c = std::io::Cursor::new(vec![0u8; 4096]);
        assert!(open(&mut c, 4096).is_err());
        let mut b = vec![0u8; 8192];
        b[1024 + 56] = 0x53;
        b[1024 + 57] = 0xEF;
        assert!(open(&mut std::io::Cursor::new(b), 8192).is_err());
    }
}
