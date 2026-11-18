//! The XFS log: older copies of inodes.
//!
//! XFS writes every metadata change to its log first (an internal circular
//! area, usually tens of MiB to 2 GiB). Inode changes are logged as the
//! whole inode core plus its data fork: the extent list of a file, or the
//! entries of a small folder. After a file is deleted, recent kernels clear
//! its inode on disk, but the log still holds the copies written while the
//! file existed, until the log wraps over them.
//!
//! Layout (fs/xfs/libxfs/xfs_log_format.h): the log is a run of records,
//! each a header sector (magic 0xFEEDBABE, cycle, length, LSN, number of
//! operations, and the original first word of every data sector; larger
//! records add extension header sectors), then the data. The first four
//! bytes of every data sector are overwritten with the cycle number on
//! disk and restored from the header. The data is a run of operations
//! (transaction id, length, flags), each carrying one region; a region too
//! big for a record continues in the next. A transaction's regions are a
//! header ("TRAN"), then items: an inode item is its format (type 0x123b,
//! number of regions, fields logged, inode number), the inode core in the
//! writing machine's byte order, and the data fork as on disk.

use crate::XfsVolume;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

const RECORD_MAGIC: u32 = 0xFEED_BABE;
const SECTOR: usize = 512;
const MAX_RECORD: usize = 256 << 10;
/// Logs larger than this are not read (the largest XFS log is 2 GiB).
const MAX_LOG: u64 = 2 << 30;
/// Inode copies kept per volume.
const MAX_COPIES: usize = 1 << 20;

const START_TRANS: u8 = 0x01;
const COMMIT_TRANS: u8 = 0x02;
const CONTINUE_TRANS: u8 = 0x04;
const TRANSACTION_CLIENT: u8 = 0x69;
const LI_INODE: u16 = 0x123b;
const LI_BUF: u16 = 0x123c;
const BLF_INODE_BUF: usize = 0x1;
const BLF_CANCEL: usize = 0x2;
/// Bytes of logged metadata blocks kept per volume.
const MAX_BUF_BYTES: usize = 512 << 20;
const ILOG_DFORK: u32 = 0x002 | 0x004 | 0x008;

/// One older copy of an inode, rebuilt in the on-disk format.
#[derive(Debug, Clone)]
pub struct LogInode {
    pub ino: u64,
    /// Log sequence number of the record that holds it (cycle, block).
    pub lsn: u64,
    /// Block (512 bytes) of that record within the log.
    pub record: u32,
    /// Volume byte offset of the copy's inode core in the log.
    pub at: u64,
    /// The inode as it would be on disk (big-endian), data fork included.
    pub raw: Vec<u8>,
}

fn be32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn be64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_be_bytes(x.try_into().unwrap())).unwrap_or(0)
}

/// Logged pieces of one block: (offset in the block, bytes).
pub type Pieces = Vec<(usize, Vec<u8>)>;

/// What the log holds: inode copies (oldest first) and logged pieces of
/// metadata blocks (folder blocks, extent B+tree blocks), by the volume
/// byte offset of the block, oldest first: (LSN, [(offset in block, bytes)]).
#[derive(Debug, Default)]
pub struct LogContents {
    pub inodes: Vec<LogInode>,
    pub blocks: HashMap<u64, Vec<(u64, Pieces)>>,
}

/// A region and the volume offset where it starts.
type Region = (Vec<u8>, u64);

/// Every inode copy and logged block piece in the log. Records the log
/// wrapped over in part (a sector stamped with another cycle) are left out.
pub fn contents<R: Read + Seek>(v: &XfsVolume, r: &mut R) -> anyhow::Result<LogContents> {
    let mut out = LogContents::default();
    let Some(start) = v.log_start else { return Ok(out) };
    let len = v.log_bytes.min(MAX_LOG).min(v.size.saturating_sub(start));
    if len < SECTOR as u64 * 2 {
        return Ok(out);
    }
    r.seek(SeekFrom::Start(start))?;
    let mut log = Vec::with_capacity(len as usize);
    r.take(len).read_to_end(&mut log)?;
    let sectors = log.len() / SECTOR;
    let sector = |i: usize| &log[(i % sectors) * SECTOR..(i % sectors) * SECTOR + SECTOR];

    // Records: (lsn, first sector, data).
    let mut records: Vec<(u64, usize, Vec<u8>, usize)> = vec![];
    let mut s = 0usize;
    while s < sectors {
        let h = sector(s);
        let (cycle, version, hlen, nops) = (be32(h, 4), be32(h, 8), be32(h, 12) as usize, be32(h, 40) as usize);
        if be32(h, 0) != RECORD_MAGIC as u64 || !(1..=2).contains(&version) || hlen == 0 || hlen > MAX_RECORD || nops == 0 || nops > hlen {
            s += 1;
            continue;
        }
        let hsize = be32(h, 320) as usize;
        let hblks = if version == 2 && hsize > 32 << 10 { hsize.div_ceil(32 << 10).min(8) } else { 1 };
        let dblks = hlen.div_ceil(SECTOR);
        let mut data = Vec::with_capacity(dblks * SECTOR);
        let mut whole = true;
        for i in 0..dblks {
            let d = sector(s + hblks + i);
            // Every data sector of a whole record is stamped with its cycle.
            if be32(d, 0) != cycle {
                whole = false;
                break;
            }
            let (j, k) = (i / 64, i % 64);
            let orig = if j == 0 { &h[44 + 4 * k..48 + 4 * k] } else { &sector(s + j)[4 + 4 * k..8 + 4 * k] };
            data.extend_from_slice(orig);
            data.extend_from_slice(&d[4..]);
        }
        if !whole {
            s += 1;
            continue;
        }
        data.truncate(hlen);
        records.push((be64(h, 16), s + hblks, data, nops));
        s += hblks + dblks;
    }
    records.sort_by_key(|x| x.0);

    // Operations, joined into regions per transaction.
    let mut open: HashMap<u64, (Vec<Region>, bool)> = HashMap::new();
    let mut buf_bytes = 0usize;
    for (lsn, first, data, nops) in &records {
        let mut p = 0usize;
        for _ in 0..*nops {
            if p + 12 > data.len() {
                break;
            }
            let (tid, olen, client, flags) = (be32(data, p), be32(data, p + 4) as usize, data[p + 8], data[p + 9]);
            let body = p + 12;
            if body + olen > data.len() {
                break;
            }
            p = body + olen;
            if client != TRANSACTION_CLIENT {
                continue;
            }
            if flags & START_TRANS != 0 {
                open.insert(tid, (vec![], false));
            }
            let t = open.entry(tid).or_insert_with(|| (vec![], false));
            if olen > 0 {
                let piece = &data[body..body + olen];
                if t.1 {
                    if let Some(last) = t.0.last_mut() {
                        last.0.extend_from_slice(piece);
                    }
                } else {
                    // Volume offset of the region's first byte.
                    let sec = first + body / SECTOR;
                    let at = v.log_start.unwrap_or(0) + ((sec % sectors) * SECTOR + body % SECTOR) as u64;
                    t.0.push((piece.to_vec(), at));
                }
            }
            t.1 = flags & CONTINUE_TRANS != 0;
            if flags & COMMIT_TRANS != 0 {
                if let Some((regions, _)) = open.remove(&tid) {
                    items(v, &regions, *lsn, (*first - 1) as u32, &mut out, &mut buf_bytes);
                }
            }
            if out.inodes.len() >= MAX_COPIES {
                return Ok(out);
            }
        }
    }
    // Transactions the log holds no commit for: what they wrote is still
    // what the file was.
    let mut rest: Vec<_> = open.into_iter().collect();
    rest.sort_by_key(|x| x.0);
    for (_, (regions, _)) in rest {
        items(v, &regions, u64::MAX, 0, &mut out, &mut buf_bytes);
    }
    Ok(out)
}

/// The inode and buffer items of one transaction's regions.
fn items(v: &XfsVolume, regions: &[Region], lsn: u64, record: u32, out: &mut LogContents, buf_bytes: &mut usize) {
    let mut i = 0usize;
    while i < regions.len() {
        let f = &regions[i].0;
        if f.len() < 4 {
            i += 1;
            continue;
        }
        // Format structures are in the writing machine's byte order.
        let (le, ty) = match (u16::from_le_bytes([f[0], f[1]]), u16::from_be_bytes([f[0], f[1]])) {
            (t, _) if (0x1230..0x1260).contains(&t) => (true, t),
            (_, t) if (0x1230..0x1260).contains(&t) => (false, t),
            _ => {
                i += 1;
                continue;
            }
        };
        let n16 = |o: usize| f.get(o..o + 2).map(|x| if le { u16::from_le_bytes([x[0], x[1]]) } else { u16::from_be_bytes([x[0], x[1]]) } as usize).unwrap_or(0);
        let n32 = |o: usize| f.get(o..o + 4).map(|x| if le { u32::from_le_bytes([x[0], x[1], x[2], x[3]]) } else { u32::from_be_bytes([x[0], x[1], x[2], x[3]]) }).unwrap_or(0);
        let size = n16(2).max(1);
        if ty == LI_INODE && size >= 2 && i + 1 < regions.len() {
            let fields = n32(4);
            // 64-bit layout (56 bytes) puts the inode number at 16, the
            // packed 32-bit one (52 bytes) at 12.
            let ino_at = if f.len() == 52 { 12 } else { 16 };
            let ino = f.get(ino_at..ino_at + 8).map(|x| if le { u64::from_le_bytes(x.try_into().unwrap()) } else { u64::from_be_bytes(x.try_into().unwrap()) }).unwrap_or(0);
            let core = &regions[i + 1];
            let fork = (fields & ILOG_DFORK != 0 && size >= 3 && i + 2 < regions.len()).then(|| regions[i + 2].0.as_slice());
            if let Some(raw) = to_disk(&core.0, fork, v.inode_size as usize) {
                out.inodes.push(LogInode { ino, lsn, record, at: core.1, raw });
            }
        }
        if ty == LI_BUF && f.len() >= 20 {
            // Logged 128-byte chunks of a block: one region per run of
            // chunks set in the bitmap.
            let flags = n16(4);
            let daddr = f.get(8..16).map(|x| if le { u64::from_le_bytes(x.try_into().unwrap()) } else { u64::from_be_bytes(x.try_into().unwrap()) }).unwrap_or(0);
            let words = (n32(16) as usize).min((f.len() - 20) / 4);
            if flags & (BLF_CANCEL | BLF_INODE_BUF) == 0 && words > 0 && *buf_bytes < MAX_BUF_BYTES {
                let bit = |k: usize| n32(20 + 4 * (k / 32)) >> (k % 32) & 1 == 1;
                let mut pieces = vec![];
                let mut k = 0usize;
                let mut region = i + 1;
                while k < words * 32 && region < (i + size).min(regions.len()) {
                    if !bit(k) {
                        k += 1;
                        continue;
                    }
                    let run = (k..words * 32).take_while(|&j| bit(j)).count();
                    let data = &regions[region].0;
                    let n = data.len().min(run * 128);
                    *buf_bytes += n;
                    pieces.push((k * 128, data[..n].to_vec()));
                    region += 1;
                    k += run;
                }
                if !pieces.is_empty() {
                    out.blocks.entry(daddr * SECTOR as u64).or_default().push((lsn, pieces));
                }
            }
        }
        i += size;
    }
}

/// The logged inode core (in the writer's byte order) and data fork as an
/// on-disk inode (big-endian).
fn to_disk(core: &[u8], fork: Option<&[u8]>, isize: usize) -> Option<Vec<u8>> {
    if core.len() < 96 {
        return None;
    }
    let le = match (core[0], core[1]) {
        (0x4e, 0x49) => true,
        (0x49, 0x4e) => false,
        _ => return None,
    };
    let version = core[4];
    if !(1..=3).contains(&version) || (version == 3 && core.len() < 176) {
        return None;
    }
    let len = if version == 3 { 176 } else { 96 };
    let mut raw = vec![0u8; isize.max(len)];
    raw[..len].copy_from_slice(&core[..len]);
    if le {
        let swap = |raw: &mut [u8], o: usize, w: usize| raw[o..o + w].reverse();
        let mut fields: Vec<(usize, usize)> = vec![(0, 2), (2, 2), (6, 2), (8, 4), (12, 4), (16, 4), (20, 2), (22, 2), (24, 8), (56, 8), (64, 8), (72, 4), (76, 4), (80, 2), (84, 4), (88, 2), (90, 2), (92, 4)];
        let flags2 = if version == 3 { u64::from_le_bytes(core[120..128].try_into().unwrap()) } else { 0 };
        let mut times = vec![32, 40, 48];
        if version == 3 {
            fields.extend([(96, 4), (100, 4), (104, 8), (112, 8), (120, 8), (128, 4), (152, 8)]);
            times.push(144);
        }
        for o in times {
            if flags2 & 0x8 != 0 {
                fields.push((o, 8));
            } else {
                fields.push((o, 4));
                fields.push((o + 4, 4));
            }
        }
        for (o, w) in fields {
            swap(&mut raw, o, w);
        }
    }
    let at = if version == 3 { 176 } else { 100 };
    if let Some(f) = fork {
        // A B+tree root is logged in its in-memory form: a whole B+tree
        // block header, then keys and pointers spaced for the logged size.
        // On disk it is the short form: level, count, keys and pointers
        // spaced for the data fork.
        let hdr = match f.get(0..4) {
            Some(b"BMA3") => 72,
            Some(b"BMAP") => 24,
            _ => 0,
        };
        if raw[5] == 3 && hdr > 0 && f.len() > hdr {
            let forkoff = raw[82] as usize;
            let fork_len = if forkoff > 0 { forkoff * 8 } else { raw.len() - at }.min(raw.len() - at);
            let (level, n) = (u16::from_be_bytes([f[4], f[5]]), u16::from_be_bytes([f[6], f[7]]) as usize);
            let in_max = (f.len() - hdr) / 16;
            let disk_max = fork_len.saturating_sub(4) / 16;
            if n <= in_max && n <= disk_max {
                let d = &mut raw[at..at + fork_len];
                d.fill(0);
                d[0..2].copy_from_slice(&level.to_be_bytes());
                d[2..4].copy_from_slice(&(n as u16).to_be_bytes());
                for k in 0..n {
                    d[4 + 8 * k..12 + 8 * k].copy_from_slice(&f[hdr + 8 * k..hdr + 8 * k + 8]);
                    let p = hdr + in_max * 8 + 8 * k;
                    d[4 + disk_max * 8 + 8 * k..12 + disk_max * 8 + 8 * k].copy_from_slice(&f[p..p + 8]);
                }
            }
        } else {
            let n = f.len().min(raw.len().saturating_sub(at));
            raw[at..at + n].copy_from_slice(&f[..n]);
        }
    }
    Some(raw)
}
