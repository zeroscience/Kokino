//! Optical media: ISO 9660 with Rock Ridge and Joliet, multisession discs,
//! and UDF (see `udf`).
//!
//! Returns the same `FsEntry` records as the other walkers. On a disc
//! written in several sessions, the newest session is the live tree; files
//! that only older sessions still list (removed or replaced later) are
//! reported as deleted, with the session they come from. Their content is
//! still on the disc: sessions only ever add.
//!
//! Names: Rock Ridge (POSIX names, modes, owners, times, symbolic links,
//! deep folders relocated to rr_moved) when present, else Joliet (Unicode),
//! else ISO 9660 names without the ";1" version.
//!
//! Times: ISO 9660 records local time with its offset from UTC, so they
//! are exact; Rock Ridge adds creation, access and attribute-change times.

#![forbid(unsafe_code)]

pub mod udf;

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

pub const ROOT_RECORD: u64 = 5;
const FIRST_RECORD: u64 = 100;
pub const SECTOR: u64 = 2048;
const MAX_ENTRIES: usize = 2_000_000;
const MAX_DIR_BYTES: u64 = 16 << 20;
const MAX_SESSIONS: usize = 99;
/// How far past one session's end the next one's descriptors are looked for
/// (lead-out, lead-in and gaps of recorded discs, in sectors).
const SESSION_GAP: u64 = 32_768;

pub(crate) fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = Vec::with_capacity(n.min(1 << 20));
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}
#[allow(dead_code)]
pub(crate) fn le16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
pub(crate) fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
#[allow(dead_code)]
pub(crate) fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

/// Seconds since the Unix epoch to FILETIME (0 stays 0).
pub(crate) fn unix_ft(secs: i64, nanos: u64) -> u64 {
    if secs == 0 && nanos == 0 {
        return 0;
    }
    ((secs as i128 + 11_644_473_600) * 10_000_000 + (nanos / 100) as i128).clamp(0, u64::MAX as i128) as u64
}

/// Local date and time with an offset (minutes east of UTC) to FILETIME.
#[allow(clippy::too_many_arguments)]
pub(crate) fn civil_ft(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32, nanos: u64, offset_min: i32) -> u64 {
    let Some(dt) = chrono::NaiveDate::from_ymd_opt(y, mo, d).and_then(|x| x.and_hms_opt(h, mi, s.min(59))) else { return 0 };
    unix_ft(dt.and_utc().timestamp() - offset_min as i64 * 60, nanos)
}

/// The 7-byte date of directory records (years since 1900, offset in 15 min).
fn dir_time(b: &[u8]) -> u64 {
    if b.len() < 7 || b[..6].iter().all(|&x| x == 0) {
        return 0;
    }
    civil_ft(1900 + b[0] as i32, b[1] as u32, b[2] as u32, b[3] as u32, b[4] as u32, b[5] as u32, 0, (b[6] as i8) as i32 * 15)
}

/// The 17-byte date of volume descriptors ("2026102008053000" + offset).
fn vd_time(b: &[u8]) -> u64 {
    if b.len() < 17 || !b[..14].iter().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    let n = |r: std::ops::Range<usize>| std::str::from_utf8(&b[r]).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    civil_ft(n(0..4) as i32, n(4..6), n(6..8), n(8..10), n(10..12), n(12..14), n(14..16) as u64 * 10_000_000, (b[16] as i8) as i32 * 15)
}

fn trim_id(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches([' ', '\0']).to_string()
}

fn ucs2(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&w).trim_end_matches([' ', '\0']).to_string()
}

/// One session's descriptors.
#[derive(Debug, Clone)]
pub struct Session {
    /// Sector where the session's volume descriptors start (minus 16).
    pub start: u64,
    pub pvd: Vec<u8>,
    pub joliet: Option<Vec<u8>>,
    pub created: u64,
    pub label: String,
}

pub struct IsoVolume {
    pub sessions: Vec<Session>,
    pub size: u64,
    pub label: String,
    pub rock_ridge: bool,
    pub joliet: bool,
    pub boot: bool,
    pub system_id: String,
    pub publisher: String,
    pub preparer: String,
    pub application: String,
}

fn descriptors<R: Read + Seek>(r: &mut R, start: u64) -> std::io::Result<Option<Session>> {
    let mut s: Option<Session> = None;
    let mut joliet = None;
    for i in 0..64u64 {
        let d = rd(r, (start + 16 + i) * SECTOR, SECTOR as usize)?;
        if d.len() < SECTOR as usize || &d[1..6] != b"CD001" {
            break;
        }
        match d[0] {
            1 if s.is_none() => {
                s = Some(Session { start, created: vd_time(&d[813..830]), label: trim_id(&d[40..72]), pvd: d.clone(), joliet: None });
            }
            // Supplementary descriptor with a UCS-2 escape sequence: Joliet.
            2 if d[88] == 0x25 && d[89] == 0x2F && matches!(d[90], 0x40 | 0x43 | 0x45) => joliet = Some(d.clone()),
            255 => break,
            _ => {}
        }
    }
    if let Some(s) = s.as_mut() {
        s.joliet = joliet;
    }
    Ok(s)
}

pub fn open<R: Read + Seek>(r: &mut R, size: u64) -> anyhow::Result<IsoVolume> {
    let first = descriptors(r, 0)?.ok_or_else(|| anyhow::anyhow!("no ISO 9660 primary volume descriptor"))?;
    let mut sessions = vec![first];
    // Later sessions start after the end of the one before, past the gap a
    // recorder leaves; each repeats the descriptors 16 sectors in.
    while sessions.len() < MAX_SESSIONS {
        let last = sessions.last().unwrap();
        let end = le32(&last.pvd, 80);
        if end <= last.start || end.saturating_mul(SECTOR) >= size {
            break;
        }
        let mut found = None;
        let limit = (end + SESSION_GAP).min(size / SECTOR);
        let mut s = end;
        while s + 17 <= limit {
            let head = rd(r, (s + 16) * SECTOR, 6)?;
            if head.len() == 6 && head[0] == 1 && &head[1..6] == b"CD001" {
                found = descriptors(r, s)?;
                break;
            }
            s += 1;
        }
        match found {
            Some(f) if f.start > last.start => sessions.push(f),
            _ => break,
        }
    }
    let newest = sessions.last().unwrap().clone();
    let pvd = &newest.pvd;
    let root = &pvd[156..190];
    let rock_ridge = has_rock_ridge(r, root)?;
    let boot = rd(r, 17 * SECTOR, 7)?.get(..7) == Some(&[0, b'C', b'D', b'0', b'0', b'1', 1]);
    let label = match &newest.joliet {
        Some(j) => ucs2(&j[40..72]),
        None => newest.label.clone(),
    };
    Ok(IsoVolume {
        size: (le32(pvd, 80) * SECTOR).min(size.max(SECTOR)),
        label: if label.is_empty() { newest.label.clone() } else { label },
        rock_ridge,
        joliet: newest.joliet.is_some(),
        boot,
        system_id: trim_id(&pvd[8..40]),
        publisher: trim_id(&pvd[318..446]),
        preparer: trim_id(&pvd[446..574]),
        application: trim_id(&pvd[574..702]),
        sessions,
    })
}

/// The root's "." record carries an SP entry when SUSP (Rock Ridge) is in use.
fn has_rock_ridge<R: Read + Seek>(r: &mut R, root: &[u8]) -> std::io::Result<bool> {
    let d = rd(r, le32(root, 2) * SECTOR, SECTOR as usize)?;
    let Some(rec) = d.get(..(d.first().copied().unwrap_or(0) as usize)) else { return Ok(false) };
    let su = 34;
    Ok(rec.len() >= su + 7 && &rec[su..su + 2] == b"SP" && rec[su + 4] == 0xBE && rec[su + 5] == 0xEF)
}

/// One directory record, decoded.
#[derive(Debug, Clone, Default)]
struct Rec {
    off: u64,
    lba: u64,
    len: u64,
    flags: u8,
    name: String,
    time: u64,
    rr: Rr,
}

#[derive(Debug, Clone, Default)]
struct Rr {
    name: Option<String>,
    mode: Option<u32>,
    links: Option<u32>,
    uid: u32,
    gid: u32,
    serial: Option<u64>,
    times: [u64; 4], // created, modified, accessed, attributes changed
    symlink: Option<String>,
    child: Option<u64>,
    relocated: bool,
}

impl IsoVolume {
    pub fn info(&self, entries: u64) -> NtfsVolumeInfo {
        let mut v = String::from("ISO 9660");
        if self.rock_ridge {
            v.push_str(" + Rock Ridge");
        }
        if self.joliet {
            v.push_str(" + Joliet");
        }
        if self.sessions.len() > 1 {
            v.push_str(&format!(", {} sessions", self.sessions.len()));
        }
        if self.boot {
            v.push_str(", bootable (El Torito)");
        }
        NtfsVolumeInfo {
            label: self.label.clone(),
            serial: kokino_core::time::filetime_to_iso(self.sessions.last().map(|s| s.created).unwrap_or(0)),
            version: v,
            cluster_size: SECTOR as u32,
            sector_size: SECTOR as u16,
            record_size: 0,
            volume_size: self.size,
            mft_records: entries,
            mft_offset: 16 * SECTOR,
            dirty: false,
        }
    }

    /// Where a file's bytes are: its extents (several for files over 4 GiB).
    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry) -> Vec<Extent> {
        let Some(first) = e.data_offset() else { return vec![] };
        if e.size == 0 {
            return vec![];
        }
        // Multi-extent files: the records that follow continue the file.
        let mut out = vec![Extent { offset: 0, len: e.size, vol: Some(first) }];
        if e.attributes & MULTI_EXTENT == 0 {
            return out;
        }
        out.clear();
        let mut pos = e.record_offset;
        let mut logical = 0u64;
        for _ in 0..1024 {
            let Ok(b) = rd(r, pos, 256) else { break };
            let n = b.first().copied().unwrap_or(0) as u64;
            if n == 0 {
                // Records never cross a sector: go on in the next one.
                pos = (pos / SECTOR + 1) * SECTOR;
                continue;
            }
            let (lba, len, flags) = (le32(&b, 2), le32(&b, 10), b.get(25).copied().unwrap_or(0));
            out.push(Extent { offset: logical, len, vol: Some(lba * SECTOR) });
            logical += len;
            pos += n;
            if flags & 0x80 == 0 || logical >= e.size {
                break;
            }
        }
        out
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if offset >= e.size {
            return Ok(vec![]);
        }
        let want = (len as u64).min(e.size - offset) as usize;
        let mut out = Vec::with_capacity(want);
        for x in self.extents(r, e) {
            let pos = offset + out.len() as u64;
            if out.len() >= want || pos >= x.offset + x.len || pos < x.offset {
                continue;
            }
            let n = ((x.offset + x.len - pos) as usize).min(want - out.len());
            let b = rd(r, x.vol.unwrap() + (pos - x.offset), n)?;
            let short = b.len() < n;
            out.extend(b);
            if short {
                break;
            }
        }
        Ok(out)
    }
}

/// `attributes` bit: the file continues in the records that follow.
pub const MULTI_EXTENT: u32 = 1 << 30;

pub struct IsoScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    pub notes: Vec<String>,
}

struct Walker<'a, R: Read + Seek> {
    v: &'a IsoVolume,
    r: &'a mut R,
    seen: HashSet<u64>,
    joliet: bool,
    rr_skip: usize,
}

/// One file as a session lists it: path, record and whether it is a folder.
type Listed = (String, Rec, u64);

pub fn scan<R: Read + Seek>(v: &IsoVolume, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<IsoScan> {
    let mut notes = vec![];
    // Walk every session, newest first: its tree is the live one.
    let mut per_session: Vec<Vec<Listed>> = vec![];
    for (si, s) in v.sessions.iter().enumerate().rev() {
        let use_joliet = !v.rock_ridge && s.joliet.is_some();
        let desc = if use_joliet { s.joliet.as_ref().unwrap() } else { &s.pvd };
        let mut w = Walker { v, r, seen: HashSet::new(), joliet: use_joliet, rr_skip: 0 };
        let root = parse_rec(&desc[156..190], 16 * SECTOR, false, 0).ok_or_else(|| anyhow::anyhow!("bad root directory record"))?;
        let list = w.walk(&root, si, &mut progress)?;
        per_session.push(list);
        if per_session.iter().map(|l| l.len()).sum::<usize>() > MAX_ENTRIES {
            notes.push("Stopped listing older sessions: too many entries.".into());
            break;
        }
    }
    let mut out = vec![FsEntry {
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
        record_offset: 16 * SECTOR,
        error: None,
        unix: None,
        name_only: None,
    }];
    let mut by_path: HashMap<String, u64> = HashMap::from([(String::new(), ROOT_RECORD)]);
    let mut live: HashMap<String, u64> = HashMap::new();
    let mut next = FIRST_RECORD;
    let newest = v.sessions.len();
    let mut older = 0u64;
    for (k, list) in per_session.iter().enumerate() {
        let session = newest - k; // 1-based
        for (path, rec, depth) in list {
            let _ = depth;
            let is_dir = rec.flags & 2 != 0;
            if k > 0 {
                // An older session: keep what the newest no longer has, or
                // has with other content.
                match live.get(path) {
                    Some(&lba) if lba == rec.lba || is_dir => continue,
                    _ => {}
                }
            } else {
                live.insert(path.clone(), rec.lba);
            }
            let parent_path = path.rsplit_once('/').map(|x| x.0).unwrap_or("");
            let parent = by_path.get(parent_path).copied().unwrap_or(ROOT_RECORD);
            let record = next;
            next += 1;
            if is_dir && !by_path.contains_key(path) {
                by_path.insert(path.clone(), record);
            }
            let deleted = k > 0;
            if deleted {
                older += 1;
            }
            let mut e = entry(rec, record, parent, path, is_dir, deleted);
            if deleted {
                e.error = Some(format!("listed in session {} of {}, gone from the newest session (removed or replaced later); its content is still on the disc", session, newest));
            }
            out.push(e);
        }
    }
    if v.sessions.len() > 1 {
        notes.push(format!(
            "This disc was written in {} sessions. The newest session is shown as the live file system; {} file(s) and folder(s) only older sessions list are shown as deleted.",
            v.sessions.len(),
            older
        ));
    }
    progress(out.len() as u64, out.len() as u64);
    let info = v.info(out.len() as u64);
    Ok(IsoScan { info, entries: out, notes })
}

fn entry(rec: &Rec, record: u64, parent: u64, path: &str, is_dir: bool, deleted: bool) -> FsEntry {
    let name = path.rsplit('/').next().unwrap_or("").to_string();
    let rr = &rec.rr;
    let t = |i: usize| if rr.times[i] != 0 { rr.times[i] } else { 0 };
    let times = Times { created: t(0), modified: if rr.times[1] != 0 { rr.times[1] } else { rec.time }, accessed: t(2), mft_modified: t(3) };
    let size = if is_dir { 0 } else { rec.len };
    let first = (!is_dir && rec.len > 0).then_some(rec.lba * SECTOR);
    let unix = rr.mode.map(|mode| UnixMeta {
        inode: rr.serial.unwrap_or(rec.lba),
        mode,
        uid: rr.uid,
        gid: rr.gid,
        deleted_time: 0,
        inode_offset: rec.off,
        journal_seq: None,
        link_target: rr.symlink.clone(),
    });
    FsEntry {
        name_only: None,
        record,
        seq: 0,
        parent,
        parent_seq: 0,
        path: format!("/{}", path),
        name,
        dos_name: None,
        is_dir,
        deleted,
        orphan: false,
        size,
        alloc_size: size.div_ceil(SECTOR) * SECTOR,
        resident: false,
        attributes: if is_dir { 0x10 } else { 0x01 } | if rec.flags & 1 != 0 { 0x02 } else { 0 } | if rec.flags & 0x80 != 0 { MULTI_EXTENT } else { 0 },
        hard_links: rr.links.unwrap_or(1) as u16,
        usn: None,
        si: Some(times),
        fname: None,
        streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset: first }] },
        has_reparse: false,
        record_offset: rec.off,
        error: None,
        unix,
    }
}

/// Parses one directory record. `joliet`: names are UCS-2.
fn parse_rec(b: &[u8], off: u64, joliet: bool, rr_skip: usize) -> Option<Rec> {
    let n = *b.first()? as usize;
    if n < 34 || n > b.len() {
        return None;
    }
    let b = &b[..n];
    let nl = b[32] as usize;
    if 33 + nl > n {
        return None;
    }
    let raw = &b[33..33 + nl];
    let name = if nl == 1 && raw[0] == 0 {
        ".".to_string()
    } else if nl == 1 && raw[0] == 1 {
        "..".to_string()
    } else if joliet {
        ucs2(raw)
    } else {
        let s = String::from_utf8_lossy(raw).into_owned();
        let s = s.split(';').next().unwrap_or("").to_string();
        s.strip_suffix('.').map(str::to_string).unwrap_or(s)
    };
    let su = 33 + nl + nl.is_multiple_of(2) as usize + rr_skip;
    let mut rec = Rec { off, lba: le32(b, 2), len: le32(b, 10), flags: b[25], name, time: dir_time(&b[18..25]), rr: Rr::default() };
    if !joliet && su < n {
        susp(&b[su..], &mut rec.rr, &mut Vec::new());
    }
    Some(rec)
}

/// System Use entries (Rock Ridge). Continuation areas (CE) are noted in
/// `ce` for the caller to read and parse.
fn susp(mut b: &[u8], rr: &mut Rr, ce: &mut Vec<(u64, u64, u64)>) {
    let mut nm = String::new();
    let mut nm_seen = false;
    let mut sl: Vec<String> = vec![];
    let mut sl_cont = false;
    while b.len() >= 4 {
        let (sig, len) = (&b[0..2], b[2] as usize);
        if len < 4 || len > b.len() {
            break;
        }
        let d = &b[4..len];
        match sig {
            b"NM" if !d.is_empty() => {
                if d[0] & 6 == 0 {
                    nm.push_str(&String::from_utf8_lossy(&d[1..]));
                    nm_seen = true;
                }
            }
            b"PX" if d.len() >= 32 => {
                rr.mode = Some(le32(d, 0) as u32);
                rr.links = Some(le32(d, 8) as u32);
                rr.uid = le32(d, 16) as u32;
                rr.gid = le32(d, 24) as u32;
                if d.len() >= 40 {
                    rr.serial = Some(le32(d, 32));
                }
            }
            b"TF" if !d.is_empty() => {
                let flags = d[0];
                let long = flags & 0x80 != 0;
                let w = if long { 17 } else { 7 };
                let mut p = 1;
                // CREATION, MODIFY, ACCESS, ATTRIBUTES, then three we ignore.
                for (bit, slot) in [(1u8, 0usize), (2, 1), (4, 2), (8, 3)] {
                    if flags & bit != 0 {
                        if let Some(t) = d.get(p..p + w) {
                            rr.times[slot] = if long { vd_time(t) } else { dir_time(t) };
                        }
                        p += w;
                    }
                }
            }
            b"SL" if !d.is_empty() => {
                let mut p = 1;
                while p + 2 <= d.len() {
                    let (cf, cl) = (d[p], d[p + 1] as usize);
                    let comp = d.get(p + 2..p + 2 + cl).unwrap_or(&[]);
                    let part = match cf & 0x0E {
                        0x02 => ".".to_string(),
                        0x04 => "..".to_string(),
                        0x08 => String::new(), // root
                        _ => String::from_utf8_lossy(comp).into_owned(),
                    };
                    if sl_cont {
                        if let Some(l) = sl.last_mut() {
                            l.push_str(&part);
                        }
                    } else {
                        sl.push(part);
                    }
                    sl_cont = cf & 1 != 0;
                    p += 2 + cl;
                }
            }
            b"CL" if d.len() >= 4 => rr.child = Some(le32(d, 0)),
            b"RE" => rr.relocated = true,
            b"CE" if d.len() >= 24 => ce.push((le32(d, 0), le32(d, 8), le32(d, 16))),
            b"ST" => break,
            _ => {}
        }
        b = &b[len..];
    }
    if nm_seen {
        rr.name = Some(nm);
    }
    if !sl.is_empty() {
        rr.symlink = Some(sl.join("/"));
    }
}

impl<'a, R: Read + Seek> Walker<'a, R> {
    /// Every entry under `root`, with paths relative to it.
    fn walk(&mut self, root: &Rec, session: usize, progress: &mut impl FnMut(u64, u64) -> bool) -> anyhow::Result<Vec<Listed>> {
        let mut out = vec![];
        // SP in the root's "." record gives the bytes to skip in every record.
        if self.v.rock_ridge && !self.joliet {
            let d = rd(self.r, root.lba * SECTOR, 64)?;
            if d.len() > 40 && &d[34..36] == b"SP" {
                self.rr_skip = d[40] as usize;
            }
        }
        let mut queue = vec![(root.clone(), String::new(), 0u64)];
        while let Some((dir, path, depth)) = queue.pop() {
            if !self.seen.insert(dir.lba) || depth > 256 {
                continue;
            }
            if out.len() % 4096 == 0 && !progress(out.len() as u64, out.len() as u64 + queue.len() as u64) {
                anyhow::bail!("scan cancelled");
            }
            let size = dir.len.min(MAX_DIR_BYTES);
            let data = rd(self.r, dir.lba * SECTOR, size as usize)?;
            let mut pos = 0usize;
            while pos < data.len() {
                let n = data[pos] as usize;
                if n == 0 {
                    pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
                    continue;
                }
                let off = dir.lba * SECTOR + pos as u64;
                let Some(mut rec) = parse_rec(&data[pos..], off, self.joliet, self.rr_skip) else {
                    pos = (pos / SECTOR as usize + 1) * SECTOR as usize;
                    continue;
                };
                pos += n;
                if rec.name == "." || rec.name == ".." {
                    continue;
                }
                // Continuation areas hold the rest of a long name or link.
                let mut ces = vec![];
                if self.v.rock_ridge && !self.joliet {
                    let raw = &data[pos - n..pos];
                    let nl = raw[32] as usize;
                    let su = 33 + nl + nl.is_multiple_of(2) as usize + self.rr_skip;
                    if su < n {
                        susp(&raw[su..], &mut Rr::default(), &mut ces);
                    }
                }
                for (blk, o, l) in ces.into_iter().take(8) {
                    let extra = rd(self.r, blk * SECTOR + o, l.min(SECTOR) as usize)?;
                    let before = rec.rr.name.clone();
                    susp(&extra, &mut rec.rr, &mut Vec::new());
                    if let (Some(a), Some(b)) = (before, rec.rr.name.as_ref()) {
                        if a != *b {
                            rec.rr.name = Some(a + b);
                        }
                    }
                }
                if rec.rr.relocated {
                    continue; // shown where its CL placeholder is
                }
                let mut is_dir = rec.flags & 2 != 0;
                if let Some(child) = rec.rr.child {
                    // Placeholder for a folder moved to rr_moved.
                    // Its "." record gives the folder's size.
                    let d = rd(self.r, child * SECTOR, 256)?;
                    rec.lba = child;
                    rec.len = le32(&d, 10).max(SECTOR);
                    rec.flags |= 2;
                    is_dir = true;
                }
                let name = rec.rr.name.clone().unwrap_or_else(|| rec.name.clone()).replace('/', "_");
                if path.is_empty() && name.eq_ignore_ascii_case("rr_moved") && self.v.rock_ridge {
                    continue;
                }
                let child_path = if path.is_empty() { name } else { format!("{}/{}", path, name) };
                if is_dir {
                    queue.push((rec.clone(), child_path.clone(), depth + 1));
                }
                out.push((child_path, rec, session as u64));
                if out.len() > MAX_ENTRIES {
                    return Ok(out);
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<std::fs::File> {
        std::fs::File::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)).ok()
    }

    fn check(name: &str) -> Option<(IsoVolume, IsoScan, std::fs::File)> {
        let mut f = fixture(name)?;
        let size = f.metadata().unwrap().len();
        let v = open(&mut f, size).unwrap();
        let s = scan(&v, &mut f, |_, _| true).unwrap();
        Some((v, s, f))
    }

    #[test]
    fn rock_ridge_and_joliet() {
        let Some((v, s, mut f)) = check("iso-rr-joliet.iso") else { return };
        assert!(v.rock_ridge && v.joliet);
        assert_eq!(v.label, "KOKINO_DISC");
        let by = |p: &str| s.entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} not in {:?}", p, s.entries.iter().map(|e| &e.path).collect::<Vec<_>>()));
        let report = by("/docs/report.txt");
        assert_eq!(report.size, 9000);
        assert_eq!(v.read(&mut f, report, 0, 9000).unwrap(), (b"Quarterly report line, lab.test internal.\n".repeat(220))[..9000].to_vec());
        assert_eq!(v.read(&mut f, by("/docs/a/b/c/d/e/f/g/h/deep.txt"), 0, 100).unwrap(), b"nine levels down\n");
        assert_eq!(v.read(&mut f, by("/A file with a long name and spaces.txt"), 0, 100).unwrap(), b"long name test\n");
        // The disc records 09:07:30 at UTC+2 (the mkisofs build used mixes up
        // summer time: the source file says 08:07:30 UTC), so 07:07:30 UTC.
        assert_eq!(kokino_core::time::filetime_to_iso(by("/README.TXT").si.unwrap().modified), "2026-10-20T07:07:30.0000000Z");
        assert!(!s.entries.iter().any(|e| e.path.to_ascii_lowercase().contains("rr_moved")));
        assert!(s.entries.iter().all(|e| !e.deleted));
    }

    #[test]
    fn older_sessions_show_what_was_removed() {
        let Some((v, s, mut f)) = check("iso-multisession.iso") else { return };
        assert_eq!(v.sessions.iter().map(|s| s.start).collect::<Vec<_>>(), vec![0, 472]);
        let later = s.entries.iter().find(|e| e.path == "/added-later.txt").expect("file from session 2");
        assert!(!later.deleted);
        let secret = s.entries.iter().find(|e| e.path == "/secret-plan.txt").expect("file only session 1 has");
        assert!(secret.deleted);
        assert!(secret.error.as_deref().unwrap_or("").contains("session 1 of 2"));
        assert_eq!(v.read(&mut f, secret, 0, 100).unwrap(), b"SECRET: meet at the lab.test office, 10:00 (test data)\n");
        // Unchanged files are listed once.
        assert_eq!(s.entries.iter().filter(|e| e.path == "/README.TXT").count(), 1);
    }
}
