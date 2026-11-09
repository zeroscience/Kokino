//! A ZIP file as a file system, so triage collections can be added as
//! evidence as they are: Velociraptor offline collections and KAPE's ZIP
//! output. The evidence stays the ZIP file (its hash is the one the
//! collector reported); files are read from it on demand.
//!
//! Entries come from the central directory (ZIP64 too). Times are taken
//! from the NTFS extra field (created, modified, accessed, in UTC) when
//! present, else from the Unix extended timestamp, else the DOS time
//! (local time of the collecting machine, kept as stored). Velociraptor
//! escapes characters in names as %XX; names under its `uploads/` folder
//! are unescaped.

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

const MAX_ENTRIES: usize = 2_000_000;
/// Largest deflated entry Kokino decompresses as a whole (for random reads).
const MAX_INFLATE: u64 = 2 << 30;
const FIRST_RECORD: u64 = 16;

#[derive(Debug, Clone)]
struct Entry {
    method: u16,
    csize: u64,
    usize: u64,
    local: u64,
    data: Option<u64>,
}

pub struct ZipVolume {
    entries: HashMap<u64, Entry>,
    listing: Vec<FsEntry>,
    /// The collector, when the layout says which.
    pub layout: &'static str,
    cache: Mutex<Option<(u64, std::sync::Arc<Vec<u8>>)>>,
    size: u64,
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0)
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

fn read_at<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> anyhow::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        let k = r.read(&mut b[got..])?;
        if k == 0 {
            break;
        }
        got += k;
    }
    b.truncate(got);
    Ok(b)
}

/// %XX escapes (Velociraptor's file names).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn dos_time(date: u16, time: u16) -> u64 {
    let (y, mo, d) = (1980 + (date >> 9) as i32, ((date >> 5) & 15) as u32, (date & 31) as u32);
    let (h, mi, s) = ((time >> 11) as u32, ((time >> 5) & 63) as u32, ((time & 31) * 2) as u32);
    chrono::NaiveDate::from_ymd_opt(y, mo, d).and_then(|x| x.and_hms_opt(h, mi, s)).map(|t| kokino_core::time::datetime_to_filetime(t.and_utc())).unwrap_or(0)
}

/// Whether the bytes start like a ZIP file.
pub fn is_zip(head: &[u8]) -> bool {
    head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06")
}

pub fn open<R: Read + Seek>(r: &mut R, len: u64) -> anyhow::Result<ZipVolume> {
    // End of central directory: in the last 64 KiB + 22 bytes.
    let tail_len = len.min(65_557);
    let tail = read_at(r, len - tail_len, tail_len as usize)?;
    let eocd = (0..tail.len().saturating_sub(21)).rev().find(|&i| &tail[i..i + 4] == b"PK\x05\x06").ok_or_else(|| anyhow::anyhow!("no ZIP end of central directory record"))?;
    let mut count = u16_at(&tail, eocd + 10) as u64;
    let mut cd_size = u32_at(&tail, eocd + 12) as u64;
    let mut cd_off = u32_at(&tail, eocd + 16) as u64;
    // ZIP64 locator just before the EOCD.
    if eocd >= 20 && &tail[eocd - 20..eocd - 16] == b"PK\x06\x07" {
        let z64 = u64_at(&tail, eocd - 20 + 8);
        let rec = read_at(r, z64, 56)?;
        if rec.starts_with(b"PK\x06\x06") {
            count = u64_at(&rec, 32);
            cd_size = u64_at(&rec, 40);
            cd_off = u64_at(&rec, 48);
        }
    }
    if cd_off.checked_add(cd_size).is_none_or(|e| e > len) || cd_size > 1 << 31 {
        anyhow::bail!("central directory outside the file");
    }
    let cd = read_at(r, cd_off, cd_size as usize)?;
    let mut raw: Vec<(String, Entry, Times, bool)> = vec![];
    let mut p = 0usize;
    while p + 46 <= cd.len() && &cd[p..p + 4] == b"PK\x01\x02" && raw.len() < MAX_ENTRIES && (raw.len() as u64) < count.max(1) * 2 {
        let method = u16_at(&cd, p + 10);
        let (mt, md) = (u16_at(&cd, p + 12), u16_at(&cd, p + 14));
        let mut csize = u32_at(&cd, p + 20) as u64;
        let mut usize_ = u32_at(&cd, p + 24) as u64;
        let (nl, el, cl) = (u16_at(&cd, p + 28) as usize, u16_at(&cd, p + 30) as usize, u16_at(&cd, p + 32) as usize);
        let mut local = u32_at(&cd, p + 42) as u64;
        let flags = u16_at(&cd, p + 8);
        let name_b = cd.get(p + 46..p + 46 + nl).unwrap_or(&[]);
        let name = if flags & 0x800 != 0 { String::from_utf8_lossy(name_b).into_owned() } else { name_b.iter().map(|&c| crate::oletext::cp1252(c)).collect() };
        let extra = cd.get(p + 46 + nl..p + 46 + nl + el).unwrap_or(&[]);
        let mut times = Times { modified: dos_time(md, mt), ..Default::default() };
        let mut utc = false;
        let mut q = 0usize;
        while q + 4 <= extra.len() {
            let (id, sz) = (u16_at(extra, q), u16_at(extra, q + 2) as usize);
            let body = extra.get(q + 4..q + 4 + sz).unwrap_or(&[]);
            match id {
                0x0001 => {
                    // ZIP64: the fields that were 0xFFFFFFFF, in order.
                    let mut k = 0;
                    if usize_ == 0xFFFF_FFFF {
                        usize_ = u64_at(body, k);
                        k += 8;
                    }
                    if csize == 0xFFFF_FFFF {
                        csize = u64_at(body, k);
                        k += 8;
                    }
                    if local == 0xFFFF_FFFF {
                        local = u64_at(body, k);
                    }
                }
                0x000a if body.len() >= 32 && u16_at(body, 4) == 1 => {
                    times = Times { modified: u64_at(body, 8), accessed: u64_at(body, 16), created: u64_at(body, 24), mft_modified: 0 };
                    utc = true;
                }
                0x5455 if !utc && body.len() >= 5 && body[0] & 1 != 0 => {
                    times.modified = kokino_artifacts::bin::unix_to_filetime(u32_at(body, 1) as i32 as i64).unwrap_or(times.modified);
                    utc = true;
                }
                _ => {}
            }
            q += 4 + sz;
        }
        raw.push((name, Entry { method, csize, usize: usize_, local, data: None }, times, utc));
        p += 46 + nl + el + cl;
    }
    if raw.is_empty() {
        anyhow::bail!("the ZIP file lists no entries");
    }
    let velociraptor = raw.iter().any(|(n, ..)| n.starts_with("uploads/"));
    let kape = raw.iter().any(|(n, ..)| n.to_ascii_lowercase().ends_with("_copylog.csv"));
    let layout = if velociraptor { "Velociraptor" } else if kape { "KAPE" } else { "" };
    // Folders: from the paths (ZIPs often list only files).
    let mut listing: Vec<FsEntry> = vec![];
    let mut dirs: HashMap<String, u64> = HashMap::new();
    let mut entries = HashMap::new();
    let mut next = FIRST_RECORD;
    let mk = |record: u64, parent: u64, name: &str, path: &str, is_dir: bool, size: u64, times: Option<Times>| FsEntry {
        record,
        seq: 1,
        parent,
        parent_seq: 1,
        name: name.to_string(),
        dos_name: None,
        path: path.to_string(),
        is_dir,
        deleted: false,
        orphan: false,
        size,
        alloc_size: size,
        resident: false,
        attributes: 0,
        hard_links: 1,
        usn: None,
        si: times,
        fname: None,
        streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset: None }] },
        has_reparse: false,
        record_offset: 0,
        error: None,
        unix: None,
        name_only: None,
    };
    listing.push(mk(kokino_ntfs::ROOT_RECORD, kokino_ntfs::ROOT_RECORD, "", "/", true, 0, None));
    dirs.insert(String::new(), kokino_ntfs::ROOT_RECORD);
    for (name, e, times, _) in raw {
        let clean = name.replace('\\', "/");
        let parts: Vec<String> = clean.split('/').filter(|s| !s.is_empty() && *s != "." && *s != "..").map(|s| if velociraptor { unescape(s) } else { s.to_string() }).collect();
        if parts.is_empty() {
            continue;
        }
        let is_dir = clean.ends_with('/');
        let mut parent = kokino_ntfs::ROOT_RECORD;
        let mut path = String::new();
        let upto = if is_dir { parts.len() } else { parts.len() - 1 };
        for part in &parts[..upto] {
            path = format!("{}/{}", path, part);
            let key = path.to_lowercase();
            parent = match dirs.get(&key) {
                Some(&r) => r,
                None => {
                    let r = next;
                    next += 1;
                    listing.push(mk(r, parent, part, &path, true, 0, if is_dir && part == parts.last().unwrap() { Some(times) } else { None }));
                    dirs.insert(key, r);
                    r
                }
            };
        }
        if is_dir {
            continue;
        }
        let fname = parts.last().unwrap();
        let rec = next;
        next += 1;
        listing.push(mk(rec, parent, fname, &format!("{}/{}", path, fname), false, e.usize, Some(times)));
        entries.insert(rec, e);
    }
    Ok(ZipVolume { entries, listing, layout, cache: Mutex::new(None), size: len })
}

impl ZipVolume {
    pub fn info(&self) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: String::new(),
            serial: String::new(),
            version: if self.layout.is_empty() { "ZIP".into() } else { format!("ZIP ({} collection)", self.layout) },
            cluster_size: 0,
            sector_size: 0,
            record_size: 0,
            volume_size: self.size,
            mft_records: self.listing.len() as u64,
            mft_offset: 0,
            dirty: false,
        }
    }

    pub fn entries(&self) -> Vec<FsEntry> {
        self.listing.clone()
    }

    fn data_offset<R: Read + Seek>(&self, r: &mut R, e: &Entry) -> anyhow::Result<u64> {
        if let Some(d) = e.data {
            return Ok(d);
        }
        let h = read_at(r, e.local, 30)?;
        if !h.starts_with(b"PK\x03\x04") {
            anyhow::bail!("local header missing");
        }
        Ok(e.local + 30 + u16_at(&h, 26) as u64 + u16_at(&h, 28) as u64)
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let e = self.entries.get(&fe.record).ok_or_else(|| anyhow::anyhow!("not a file"))?;
        if offset >= e.usize {
            return Ok(vec![]);
        }
        let n = len.min((e.usize - offset) as usize);
        let start = self.data_offset(r, e)?;
        match e.method {
            0 => read_at(r, start + offset, n),
            8 => {
                if e.usize > MAX_INFLATE {
                    anyhow::bail!("compressed entry of {} bytes is larger than the {} byte limit", e.usize, MAX_INFLATE);
                }
                let cached = self.cache.lock().unwrap().as_ref().filter(|(rec, _)| *rec == fe.record).map(|(_, d)| d.clone());
                let data = match cached {
                    Some(d) => d,
                    None => {
                        let comp = read_at(r, start, e.csize.min(MAX_INFLATE) as usize)?;
                        let mut out = Vec::with_capacity(e.usize as usize);
                        flate2::read::DeflateDecoder::new(&comp[..]).take(e.usize).read_to_end(&mut out)?;
                        let d = std::sync::Arc::new(out);
                        *self.cache.lock().unwrap() = Some((fe.record, d.clone()));
                        d
                    }
                };
                let o = (offset as usize).min(data.len());
                Ok(data[o..(o + n).min(data.len())].to_vec())
            }
            m => anyhow::bail!("ZIP compression method {} is not supported", m),
        }
    }

    pub fn extents<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry) -> Vec<Extent> {
        match self.entries.get(&fe.record) {
            Some(e) if e.method == 0 => self.data_offset(r, e).map(|o| vec![Extent { offset: 0, len: e.usize, vol: Some(o) }]).unwrap_or_default(),
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A Velociraptor-style collection: an escaped drive folder, a stored and
    /// a deflated file, one with the NTFS times extra field.
    #[test]
    fn velociraptor_layout_and_reads() {
        let mut out = std::io::Cursor::new(vec![]);
        let mut cd = vec![];
        let mut add = |out: &mut std::io::Cursor<Vec<u8>>, name: &str, data: &[u8], deflate: bool, ntfs: Option<(u64, u64, u64)>| {
            let local = out.position() as u32;
            let body = if deflate {
                let mut z = flate2::write::DeflateEncoder::new(vec![], flate2::Compression::default());
                z.write_all(data).unwrap();
                z.finish().unwrap()
            } else {
                data.to_vec()
            };
            let crc = { let mut c = flate2::Crc::new(); c.update(data); c.sum() };
            let mut extra = vec![];
            if let Some((m, a, c)) = ntfs {
                extra.extend_from_slice(&0x000au16.to_le_bytes());
                extra.extend_from_slice(&32u16.to_le_bytes());
                extra.extend_from_slice(&[0; 4]);
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&24u16.to_le_bytes());
                for t in [m, a, c] {
                    extra.extend_from_slice(&t.to_le_bytes());
                }
            }
            let method: u16 = if deflate { 8 } else { 0 };
            let mut lh = b"PK\x03\x04".to_vec();
            for v in [20u16, 0x800, method, 0, 0x5a21] {
                lh.extend_from_slice(&v.to_le_bytes());
            }
            lh.extend_from_slice(&crc.to_le_bytes());
            lh.extend_from_slice(&(body.len() as u32).to_le_bytes());
            lh.extend_from_slice(&(data.len() as u32).to_le_bytes());
            lh.extend_from_slice(&(name.len() as u16).to_le_bytes());
            lh.extend_from_slice(&0u16.to_le_bytes());
            lh.extend_from_slice(name.as_bytes());
            out.write_all(&lh).unwrap();
            out.write_all(&body).unwrap();
            let mut c = b"PK\x01\x02".to_vec();
            for v in [20u16, 20, 0x800, method, 0, 0x5a21] {
                c.extend_from_slice(&v.to_le_bytes());
            }
            c.extend_from_slice(&crc.to_le_bytes());
            c.extend_from_slice(&(body.len() as u32).to_le_bytes());
            c.extend_from_slice(&(data.len() as u32).to_le_bytes());
            c.extend_from_slice(&(name.len() as u16).to_le_bytes());
            c.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            c.extend_from_slice(&[0; 6]); // comment length, disk, internal attributes
            c.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            c.extend_from_slice(&local.to_le_bytes());
            c.extend_from_slice(name.as_bytes());
            c.extend_from_slice(&extra);
            cd.extend_from_slice(&c);
        };
        let t = 133_000_000_000_000_000u64;
        let hive = b"regf hive bytes ".repeat(500);
        add(&mut out, "uploads/auto/C%3A/Windows/System32/config/SYSTEM", &hive, true, Some((t, t + 1, t - 10)));
        add(&mut out, "uploads/ntfs/%5C%5C.%5CC%3A/%24MFT", b"FILE0 record", false, None);
        add(&mut out, "log.json", b"{}", false, None);
        let cd_off = out.position() as u32;
        out.write_all(&cd).unwrap();
        let mut eocd = b"PK\x05\x06".to_vec();
        eocd.extend_from_slice(&[0; 4]);
        eocd.extend_from_slice(&3u16.to_le_bytes());
        eocd.extend_from_slice(&3u16.to_le_bytes());
        eocd.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        eocd.extend_from_slice(&cd_off.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        out.write_all(&eocd).unwrap();
        let bytes = out.into_inner();
        let len = bytes.len() as u64;
        let mut r = std::io::Cursor::new(bytes);
        let z = open(&mut r, len).unwrap();
        assert_eq!(z.layout, "Velociraptor");
        let ls = z.entries();
        let sys = ls.iter().find(|e| e.path == "/uploads/auto/C:/Windows/System32/config/SYSTEM").expect("unescaped path");
        assert_eq!(sys.si.unwrap(), Times { modified: t, accessed: t + 1, created: t - 10, mft_modified: 0 });
        assert_eq!(z.read(&mut r, sys, 0, 1 << 20).unwrap(), hive);
        assert_eq!(z.read(&mut r, sys, 16, 4).unwrap(), b"regf");
        let mft = ls.iter().find(|e| e.name == "$MFT").unwrap();
        assert_eq!(mft.path, "/uploads/ntfs/\\\\.\\C:/$MFT");
        assert_eq!(z.read(&mut r, mft, 0, 100).unwrap(), b"FILE0 record");
        assert_eq!(z.extents(&mut r, mft).len(), 1);
        // Folders were made from the paths, each with its parent.
        let config = ls.iter().find(|e| e.path == "/uploads/auto/C:/Windows/System32/config").unwrap();
        assert!(config.is_dir && sys.parent == config.record);
        assert!(open(&mut std::io::Cursor::new(b"PK\x03\x04 nothing else".to_vec()), 20).is_err());
    }
}
