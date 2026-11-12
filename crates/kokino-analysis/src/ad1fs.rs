//! AccessData AD1 logical images (FTK Imager "custom content images"),
//! versions 3 and 4, as a file system. The evidence reader joins the
//! segments (.ad1, .ad2, ...) without their 512-byte margins; addresses in
//! the image are offsets in that joined stream.
//!
//! Layout (from the public notes on the format, pyad1 and dissect.evidence;
//! checked on an image FTK Imager 3.4 made, every file against the MD5 FTK
//! recorded): an image header ("ADLOGICALIMAGE": version, zlib chunk size,
//! first item, the source's path), then items linked as a tree: next
//! sibling, first child, first metadata record, compressed data, size,
//! type (0 file, 2 deleted, 5 folder), name, parent. Content is zlib
//! compressed in chunks (64 KiB each), listed by a table of offsets.
//! Metadata records (category, key, text value) carry times (UTC, to the
//! microsecond), DOS attributes and the MD5 and SHA-1 FTK computed.

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

pub const SIGNATURE: &[u8] = b"ADLOGICALIMAGE";
const MAX_ITEMS: usize = 2_000_000;
const MAX_META: usize = 4096;
const MAX_NAME: u64 = 32 << 10;
const MAX_CHUNKS: u64 = 1 << 24;
const FIRST_RECORD: u64 = 64;

fn u32_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64).unwrap_or(0)
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0)
}

fn read_at<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> anyhow::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    // Grows with what is there, never by what a damaged length claims.
    let mut b = Vec::new();
    r.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}

#[derive(Debug, Clone)]
struct Item {
    data: u64,
    size: u64,
}

/// What FTK recorded for a file.
#[derive(Debug, Clone, Default)]
pub struct Recorded {
    pub md5: String,
    pub sha1: String,
}

pub struct Ad1Volume {
    items: HashMap<u64, Item>,
    listing: Vec<FsEntry>,
    pub version: u32,
    pub source: String,
    chunk: u64,
    pub recorded: HashMap<u64, Recorded>,
    pub notes: Vec<String>,
    size: u64,
    /// Chunk offsets of the file read last, and its last chunk.
    cache: Mutex<Option<(u64, Vec<u64>, u64, Vec<u8>)>>,
}

/// "20180502T074659.164650" (UTC) as a FILETIME.
fn ftk_time(s: &str) -> u64 {
    let s = s.trim();
    let (main, frac) = s.split_once('.').unwrap_or((s, ""));
    let Ok(t) = chrono::NaiveDateTime::parse_from_str(main, "%Y%m%dT%H%M%S") else { return 0 };
    let secs = t.and_utc().timestamp() + 11_644_473_600;
    if secs < 0 {
        return 0;
    }
    let digits: String = frac.chars().filter(|c| c.is_ascii_digit()).take(7).collect();
    let sub = if digits.is_empty() { 0 } else { digits.parse::<u64>().unwrap_or(0) * 10u64.pow(7 - digits.len() as u32) };
    secs as u64 * 10_000_000 + sub
}

pub fn is_ad1(head: &[u8]) -> bool {
    head.starts_with(SIGNATURE)
}

pub fn open<R: Read + Seek>(r: &mut R, len: u64) -> anyhow::Result<Ad1Volume> {
    let h = read_at(r, 0, 512)?;
    if !is_ad1(&h) {
        anyhow::bail!("not an AD1 logical image");
    }
    let version = u32_at(&h, 16) as u32;
    if version != 3 && version != 4 {
        anyhow::bail!("AD1 version {} is not supported (3 and 4 are)", version);
    }
    let chunk = u32_at(&h, 24);
    if chunk == 0 || chunk > 16 << 20 {
        anyhow::bail!("the AD1 image header is damaged (chunk size {})", chunk);
    }
    let first = u64_at(&h, 36);
    let nlen = u32_at(&h, 44).min(4096) as usize;
    let at = if version == 4 { u64_at(&h, 52).max(48) as usize } else { 48 };
    let source = String::from_utf8_lossy(&read_at(r, at as u64, nlen)?).trim_end_matches('\0').to_string();

    let mut listing: Vec<FsEntry> = vec![];
    let mut items = HashMap::new();
    let mut recorded = HashMap::new();
    let mut notes = vec![];
    let mk = |record: u64, parent: u64, name: &str, path: &str, is_dir: bool, size: u64, times: Option<Times>, attributes: u32, deleted: bool| FsEntry {
        record,
        seq: 1,
        parent,
        parent_seq: 1,
        name: name.to_string(),
        dos_name: None,
        path: path.to_string(),
        is_dir,
        deleted,
        orphan: false,
        size,
        alloc_size: size,
        resident: false,
        attributes,
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
    listing.push(mk(kokino_ntfs::ROOT_RECORD, kokino_ntfs::ROOT_RECORD, "", "/", true, 0, None, 0x10, false));
    let mut seen = std::collections::HashSet::new();
    // (item address, parent record, parent path)
    let mut todo: Vec<(u64, u64, String)> = vec![(first, kokino_ntfs::ROOT_RECORD, String::new())];
    let mut next_rec = FIRST_RECORD;
    let mut deleted = 0;
    let mut broken = false;
    while let Some((mut a, parent, ppath)) = todo.pop() {
        // Siblings in order; children are visited after.
        while a != 0 && listing.len() < MAX_ITEMS {
            if a >= len || !seen.insert(a) {
                broken = true;
                break;
            }
            let ih = read_at(r, a, 48)?;
            if ih.len() < 48 {
                broken = true;
                break;
            }
            let (next, child, meta, data, size) = (u64_at(&ih, 0), u64_at(&ih, 8), u64_at(&ih, 16), u64_at(&ih, 24), u64_at(&ih, 32));
            let (kind, nl) = (u32_at(&ih, 40), u32_at(&ih, 44));
            if nl > MAX_NAME {
                broken = true;
                break;
            }
            let name = String::from_utf8_lossy(&read_at(r, a + 48, nl as usize)?).replace(['/', '\0'], "_");
            let is_dir = kind == 5;
            let mut times = Times::default();
            let mut attrs = if is_dir { 0x10 } else { 0 };
            let mut rec_hash = Recorded::default();
            let mut m = meta;
            let mut k = 0;
            while m != 0 && k < MAX_META && m < len {
                k += 1;
                let mh = read_at(r, m, 20)?;
                if mh.len() < 20 {
                    break;
                }
                let (nm, key, vl) = (u64_at(&mh, 0), u32_at(&mh, 12), u32_at(&mh, 16).min(1 << 16));
                let v = String::from_utf8_lossy(&read_at(r, m + 20, vl as usize)?).trim_end_matches('\0').to_string();
                match key {
                    0x07 => times.accessed = ftk_time(&v),
                    0x08 => times.created = ftk_time(&v),
                    0x09 => times.modified = ftk_time(&v),
                    0xA002 => times.mft_modified = ftk_time(&v),
                    0x1002 if v == "true" => attrs |= 0x2,
                    0x1003 if v == "true" => attrs |= 0x4,
                    0x1004 if v == "true" => attrs |= 0x1,
                    0x1005 if v == "true" => attrs |= 0x20,
                    0x5001 => rec_hash.md5 = v.to_ascii_lowercase(),
                    0x5002 => rec_hash.sha1 = v.to_ascii_lowercase(),
                    _ => {}
                }
                if nm == m {
                    break;
                }
                m = nm;
            }
            let path = format!("{}/{}", ppath, name);
            let rec = next_rec;
            next_rec += 1;
            let del = kind == 2;
            deleted += del as usize;
            let t = (times.created | times.modified | times.accessed) != 0;
            listing.push(mk(rec, parent, &name, &path, is_dir, if is_dir { 0 } else { size }, t.then_some(times), attrs, del));
            if !is_dir {
                items.insert(rec, Item { data, size });
                if !rec_hash.md5.is_empty() || !rec_hash.sha1.is_empty() {
                    recorded.insert(rec, rec_hash);
                }
            }
            if child != 0 {
                todo.push((child, rec, path));
            }
            a = next;
        }
    }
    if listing.len() <= 1 {
        anyhow::bail!("the AD1 image lists no files");
    }
    if broken {
        notes.push("The item tree of the image is damaged at some point; what follows it there is not listed.".into());
    }
    if deleted > 0 {
        notes.push(format!("{} item(s) were deleted files when the image was made.", deleted));
    }
    Ok(Ad1Volume { items, listing, version, source, chunk, recorded, notes, size: len, cache: Mutex::new(None) })
}

impl Ad1Volume {
    pub fn info(&self) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: self.source.clone(),
            serial: String::new(),
            version: format!("AD1 v{} (FTK Imager logical image)", self.version),
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

    fn chunk_table<R: Read + Seek>(&self, r: &mut R, e: &Item) -> anyhow::Result<Vec<u64>> {
        let n = u64_at(&read_at(r, e.data, 8)?, 0);
        if n > MAX_CHUNKS || n.saturating_mul(self.chunk) < e.size || (n + 1).saturating_mul(8) > self.size.saturating_sub(e.data) {
            anyhow::bail!("the file's chunk table is damaged");
        }
        let t = read_at(r, e.data + 8, (n as usize + 1) * 8)?;
        Ok((0..=n as usize).map(|i| u64_at(&t, i * 8)).collect())
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let e = self.items.get(&fe.record).ok_or_else(|| anyhow::anyhow!("not a file"))?;
        if offset >= e.size || e.data == 0 {
            return Ok(vec![]);
        }
        let n = len.min((e.size - offset) as usize);
        let mut cache = self.cache.lock().unwrap();
        if cache.as_ref().is_none_or(|c| c.0 != fe.record) {
            *cache = Some((fe.record, self.chunk_table(r, e)?, u64::MAX, vec![]));
        }
        let c = cache.as_mut().unwrap();
        let mut out = Vec::with_capacity(n);
        let mut at = offset;
        while out.len() < n {
            let k = at / self.chunk;
            if c.2 != k {
                let (a, b) = (*c.1.get(k as usize).ok_or_else(|| anyhow::anyhow!("past the file's last chunk"))?, *c.1.get(k as usize + 1).ok_or_else(|| anyhow::anyhow!("past the file's last chunk"))?);
                if b < a || b - a > self.chunk * 2 + 1024 {
                    anyhow::bail!("a chunk of the file is damaged");
                }
                let z = read_at(r, a, (b - a) as usize)?;
                let mut d = Vec::new();
                flate2::read::ZlibDecoder::new(&z[..]).take(self.chunk).read_to_end(&mut d).map_err(|x| anyhow::anyhow!("a chunk of the file does not decompress: {}", x))?;
                c.2 = k;
                c.3 = d;
            }
            let w = (at - k * self.chunk) as usize;
            if w >= c.3.len() {
                break;
            }
            let take = (n - out.len()).min(c.3.len() - w);
            out.extend_from_slice(&c.3[w..w + take]);
            at += take as u64;
        }
        Ok(out)
    }

    /// Content is compressed: no byte of it is at one place in the image.
    pub fn extents(&self, _fe: &FsEntry) -> Vec<Extent> {
        vec![]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Writes an AD1 v4 image as FTK lays one out (joined, without the
    /// segment margins): items as (path, content), folders made as needed.
    pub(crate) fn build(files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use std::io::Write;
        let mut d = vec![0u8; 92];
        d[..14].copy_from_slice(SIGNATURE);
        d[16..20].copy_from_slice(&4u32.to_le_bytes());
        d[20..24].copy_from_slice(&1u32.to_le_bytes());
        d[24..28].copy_from_slice(&65536u32.to_le_bytes());
        let src = b"C:\\Lab\\Data";
        d[44..48].copy_from_slice(&(src.len() as u32).to_le_bytes());
        d[48..50].copy_from_slice(b"AD");
        d[52..60].copy_from_slice(&92u64.to_le_bytes());
        d.extend(src);
        let first = d.len() as u64;
        d[36..44].copy_from_slice(&first.to_le_bytes());
        // A folder "docs" holding the files, all at the top otherwise.
        let mut prev_sibling: Option<usize> = None;
        let folder = d.len();
        let item = |d: &mut Vec<u8>, name: &str, kind: u32, size: u64, parent: u64| -> usize {
            let a = d.len();
            d.extend([0u8; 40]);
            d[a + 32..a + 40].copy_from_slice(&size.to_le_bytes());
            d.extend(kind.to_le_bytes());
            d.extend((name.len() as u32).to_le_bytes());
            d.extend(name.as_bytes());
            d.extend(parent.to_le_bytes());
            a
        };
        let meta = |d: &mut Vec<u8>, at_item: usize, recs: &[(u32, u32, String)]| {
            let first = d.len();
            for (i, (cat, key, v)) in recs.iter().enumerate() {
                let a = d.len();
                let next = if i + 1 < recs.len() { (a + 20 + v.len()) as u64 } else { 0 };
                d.extend(next.to_le_bytes());
                d.extend(cat.to_le_bytes());
                d.extend(key.to_le_bytes());
                d.extend((v.len() as u32).to_le_bytes());
                d.extend(v.as_bytes());
            }
            d[at_item + 16..at_item + 24].copy_from_slice(&(first as u64).to_le_bytes());
        };
        let f = item(&mut d, "docs", 5, 0, 0);
        meta(&mut d, f, &[(5, 8, "20261021T023000.000000".into())]);
        for (name, content, del) in files {
            let a = item(&mut d, name, if *del { 2 } else { 0 }, content.len() as u64, folder as u64);
            match prev_sibling {
                None => d[folder + 8..folder + 16].copy_from_slice(&(a as u64).to_le_bytes()),
                Some(p) => d[p..p + 8].copy_from_slice(&(a as u64).to_le_bytes()),
            }
            prev_sibling = Some(a);
            if !content.is_empty() {
                let chunks: Vec<Vec<u8>> = content
                    .chunks(65536)
                    .map(|c| {
                        let mut z = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
                        z.write_all(c).unwrap();
                        z.finish().unwrap()
                    })
                    .collect();
                let table = d.len();
                d[a + 24..a + 32].copy_from_slice(&(table as u64).to_le_bytes());
                d.extend((chunks.len() as u64).to_le_bytes());
                let mut at = table + 8 + (chunks.len() + 1) * 8;
                for c in &chunks {
                    d.extend((at as u64).to_le_bytes());
                    at += c.len();
                }
                d.extend((at as u64).to_le_bytes());
                for c in &chunks {
                    d.extend(c);
                }
            }
            let md5 = kokino_core::hashing::hash_reader(*content, |_| true).unwrap().0.md5;
            meta(&mut d, a, &[(1, 0x5001, md5), (5, 0x07, "20261021T023500.250000".into()), (5, 0x08, "20261020T080000.000000".into()), (5, 0x09, "20261021T023000.000000".into()), (4, 0x1002, "true".into())]);
        }
        d
    }

    #[test]
    fn reads_an_ad1_image() {
        let big: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
        let img = build(&[("notes.txt", b"meet at the lab at noon", false), ("ledger.bin", &big, false), ("wiped.txt", b"gone", true)]);
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/ad1");
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("lab.ad1"), &img).unwrap();
        }

        let mut r = std::io::Cursor::new(&img);
        let v = open(&mut r, img.len() as u64).unwrap();
        assert_eq!((v.version, v.source.as_str()), (4, "C:\\Lab\\Data"));
        let e = v.entries();
        let paths: Vec<&str> = e.iter().map(|x| x.path.as_str()).collect();
        assert_eq!(paths, ["/", "/docs", "/docs/notes.txt", "/docs/ledger.bin", "/docs/wiped.txt"]);
        let ledger = e.iter().find(|x| x.name == "ledger.bin").unwrap();
        assert_eq!(v.read(&mut r, ledger, 0, big.len()).unwrap(), big);
        assert_eq!(v.read(&mut r, ledger, 65_530, 20).unwrap(), &big[65_530..65_550], "across a chunk");
        let notes = e.iter().find(|x| x.name == "notes.txt").unwrap();
        assert_eq!(v.read(&mut r, notes, 0, 100).unwrap(), b"meet at the lab at noon");
        assert_eq!(notes.si.unwrap().modified, ftk_time("20261021T023000"));
        assert_eq!(notes.si.unwrap().accessed % 10_000_000, 2_500_000);
        assert_eq!(notes.attributes & 2, 2, "hidden");
        assert!(e.iter().find(|x| x.name == "wiped.txt").unwrap().deleted);
        assert!(v.recorded[&notes.record].md5.len() == 32);
        assert!(v.notes.iter().any(|n| n.starts_with("1 item(s) were deleted")));
        // A loop in the tree stops there.
        let mut bad = img.clone();
        let first = u64_at(&bad, 36) as usize;
        let child = u64_at(&bad, first + 8) as usize;
        bad[child..child + 8].copy_from_slice(&(child as u64).to_le_bytes());
        let v = open(&mut std::io::Cursor::new(&bad), bad.len() as u64).unwrap();
        assert!(v.notes.iter().any(|n| n.contains("damaged")));
    }
}

/// Local validation on pyad1's image (not in the repository): runs only
/// when `target/validation/ad1/` holds it. Every file against the MD5 FTK
/// recorded.
#[cfg(test)]
mod validation {
    use super::*;

    #[test]
    fn ftk_imager_image() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/ad1");
        let p = dir.join("text-and-pictures.ad1");
        if !p.is_file() {
            return;
        }
        let ev = kokino_image::Evidence::open(&p).unwrap();
        assert_eq!(ev.format, kokino_image::ImageFormat::Ad1);
        assert_eq!(ev.files().len(), 4);
        let mut r = ev.reader().unwrap();
        let v = open(&mut r, ev.size).unwrap();
        let mut checked = 0;
        for e in v.entries().iter().filter(|e| !e.is_dir) {
            let d = v.read(&mut r, e, 0, e.size as usize).unwrap();
            assert_eq!(d.len() as u64, e.size);
            let md5 = kokino_core::hashing::hash_reader(&d[..], |_| true).unwrap().0.md5;
            assert_eq!(md5, v.recorded[&e.record].md5, "{}", e.path);
            checked += 1;
        }
        eprintln!("{}: {} files match FTK's MD5; source {}", p.display(), checked, v.source);
        assert_eq!(checked, 8);
    }
}
