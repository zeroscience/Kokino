//! A tar archive as a file system, for triage collections packed as tar:
//! UAC (Unix-like Artifacts Collector) for Linux, macOS and other Unix
//! systems, and any collection made with `tar`. The evidence stays the
//! archive (its hash is the one the collector reported).
//!
//! Plain tar is read in place. A gzip-compressed archive (.tar.gz, UAC's
//! default) cannot be read at random places, so it is decompressed once
//! into memory when opened, up to `MAX_GZIP` bytes.
//!
//! Headers: POSIX ustar (with the name prefix), GNU long names and links
//! ('L', 'K') and PAX extended headers ('x': path, linkpath, size, uid,
//! gid, mtime, atime, ctime with fractions; libarchive's creationtime).
//! Times are UTC.
//!
//! `pack` turns a folder (a triage collection copied out as plain files)
//! into such an archive, hashing every file as it copies it, so a folder
//! can be examined the same way.

use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times, UnixMeta};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

const MAX_ENTRIES: usize = 2_000_000;
/// Largest uncompressed size of a .tar.gz read (it is held in memory).
pub const MAX_GZIP: u64 = 1 << 30;
/// Above the record numbers NTFS keeps for itself (0 to 23), which the
/// summary leaves out.
const FIRST_RECORD: u64 = 64;

#[derive(Debug, Clone)]
struct Item {
    data: u64,
    size: u64,
}

enum Src {
    Plain,
    Mem(Arc<Vec<u8>>),
}

pub struct TarVolume {
    items: HashMap<u64, Item>,
    listing: Vec<FsEntry>,
    src: Src,
    /// The collector, when the layout says which.
    pub layout: &'static str,
    pub notes: Vec<String>,
    size: u64,
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

/// A numeric field: octal digits, or base-256 when the top bit is set.
fn num(b: &[u8]) -> u64 {
    if b.first().is_some_and(|&c| c & 0x80 != 0) {
        return b.iter().enumerate().fold(0u64, |acc, (i, &c)| (acc << 8) | (if i == 0 { c & 0x7F } else { c }) as u64);
    }
    b.iter().skip_while(|&&c| c == b' ' || c == 0).take_while(|&&c| (b'0'..=b'7').contains(&c)).fold(0u64, |acc, &c| acc.saturating_mul(8).saturating_add((c - b'0') as u64))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn checksum_ok(h: &[u8]) -> bool {
    let want = num(&h[148..156]);
    let sum: u64 = h.iter().enumerate().map(|(i, &c)| if (148..156).contains(&i) { b' ' as u64 } else { c as u64 }).sum();
    // Some old writers summed signed bytes.
    let signed: i64 = h.iter().enumerate().map(|(i, &c)| if (148..156).contains(&i) { b' ' as i64 } else { c as i8 as i64 }).sum();
    want == sum || want as i64 == signed
}

/// A tar header block: the checksum adds up.
pub fn is_tar(head: &[u8]) -> bool {
    head.len() >= 512 && !head[..512].iter().all(|&c| c == 0) && checksum_ok(&head[..512]) && head[0] != 0
}

/// Whether the bytes start like gzip.
pub fn is_gzip(head: &[u8]) -> bool {
    head.len() >= 3 && head[0] == 0x1F && head[1] == 0x8B && head[2] == 8
}

/// PAX "len key=value\n" records.
fn pax(d: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut p = 0;
    while p < d.len() {
        let Some(sp) = d[p..].iter().position(|&c| c == b' ') else { break };
        let Ok(n) = std::str::from_utf8(&d[p..p + sp]).unwrap_or("").parse::<usize>() else { break };
        if n <= sp + 1 || p + n > d.len() {
            break;
        }
        let rec = &d[p + sp + 1..p + n];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&c| c == b'=') {
            out.insert(String::from_utf8_lossy(&rec[..eq]).into_owned(), String::from_utf8_lossy(&rec[eq + 1..]).into_owned());
        }
        p += n;
    }
    out
}

/// Seconds (with an optional fraction, as PAX writes them) to FILETIME.
fn pax_time(s: &str) -> Option<u64> {
    let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = secs.parse().ok()?;
    let mut ft = kokino_artifacts::bin::unix_to_filetime(secs)?;
    let digits: String = frac.chars().take(7).collect();
    if !digits.is_empty() {
        let f: u64 = digits.parse().ok()?;
        ft += f * 10u64.pow(7 - digits.len() as u32);
    }
    Some(ft)
}

struct Raw {
    path: String,
    kind: u8,
    data: u64,
    size: u64,
    times: Times,
    unix: UnixMeta,
}

pub fn open<R: Read + Seek>(r: &mut R, len: u64) -> anyhow::Result<TarVolume> {
    let head = read_at(r, 0, 4)?;
    let (src, total, gz) = if is_gzip(&head) {
        r.seek(SeekFrom::Start(0))?;
        let mut out = vec![];
        flate2::read::MultiGzDecoder::new(std::io::BufReader::new(&mut *r).take(len)).take(MAX_GZIP + 1).read_to_end(&mut out).map_err(|e| anyhow::anyhow!("gzip: {}", e))?;
        if out.len() as u64 > MAX_GZIP {
            anyhow::bail!("this .tar.gz holds more than {} GiB: decompress it (gzip -d) and add the .tar, which is read in place", MAX_GZIP >> 30);
        }
        let n = out.len() as u64;
        (Src::Mem(Arc::new(out)), n, true)
    } else {
        (Src::Plain, len, false)
    };
    let mut rd = |off: u64, n: usize| -> anyhow::Result<Vec<u8>> {
        match &src {
            Src::Plain => read_at(r, off, n),
            Src::Mem(m) => {
                let o = (off as usize).min(m.len());
                Ok(m[o..(o + n).min(m.len())].to_vec())
            }
        }
    };
    let mut raws: Vec<Raw> = vec![];
    let mut notes = vec![];
    let (mut long_name, mut long_link, mut ext): (Option<String>, Option<String>, HashMap<String, String>) = (None, None, HashMap::new());
    let mut off = 0u64;
    while off.saturating_add(512) <= total && raws.len() < MAX_ENTRIES {
        let h = rd(off, 512)?;
        if h.len() < 512 || h.iter().all(|&c| c == 0) {
            break;
        }
        if !checksum_ok(&h) {
            notes.push(format!("The archive is damaged at byte {} (a header's checksum does not add up); what follows it is not listed.", off));
            break;
        }
        let kind = h[156];
        let data = off + 512;
        let mut size = num(&h[124..136]);
        if matches!(kind, b'0' | 0 | b'7' | b'S') {
            if let Some(s) = ext.get("size").and_then(|s| s.parse().ok()) {
                size = s;
            }
        }
        let Some(next) = size.checked_add(511).map(|s| s / 512 * 512).and_then(|s| data.checked_add(s)) else { break };
        match kind {
            b'L' => long_name = Some(cstr(&rd(data, size.min(1 << 16) as usize)?)),
            b'K' => long_link = Some(cstr(&rd(data, size.min(1 << 16) as usize)?)),
            b'x' => ext = pax(&rd(data, size.min(1 << 20) as usize)?),
            b'g' => {}
            _ => {
                let ustar = &h[257..262] == b"ustar";
                let mut name = cstr(&h[0..100]);
                let prefix = if ustar { cstr(&h[345..500]) } else { String::new() };
                if !prefix.is_empty() {
                    name = format!("{}/{}", prefix, name);
                }
                let path = ext.remove("path").or(long_name.take()).unwrap_or(name);
                let link = ext.remove("linkpath").or(long_link.take()).unwrap_or_else(|| cstr(&h[157..257]));
                let mtime = ext.get("mtime").and_then(|t| pax_time(t)).or_else(|| kokino_artifacts::bin::unix_to_filetime(num(&h[136..148]) as i64)).unwrap_or(0);
                let times = Times {
                    modified: mtime,
                    accessed: ext.get("atime").and_then(|t| pax_time(t)).unwrap_or(0),
                    created: ext.get("LIBARCHIVE.creationtime").and_then(|t| pax_time(t)).unwrap_or(0),
                    mft_modified: ext.get("ctime").and_then(|t| pax_time(t)).unwrap_or(0),
                };
                let mode = num(&h[100..108]) as u32 & 0o7777;
                let ftype = match kind {
                    b'5' => 0o040000,
                    b'2' => 0o120000,
                    b'3' => 0o020000,
                    b'4' => 0o060000,
                    b'6' => 0o010000,
                    _ => 0o100000,
                };
                let unix = UnixMeta {
                    inode: 0,
                    mode: ftype | mode,
                    uid: ext.get("uid").and_then(|s| s.parse().ok()).unwrap_or(num(&h[108..116]) as u32),
                    gid: ext.get("gid").and_then(|s| s.parse().ok()).unwrap_or(num(&h[116..124]) as u32),
                    deleted_time: 0,
                    inode_offset: 0,
                    journal_seq: None,
                    link_target: (matches!(kind, b'1' | b'2') && !link.is_empty()).then(|| link.clone()),
                };
                // Data only for regular files; a hard link reads its target's.
                let (data, size) = match kind {
                    b'0' | 0 | b'7' | b'S' => (data, size),
                    _ => (0, 0),
                };
                if kind == b'S' && notes.len() < 20 {
                    notes.push(format!("{} is a sparse file: it is shown as stored, without its holes.", path));
                }
                raws.push(Raw { path, kind, data, size, times, unix });
                ext.clear();
            }
        }
        off = next;
    }
    if raws.is_empty() {
        anyhow::bail!("the tar archive lists no files");
    }
    // Hard links: the content of the file they name.
    let by_path: HashMap<String, (u64, u64)> = raws.iter().filter(|x| matches!(x.kind, b'0' | 0 | b'7' | b'S')).map(|x| (x.path.trim_start_matches("./").to_string(), (x.data, x.size))).collect();
    for x in raws.iter_mut().filter(|x| x.kind == b'1') {
        if let Some(&(d, s)) = x.unix.link_target.as_ref().and_then(|t| by_path.get(t.trim_start_matches("./"))) {
            x.data = d;
            x.size = s;
        }
    }
    let uac = raws.iter().any(|x| x.path.trim_start_matches("./").starts_with("[root]/")) && raws.iter().any(|x| { let p = x.path.trim_start_matches("./"); p == "uac.log" || p.starts_with("live_response/") });
    let layout = if uac { "UAC" } else { "" };

    let mut listing: Vec<FsEntry> = vec![];
    let mut dirs: HashMap<String, u64> = HashMap::new();
    let mut items = HashMap::new();
    let mut next_rec = FIRST_RECORD;
    let mk = |record: u64, parent: u64, name: &str, path: &str, is_dir: bool, size: u64, times: Option<Times>, unix: Option<UnixMeta>| FsEntry {
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
        unix,
        name_only: None,
    };
    listing.push(mk(kokino_ntfs::ROOT_RECORD, kokino_ntfs::ROOT_RECORD, "", "/", true, 0, None, None));
    dirs.insert(String::new(), kokino_ntfs::ROOT_RECORD);
    for x in raws {
        let parts: Vec<&str> = x.path.split('/').filter(|s| !s.is_empty() && *s != "." && *s != "..").collect();
        if parts.is_empty() {
            continue;
        }
        let is_dir = x.kind == b'5';
        let mut parent = kokino_ntfs::ROOT_RECORD;
        let mut path = String::new();
        for (i, part) in parts.iter().enumerate() {
            let last = i == parts.len() - 1;
            path = format!("{}/{}", path, part);
            if last && !is_dir {
                break;
            }
            parent = match dirs.get(&path) {
                Some(&rec) => {
                    if last {
                        // A folder listed after files inside it: keep its own times.
                        if let Some(e) = listing.iter_mut().find(|e| e.record == rec) {
                            e.si = Some(x.times);
                            e.unix = Some(x.unix.clone());
                        }
                    }
                    rec
                }
                None => {
                    let rec = next_rec;
                    next_rec += 1;
                    let (t, u) = if last { (Some(x.times), Some(x.unix.clone())) } else { (None, None) };
                    listing.push(mk(rec, parent, part, &path, true, 0, t, u));
                    dirs.insert(path.clone(), rec);
                    rec
                }
            };
        }
        if is_dir {
            continue;
        }
        let rec = next_rec;
        next_rec += 1;
        listing.push(mk(rec, parent, parts[parts.len() - 1], &path, false, x.size, Some(x.times), Some(x.unix)));
        items.insert(rec, Item { data: x.data, size: x.size });
    }
    if gz {
        notes.insert(0, format!("A gzip-compressed tar archive ({} bytes uncompressed), decompressed in memory to be read.", total));
    }
    Ok(TarVolume { items, listing, src, layout, notes, size: len })
}

impl TarVolume {
    pub fn info(&self) -> NtfsVolumeInfo {
        let gz = matches!(self.src, Src::Mem(_));
        NtfsVolumeInfo {
            label: String::new(),
            serial: String::new(),
            version: format!("{}{}", if gz { "tar.gz" } else { "tar" }, if self.layout.is_empty() { String::new() } else { format!(" ({} collection)", self.layout) }),
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

    pub fn read<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let e = self.items.get(&fe.record).ok_or_else(|| anyhow::anyhow!("not a file"))?;
        if offset >= e.size {
            return Ok(vec![]);
        }
        let n = len.min((e.size - offset) as usize);
        let at = e.data + offset;
        match &self.src {
            Src::Plain => read_at(r, at, n),
            Src::Mem(m) => {
                let o = (at as usize).min(m.len());
                Ok(m[o..(o + n).min(m.len())].to_vec())
            }
        }
    }

    pub fn extents(&self, fe: &FsEntry) -> Vec<Extent> {
        match (self.items.get(&fe.record), &self.src) {
            (Some(e), Src::Plain) if e.size > 0 => vec![Extent { offset: 0, len: e.size, vol: Some(e.data) }],
            _ => vec![],
        }
    }
}

/// What `pack` wrote: one line per file (path, size, SHA-256, times)
/// and what it could not read.
#[derive(Debug, Default)]
pub struct Packed {
    pub files: u64,
    pub bytes: u64,
    /// "path<TAB>size<TAB>sha256<TAB>modified" lines, sorted by path.
    pub manifest: String,
    pub skipped: Vec<String>,
}

fn pax_rec(k: &str, v: &str) -> String {
    let body = format!(" {}={}\n", k, v);
    let mut n = body.len() + 1;
    while format!("{}{}", n, body).len() != n {
        n += 1;
    }
    format!("{}{}", n, body)
}

fn ustar(name: &str, kind: u8, size: u64, mtime: u64, mode: u32, link: &str) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    let put = |h: &mut Vec<u8>, at: usize, s: &[u8], max: usize| h[at..at + s.len().min(max)].copy_from_slice(&s[..s.len().min(max)]);
    put(&mut h, 0, name.as_bytes(), 99);
    put(&mut h, 100, format!("{:07o}\0", mode & 0o7777).as_bytes(), 8);
    put(&mut h, 108, b"0000000\0", 8);
    put(&mut h, 116, b"0000000\0", 8);
    put(&mut h, 124, format!("{:011o}\0", size.min(0o77777777777)).as_bytes(), 12);
    put(&mut h, 136, format!("{:011o}\0", mtime.min(0o77777777777)).as_bytes(), 12);
    h[156] = kind;
    put(&mut h, 157, link.as_bytes(), 99);
    put(&mut h, 257, b"ustar\x0000", 8);
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&c| c as u64).sum();
    put(&mut h, 148, format!("{:06o}\0 ", sum).as_bytes(), 8);
    h
}

fn unix_time(t: std::io::Result<std::time::SystemTime>) -> Option<String> {
    let d = t.ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(format!("{}.{:09}", d.as_secs(), d.subsec_nanos()))
}

/// Packs the folder `src` into the tar file `dest`: every file and folder
/// with its times (PAX, to the nanosecond, with the creation time where the
/// system keeps one), symbolic links as links (never followed). Files are
/// opened read-only and hashed as they are copied. `progress(bytes, files)`
/// returns false to stop.
pub fn pack(src: &std::path::Path, dest: &std::path::Path, progress: &mut dyn FnMut(u64, u64) -> bool) -> anyhow::Result<Packed> {
    use std::io::Write;
    let mut list = vec![];
    let mut todo = vec![src.to_path_buf()];
    while let Some(d) = todo.pop() {
        let mut rd: Vec<std::fs::DirEntry> = std::fs::read_dir(&d)?.flatten().collect();
        rd.sort_by_key(|e| e.file_name());
        for e in rd {
            let ft = e.file_type()?;
            if ft.is_dir() {
                todo.push(e.path());
            }
            list.push(e.path());
            if list.len() > MAX_ENTRIES {
                anyhow::bail!("more than {} files and folders", MAX_ENTRIES);
            }
        }
    }
    list.sort();
    let mut out = std::io::BufWriter::new(std::fs::File::create(dest)?);
    let mut packed = Packed::default();
    let mut lines = vec![];
    for p in list {
        let rel = p.strip_prefix(src).unwrap_or(&p).to_string_lossy().replace('\\', "/");
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                packed.skipped.push(format!("{}: {}", rel, e));
                continue;
            }
        };
        let ft = meta.file_type();
        let (kind, link) = if ft.is_symlink() {
            (b'2', std::fs::read_link(&p).map(|l| l.to_string_lossy().replace('\\', "/")).unwrap_or_default())
        } else if ft.is_dir() {
            (b'5', String::new())
        } else {
            (b'0', String::new())
        };
        // Opened read-only before anything is written, so a locked file is
        // skipped whole.
        let file = if kind == b'0' {
            match std::fs::File::open(&p) {
                Ok(f) => Some(f),
                Err(e) => {
                    packed.skipped.push(format!("{}: {}", rel, e));
                    continue;
                }
            }
        } else {
            None
        };
        let size = if file.is_some() { meta.len() } else { 0 };
        let mut recs = pax_rec("path", &format!("{}{}", rel, if kind == b'5' { "/" } else { "" }));
        if !link.is_empty() {
            recs.push_str(&pax_rec("linkpath", &link));
        }
        for (k, t) in [("mtime", unix_time(meta.modified())), ("atime", unix_time(meta.accessed())), ("LIBARCHIVE.creationtime", unix_time(meta.created()))] {
            if let Some(t) = t {
                recs.push_str(&pax_rec(k, &t));
            }
        }
        recs.push_str(&pax_rec("size", &size.to_string()));
        let pad = |n: u64| vec![0u8; (n.div_ceil(512) * 512 - n) as usize];
        out.write_all(&ustar("PaxHeader", b'x', recs.len() as u64, 0, 0o644, ""))?;
        out.write_all(recs.as_bytes())?;
        out.write_all(&pad(recs.len() as u64))?;
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        #[cfg(unix)]
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions());
        #[cfg(not(unix))]
        let mode = if kind == b'5' { 0o755 } else if meta.permissions().readonly() { 0o444 } else { 0o644 };
        out.write_all(&ustar(&rel.chars().take(90).collect::<String>(), kind, size, mtime, mode, &link))?;
        if let Some(mut f) = file {
            // Exactly the size recorded: a file that shrank while being read
            // is padded with zeros (and noted), one that grew is cut.
            let mut h = kokino_core::hashing::MultiHasher::default();
            let mut buf = vec![0u8; 1 << 20];
            let mut left = size;
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = std::io::Read::read(&mut f, &mut buf[..want])?;
                if n == 0 {
                    packed.skipped.push(format!("{}: {} bytes short of its size while being read; zeros written instead", rel, left));
                    let z = vec![0u8; want];
                    while left > 0 {
                        let k = left.min(z.len() as u64) as usize;
                        out.write_all(&z[..k])?;
                        h.update(&z[..k]);
                        left -= k as u64;
                    }
                    break;
                }
                out.write_all(&buf[..n])?;
                h.update(&buf[..n]);
                left -= n as u64;
            }
            out.write_all(&pad(size))?;
            lines.push(format!("{}\t{}\t{}\t{}", rel, size, h.finish().sha256, mtime));
            packed.files += 1;
            packed.bytes += size;
            if !progress(packed.bytes, packed.files) {
                anyhow::bail!("packing cancelled");
            }
        }
    }
    out.write_all(&[0u8; 1024])?;
    out.flush()?;
    packed.manifest = lines.join("\n") + "\n";
    Ok(packed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn header(name: &str, kind: u8, size: u64, mtime: u64, link: &str) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        let (prefix, name) = if name.len() > 100 { name.rsplit_once('/').unwrap() } else { ("", name) };
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0001750\0");
        h[116..124].copy_from_slice(b"0001750\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", size).as_bytes());
        h[136..148].copy_from_slice(format!("{:011o}\0", mtime).as_bytes());
        h[156] = kind;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..265].copy_from_slice(b"ustar\x0000");
        h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|&c| c as u64).sum();
        h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
        h
    }

    /// A tar file in memory: (name, kind, data, link), with PAX and GNU
    /// long-name records where asked ("pax:" and "gnu:" name prefixes).
    pub(crate) fn tar(entries: &[(&str, u8, &[u8], &str)]) -> Vec<u8> {
        let mut out = vec![];
        let pad = |out: &mut Vec<u8>| out.resize(out.len().div_ceil(512) * 512, 0);
        for (name, kind, data, link) in entries {
            let mut name = name.to_string();
            if let Some(n) = name.strip_prefix("pax:") {
                let rec = |k: &str, v: &str| {
                    let body = format!(" {}={}\n", k, v);
                    let mut n = body.len() + 1;
                    while format!("{}{}", n, body).len() != n {
                        n += 1;
                    }
                    format!("{}{}", n, body)
                };
                let recs = format!("{}{}", rec("path", n), rec("mtime", "1735689600.5"));
                out.extend(header("PaxHeaders/x", b'x', recs.len() as u64, 0, ""));
                out.extend(recs.as_bytes());
                pad(&mut out);
                name = "placeholder".into();
            } else if let Some(n) = name.strip_prefix("gnu:") {
                out.extend(header("././@LongLink", b'L', n.len() as u64 + 1, 0, ""));
                out.extend(n.as_bytes());
                out.push(0);
                pad(&mut out);
                name = n[..90].to_string();
            }
            out.extend(header(&name, *kind, data.len() as u64, 1_700_000_000, link));
            out.extend(*data);
            pad(&mut out);
        }
        out.extend(vec![0u8; 1024]);
        out
    }

    #[test]
    fn reads_tar_and_tar_gz() {
        let long = format!("[root]/home/alice/{}/notes.txt", "deep".repeat(30));
        let t = tar(&[
            ("[root]/etc/", b'5', b"", ""),
            ("[root]/etc/passwd", b'0', b"root:x:0:0:root:/root:/bin/bash\n", ""),
            ("[root]/etc/hostname-link", b'2', b"", "hostname"),
            ("[root]/etc/passwd-copy", b'1', b"", "[root]/etc/passwd"),
            (&format!("gnu:{}", long), b'0', b"long name", ""),
            ("pax:[root]/var/log/caf\u{e9}.log", b'0', b"pax entry", ""),
            ("uac.log", b'0', b"UAC log", ""),
        ]);
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &t).unwrap();
        let gz = gz.finish().unwrap();
        assert!(is_tar(&t) && is_gzip(&gz));
        for data in [t.clone(), gz] {
            let mut r = std::io::Cursor::new(&data);
            let v = open(&mut r, data.len() as u64).unwrap();
            assert_eq!(v.layout, "UAC");
            let es = v.entries();
            let get = |p: &str| es.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("{} missing", p)).clone();
            let pw = get("/[root]/etc/passwd");
            assert_eq!(v.read(&mut r, &pw, 0, 100).unwrap(), b"root:x:0:0:root:/root:/bin/bash\n");
            assert_eq!(v.read(&mut r, &pw, 5, 3).unwrap(), b"x:0");
            assert_eq!(pw.unix.as_ref().unwrap().mode_string(), "-rw-r--r--");
            assert_eq!((pw.unix.as_ref().unwrap().uid, pw.si.unwrap().modified), (1000, kokino_artifacts::bin::unix_to_filetime(1_700_000_000).unwrap()));
            assert_eq!(v.read(&mut r, &get("/[root]/etc/passwd-copy"), 0, 4).unwrap(), b"root");
            assert_eq!(get("/[root]/etc/hostname-link").unix.unwrap().link_target.as_deref(), Some("hostname"));
            assert_eq!(v.read(&mut r, &get(&format!("/{}", long)), 0, 50).unwrap(), b"long name");
            let p = get("/[root]/var/log/caf\u{e9}.log");
            assert_eq!(v.read(&mut r, &p, 0, 50).unwrap(), b"pax entry");
            assert_eq!(p.si.unwrap().modified, kokino_artifacts::bin::unix_to_filetime(1_735_689_600).unwrap() + 5_000_000);
            assert!(get("/[root]/etc").is_dir && get("/[root]").is_dir);
        }
        // Plain tar data is in place: extents point into the archive.
        let mut r = std::io::Cursor::new(&t);
        let v = open(&mut r, t.len() as u64).unwrap();
        let pw = v.entries().into_iter().find(|e| e.path == "/[root]/etc/passwd").unwrap();
        let x = v.extents(&pw);
        assert_eq!(&t[x[0].vol.unwrap() as usize..][..4], b"root");
    }

    #[test]
    fn damaged_archives() {
        let mut t = tar(&[("a.txt", b'0', b"aaaa", ""), ("b.txt", b'0', b"bbbb", "")]);
        t[1024 + 10] ^= 0xFF; // b.txt's header
        let v = open(&mut std::io::Cursor::new(&t), t.len() as u64).unwrap();
        assert_eq!(v.entries().iter().filter(|e| !e.is_dir).count(), 1);
        assert!(v.notes[0].contains("damaged at byte 1024"));
        assert!(open(&mut std::io::Cursor::new(vec![0u8; 2048]), 2048).is_err());
        assert_eq!(num(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]), 256);
    }

    /// A folder packed and read back: names (also non-ASCII and long),
    /// sizes, content, times to the second, the manifest.
    #[test]
    fn packs_a_folder() {
        let base = std::env::temp_dir().join(format!("kokino-pack-{}", std::process::id()));
        let src = base.join("C");
        let deep = src.join("Users").join("alice").join(format!("{}", "Documents-".repeat(12)));
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(src.join("Users/alice/caf\u{e9}.txt"), b"accent").unwrap();
        std::fs::write(deep.join("report.txt"), vec![b'x'; 70_000]).unwrap();
        std::fs::create_dir_all(src.join("Windows/System32/config")).unwrap();
        std::fs::write(src.join("Windows/System32/config/SYSTEM"), b"regf....").unwrap();
        let dest = base.join("pack.tar");
        let p = pack(&src, &dest, &mut |_, _| true).unwrap();
        assert_eq!((p.files, p.bytes), (3, 6 + 70_000 + 8));
        assert!(p.manifest.contains("Windows/System32/config/SYSTEM\t8\t"));
        let d = std::fs::read(&dest).unwrap();
        let mut r = std::io::Cursor::new(&d);
        let v = open(&mut r, d.len() as u64).unwrap();
        let es = v.entries();
        let get = |path: &str| es.iter().find(|e| e.path == path).unwrap_or_else(|| panic!("{} missing: {:?}", path, es.iter().map(|e| &e.path).collect::<Vec<_>>())).clone();
        let rep = get(&format!("/Users/alice/{}/report.txt", "Documents-".repeat(12)));
        assert_eq!(v.read(&mut r, &rep, 69_990, 100).unwrap(), vec![b'x'; 10]);
        assert_eq!(v.read(&mut r, &get("/Users/alice/caf\u{e9}.txt"), 0, 10).unwrap(), b"accent");
        let want = std::fs::metadata(src.join("Windows/System32/config/SYSTEM")).unwrap().modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let got = get("/Windows/System32/config/SYSTEM").si.unwrap().modified;
        assert_eq!(got / 10_000_000, kokino_artifacts::bin::unix_to_filetime(want).unwrap() / 10_000_000);
        assert!(get("/Users").is_dir);
        std::fs::remove_dir_all(&base).ok();
    }
}
