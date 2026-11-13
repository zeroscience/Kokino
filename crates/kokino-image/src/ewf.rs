//! Expert Witness Compression Format, version 1 (E01, as written by EnCase,
//! FTK Imager, ewfacquire and Guymager).
//!
//! Layout, per segment file (.E01, .E02, ... .E99, .EAA ... .ZZZ):
//!
//! ```text
//! file header (13 bytes)  "EVF\x09\x0d\x0a\xff\x00", 0x01, segment number u16, 0x0000
//! section*                76-byte descriptor + data, chained by absolute offsets
//!   descriptor            type[16] next_offset u64 size u64 pad[40] adler32
//!   header / header2      zlib text: case, examiner, notes, acquisition dates (header2 is UTF-16)
//!   volume / disk         geometry: chunk count, sectors per chunk, bytes per sector, sector count
//!   sectors               chunk data
//!   table (+ table2 copy) entry count, base offset, adler32, then u32 entries:
//!                         bit 31 = zlib-compressed, bits 0..30 = offset from base
//!   error2                sector ranges the acquisition tool could not read
//!   hash / digest         MD5 (and SHA-1) of the media stream as acquired
//!   next / done           end of this segment / end of the image
//! ```
//!
//! Uncompressed chunks carry a trailing Adler-32, compressed chunks a zlib
//! stream (whose Adler-32 trailer the decoder checks). Every descriptor and
//! table checksum is verified; a mismatch is an error, never silently skipped.

use anyhow::{bail, Context};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SIGNATURE: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
pub const SIGNATURE_V2: &[u8; 8] = b"EVF2\x0d\x0a\x81\x00";
const DESCRIPTOR: u64 = 76;
const MAX_CHUNK: u32 = 64 << 20;

#[derive(Debug, Clone, Copy)]
struct Chunk {
    seg: u32,
    offset: u64,
    stored: u32,
    compressed: bool,
    /// EWF2: the chunk is this 8-byte pattern repeated (nothing stored).
    pattern: Option<u64>,
}

/// What the acquisition tool recorded about the media and the acquisition.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EwfInfo {
    pub segments: Vec<String>,
    pub media_size: u64,
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
    pub chunk_count: u64,
    pub compressed_chunks: u64,
    /// "removable", "fixed", "optical", "logical", "memory" or the raw code.
    pub media_type: String,
    pub set_identifier: String,
    /// Acquisition metadata from header2 (or header), keyed by readable names.
    pub acquisition: BTreeMap<String, String>,
    /// MD5 / SHA-1 stored by the acquisition tool (lowercase hex).
    pub md5: Option<String>,
    pub sha1: Option<String>,
    /// Sector ranges the acquisition tool could not read: (first sector, count).
    pub read_errors: Vec<(u64, u64)>,
}

#[derive(Debug)]
pub struct EwfImage {
    paths: Vec<PathBuf>,
    chunks: Vec<Chunk>,
    chunk_size: u32,
    pub info: EwfInfo,
}

impl EwfImage {
    pub fn open(first: &Path) -> anyhow::Result<EwfImage> {
        let mut sig = [0u8; 8];
        if File::open(first).and_then(|mut f| f.read_exact(&mut sig)).is_ok() && &sig == SIGNATURE_V2 {
            return Self::open_v2(first);
        }
        let mut paths = vec![];
        let mut chunks: Vec<Chunk> = vec![];
        let mut info = EwfInfo::default();
        let mut have_header2 = false;
        let mut geometry: Option<(u64, u32, u32, u64)> = None;
        let mut done = false;

        for seg_no in 1u32.. {
            let path = segment_path(first, seg_no).with_context(|| format!("too many segments after {}", first.display()))?;
            if !path.exists() {
                if seg_no == 1 {
                    bail!("{} not found", path.display());
                }
                bail!("segment {} of the image is missing: expected {}", seg_no, path.display());
            }
            let mut f = File::open(&path).with_context(|| format!("cannot open {}", path.display()))?;
            let flen = f.metadata()?.len();
            let mut fh = [0u8; 13];
            f.read_exact(&mut fh).with_context(|| format!("{}: truncated file header", path.display()))?;
            if &fh[..8] == SIGNATURE_V2 {
                return Self::open_v2(first);
            }
            if &fh[..8] != SIGNATURE {
                bail!("{}: not an EWF segment (bad signature)", path.display());
            }
            let found = u16::from_le_bytes([fh[9], fh[10]]) as u32;
            if found != seg_no {
                bail!("{}: holds segment {} where segment {} was expected", path.display(), found, seg_no);
            }
            let seg_idx = paths.len() as u32;
            paths.push(path.clone());

            let mut off = 13u64;
            let mut sectors: Option<(u64, u64)> = None;
            let mut table_failed = false;
            loop {
                if off + DESCRIPTOR > flen {
                    bail!("{}: section chain runs past end of file at offset {}", path.display(), off);
                }
                let d = read_at(&mut f, off, DESCRIPTOR as usize)?;
                if adler32(&d[..72]) != le32(&d[72..]) {
                    bail!("{}: section descriptor checksum mismatch at offset {}", path.display(), off);
                }
                let kind = String::from_utf8_lossy(&d[..16]).trim_end_matches('\0').to_string();
                let next = le64(&d[16..]);
                let size = le64(&d[24..]);
                let data_off = off + DESCRIPTOR;
                let data_len = size.saturating_sub(DESCRIPTOR).min(flen.saturating_sub(data_off));

                match kind.as_str() {
                    "header2" if !have_header2 => {
                        if let Ok(t) = inflate_text(&read_at(&mut f, data_off, data_len as usize)?, true) {
                            info.acquisition = parse_header(&t, true);
                            have_header2 = true;
                        }
                    }
                    "header" if !have_header2 && info.acquisition.is_empty() => {
                        if let Ok(t) = inflate_text(&read_at(&mut f, data_off, data_len as usize)?, false) {
                            info.acquisition = parse_header(&t, false);
                        }
                    }
                    "volume" | "disk" if geometry.is_none() => {
                        let v = read_at(&mut f, data_off, data_len.min(1052) as usize)?;
                        if v.len() < 24 {
                            bail!("{}: volume section too short", path.display());
                        }
                        let chunk_count = le32(&v[4..]) as u64;
                        let spc = le32(&v[8..]);
                        let bps = le32(&v[12..]);
                        let sectors_n = if v.len() >= 1052 { le64(&v[16..]) } else { le32(&v[16..]) as u64 };
                        if v.len() >= 1052 {
                            info.media_type = match v[0] {
                                0x00 => "removable".into(),
                                0x01 => "fixed".into(),
                                0x03 => "optical".into(),
                                0x0e => "logical".into(),
                                0x10 => "memory".into(),
                                x => format!("0x{:02x}", x),
                            };
                            info.set_identifier = guid(&v[64..80]);
                        }
                        if spc == 0 || bps == 0 || (spc as u64) * (bps as u64) > MAX_CHUNK as u64 {
                            bail!("{}: implausible geometry ({} sectors per chunk, {} bytes per sector)", path.display(), spc, bps);
                        }
                        geometry = Some((chunk_count, spc, bps, sectors_n));
                    }
                    "sectors" => sectors = Some((data_off, off + size)),
                    "table" | "table2" => {
                        if kind == "table2" && !table_failed {
                            off = next_or_break(off, next, &path)?;
                            continue;
                        }
                        let t = read_at(&mut f, data_off, data_len as usize)?;
                        let start = chunks.len();
                        match parse_table(&t, seg_idx, sectors, off, &mut chunks) {
                            Ok(_) => table_failed = false,
                            Err(_) if kind == "table" => {
                                chunks.truncate(start);
                                table_failed = true;
                            }
                            Err(e) => return Err(e.context(format!("{}: table and table2 both unreadable", path.display()))),
                        }
                        if kind == "table2" && table_failed {
                            bail!("{}: chunk table unreadable", path.display());
                        }
                    }
                    "error2" => {
                        let e = read_at(&mut f, data_off, data_len as usize)?;
                        if e.len() >= 520 {
                            let n = le32(&e) as usize;
                            for i in 0..n {
                                let p = 520 + i * 8;
                                if p + 8 > e.len() {
                                    break;
                                }
                                info.read_errors.push((le32(&e[p..]) as u64, le32(&e[p + 4..]) as u64));
                            }
                        }
                    }
                    "hash" => {
                        let h = read_at(&mut f, data_off, 16)?;
                        info.md5.get_or_insert_with(|| hexs(&h));
                    }
                    "digest" => {
                        let h = read_at(&mut f, data_off, 36)?;
                        info.md5 = Some(hexs(&h[..16]));
                        info.sha1 = Some(hexs(&h[16..36]));
                    }
                    "done" => {
                        done = true;
                        break;
                    }
                    "next" => break,
                    _ => {}
                }
                off = match next_or_break(off, next, &path)? {
                    n if n == off => break,
                    n => n,
                };
            }
            if done {
                break;
            }
        }

        let (chunk_count, spc, bps, sectors_n) = geometry.context("no volume section found")?;
        let chunk_size = spc.checked_mul(bps).filter(|&c| c > 0).context("chunk size out of range")?;
        if chunks.len() as u64 != chunk_count {
            bail!("chunk tables list {} chunks but the volume section says {}", chunks.len(), chunk_count);
        }
        let media_size = sectors_n.checked_mul(bps as u64).context("media size out of range")?;
        if chunk_count.checked_mul(chunk_size as u64).is_none_or(|cap| media_size > cap) {
            bail!("media size {} exceeds what {} chunks can hold", media_size, chunk_count);
        }
        info.segments = paths.iter().map(|p| p.display().to_string()).collect();
        info.media_size = media_size;
        info.bytes_per_sector = bps;
        info.sectors_per_chunk = spc;
        info.chunk_count = chunk_count;
        info.compressed_chunks = chunks.iter().filter(|c| c.compressed).count() as u64;
        Ok(EwfImage { paths, chunks, chunk_size, info })
    }

    pub fn size(&self) -> u64 {
        self.info.media_size
    }

    pub fn reader(self: &Arc<Self>) -> EwfReader {
        EwfReader { img: self.clone(), pos: 0, files: vec![], cache: vec![] }
    }
}

fn next_or_break(off: u64, next: u64, path: &Path) -> anyhow::Result<u64> {
    if next != off && next < off + DESCRIPTOR {
        bail!("{}: section chain goes backwards at offset {}", path.display(), off);
    }
    Ok(next)
}

/// Appends the table's chunks. Returns how many were added.
fn parse_table(t: &[u8], seg: u32, sectors: Option<(u64, u64)>, table_off: u64, out: &mut Vec<Chunk>) -> anyhow::Result<usize> {
    if t.len() < 24 {
        bail!("table too short");
    }
    if adler32(&t[..20]) != le32(&t[20..]) {
        bail!("table header checksum mismatch");
    }
    let n = le32(t) as usize;
    let base = le64(&t[8..]);
    if t.len() < 24 + n * 4 {
        bail!("table holds fewer entries than it declares");
    }
    let raw = &t[24..24 + n * 4];
    if t.len() >= 24 + n * 4 + 4 && adler32(raw) != le32(&t[24 + n * 4..]) {
        bail!("table entries checksum mismatch");
    }
    // Chunk data ends where the sectors section ends (or, for very old files
    // without one, where this table section starts).
    let data_end = sectors.map(|s| s.1).unwrap_or(table_off);
    let mut offs: Vec<(u64, bool)> = Vec::with_capacity(n);
    let mut overflow = false;
    for i in 0..n {
        let e = le32(&raw[i * 4..]);
        let mut o = (e & 0x7fff_ffff) as u64;
        let mut comp = e & 0x8000_0000 != 0;
        // EnCase without a base offset sets bit 31 on uncompressed chunks past
        // 2 GiB. Once offsets would go backwards, treat bit 31 as an offset bit.
        if let Some(&(prev, _)) = offs.last() {
            if !overflow && comp && base + o < prev && base + (e as u64) > prev {
                overflow = true;
            }
        }
        if overflow {
            o = e as u64;
            comp = false;
        }
        offs.push((base + o, comp));
    }
    for i in 0..n {
        let (o, comp) = offs[i];
        let end = if i + 1 < n { offs[i + 1].0 } else { data_end };
        if end <= o || end - o > (MAX_CHUNK as u64) + 4 {
            bail!("chunk {} has an implausible size", out.len());
        }
        out.push(Chunk { seg, offset: o, stored: (end - o) as u32, compressed: comp, pattern: None });
    }
    Ok(n)
}

/// Lowercased keys mapped to readable names; unknown keys are kept as-is.
fn parse_header(t: &str, v2: bool) -> BTreeMap<String, String> {
    let lines: Vec<&str> = t.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut out = BTreeMap::new();
    let Some(ki) = lines.iter().position(|l| l.split('\t').any(|k| k == "c") && l.contains('\t')) else { return out };
    let keys: Vec<&str> = lines[ki].split('\t').collect();
    let vals: Vec<&str> = lines.get(ki + 1).map(|l| l.split('\t').collect()).unwrap_or_default();
    for (k, v) in keys.iter().zip(vals.iter()) {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let name = match *k {
            "c" => "case_number",
            "n" => "evidence_number",
            "a" => "description",
            "e" => "examiner",
            "t" => "notes",
            "md" => "model",
            "sn" => "serial_number",
            "l" => "device_label",
            "av" => "acquisition_software",
            "ov" => "acquisition_os",
            "m" => "acquired",
            "u" => "system_date",
            "p" => continue,
            "pid" => "process_id",
            "dc" => "unknown_dc",
            "ext" => "extents",
            "r" => "compression",
            other => other,
        };
        let v = match *k {
            "m" | "u" => header_date(v, v2),
            "r" => match v {
                "n" => "none".into(),
                "f" => "fast".into(),
                "b" => "best".into(),
                other => other.to_string(),
            },
            _ => v.to_string(),
        };
        out.insert(name.to_string(), v);
    }
    out
}

/// header2 stores Unix seconds; header stores "YYYY MM DD hh mm ss" local time.
fn header_date(v: &str, v2: bool) -> String {
    if v2 {
        if let Ok(secs) = v.parse::<i64>() {
            let days = secs.div_euclid(86400);
            let rem = secs.rem_euclid(86400);
            let (y, m, d) = civil(days);
            return format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60);
        }
    }
    let p: Vec<&str> = v.split_whitespace().collect();
    if p.len() == 6 {
        return format!("{}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2} (local time of acquiring machine)", p[0], p[1], p[2], p[3], p[4], p[5]);
    }
    v.to_string()
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn inflate_text(data: &[u8], utf16: bool) -> anyhow::Result<String> {
    let mut out = vec![];
    flate2::read::ZlibDecoder::new(data).take(16 << 20).read_to_end(&mut out)?;
    if utf16 {
        let mut u: Vec<u16> = out.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        if u.first() == Some(&0xfeff) {
            u.remove(0);
        }
        Ok(String::from_utf16_lossy(&u))
    } else {
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

/// `.E01` .. `.E99`, then `.EAA` .. `.EZZ`, `.FAA` .. `.ZZZ`, keeping the case of the first segment.
pub fn segment_path(first: &Path, n: u32) -> Option<PathBuf> {
    let ext = first.extension()?.to_str()?;
    let lead = ext.chars().next()?;
    let lower = lead.is_ascii_lowercase();
    let ext = if n <= 99 {
        format!("{}{:02}", lead, n)
    } else {
        let k = n - 100;
        let first_c = (lead.to_ascii_uppercase() as u8).checked_add((k / 676) as u8)?;
        if first_c > b'Z' {
            return None;
        }
        let s = format!("{}{}{}", first_c as char, (b'A' + (k / 26 % 26) as u8) as char, (b'A' + (k % 26) as u8) as char);
        if lower { s.to_ascii_lowercase() } else { s }
    };
    Some(first.with_extension(ext))
}

/// The `.Ex01` segment names: `.Ex01` .. `.Ex99`, then `.ExAA` .. `.ExZZ`,
/// `.EyAA` .. `.EzZZ`, keeping the case of the first segment.
pub fn segment_path_v2(first: &Path, n: u32) -> Option<PathBuf> {
    let ext = first.extension()?.to_str()?;
    let mut c = ext.chars();
    let (lead, second) = (c.next()?, c.next()?);
    let lower = second.is_ascii_lowercase();
    let ext = if n <= 99 {
        format!("{}{}{:02}", lead, second, n)
    } else {
        let k = n - 100;
        let s2 = (second.to_ascii_lowercase() as u8).checked_add((k / 676) as u8)?;
        if s2 > b'z' {
            return None;
        }
        let tail = format!("{}{}", (b'A' + (k / 26 % 26) as u8) as char, (b'A' + (k % 26) as u8) as char);
        format!("{}{}{}", lead, s2 as char, if lower { tail } else { tail.to_ascii_uppercase() })
    };
    Some(first.with_extension(ext))
}

/// An EWF2 serialized object ("1", "main", tags, values): tag to value.
fn ewf2_object(t: &str) -> BTreeMap<String, String> {
    let lines: Vec<&str> = t.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut out = BTreeMap::new();
    let Some(mi) = lines.iter().position(|l| *l == "main") else { return out };
    let keys: Vec<&str> = lines.get(mi + 1).map(|l| l.split('\t').collect()).unwrap_or_default();
    let vals: Vec<&str> = lines.get(mi + 2).map(|l| l.split('\t').collect()).unwrap_or_default();
    for (k, v) in keys.iter().zip(vals.iter()) {
        let v = v.trim().replace(['\u{1}', '\u{2}', '\u{3}'], " ");
        if !v.is_empty() {
            out.insert(k.to_string(), v);
        }
    }
    out
}

impl EwfImage {
    /// EWF version 2 (EnCase 7 and later `.Ex01`): every segment's sections
    /// read back to front from the descriptor at its end; device information
    /// and case data as serialized objects; 16-byte chunk table entries
    /// (offset or fill pattern, size, flags); MD5 and SHA-1 sections; the
    /// error table. Encrypted images are refused; bzip2 chunks are reported.
    fn open_v2(first: &Path) -> anyhow::Result<EwfImage> {
        let mut paths = vec![];
        let mut chunks: Vec<Chunk> = vec![];
        let mut info = EwfInfo::default();
        let mut device: Option<BTreeMap<String, String>> = None;
        let mut case: Option<BTreeMap<String, String>> = None;
        let mut set_id: Option<[u8; 16]> = None;
        let mut bzip2 = false;
        let mut done = false;
        // Named .Ex01, .Ex02 ... as EnCase does; an image named .E01 by
        // mistake continues as .E02 ...
        let v2_names = first.extension().is_some_and(|e| e.len() == 4);
        for seg_no in 1u32.. {
            let path = match seg_no {
                1 => Some(first.to_path_buf()),
                n if v2_names => segment_path_v2(first, n),
                n => segment_path(first, n),
            }
            .with_context(|| format!("too many segments after {}", first.display()))?;
            if !path.exists() {
                if seg_no == 1 {
                    bail!("{} not found", path.display());
                }
                bail!("segment {} of the image is missing: expected {}", seg_no, path.display());
            }
            let mut f = File::open(&path).with_context(|| format!("cannot open {}", path.display()))?;
            let flen = f.metadata()?.len();
            let mut fh = [0u8; 32];
            f.read_exact(&mut fh).with_context(|| format!("{}: truncated file header", path.display()))?;
            if &fh[..8] != SIGNATURE_V2 {
                bail!("{}: not an Ex01 segment (bad signature)", path.display());
            }
            if fh[8] != 2 {
                bail!("{}: EWF version {}.{} is not supported", path.display(), fh[8], fh[9]);
            }
            let comp = u16::from_le_bytes([fh[10], fh[11]]);
            bzip2 |= comp == 2;
            let found = le32(&fh[12..]);
            if found != seg_no {
                bail!("{}: holds segment {} where segment {} was expected", path.display(), found, seg_no);
            }
            let id: [u8; 16] = fh[16..32].try_into().unwrap();
            match set_id {
                None => set_id = Some(id),
                Some(s) if s != id => bail!("{}: belongs to another image (set identifier differs)", path.display()),
                _ => {}
            }
            let seg_idx = paths.len() as u32;
            paths.push(path.clone());
            // The descriptors, last to first.
            let mut secs: Vec<(u32, u64, u64)> = vec![];
            let mut off = flen.checked_sub(64).filter(|&o| o >= 32).with_context(|| format!("{}: too short", path.display()))?;
            loop {
                let d = read_at(&mut f, off, 64)?;
                if adler32(&d[..60]) != le32(&d[60..]) {
                    bail!("{}: section descriptor checksum mismatch at offset {}", path.display(), off);
                }
                let (kind, flags, prev, size) = (le32(&d), le32(&d[4..]), le64(&d[8..]), le64(&d[16..]));
                if flags & 2 != 0 {
                    bail!("this Ex01 image is encrypted; encrypted Ex01 images are not supported yet");
                }
                if size > off {
                    bail!("{}: section at offset {} is larger than what comes before it", path.display(), off);
                }
                secs.push((kind, off - size, size));
                if prev == 0 {
                    break;
                }
                if prev >= off || prev < 32 || secs.len() > 1 << 20 {
                    bail!("{}: section chain goes forward or loops at offset {}", path.display(), off);
                }
                off = prev;
            }
            secs.reverse();
            for (kind, data_off, size) in secs {
                let text = |f: &mut File| -> Option<BTreeMap<String, String>> {
                    let raw = read_at(f, data_off, size.min(16 << 20) as usize).ok()?;
                    let t = match comp {
                        0 => {
                            let u: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                            String::from_utf16_lossy(u.strip_prefix(&[0xfeff]).unwrap_or(&u))
                        }
                        _ => inflate_text(&raw, true).ok()?,
                    };
                    Some(ewf2_object(&t))
                };
                match kind {
                    1 if device.is_none() => device = text(&mut f),
                    2 if case.is_none() => case = text(&mut f),
                    4 => {
                        let t = read_at(&mut f, data_off, size.min(64 << 20) as usize)?;
                        if t.len() < 20 || adler32(&t[..16]) != le32(&t[16..]) {
                            bail!("{}: chunk table header checksum mismatch", path.display());
                        }
                        let (first_chunk, n) = (le64(&t), le32(&t[8..]) as usize);
                        if first_chunk != chunks.len() as u64 {
                            bail!("{}: chunk table starts at chunk {} where {} was expected", path.display(), first_chunk, chunks.len());
                        }
                        let entries = t.get(32..32 + n * 16).with_context(|| format!("{}: chunk table holds fewer entries than it declares", path.display()))?;
                        if let Some(sum) = t.get(32 + n * 16..36 + n * 16) {
                            if adler32(entries) != le32(sum) {
                                bail!("{}: chunk table entries checksum mismatch", path.display());
                            }
                        }
                        for e in entries.chunks_exact(16) {
                            let (o, stored, flags) = (le64(e), le32(&e[8..]), le32(&e[12..]));
                            let compressed = flags & 1 != 0;
                            let pattern = (compressed && flags & 4 != 0).then_some(o);
                            if pattern.is_none() && (stored == 0 || stored > MAX_CHUNK + 4 || o.checked_add(stored as u64).is_none_or(|x| x > flen)) {
                                bail!("{}: chunk {} has an implausible place or size", path.display(), chunks.len());
                            }
                            chunks.push(Chunk { seg: seg_idx, offset: o, stored, compressed, pattern });
                        }
                    }
                    5 => {
                        let e = read_at(&mut f, data_off, size.min(64 << 20) as usize)?;
                        let n = le32(&e) as usize;
                        for i in 0..n.min(1 << 20) {
                            let Some(x) = e.get(32 + i * 16..48 + i * 16) else { break };
                            info.read_errors.push((le64(x), le32(&x[8..]) as u64));
                        }
                    }
                    8 => info.md5 = Some(hexs(&read_at(&mut f, data_off, 16)?)),
                    9 => info.sha1 = Some(hexs(&read_at(&mut f, data_off, 20)?)),
                    0xf => done = true,
                    _ => {}
                }
            }
            if done {
                break;
            }
        }
        let device = device.context("no device information section found")?;
        let case = case.unwrap_or_default();
        let num = |m: &BTreeMap<String, String>, k: &str| m.get(k).and_then(|v| v.parse::<u64>().ok());
        let bps = num(&device, "bp").unwrap_or(512) as u32;
        let spc = num(&case, "sb").unwrap_or(64) as u32;
        let sectors_n = num(&device, "ts").context("the device information has no sector count")?;
        if spc == 0 || bps == 0 || (spc as u64) * (bps as u64) > MAX_CHUNK as u64 {
            bail!("implausible geometry ({} sectors per chunk, {} bytes per sector)", spc, bps);
        }
        let chunk_size = spc * bps;
        let media_size = sectors_n.checked_mul(bps as u64).context("media size out of range")?;
        let chunk_count = chunks.len() as u64;
        if let Some(tb) = num(&case, "tb") {
            if tb != chunk_count {
                bail!("chunk tables list {} chunks but the case data says {}", chunk_count, tb);
            }
        }
        if chunk_count.checked_mul(chunk_size as u64).is_none_or(|cap| media_size > cap) {
            bail!("media size {} exceeds what {} chunks can hold", media_size, chunk_count);
        }
        if bzip2 && chunks.iter().any(|c| c.compressed && c.pattern.is_none()) {
            bail!("this Ex01 image is compressed with bzip2, which Kokino does not read yet");
        }
        info.media_type = match device.get("dt").map(|s| s.as_str()) {
            Some("f") => "fixed".into(),
            Some("r") => "removable".into(),
            Some("c") => "optical".into(),
            Some("l") => "logical".into(),
            Some("m") => "memory".into(),
            Some(x) => x.to_string(),
            None => String::new(),
        };
        if let Some(id) = set_id {
            info.set_identifier = guid(&id);
        }
        for (k, name) in [("sn", "serial_number"), ("md", "model"), ("lb", "device_label")] {
            if let Some(v) = device.get(k) {
                info.acquisition.insert(name.into(), v.clone());
            }
        }
        for (k, name) in [("nm", "description"), ("cn", "case_number"), ("en", "evidence_number"), ("ex", "examiner"), ("nt", "notes"), ("av", "acquisition_software"), ("os", "acquisition_os"), ("tt", "acquired"), ("at", "system_date")] {
            if let Some(v) = case.get(k) {
                let v = if k == "tt" || k == "at" { header_date(v, true) } else { v.clone() };
                info.acquisition.insert(name.into(), v);
            }
        }
        if let Some(w) = case.get("wb") {
            info.acquisition.insert("write_blocker".into(), match w.as_str() { "1" => "FastBloc".into(), "2" => "Tableau".into(), x => x.to_string() });
        }
        info.acquisition.insert("format".into(), "EWF2 (Ex01)".into());
        info.segments = paths.iter().map(|p| p.display().to_string()).collect();
        info.media_size = media_size;
        info.bytes_per_sector = bps;
        info.sectors_per_chunk = spc;
        info.chunk_count = chunk_count;
        info.compressed_chunks = chunks.iter().filter(|c| c.compressed).count() as u64;
        Ok(EwfImage { paths, chunks, chunk_size, info })
    }
}

/// Logical media stream of an EWF image. Keeps a few decompressed chunks.
pub struct EwfReader {
    img: Arc<EwfImage>,
    pos: u64,
    files: Vec<Option<File>>,
    cache: Vec<(u64, Arc<Vec<u8>>)>,
}

impl EwfReader {
    fn chunk(&mut self, idx: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Some(i) = self.cache.iter().position(|(k, _)| *k == idx) {
            let hit = self.cache.remove(i);
            self.cache.push(hit.clone());
            return Ok(hit.1);
        }
        let c = self.img.chunks[idx as usize];
        if let Some(p) = c.pattern {
            let size = self.img.chunk_size as usize;
            let data: Vec<u8> = p.to_le_bytes().iter().copied().cycle().take(size).collect();
            return Ok(Arc::new(data));
        }
        if self.files.len() < self.img.paths.len() {
            self.files.resize_with(self.img.paths.len(), || None);
        }
        let slot = &mut self.files[c.seg as usize];
        if slot.is_none() {
            *slot = Some(File::open(&self.img.paths[c.seg as usize])?);
        }
        let f = slot.as_mut().unwrap();
        let mut raw = vec![0u8; c.stored as usize];
        f.seek(SeekFrom::Start(c.offset))?;
        f.read_exact(&mut raw)?;
        let size = self.img.chunk_size as usize;
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("EWF chunk {} (segment {}, offset {}): {}", idx, c.seg + 1, c.offset, what));
        let data = if c.compressed {
            let mut out = Vec::with_capacity(size);
            flate2::read::ZlibDecoder::new(&raw[..]).take(size as u64 + 1).read_to_end(&mut out).map_err(|e| bad(&format!("zlib error: {}", e)))?;
            if out.len() > size {
                return Err(bad("decompresses to more than the chunk size"));
            }
            out
        } else {
            if raw.len() < 4 {
                return Err(bad("too short"));
            }
            // The stored size normally includes a 4-byte Adler-32. Some writers
            // omit it for the last chunk, which then ends at the section end.
            let with_sum = raw.len() - 4;
            if adler32(&raw[..with_sum]) == le32(&raw[with_sum..]) {
                raw.truncate(with_sum);
            } else if raw.len() > size {
                return Err(bad("checksum mismatch"));
            }
            raw.truncate(size);
            raw
        };
        let data = Arc::new(data);
        if self.cache.len() >= 8 {
            self.cache.remove(0);
        }
        self.cache.push((idx, data.clone()));
        Ok(data)
    }
}

impl Read for EwfReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.img.size();
        if self.pos >= size || buf.is_empty() {
            return Ok(0);
        }
        let cs = self.img.chunk_size as u64;
        let idx = self.pos / cs;
        let within = (self.pos % cs) as usize;
        let data = self.chunk(idx)?;
        if within >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("EWF chunk {} is shorter than expected", idx)));
        }
        let n = (data.len() - within).min(buf.len()).min((size - self.pos) as usize);
        buf[..n].copy_from_slice(&data[within..within + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for EwfReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.img.size() as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

fn read_at(f: &mut File, off: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0u8; len];
    f.seek(SeekFrom::Start(off))?;
    f.read_exact(&mut b)?;
    Ok(b)
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn guid(b: &[u8]) -> String {
    if b.iter().all(|&x| x == 0) {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u16::from_le_bytes(b[4..6].try_into().unwrap()),
        u16::from_le_bytes(b[6..8].try_into().unwrap()),
        hexs(&b[8..10]),
        hexs(&b[10..16])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler_known_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn segment_names() {
        let p = Path::new("img.E01");
        assert_eq!(segment_path(p, 2).unwrap(), Path::new("img.E02"));
        assert_eq!(segment_path(p, 99).unwrap(), Path::new("img.E99"));
        assert_eq!(segment_path(p, 100).unwrap(), Path::new("img.EAA"));
        assert_eq!(segment_path(p, 101).unwrap(), Path::new("img.EAB"));
        assert_eq!(segment_path(p, 776).unwrap(), Path::new("img.FAA"));
        assert_eq!(segment_path(Path::new("x.e01"), 100).unwrap(), Path::new("x.eaa"));
    }

    #[test]
    fn header2_dates_and_keys() {
        let t = "3\nmain\na\tc\tn\te\tt\tav\tov\tm\tu\tp\nDisk\t2026-041\t1\tJ. Doe\tseized\t20.0\tWin\t1700000000\t1700000100\t0\n\n";
        let m = parse_header(t, true);
        assert_eq!(m["case_number"], "2026-041");
        assert_eq!(m["examiner"], "J. Doe");
        assert_eq!(m["acquired"], "2023-11-14T22:13:20Z");
        assert!(!m.contains_key("p"));
    }

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
    }

    fn sha256_of(r: &mut impl Read) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 50_000];
        loop {
            let n = r.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        hexs(&h.finalize())
    }

    /// Fixtures from scripts/make_e01_fixture.py: the media stream must be
    /// byte-identical to the raw image it was made from.
    #[test]
    fn e01_fixtures_match_raw() {
        let raw = std::fs::read(fixture("disk-af.img")).unwrap();
        let want = sha256_of(&mut &raw[..]);
        for name in ["disk-af.E01", "disk-af-split.E01"] {
            let img = Arc::new(EwfImage::open(&fixture(name)).unwrap());
            assert_eq!(img.size(), raw.len() as u64, "{name}");
            assert_eq!(sha256_of(&mut img.reader()), want, "{name}");
            {
                use md5::Digest;
                assert_eq!(img.info.md5.as_deref(), Some(hexs(&md5::Md5::digest(&raw)).as_str()), "{name}");
                assert_eq!(img.info.sha1.as_deref(), Some(hexs(&sha1::Sha1::digest(&raw)).as_str()), "{name}");
            }
            assert!(img.info.compressed_chunks > 0 && img.info.compressed_chunks < img.info.chunk_count, "{name}: mixed chunks");
            assert_eq!(img.info.acquisition["case_number"], "LAB-001");
            assert_eq!(img.info.acquisition["serial_number"], "SN-0000-TEST");
            assert_eq!(img.info.acquisition["acquired"], "2026-10-26T09:30:00Z");
            assert_eq!(img.info.media_type, "fixed");
        }
        let split = EwfImage::open(&fixture("disk-af-split.E01")).unwrap();
        assert_eq!(split.info.segments.len(), 3);

        // Random access across chunk and segment boundaries.
        let img = Arc::new(EwfImage::open(&fixture("disk-af-split.E01")).unwrap());
        let mut r = img.reader();
        for &off in &[0u64, 32767, 32768, 60 * 32768 - 3, 120 * 32768 + 5, raw.len() as u64 - 10] {
            let mut b = [0u8; 10];
            r.seek(SeekFrom::Start(off)).unwrap();
            r.read_exact(&mut b).unwrap();
            assert_eq!(&b[..], &raw[off as usize..off as usize + 10], "offset {off}");
        }
    }

    /// Ex01 written by an independent tool (ewf-image's ewf-cli, which
    /// checks its output against libewf) from the lab disks: four segments
    /// of zlib chunks, and one uncompressed set with pattern-filled chunks.
    #[test]
    fn ex01_fixtures_match_raw() {
        for (img, raw, segs, case) in [("disk-win-ex.Ex01", "disk-win.img", 4, Some(("LAB-2026-014", "alice"))), ("disk-fat-raw.Ex01", "disk-fat.img", 1, None)] {
            let raw = std::fs::read(fixture(raw)).unwrap();
            let e = Arc::new(EwfImage::open(&fixture(img)).unwrap());
            assert_eq!(e.size(), raw.len() as u64, "{img}");
            assert_eq!(sha256_of(&mut e.reader()), sha256_of(&mut &raw[..]), "{img}");
            assert_eq!(e.info.segments.len(), segs, "{img}");
            {
                use md5::Digest;
                assert_eq!(e.info.md5.as_deref(), Some(hexs(&md5::Md5::digest(&raw)).as_str()), "{img}");
            }
            assert_eq!(e.info.acquisition["format"], "EWF2 (Ex01)");
            if let Some((cn, ex)) = case {
                assert_eq!((e.info.acquisition["case_number"].as_str(), e.info.acquisition["examiner"].as_str()), (cn, ex));
            }
            // Random access across chunks and segments.
            let mut r = e.reader();
            for &off in &[0u64, 32_767, 40 * 32_768 - 3, 81 * 32_768 + 5, raw.len() as u64 - 10] {
                let mut b = [0u8; 10];
                r.seek(SeekFrom::Start(off)).unwrap();
                r.read_exact(&mut b).unwrap();
                assert_eq!(&b[..], &raw[off as usize..off as usize + 10], "{img} at {off}");
            }
        }
        let fat = EwfImage::open(&fixture("disk-fat-raw.Ex01")).unwrap();
        assert!(fat.chunks.iter().any(|c| c.pattern.is_some()), "pattern-filled chunks read");
        assert_eq!(segment_path_v2(Path::new("a.Ex01"), 100).unwrap(), Path::new("a.ExAA"));
        assert_eq!(segment_path_v2(Path::new("a.ex01"), 2).unwrap(), Path::new("a.ex02"));
        // A changed byte in a section descriptor is caught.
        let d = std::env::temp_dir().join(format!("kokino-ex01-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let mut b = std::fs::read(fixture("disk-fat-raw.Ex01")).unwrap();
        let n = b.len();
        b[n - 70] ^= 1;
        std::fs::write(d.join("bad.Ex01"), &b).unwrap();
        assert!(EwfImage::open(&d.join("bad.Ex01")).is_err());
        // A missing segment is named.
        for i in [1, 2, 4] {
            std::fs::copy(fixture(&format!("disk-win-ex.Ex0{i}")), d.join(format!("w.Ex0{i}"))).unwrap();
        }
        let err = EwfImage::open(&d.join("w.Ex01")).unwrap_err().to_string();
        assert!(err.contains("segment 3"), "{err}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn partial_last_chunk_header_v1_and_errors() {
        let raw = std::fs::read(fixture("disk-af.img")).unwrap();
        let img = Arc::new(EwfImage::open(&fixture("disk-af-odd.E01")).unwrap());
        assert_eq!(img.size(), 1954 * 512);
        assert_eq!(sha256_of(&mut img.reader()), sha256_of(&mut &raw[..1954 * 512]));
        assert_eq!(img.info.read_errors, vec![(100, 8), (1900, 2)]);
        assert_eq!(img.info.acquisition["examiner"], "Lab Examiner");
        assert!(img.info.acquisition["acquired"].starts_with("2026-10-26 09:30:00"));
    }

    fn tampered(name: &str, f: impl Fn(&mut Vec<u8>)) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kokino-ewf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut b = std::fs::read(fixture(name)).unwrap();
        f(&mut b);
        let p = dir.join(format!("t{}.E01", b.len() ^ (b[b.len() / 2] as usize) << 3 ^ name.len()));
        std::fs::write(&p, b).unwrap();
        p
    }

    /// Corruption anywhere must surface as an error naming the chunk or
    /// section, never as silently wrong bytes.
    #[test]
    fn corruption_is_reported() {
        let good = EwfImage::open(&fixture("disk-af.E01")).unwrap();
        let comp = good.chunks.iter().position(|c| c.compressed).unwrap();
        let plain = good.chunks.iter().position(|c| !c.compressed).unwrap();
        let cs = good.chunk_size as u64;

        for (idx, label) in [(comp, "zlib"), (plain, "checksum")] {
            let c = good.chunks[idx];
            let p = tampered("disk-af.E01", |b| b[c.offset as usize + c.stored as usize / 2] ^= 0x5a);
            let img = Arc::new(EwfImage::open(&p).unwrap());
            let mut r = img.reader();
            r.seek(SeekFrom::Start(idx as u64 * cs)).unwrap();
            let err = r.read(&mut [0u8; 16]).unwrap_err().to_string();
            assert!(err.contains(&format!("chunk {}", idx)) && err.contains(label), "{label}: {err}");
            std::fs::remove_file(p).ok();
        }

        // A flipped bit in a section descriptor (the "volume" type name).
        let p = tampered("disk-af.E01", |b| {
            let i = b.windows(6).position(|w| w == b"volume").unwrap();
            b[i + 1] ^= 1;
        });
        assert!(EwfImage::open(&p).unwrap_err().to_string().contains("descriptor checksum"));
        std::fs::remove_file(p).ok();

        // A missing middle segment.
        let dir = std::env::temp_dir().join(format!("kokino-ewf-seg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for e in ["E01", "E03"] {
            std::fs::copy(fixture(&format!("disk-af-split.{e}")), dir.join(format!("x.{e}"))).unwrap();
        }
        let err = EwfImage::open(&dir.join("x.E01")).unwrap_err().to_string();
        assert!(err.contains("segment 2") && err.contains("missing"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
