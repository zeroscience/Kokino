//! One interface over the file systems Kokino parses: NTFS, FAT12/16/32,
//! exFAT, ext2/3/4, ISO 9660, UDF, HFS+ and APFS. Callers hold a volume reader (see `volume_reader`) and an `Fs`
//! opened on it, and read files by their `FsEntry`.

use kokino_image::{FsKind, Volume};
use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, UnreadableRecord};
use std::io::{Read, Seek};

pub enum Fs {
    Ntfs(kokino_ntfs::Ntfs),
    Fat(kokino_fat::FatVolume),
    Ext(kokino_ext::ExtVolume),
    Iso(kokino_iso::IsoVolume),
    Udf(kokino_iso::udf::UdfVolume),
    Hfs(kokino_mac::hfs::HfsVolume),
    Apfs(kokino_mac::apfs::ApfsContainer),
    Zip(crate::zipfs::ZipVolume),
    Tar(crate::tarfs::TarVolume),
    Ad1(crate::ad1fs::Ad1Volume),
    Aff4L(crate::aff4lfs::Aff4LVolume),
}

/// What a file-system walk produced.
pub struct FsScan {
    pub info: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    pub unreadable: Vec<UnreadableRecord>,
    /// Plain-language notes about the walk for the volume summary.
    pub notes: Vec<String>,
}

/// File systems with a parser.
pub fn supported(k: FsKind) -> bool {
    matches!(k, FsKind::Ntfs | FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat | FsKind::Ext | FsKind::Iso9660 | FsKind::Udf | FsKind::HfsPlus | FsKind::Apfs | FsKind::Zip | FsKind::Tar | FsKind::Ad1 | FsKind::Aff4L)
}

impl Fs {
    pub fn open<R: Read + Seek>(r: &mut R, v: &Volume) -> anyhow::Result<Fs> {
        match v.fs {
            FsKind::Ntfs => Ok(Fs::Ntfs(kokino_ntfs::open_ntfs(r)?)),
            FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat => Ok(Fs::Fat(kokino_fat::open(r, v.length)?)),
            FsKind::Ext => Ok(Fs::Ext(kokino_ext::open(r, v.length)?)),
            FsKind::Iso9660 => {
                // A bridge disc also carries UDF, which keeps full names,
                // owners, permissions, creation times and deleted entries.
                // ISO 9660 wins only when it holds history UDF lacks: older
                // sessions.
                let iso = kokino_iso::open(r, v.length)?;
                if iso.sessions.len() == 1 {
                    if let Ok(u) = kokino_iso::udf::open(r, v.length) {
                        return Ok(Fs::Udf(u));
                    }
                }
                Ok(Fs::Iso(iso))
            }
            FsKind::Udf => Ok(Fs::Udf(kokino_iso::udf::open(r, v.length)?)),
            FsKind::HfsPlus => Ok(Fs::Hfs(kokino_mac::hfs::open(r, v.length)?)),
            FsKind::Apfs => Ok(Fs::Apfs(kokino_mac::apfs::open(r, v.length)?)),
            FsKind::Zip => Ok(Fs::Zip(crate::zipfs::open(r, v.length)?)),
            FsKind::Tar => Ok(Fs::Tar(crate::tarfs::open(r, v.length)?)),
            FsKind::Ad1 => Ok(Fs::Ad1(crate::ad1fs::open(r, v.length)?)),
            FsKind::Aff4L => Ok(Fs::Aff4L(crate::aff4lfs::open(r, v.length)?)),
            _ => anyhow::bail!("no parser for {}", v.fs_label),
        }
    }

    pub fn is_mac(&self) -> bool {
        matches!(self, Fs::Hfs(_) | Fs::Apfs(_))
    }

    pub fn is_fat(&self) -> bool {
        matches!(self, Fs::Fat(_))
    }

    /// NTFS: metadata files ($MFT and the rest) sit in the first records.
    pub fn is_ntfs(&self) -> bool {
        matches!(self, Fs::Ntfs(_))
    }

    pub fn is_ext(&self) -> bool {
        matches!(self, Fs::Ext(_))
    }

    /// A triage collection or logical image read as a file system (ZIP,
    /// tar, AD1, AFF4-L).
    pub fn is_collection(&self) -> bool {
        matches!(self, Fs::Zip(_) | Fs::Tar(_) | Fs::Ad1(_) | Fs::Aff4L(_))
    }

    pub fn is_optical(&self) -> bool {
        matches!(self, Fs::Iso(_) | Fs::Udf(_))
    }

    /// Walks every entry; `progress(done, total)` may return false to cancel.
    pub fn scan<R: Read + Seek>(&self, r: &mut R, progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<FsScan> {
        match self {
            Fs::Ntfs(n) => {
                let s = kokino_ntfs::scan_with(n, r, progress)?;
                Ok(FsScan { info: s.volume, entries: s.entries, unreadable: s.unreadable, notes: vec![] })
            }
            Fs::Fat(v) => {
                let s = kokino_fat::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: vec![] })
            }
            Fs::Ext(v) => {
                let s = kokino_ext::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: s.notes })
            }
            Fs::Iso(v) => {
                let s = kokino_iso::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: s.notes })
            }
            Fs::Udf(v) => {
                let s = kokino_iso::udf::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: s.notes })
            }
            Fs::Hfs(v) => {
                let s = kokino_mac::hfs::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: s.notes })
            }
            Fs::Apfs(v) => {
                let s = kokino_mac::apfs::scan(v, r, progress)?;
                Ok(FsScan { info: s.info, entries: s.entries, unreadable: vec![], notes: s.notes })
            }
            Fs::Zip(z) => {
                let entries = z.entries();
                let mut notes = vec![format!("A ZIP file{}: files are read from it as stored; it has no deleted files or free space.", if z.layout.is_empty() { String::new() } else { format!(" ({} collection)", z.layout) })];
                if entries.iter().all(|e| e.si.is_none_or(|t| t.created == 0)) {
                    notes.push("The ZIP keeps only a modified time per file, in the collecting computer's local time and to 2 seconds, unless it has extended time fields.".into());
                }
                Ok(FsScan { info: z.info(), entries, unreadable: vec![], notes })
            }
            Fs::Tar(t) => {
                let mut notes = vec![format!("A tar archive{}: files are read from it as stored; it has no deleted files or free space. Times are those the archive recorded (UTC).", if t.layout.is_empty() { String::new() } else { format!(" ({} collection)", t.layout) })];
                notes.extend(t.notes.iter().cloned());
                Ok(FsScan { info: t.info(), entries: t.entries(), unreadable: vec![], notes })
            }
            Fs::Ad1(a) => {
                let mut notes = vec![format!(
                    "An AccessData AD1 logical image (FTK Imager custom content image, version {}) of {}: files are read from it as FTK stored them; it has no free space. Times are those FTK recorded (UTC). FTK recorded MD5 and SHA-1 hashes for {} file(s).",
                    a.version,
                    if a.source.is_empty() { "an unnamed source".to_string() } else { a.source.clone() },
                    a.recorded.len()
                )];
                notes.extend(a.notes.iter().cloned());
                Ok(FsScan { info: a.info(), entries: a.entries(), unreadable: vec![], notes })
            }
            Fs::Aff4L(a) => {
                let mut notes = vec!["An AFF4-L logical image: files are read from the container as stored, with the names, times (UTC) and hashes it recorded; it has no free space.".to_string()];
                notes.extend(a.notes.iter().cloned());
                Ok(FsScan { info: a.info(), entries: a.entries(), unreadable: vec![], notes })
            }
        }
    }

    /// Up to `len` bytes of a stream from `offset` ("" is the main stream;
    /// FAT has no named streams).
    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        if let Some(n) = &e.name_only {
            anyhow::bail!("no content: this name was recovered from {}, not from an MFT record", n.source);
        }
        match self {
            Fs::Ntfs(n) => kokino_ntfs::read_stream_with(n, r, e.record, stream, offset, len),
            Fs::Fat(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Fat(v) => v.read(r, e, offset, len),
            Fs::Ext(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Ext(v) => v.read(r, e, offset, len),
            Fs::Iso(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Iso(v) => v.read(r, e, offset, len),
            Fs::Udf(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Udf(v) => v.read(r, e, offset, len),
            Fs::Hfs(v) if stream == "rsrc" => v.read_rsrc(r, e, offset, len),
            Fs::Hfs(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Hfs(v) => v.read(r, e, offset, len),
            Fs::Apfs(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Apfs(v) => v.read(r, e, offset, len),
            Fs::Zip(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Zip(z) => z.read(r, e, offset, len),
            Fs::Tar(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Tar(t) => t.read(r, e, offset, len),
            Fs::Ad1(_) | Fs::Aff4L(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Ad1(a) => a.read(r, e, offset, len),
            Fs::Aff4L(a) => a.read(r, e, offset, len),
        }
    }

    /// Where a stream's bytes live in the volume.
    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, stream: &str) -> anyhow::Result<Vec<Extent>> {
        if e.name_only.is_some() {
            return Ok(vec![]);
        }
        match self {
            Fs::Ntfs(n) => kokino_ntfs::stream_extents(n, r, e.record, stream),
            Fs::Fat(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Fat(v) => Ok(v.extents(e)),
            Fs::Ext(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Ext(v) => v.extents(r, e),
            Fs::Iso(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Iso(v) => Ok(v.extents(r, e)),
            Fs::Udf(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Udf(v) => Ok(v.extents(r, e)),
            Fs::Hfs(_) | Fs::Apfs(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Hfs(v) => Ok(v.extents(r, e)),
            Fs::Apfs(v) => Ok(v.extents(r, e)),
            Fs::Zip(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Zip(z) => Ok(z.extents(r, e)),
            Fs::Tar(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Tar(t) => Ok(t.extents(e)),
            Fs::Ad1(_) | Fs::Aff4L(_) if !stream.is_empty() => anyhow::bail!("no such stream"),
            Fs::Ad1(a) => Ok(a.extents(e)),
            Fs::Aff4L(a) => Ok(a.extents(r, e)),
        }
    }

    /// Unallocated clusters: (volume byte offset, length).
    pub fn free_runs<R: Read + Seek>(&self, r: &mut R) -> anyhow::Result<Vec<(u64, u64)>> {
        match self {
            Fs::Ntfs(n) => kokino_ntfs::free_runs(n, r),
            Fs::Fat(v) => Ok(v.free_runs()),
            Fs::Ext(v) => Ok(v.free_runs(r)),
            // A pressed or recorded disc has no free space to carve.
            Fs::Iso(_) | Fs::Udf(_) => Ok(vec![]),
            Fs::Hfs(v) => Ok(v.free_runs(r)),
            // APFS free space (space manager) is not read yet.
            Fs::Apfs(_) => Ok(vec![]),
            Fs::Zip(_) | Fs::Tar(_) | Fs::Ad1(_) | Fs::Aff4L(_) => Ok(vec![]),
        }
    }
}

/// Anything that reads bytes at an offset, as `Read + Seek`, with a 64 KiB
/// cache: lets parsers that seek (PST) read a file through its file system
/// without holding it in memory.
pub struct ReadAt<F: FnMut(u64, usize) -> std::io::Result<Vec<u8>>> {
    f: F,
    size: u64,
    pos: u64,
    cache: (u64, Vec<u8>),
}

const READ_AT_CHUNK: u64 = 64 * 1024;

impl<F: FnMut(u64, usize) -> std::io::Result<Vec<u8>>> ReadAt<F> {
    pub fn new(size: u64, f: F) -> Self {
        ReadAt { f, size, pos: 0, cache: (u64::MAX, vec![]) }
    }
}

impl<F: FnMut(u64, usize) -> std::io::Result<Vec<u8>>> Read for ReadAt<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let chunk = self.pos / READ_AT_CHUNK * READ_AT_CHUNK;
        if self.cache.0 != chunk {
            let n = READ_AT_CHUNK.min(self.size - chunk) as usize;
            self.cache = (chunk, (self.f)(chunk, n)?);
        }
        let w = (self.pos - chunk) as usize;
        let have = self.cache.1.len().saturating_sub(w);
        if have == 0 {
            return Ok(0);
        }
        let n = buf.len().min(have);
        buf[..n].copy_from_slice(&self.cache.1[w..w + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<F: FnMut(u64, usize) -> std::io::Result<Vec<u8>>> Seek for ReadAt<F> {
    fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
        self.pos = match p {
            std::io::SeekFrom::Start(x) => x,
            std::io::SeekFrom::End(x) => (self.size as i64).saturating_add(x).max(0) as u64,
            std::io::SeekFrom::Current(x) => (self.pos.min(i64::MAX as u64) as i64).saturating_add(x).max(0) as u64,
        };
        Ok(self.pos)
    }
}

/// A file's main stream as `Read + Seek`, read through its file system.
pub fn stream<'a, R: Read + Seek>(fs: &'a Fs, r: &'a mut R, e: &'a FsEntry) -> ReadAt<impl FnMut(u64, usize) -> std::io::Result<Vec<u8>> + 'a> {
    ReadAt::new(e.size, move |off, n| fs.read(r, e, "", off, n).map_err(|x| std::io::Error::other(format!("{:#}", x))))
}
