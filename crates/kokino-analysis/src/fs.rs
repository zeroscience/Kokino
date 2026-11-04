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
    matches!(k, FsKind::Ntfs | FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat | FsKind::Ext | FsKind::Iso9660 | FsKind::Udf | FsKind::HfsPlus | FsKind::Apfs)
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
            _ => anyhow::bail!("no parser for {}", v.fs_label),
        }
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
        }
    }

    /// Up to `len` bytes of a stream from `offset` ("" is the main stream;
    /// FAT has no named streams).
    pub fn read<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
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
        }
    }

    /// Where a stream's bytes live in the volume.
    pub fn extents<R: Read + Seek>(&self, r: &mut R, e: &FsEntry, stream: &str) -> anyhow::Result<Vec<Extent>> {
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
        }
    }
}
