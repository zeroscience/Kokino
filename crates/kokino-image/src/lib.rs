//! Read-only evidence sources and volume systems.
//!
//! Every file is opened with `File::open` (read-only). Nothing in this crate
//! can write to evidence.

#![forbid(unsafe_code)]

pub mod bde;
pub mod ewf;
pub mod source;
pub mod vdisk;
pub mod vss;
pub mod volume;

pub use ewf::EwfInfo;
pub use source::{Evidence, EvidenceReader, ImageFormat};
pub use volume::{detect_volumes, BitLockerRef, FsKind, ShadowRef, Volume, VolumeKind};

use std::io::{self, Read, Seek, SeekFrom};

/// A window `[start, start + len)` over another reader, so filesystem parsers
/// see offset 0 at the start of their volume.
pub struct SubReader<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> SubReader<R> {
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Self { inner, start, len, pos: 0 }
    }
}

impl<R: Read + Seek> Read for SubReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let max = ((self.len - self.pos) as usize).min(buf.len());
        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let n = self.inner.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SubReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Read-through cache of aligned 64 KiB blocks. Filesystem parsers issue many
/// small seeks and reads (MFT records, index nodes); this turns them into a
/// few large reads.
pub struct BlockCache<R> {
    inner: R,
    len: u64,
    pos: u64,
    blocks: Vec<(u64, Vec<u8>)>,
    clock: usize,
}

const BLOCK: u64 = 64 * 1024;
const BLOCKS: usize = 64;

impl<R: Read + Seek> BlockCache<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        let len = inner.seek(SeekFrom::End(0))?;
        Ok(Self { inner, len, pos: 0, blocks: Vec::with_capacity(BLOCKS), clock: 0 })
    }

    fn block(&mut self, index: u64) -> io::Result<&[u8]> {
        if let Some(i) = self.blocks.iter().position(|(b, _)| *b == index) {
            return Ok(&self.blocks[i].1);
        }
        let start = index * BLOCK;
        let want = BLOCK.min(self.len.saturating_sub(start)) as usize;
        let mut buf = vec![0u8; want];
        let got = read_at(&mut self.inner, start, &mut buf)?;
        buf.truncate(got);
        let slot = if self.blocks.len() < BLOCKS {
            self.blocks.push((index, buf));
            self.blocks.len() - 1
        } else {
            self.clock = (self.clock + 1) % BLOCKS;
            self.blocks[self.clock] = (index, buf);
            self.clock
        };
        Ok(&self.blocks[slot].1)
    }
}

impl<R: Read + Seek> Read for BlockCache<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        // Large reads bypass the cache.
        if buf.len() as u64 >= BLOCK {
            let n = read_at(&mut self.inner, self.pos, buf)?;
            self.pos += n as u64;
            return Ok(n);
        }
        let pos = self.pos;
        let within = (pos % BLOCK) as usize;
        let block = self.block(pos / BLOCK)?;
        if within >= block.len() {
            return Ok(0);
        }
        let n = (block.len() - within).min(buf.len());
        buf[..n].copy_from_slice(&block[within..within + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for BlockCache<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Reads up to `buf.len()` bytes at `offset`, tolerating short reads at EOF.
pub fn read_at<R: Read + Seek>(r: &mut R, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    r.seek(SeekFrom::Start(offset))?;
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(got)
}

/// A volume as the file systems read it: a slice of the evidence, or a
/// Volume Shadow Copy rebuilt from one.
pub enum VolReader {
    Plain(SubReader<EvidenceReader>),
    Shadow(Box<vss::ShadowReader<SubReader<EvidenceReader>>>),
    BitLocker(Box<bde::BdeReader<SubReader<EvidenceReader>>>),
}

impl Read for VolReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            VolReader::Plain(r) => r.read(buf),
            VolReader::Shadow(r) => r.read(buf),
            VolReader::BitLocker(r) => r.read(buf),
        }
    }
}

impl Seek for VolReader {
    fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            VolReader::Plain(r) => r.seek(p),
            VolReader::Shadow(r) => r.seek(p),
            VolReader::BitLocker(r) => r.seek(p),
        }
    }
}

/// The reader for a detected volume (a shadow copy is read through its snapshot).
pub fn volume_reader(ev: &Evidence, v: &Volume) -> std::io::Result<VolReader> {
    if v.bitlocker.is_some() {
        let mut sub = SubReader::new(ev.reader()?, v.start, v.length);
        let key = bitlocker_key(ev, v, &mut sub).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "BitLocker volume is locked"))?;
        return Ok(VolReader::BitLocker(Box::new(bde::BdeReader::new(sub, v.length, &key)?)));
    }
    match &v.shadow {
        None => Ok(VolReader::Plain(SubReader::new(ev.reader()?, v.start, v.length))),
        Some(s) => {
            // The base volume's full length: the stores live there.
            let base = SubReader::new(ev.reader()?, v.start, ev.size.saturating_sub(v.start));
            let base_len = ev.size.saturating_sub(v.start);
            Ok(VolReader::Shadow(Box::new(vss::ShadowReader::new(base, base_len, s.store)?)))
        }
    }
}

/// The key for a BitLocker volume: given with the evidence, or the clear key
/// stored on it when protection is suspended.
fn bitlocker_key<R: Read + Seek>(ev: &Evidence, v: &Volume, r: &mut R) -> Option<bde::Key> {
    if let Some(k) = ev.bitlocker_key(v.start) {
        return Some(k.clone());
    }
    let info = bde::info(r, v.length).ok()?;
    bde::unlock(&info, &bde::Secret::ClearKey).ok()
}

/// The decrypted views of the BitLocker volumes in `vols` that can be read
/// (key given, or protection suspended), each a volume of its own numbered
/// after the others.
pub fn unlocked_volumes(ev: &Evidence, vols: &[Volume]) -> Vec<Volume> {
    let mut out = vec![];
    for v in vols.iter().filter(|v| v.fs == FsKind::BitLocker && !v.is_virtual()) {
        let Ok(base) = ev.reader() else { continue };
        let mut sub = SubReader::new(base, v.start, v.length);
        let Some(key) = bitlocker_key(ev, v, &mut sub) else { continue };
        let Ok(mut r) = bde::BdeReader::new(sub, v.length, &key) else { continue };
        let fs = volume::detect_fs(&mut r, 0);
        let mut u = volume::mk(vols.len() + out.len(), v.kind, v.start, v.length, format!("Volume {} decrypted ({}, unlocked with: {})", v.index, bde::method_label(key.method), key.protector.to_lowercase()), fs);
        u.fs_label = format!("{} (BitLocker, unlocked)", fs.label());
        u.bitlocker = Some(BitLockerRef { of_volume: v.index, method: bde::method_label(key.method).into(), protector: key.protector.clone() });
        out.push(u);
    }
    out
}

/// Tries a BitLocker secret on every BitLocker volume of the evidence and
/// keeps the keys it opens. Returns, per BitLocker volume, its index and
/// start and what happened.
pub fn unlock_bitlocker(ev: Evidence, secret: &bde::Secret) -> (Evidence, Vec<(usize, u64, Result<bde::Key, String>)>) {
    let mut out = vec![];
    let vols = match ev.reader() {
        Ok(mut r) => detect_volumes(&mut r, ev.size),
        Err(_) => vec![],
    };
    let mut ev = ev;
    for v in vols.iter().filter(|v| v.fs == FsKind::BitLocker && !v.is_virtual()) {
        let res = ev.reader().map_err(|e| e.to_string()).and_then(|base| {
            let mut sub = SubReader::new(base, v.start, v.length);
            let info = bde::info(&mut sub, v.length).map_err(|e| e.to_string())?;
            bde::unlock(&info, secret)
        });
        if let Ok(k) = &res {
            ev = ev.with_bitlocker_key(v.start, k.clone());
        }
        out.push((v.index, v.start, res));
    }
    (ev, out)
}
