//! Read-only evidence sources and volume systems.
//!
//! Every file is opened with `File::open` (read-only). Nothing in this crate
//! can write to evidence.

#![forbid(unsafe_code)]

pub mod ewf;
pub mod source;
pub mod volume;

pub use ewf::EwfInfo;
pub use source::{Evidence, EvidenceReader, ImageFormat};
pub use volume::{detect_volumes, FsKind, Volume, VolumeKind};

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
