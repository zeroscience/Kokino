//! Evidence image formats.
//!
//! Supported: raw (dd/img/bin), split raw (.001, .002, ...), EWF / E01 (all
//! segments), VHD (fixed, dynamic, differencing), VHDX, VMDK (flat, sparse,
//! streamOptimized, split, snapshots; see `vdisk`).
//! Detected but not yet readable: Ex01.

use anyhow::{bail, Context};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ewf::{EwfImage, EwfInfo, EwfReader};
use crate::vdisk::{VDisk, VDiskReader};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImageFormat {
    Raw,
    SplitRaw,
    VhdFixed,
    Ewf,
    /// VHD dynamic or differencing, VHDX, VMDK: `Evidence::vdisk_label` says which.
    Virtual,
}

impl ImageFormat {
    pub fn label(&self) -> &'static str {
        match self {
            ImageFormat::Raw => "Raw (dd)",
            ImageFormat::SplitRaw => "Split raw",
            ImageFormat::VhdFixed => "VHD (fixed)",
            ImageFormat::Ewf => "EWF (E01)",
            ImageFormat::Virtual => "Virtual disk",
        }
    }
}

#[derive(Debug, Clone)]
struct Part {
    path: PathBuf,
    start: u64,
    len: u64,
}

/// An opened (read-only) evidence image. Cheap to clone; readers open their own handles.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub path: PathBuf,
    pub format: ImageFormat,
    pub size: u64,
    parts: Vec<Part>,
    ewf: Option<Arc<EwfImage>>,
    vdisk: Option<Arc<VDisk>>,
}

impl Evidence {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Evidence> {
        let path = path.as_ref().to_path_buf();
        let meta = std::fs::metadata(&path).with_context(|| format!("cannot open {}", path.display()))?;
        if !meta.is_file() {
            bail!("{} is not a regular file", path.display());
        }
        let len = meta.len();
        let mut f = File::open(&path)?;
        let mut head = [0u8; 8];
        let n = f.read(&mut head)?;

        if n >= 8 && (&head == crate::ewf::SIGNATURE || &head == crate::ewf::SIGNATURE_V2) {
            // Any segment opens the whole set; the evidence is named by its first segment.
            let first = crate::ewf::segment_path(&path, 1).unwrap_or(path);
            let img = Arc::new(EwfImage::open(&first)?);
            return Ok(Evidence { size: img.size(), path: first, format: ImageFormat::Ewf, parts: vec![], ewf: Some(img), vdisk: None });
        }
        if let Some(v) = crate::vdisk::open(&path)? {
            let v = Arc::new(v);
            return Ok(Evidence { size: v.size, path, format: ImageFormat::Virtual, parts: vec![], ewf: None, vdisk: Some(v) });
        }

        if let Some(parts) = split_parts(&path)? {
            let size = parts.iter().map(|p| p.len).sum();
            return Ok(Evidence { path, format: ImageFormat::SplitRaw, size, parts, ewf: None, vdisk: None });
        }

        if len >= 512 {
            let mut footer = [0u8; 512];
            f.seek(SeekFrom::Start(len - 512))?;
            f.read_exact(&mut footer)?;
            if &footer[..8] == b"conectix" {
                // Dynamic and differencing VHDs were opened above.
                let parts = vec![Part { path: path.clone(), start: 0, len: len - 512 }];
                return Ok(Evidence { path, format: ImageFormat::VhdFixed, size: len - 512, parts, ewf: None, vdisk: None });
            }
        }

        let parts = vec![Part { path: path.clone(), start: 0, len }];
        Ok(Evidence { path, format: ImageFormat::Raw, size: len, parts, ewf: None, vdisk: None })
    }

    pub fn reader(&self) -> io::Result<EvidenceReader> {
        Ok(EvidenceReader { parts: self.parts.clone(), size: self.size, pos: 0, open: None, ewf: self.ewf.as_ref().map(|i| i.reader()), vd: self.vdisk.as_ref().map(|v| v.reader()) })
    }

    /// What kind of virtual disk this is ("VMDK (streamOptimized)", "VHDX
    /// (differencing) (+1 parent)"), and what to know about it.
    pub fn vdisk_info(&self) -> Option<(&str, &[String])> {
        self.vdisk.as_ref().map(|v| (v.label.as_str(), v.notes.as_slice()))
    }

    /// The format as shown to people: the virtual disk kind when there is one.
    pub fn format_label(&self) -> String {
        match &self.vdisk {
            Some(v) => v.label.clone(),
            None => self.format.label().to_string(),
        }
    }

    /// Acquisition metadata and stored hashes, for EWF images.
    pub fn ewf_info(&self) -> Option<&EwfInfo> {
        self.ewf.as_ref().map(|i| &i.info)
    }

    /// Every file that makes up the image (all segments or parts).
    pub fn files(&self) -> Vec<PathBuf> {
        if let Some(v) = &self.vdisk {
            let mut f = v.files.clone();
            f.dedup();
            return f;
        }
        match &self.ewf {
            Some(i) => i.info.segments.iter().map(PathBuf::from).collect(),
            None => self.parts.iter().map(|p| p.path.clone()).collect(),
        }
    }
}

/// For `x.001` collect `x.002`, `x.003`, ... while they exist.
fn split_parts(path: &Path) -> anyhow::Result<Option<Vec<Part>>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext.len() != 3 || ext != "001" {
        return Ok(None);
    }
    let mut parts = vec![];
    let mut start = 0u64;
    for i in 1..=9999u32 {
        let p = path.with_extension(format!("{:03}", i));
        let Ok(m) = std::fs::metadata(&p) else { break };
        parts.push(Part { path: p, start, len: m.len() });
        start += m.len();
    }
    Ok(if parts.len() > 1 { Some(parts) } else { None })
}

/// `Read + Seek` over the logical image stream (all parts, footer excluded).
pub struct EvidenceReader {
    parts: Vec<Part>,
    size: u64,
    pos: u64,
    open: Option<(usize, File)>,
    ewf: Option<EwfReader>,
    vd: Option<VDiskReader>,
}

impl EvidenceReader {
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for EvidenceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.ewf.as_mut() {
            e.seek(SeekFrom::Start(self.pos))?;
            let n = e.read(buf)?;
            self.pos += n as u64;
            return Ok(n);
        }
        if let Some(v) = self.vd.as_mut() {
            v.seek(SeekFrom::Start(self.pos))?;
            let n = v.read(buf)?;
            self.pos += n as u64;
            return Ok(n);
        }
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let idx = self
            .parts
            .iter()
            .position(|p| self.pos >= p.start && self.pos < p.start + p.len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "offset outside image"))?;
        if self.open.as_ref().map(|(i, _)| *i) != Some(idx) {
            self.open = Some((idx, File::open(&self.parts[idx].path)?));
        }
        let part = &self.parts[idx];
        let within = self.pos - part.start;
        let max = ((part.len - within) as usize).min(buf.len());
        let f = &mut self.open.as_mut().unwrap().1;
        f.seek(SeekFrom::Start(within))?;
        let n = f.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for EvidenceReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}
