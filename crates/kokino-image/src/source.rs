//! Evidence image formats.
//!
//! Supported: raw (dd/img/bin), split raw (.001, .002, ...), EWF / E01 (all
//! segments), VHD (fixed, dynamic, differencing), VHDX, VMDK (flat, sparse,
//! streamOptimized, split, snapshots; see `vdisk`), AFF4 disk images
//! (see `aff4`), AccessData AD1 logical images (the segments joined without
//! their 512-byte margins; the items are read by the analysis as a file
//! system). Detected but not yet readable: Ex01, encrypted AD1.

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
    /// AFF4 disk image (one container or a striped set).
    Aff4,
    /// AccessData AD1 logical image (FTK Imager custom content image).
    Ad1,
    /// AFF4-L logical image: the container is read as a file system.
    Aff4Logical,
}

impl ImageFormat {
    pub fn label(&self) -> &'static str {
        match self {
            ImageFormat::Raw => "Raw (dd)",
            ImageFormat::SplitRaw => "Split raw",
            ImageFormat::VhdFixed => "VHD (fixed)",
            ImageFormat::Ewf => "EWF (E01)",
            ImageFormat::Virtual => "Virtual disk",
            ImageFormat::Aff4 => "AFF4",
            ImageFormat::Ad1 => "AD1 (logical image)",
            ImageFormat::Aff4Logical => "AFF4-L (logical image)",
        }
    }
}

#[derive(Debug, Clone)]
struct Part {
    path: PathBuf,
    start: u64,
    len: u64,
    /// Bytes at the start of the file that are not image data (an AD1
    /// segment's margin).
    skip: u64,
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
    aff4: Option<Arc<crate::aff4::Aff4Disk>>,
    /// BitLocker keys known for volumes of this evidence, by volume start.
    bitlocker: Vec<(u64, crate::bde::Key)>,
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
            return Ok(Evidence { size: img.size(), path: first, format: ImageFormat::Ewf, parts: vec![], ewf: Some(img), vdisk: None, aff4: None, bitlocker: vec![] });
        }
        if head.starts_with(b"ADSEGME") {
            let (first, parts) = ad1_segments(&path)?;
            let size = parts.iter().map(|p| p.len).sum();
            return Ok(Evidence { path: first, format: ImageFormat::Ad1, size, parts, ewf: None, vdisk: None, aff4: None, bitlocker: vec![] });
        }
        if head.starts_with(b"PK") {
            if let Some(a) = crate::aff4::open_disk(&path)? {
                let a = Arc::new(a);
                return Ok(Evidence { size: a.size, path, format: ImageFormat::Aff4, parts: vec![], ewf: None, vdisk: None, aff4: Some(a), bitlocker: vec![] });
            }
            if crate::aff4::is_container(&mut f, len) {
                let parts = vec![Part { path: path.clone(), start: 0, len, skip: 0 }];
                return Ok(Evidence { path, format: ImageFormat::Aff4Logical, size: len, parts, ewf: None, vdisk: None, aff4: None, bitlocker: vec![] });
            }
        }
        if let Some(v) = crate::vdisk::open(&path)? {
            let v = Arc::new(v);
            return Ok(Evidence { size: v.size, path, format: ImageFormat::Virtual, parts: vec![], ewf: None, vdisk: Some(v), aff4: None, bitlocker: vec![] });
        }

        if let Some(parts) = split_parts(&path)? {
            let size = parts.iter().map(|p| p.len).sum();
            return Ok(Evidence { path, format: ImageFormat::SplitRaw, size, parts, ewf: None, vdisk: None, aff4: None, bitlocker: vec![] });
        }

        if len >= 512 {
            let mut footer = [0u8; 512];
            f.seek(SeekFrom::Start(len - 512))?;
            f.read_exact(&mut footer)?;
            if &footer[..8] == b"conectix" {
                // Dynamic and differencing VHDs were opened above.
                let parts = vec![Part { path: path.clone(), start: 0, len: len - 512, skip: 0 }];
                return Ok(Evidence { path, format: ImageFormat::VhdFixed, size: len - 512, parts, ewf: None, vdisk: None, aff4: None, bitlocker: vec![] });
            }
        }

        let parts = vec![Part { path: path.clone(), start: 0, len, skip: 0 }];
        Ok(Evidence { path, format: ImageFormat::Raw, size: len, parts, ewf: None, vdisk: None, aff4: None, bitlocker: vec![] })
    }

    /// Adds the key for the BitLocker volume starting at byte `start`.
    pub fn with_bitlocker_key(mut self, start: u64, key: crate::bde::Key) -> Evidence {
        self.bitlocker.retain(|(s, _)| *s != start);
        self.bitlocker.push((start, key));
        self
    }

    /// The key given for the BitLocker volume starting at byte `start`.
    pub fn bitlocker_key(&self, start: u64) -> Option<&crate::bde::Key> {
        self.bitlocker.iter().find(|(s, _)| *s == start).map(|(_, k)| k)
    }

    pub fn reader(&self) -> io::Result<EvidenceReader> {
        Ok(EvidenceReader { parts: self.parts.clone(), size: self.size, pos: 0, open: None, ewf: self.ewf.as_ref().map(|i| i.reader()), vd: self.vdisk.as_ref().map(|v| v.reader()), aff4: self.aff4.as_ref().map(|a| a.reader()) })
    }

    /// What kind of virtual disk this is ("VMDK (streamOptimized)", "VHDX
    /// (differencing) (+1 parent)"), and what to know about it.
    pub fn vdisk_info(&self) -> Option<(&str, &[String])> {
        if let Some(a) = &self.aff4 {
            return Some((a.label.as_str(), a.notes.as_slice()));
        }
        self.vdisk.as_ref().map(|v| (v.label.as_str(), v.notes.as_slice()))
    }

    /// The AFF4 image, for AFF4 evidence.
    pub fn aff4(&self) -> Option<&crate::aff4::Aff4Disk> {
        self.aff4.as_deref()
    }

    /// Whether the image is so large that hashing every byte of it would
    /// not end (a sparse AFF4 image of exabytes): its container files are
    /// hashed instead.
    pub fn hash_containers(&self) -> bool {
        self.aff4.is_some() && self.size > 1 << 44
    }

    /// The format as shown to people: the virtual disk kind when there is one.
    pub fn format_label(&self) -> String {
        if let Some(a) = &self.aff4 {
            return a.label.clone();
        }
        match &self.vdisk {
            Some(v) => v.label.clone(),
            None => self.format.label().to_string(),
        }
    }

    /// Acquisition metadata and stored hashes, for EWF images.
    pub fn ewf_info(&self) -> Option<&EwfInfo> {
        self.ewf.as_ref().map(|i| &i.info)
    }

    /// The container files one after another (for `hash_containers`).
    pub fn containers_reader(&self) -> io::Result<Box<dyn Read + Send>> {
        let mut r: Box<dyn Read + Send> = Box::new(io::empty());
        for p in self.files() {
            r = Box::new(r.chain(File::open(p)?));
        }
        Ok(r)
    }

    /// Every file that makes up the image (all segments or parts).
    pub fn files(&self) -> Vec<PathBuf> {
        if let Some(a) = &self.aff4 {
            return a.files.clone();
        }
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

/// The segments of an AD1 image from any one of them: (first segment, parts
/// without their margins). Each segment's header says its number and how
/// many there are.
fn ad1_segments(path: &Path) -> anyhow::Result<(PathBuf, Vec<Part>)> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let (stem, digits) = ext.split_at(ext.find(|c: char| c.is_ascii_digit()).unwrap_or(ext.len()));
    if !stem.eq_ignore_ascii_case("ad") || digits.is_empty() {
        bail!("an AD1 segment is named .ad1, .ad2, ...: {} is not", path.display());
    }
    let seg = |n: u32| path.with_extension(format!("{}{}", stem, n));
    let header = |p: &Path| -> anyhow::Result<(u32, u32, u64)> {
        let mut f = File::open(p).with_context(|| format!("AD1 segment {} is missing", p.display()))?;
        let mut h = [0u8; 512];
        f.read_exact(&mut h).with_context(|| format!("{} is too short for an AD1 segment", p.display()))?;
        if !h.starts_with(b"ADSEGMENTEDFILE") {
            bail!("{} is not an AD1 segment", p.display());
        }
        let n = u32::from_le_bytes(h[24..28].try_into().unwrap());
        let count = u32::from_le_bytes(h[28..32].try_into().unwrap());
        Ok((n, count, f.metadata()?.len()))
    };
    let (_, count, _) = header(path)?;
    if count == 0 || count > 100_000 {
        bail!("the AD1 segment header is damaged (segment count {})", count);
    }
    let mut parts = vec![];
    let mut start = 0u64;
    for n in 1..=count {
        let p = seg(n);
        let (num, c, len) = header(&p)?;
        if num != n || c != count {
            bail!("{} says it is segment {} of {}; expected {} of {}", p.display(), num, c, n, count);
        }
        let len = len.saturating_sub(512);
        parts.push(Part { path: p, start, len, skip: 512 });
        start += len;
    }
    let mut first = [0u8; 16];
    {
        let mut f = File::open(&parts[0].path)?;
        f.seek(SeekFrom::Start(512))?;
        let _ = f.read(&mut first)?;
    }
    if first.starts_with(b"ADCRYPT") {
        bail!("this AD1 image is encrypted (AD Encryption); encrypted AD1 images are not supported yet: decrypt it in FTK Imager and add the result");
    }
    Ok((seg(1), parts))
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
        parts.push(Part { path: p, start, len: m.len(), skip: 0 });
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
    aff4: Option<crate::aff4::Aff4Reader>,
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
        if let Some(a) = self.aff4.as_mut() {
            a.seek(SeekFrom::Start(self.pos))?;
            let n = a.read(buf)?;
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
        f.seek(SeekFrom::Start(part.skip + within))?;
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
