//! Virtual disks: VHD (dynamic and differencing), VHDX (dynamic, fixed and
//! differencing) and VMDK (flat, hosted sparse, streamOptimized, split into
//! extents, and snapshots).
//!
//! Each format becomes a map from the virtual disk's byte offsets to places
//! in its files: data at a file offset, zeros, a compressed grain, or "ask
//! the parent" for differencing disks and snapshots, whose parents are found
//! next to them from the names the child records. Everything is read-only;
//! a VHDX log that was not replayed is reported, not applied.

use anyhow::{bail, Context};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SECTOR: u64 = 512;
/// Largest virtual disk accepted (64 TiB, the VHDX maximum).
const MAX_SIZE: u64 = 64 << 40;
const MAX_TABLE_BYTES: u64 = 512 << 20;
const MAX_CHAIN: usize = 32;

fn be32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn be64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_be_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn le16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

fn rd(f: &mut File, off: u64, n: usize) -> io::Result<Vec<u8>> {
    f.seek(SeekFrom::Start(off))?;
    let mut b = Vec::with_capacity(n.min(1 << 20));
    f.take(n as u64).read_to_end(&mut b)?;
    Ok(b)
}

fn utf16le(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&w)
}
fn utf16be(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&w)
}

/// Where a run of virtual bytes lives.
#[derive(Debug, Clone, Copy)]
enum Loc {
    /// In a file of this disk at an offset.
    Data { file: usize, off: u64 },
    Zero,
    /// Not in this disk: read the parent.
    Parent,
    /// Inside a deflate-compressed VMDK grain stored at `off` (bytes).
    Grain { file: usize, off: u64, grain: u64, within: u64 },
}

#[derive(Debug)]
enum Layer {
    Vhd { file: usize, bat: Vec<u32>, block: u64, bitmap: u64, diff: bool },
    Vhdx { file: usize, bat: Vec<u64>, block: u64, chunk_ratio: u64, sector: u64, diff: bool },
    Vmdk { extents: Vec<Extent> },
}

#[derive(Debug)]
struct Extent {
    start: u64,
    len: u64,
    kind: ExtKind,
}

#[derive(Debug)]
enum ExtKind {
    Flat { file: usize, off: u64 },
    Zero,
    Sparse { file: usize, gd: Vec<u32>, grain: u64, gtes: u64, compressed: bool },
}

/// One disk of a chain: its map and what it is.
#[derive(Debug)]
struct Disk {
    layer: Layer,
}

/// An opened virtual disk with its parents (child first).
#[derive(Debug)]
pub struct VDisk {
    pub label: String,
    pub size: u64,
    /// Every file read, child first.
    pub files: Vec<PathBuf>,
    /// Plain-language remarks (unreplayed log, parent mismatch, ...).
    pub notes: Vec<String>,
    chain: Vec<Disk>,
}

/// Opens a virtual disk if `path` is one (`Ok(None)` otherwise).
pub fn open(path: &Path) -> anyhow::Result<Option<VDisk>> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let head = rd(&mut f, 0, 512)?;
    let kind = if head.starts_with(b"vhdxfile") {
        "vhdx"
    } else if head.starts_with(b"KDMV") || head.starts_with(b"# Disk DescriptorFile") || (head.starts_with(b"#") && String::from_utf8_lossy(&head).contains("createType")) {
        "vmdk"
    } else if len >= 512 && rd(&mut f, len - 512, 8)? == b"conectix" && be32(&rd(&mut f, len - 512, 64)?, 60) != 2 {
        "vhd"
    } else {
        return Ok(None);
    };
    let mut v = VDisk { label: String::new(), size: 0, files: vec![], notes: vec![], chain: vec![] };
    let mut next = Some(path.to_path_buf());
    let mut labels = vec![];
    while let Some(p) = next.take() {
        if v.chain.len() >= MAX_CHAIN {
            bail!("more than {} differencing disks in the chain", MAX_CHAIN);
        }
        if v.files.iter().any(|x| x == &p) {
            bail!("differencing chain loops back to {}", p.display());
        }
        let (layer, size, label, parent) = match kind {
            "vhd" => open_vhd(&p, &mut v)?,
            "vhdx" => open_vhdx(&p, &mut v)?,
            _ => open_vmdk(&p, &mut v)?,
        };
        if v.chain.is_empty() {
            v.size = size;
        } else if size != v.size {
            v.notes.push(format!("parent {} is {} bytes, the child {}; the child's size is used", p.display(), size, v.size));
        }
        labels.push(label);
        v.chain.push(Disk { layer });
        next = parent;
    }
    v.label = if labels.len() > 1 { format!("{} (+{} parent{})", labels[0], labels.len() - 1, if labels.len() > 2 { "s" } else { "" }) } else { labels.remove(0) };
    Ok(Some(v))
}

fn add_file(v: &mut VDisk, p: &Path) -> usize {
    v.files.push(p.to_path_buf());
    v.files.len() - 1
}

/// The parent file named by a child, looked up next to the child first.
fn find_parent(child: &Path, names: &[String]) -> anyhow::Result<PathBuf> {
    let dir = child.parent().unwrap_or(Path::new("."));
    let mut tried = vec![];
    for n in names.iter().filter(|n| !n.is_empty()) {
        let norm = n.replace('\\', "/");
        let rel = norm.trim_start_matches("./");
        for c in [dir.join(rel), PathBuf::from(&norm), dir.join(rel.rsplit('/').next().unwrap_or(rel))] {
            if c.is_file() {
                return Ok(c);
            }
            tried.push(c.display().to_string());
        }
    }
    bail!("parent disk not found (looked for {})", if tried.is_empty() { "a name in the child".to_string() } else { tried.join(", ") })
}

// ---------------------------------------------------------------- VHD

type Opened = (Layer, u64, String, Option<PathBuf>);

fn open_vhd(p: &Path, v: &mut VDisk) -> anyhow::Result<Opened> {
    let mut f = File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let len = f.metadata()?.len();
    let footer = rd(&mut f, len.saturating_sub(512), 512)?;
    if !footer.starts_with(b"conectix") {
        bail!("{} is not a VHD", p.display());
    }
    let sum: u32 = footer.iter().enumerate().filter(|(i, _)| !(64..68).contains(i)).map(|(_, &b)| b as u32).fold(0, u32::wrapping_add);
    if !sum != be32(&footer, 64) as u32 {
        v.notes.push(format!("{}: footer checksum does not match", p.display()));
    }
    let size = be64(&footer, 48);
    let disk_type = be32(&footer, 60);
    if size > MAX_SIZE || !size.is_multiple_of(SECTOR) {
        bail!("VHD size {} out of range", size);
    }
    let file = add_file(v, p);
    if disk_type == 2 {
        let layer = Layer::Vmdk { extents: vec![Extent { start: 0, len: size, kind: ExtKind::Flat { file, off: 0 } }] };
        return Ok((layer, size, "VHD (fixed)".into(), None));
    }
    if disk_type != 3 && disk_type != 4 {
        bail!("VHD disk type {} not supported", disk_type);
    }
    let hdr = rd(&mut f, be64(&footer, 16), 1024)?;
    if !hdr.starts_with(b"cxsparse") {
        bail!("VHD dynamic header missing");
    }
    let bat_off = be64(&hdr, 16);
    let entries = be32(&hdr, 28);
    let block = be32(&hdr, 32);
    if block < SECTOR || !block.is_power_of_two() || block > 256 << 20 || entries.saturating_mul(4) > MAX_TABLE_BYTES.min(len) || entries.saturating_mul(block) < size {
        bail!("VHD block table out of range");
    }
    let raw = rd(&mut f, bat_off, (entries * 4) as usize)?;
    let bat: Vec<u32> = raw.chunks_exact(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect();
    let bitmap = (block / SECTOR).div_ceil(8).div_ceil(SECTOR) * SECTOR;
    let diff = disk_type == 4;
    let mut parent = None;
    if diff {
        let mut names = vec![];
        for i in 0..8 {
            let e = &hdr[576 + 24 * i..600 + 24 * i];
            let code = &e[0..4];
            let (dlen, doff) = (be32(e, 8), be64(e, 16));
            if dlen == 0 || dlen > 4096 {
                continue;
            }
            let d = rd(&mut f, doff, dlen as usize)?;
            match code {
                b"W2ru" | b"W2ku" => names.push(utf16le(&d)),
                b"Wi2r" | b"Wi2k" | b"Mac " | b"MacX" => names.push(String::from_utf8_lossy(&d).trim_end_matches('\0').trim_start_matches("file://").to_string()),
                _ => {}
            }
        }
        names.push(utf16be(&hdr[64..576]));
        let pp = find_parent(p, &names)?;
        // The parent's unique id should be the one the child recorded.
        let mut pf = File::open(&pp)?;
        let plen = pf.metadata()?.len();
        let pfoot = rd(&mut pf, plen.saturating_sub(512), 512)?;
        if pfoot.get(68..84) != hdr.get(40..56) {
            v.notes.push(format!("{}: its parent {} has a different unique id than the child recorded (the parent may have changed since)", p.display(), pp.display()));
        }
        parent = Some(pp);
    }
    let label = if diff { "VHD (differencing)" } else { "VHD (dynamic)" };
    Ok((Layer::Vhd { file, bat, block, bitmap, diff }, size, label.into(), parent))
}

// ---------------------------------------------------------------- VHDX

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82F6_3B78 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// GUID text ("2DC27766-F623-4200-9D64-115E9BFD4A08") to its on-disk bytes.
fn guid(s: &str) -> [u8; 16] {
    let h: Vec<u8> = s.split('-').flat_map(|p| (0..p.len()).step_by(2).map(move |i| u8::from_str_radix(&p[i..i + 2], 16).unwrap_or(0))).collect();
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&[h[3], h[2], h[1], h[0]]);
    g[4..6].copy_from_slice(&[h[5], h[4]]);
    g[6..8].copy_from_slice(&[h[7], h[6]]);
    g[8..16].copy_from_slice(&h[8..16]);
    g
}

fn guid_text(g: &[u8]) -> String {
    if g.len() < 16 {
        return String::new();
    }
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

fn open_vhdx(p: &Path, v: &mut VDisk) -> anyhow::Result<Opened> {
    let mut f = File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let len = f.metadata()?.len();
    if !rd(&mut f, 0, 8)?.starts_with(b"vhdxfile") {
        bail!("{} is not a VHDX", p.display());
    }
    // The valid header with the highest sequence number is current.
    let mut header: Option<Vec<u8>> = None;
    for off in [64u64 << 10, 128 << 10] {
        let mut h = rd(&mut f, off, 4096)?;
        if h.len() < 4096 || !h.starts_with(b"head") {
            continue;
        }
        let want = le32(&h, 4) as u32;
        h[4..8].fill(0);
        if crc32c(&h) != want {
            continue;
        }
        h[4..8].copy_from_slice(&want.to_le_bytes());
        if header.as_ref().is_none_or(|x| le64(&h, 8) > le64(x, 8)) {
            header = Some(h);
        }
    }
    let header = header.ok_or_else(|| anyhow::anyhow!("no valid VHDX header"))?;
    if header[48..64].iter().any(|&b| b != 0) {
        v.notes.push(format!(
            "{}: the VHDX log holds writes that were never applied (the disk was not shut down cleanly); Kokino reads the disk without them, so the newest changes may be missing",
            p.display()
        ));
    }
    let data_write = guid_text(&header[32..48]);
    // Region table: BAT and metadata.
    let mut regions = HashMap::new();
    for off in [192u64 << 10, 256 << 10] {
        let mut rt = rd(&mut f, off, 64 << 10)?;
        if rt.len() < 64 << 10 || !rt.starts_with(b"regi") {
            continue;
        }
        let want = le32(&rt, 4) as u32;
        rt[4..8].fill(0);
        if crc32c(&rt) != want {
            continue;
        }
        let n = le32(&rt, 8).min(2047) as usize;
        for i in 0..n {
            let e = &rt[16 + 32 * i..48 + 32 * i];
            regions.insert(e[0..16].to_vec(), (le64(e, 16), le32(e, 24)));
        }
        break;
    }
    let (bat_off, bat_len) = *regions.get(guid("2DC27766-F623-4200-9D64-115E9BFD4A08").as_slice()).ok_or_else(|| anyhow::anyhow!("VHDX has no block table"))?;
    let (md_off, md_len) = *regions.get(guid("8B7CA206-4790-4B9A-B8FE-575F050F886E").as_slice()).ok_or_else(|| anyhow::anyhow!("VHDX has no metadata"))?;
    let md = rd(&mut f, md_off, md_len.min(8 << 20) as usize)?;
    if !md.starts_with(b"metadata") {
        bail!("VHDX metadata region not recognized");
    }
    let mut items: HashMap<Vec<u8>, &[u8]> = HashMap::new();
    for i in 0..le16(&md, 10).min(2047) as usize {
        let Some(e) = md.get(32 + 32 * i..64 + 32 * i) else { break };
        let (o, l) = (le32(e, 16) as usize, le32(e, 20) as usize);
        if let Some(d) = md.get(o..o.saturating_add(l)) {
            items.insert(e[0..16].to_vec(), d);
        }
    }
    let item = |g: &str| items.get(guid(g).as_slice()).copied().unwrap_or(&[]);
    let params = item("CAA16737-FA36-4D43-B3B6-33F0AA44E76B");
    let block = le32(params, 0);
    let has_parent = le32(params, 4) & 2 != 0;
    let size = le64(item("2FA54224-CD1B-4876-B211-5DBED83BF4B8"), 0);
    let sector = le32(item("8141BF1D-A96F-4709-BA47-F233A8FAAB5F"), 0);
    if !(1 << 20..=256 << 20).contains(&block) || !block.is_power_of_two() || !(sector == 512 || sector == 4096) || size == 0 || size > MAX_SIZE || !size.is_multiple_of(sector) {
        bail!("VHDX geometry out of range");
    }
    let chunk_ratio = (1u64 << 23) * sector / block;
    let blocks = size.div_ceil(block);
    let entries = if has_parent { blocks.div_ceil(chunk_ratio) * (chunk_ratio + 1) } else { blocks + (blocks - 1) / chunk_ratio };
    if entries * 8 > bat_len.max(8) || entries * 8 > MAX_TABLE_BYTES.min(len) {
        bail!("VHDX block table too small or too large");
    }
    let raw = rd(&mut f, bat_off, (entries * 8) as usize)?;
    let bat: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    let file = add_file(v, p);
    let mut parent = None;
    if has_parent {
        let loc = item("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C");
        let mut kv = HashMap::new();
        for i in 0..le16(loc, 18).min(64) as usize {
            let Some(e) = loc.get(20 + 12 * i..32 + 12 * i) else { break };
            let (ko, vo, kl, vl) = (le32(e, 0) as usize, le32(e, 4) as usize, le16(e, 8) as usize, le16(e, 10) as usize);
            if let (Some(k), Some(val)) = (loc.get(ko..ko.saturating_add(kl)), loc.get(vo..vo.saturating_add(vl))) {
                kv.insert(utf16le(k), utf16le(val));
            }
        }
        let names: Vec<String> = ["relative_path", "absolute_win32_path", "volume_path"].iter().filter_map(|k| kv.get(*k).cloned()).collect();
        let pp = find_parent(p, &names)?;
        // parent_linkage is the parent's data write GUID.
        if let Some(link) = kv.get("parent_linkage") {
            let mut pf = File::open(&pp)?;
            let mut best: Option<Vec<u8>> = None;
            for off in [64u64 << 10, 128 << 10] {
                let h = rd(&mut pf, off, 4096)?;
                if h.starts_with(b"head") && best.as_ref().is_none_or(|x| le64(&h, 8) > le64(x, 8)) {
                    best = Some(h);
                }
            }
            let theirs = best.map(|h| guid_text(&h[32..48])).unwrap_or_default();
            if !link.trim_matches(|c| c == '{' || c == '}').eq_ignore_ascii_case(&theirs) {
                v.notes.push(format!("{}: its parent {} was written after the child was made (data write GUID differs); content may not match", p.display(), pp.display()));
            }
        }
        parent = Some(pp);
    }
    let _ = data_write;
    let label = if has_parent { "VHDX (differencing)" } else { "VHDX" };
    Ok((Layer::Vhdx { file, bat, block, chunk_ratio, sector, diff: has_parent }, size, label.into(), parent))
}

// ---------------------------------------------------------------- VMDK

fn open_vmdk(p: &Path, v: &mut VDisk) -> anyhow::Result<Opened> {
    let mut f = File::open(p).with_context(|| format!("cannot open {}", p.display()))?;
    let head = rd(&mut f, 0, 512)?;
    // A descriptor embedded in a sparse extent describes that file, whatever
    // name it records (OVA exports say "generated-stream.vmdk").
    let embedded = head.starts_with(b"KDMV");
    let desc = if embedded {
        let (off, n) = (le64(&head, 28), le64(&head, 36));
        if off == 0 || n == 0 {
            bail!("{} is a sparse extent without a descriptor; open the descriptor .vmdk instead", p.display());
        }
        String::from_utf8_lossy(&rd(&mut f, off.saturating_mul(SECTOR), n.min(2048).saturating_mul(SECTOR) as usize)?).into_owned()
    } else {
        String::from_utf8_lossy(&rd(&mut f, 0, 1 << 20)?).into_owned()
    };
    let desc = desc.trim_end_matches('\0');
    let dir = p.parent().unwrap_or(Path::new("."));
    let mut kv = HashMap::new();
    let mut extents = vec![];
    let mut start = 0u64;
    let mut ftypes = vec![];
    for line in desc.lines().map(str::trim) {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, val)) = line.split_once('=') {
            if !k.trim().contains(' ') {
                kv.insert(k.trim().to_string(), val.trim().trim_matches('"').to_string());
                continue;
            }
        }
        // RW 4192256 SPARSE "name.vmdk" [offset]
        let mut parts = line.splitn(4, ' ');
        let (Some(access), Some(n), Some(ty)) = (parts.next(), parts.next(), parts.next()) else { continue };
        if !matches!(access, "RW" | "RDONLY" | "NOACCESS") {
            continue;
        }
        let sectors: u64 = n.parse().with_context(|| format!("bad extent size in {}", line))?;
        let len = sectors.checked_mul(SECTOR).filter(|&l| start.saturating_add(l) <= MAX_SIZE).ok_or_else(|| anyhow::anyhow!("VMDK extent too large"))?;
        let rest = parts.next().unwrap_or("");
        let name = rest.split('"').nth(1).unwrap_or("");
        let off_sectors: u64 = rest.rsplit('"').next().unwrap_or("").trim().parse().unwrap_or(0);
        ftypes.push(ty.to_string());
        let kind = match ty {
            "ZERO" => ExtKind::Zero,
            "FLAT" | "VMFS" | "VMFSRDM" | "VMFSRAW" => {
                let ep = dir.join(name);
                if !ep.is_file() {
                    bail!("extent file {} not found", ep.display());
                }
                ExtKind::Flat { file: add_file(v, &ep), off: off_sectors.saturating_mul(SECTOR) }
            }
            "SPARSE" => {
                let ep = if embedded || name.is_empty() { p.to_path_buf() } else { dir.join(name) };
                if !ep.is_file() {
                    bail!("extent file {} not found", ep.display());
                }
                sparse_extent(&ep, v)?
            }
            other => bail!("VMDK extent type {} is not supported yet (ESXi snapshot formats VMFSSPARSE and SESPARSE)", other),
        };
        extents.push(Extent { start, len, kind });
        start += len;
    }
    if extents.is_empty() {
        bail!("VMDK descriptor lists no extents");
    }
    let create = kv.get("createType").cloned().unwrap_or_default();
    let mut parent = None;
    if let Some(hint) = kv.get("parentFileNameHint") {
        let pp = find_parent(p, std::slice::from_ref(hint))?;
        if let (Some(want), Ok(pd)) = (kv.get("parentCID"), std::fs::read(&pp)) {
            let text = if pd.starts_with(b"KDMV") { String::from_utf8_lossy(&pd[(le64(&pd, 28) * SECTOR) as usize..((le64(&pd, 28) + le64(&pd, 36)) * SECTOR).min(pd.len() as u64) as usize]).into_owned() } else { String::from_utf8_lossy(&pd[..pd.len().min(1 << 20)]).into_owned() };
            let cid = text.lines().find_map(|l| l.trim().strip_prefix("CID=")).unwrap_or("");
            if !cid.eq_ignore_ascii_case(want) {
                v.notes.push(format!("{}: its parent {} has CID {}, the snapshot expects {} (the parent changed after the snapshot)", p.display(), pp.display(), cid, want));
            }
        }
        parent = Some(pp);
    }
    let label = format!("VMDK ({})", if create.is_empty() { ftypes.join(", ") } else { create });
    Ok((Layer::Vmdk { extents }, start, label, parent))
}

fn sparse_extent(p: &Path, v: &mut VDisk) -> anyhow::Result<ExtKind> {
    let mut f = File::open(p)?;
    let len = f.metadata()?.len();
    let mut h = rd(&mut f, 0, 512)?;
    if !h.starts_with(b"KDMV") {
        bail!("{} is not a VMDK sparse extent", p.display());
    }
    let mut gd_off = le64(&h, 56);
    let compressed = le32(&h, 8) & 0x10000 != 0;
    if gd_off == u64::MAX {
        // streamOptimized: the footer near the end has the real offsets.
        let footer = rd(&mut f, len.saturating_sub(1024), 512)?;
        if !footer.starts_with(b"KDMV") {
            bail!("{}: streamOptimized footer missing (the file may be truncated)", p.display());
        }
        h = footer;
        gd_off = le64(&h, 56);
    }
    let capacity = le64(&h, 12);
    let grain = le64(&h, 20);
    let gtes = le32(&h, 44);
    if grain == 0 || !grain.is_power_of_two() || grain > 1 << 16 || gtes == 0 || gtes > 1 << 16 || capacity > MAX_SIZE / SECTOR {
        bail!("{}: sparse header out of range", p.display());
    }
    let grains = capacity.div_ceil(grain);
    let ngt = grains.div_ceil(gtes);
    if ngt * 4 > MAX_TABLE_BYTES.min(len.max(4)) {
        bail!("{}: grain directory larger than the file", p.display());
    }
    let raw = rd(&mut f, gd_off.saturating_mul(SECTOR), (ngt * 4) as usize)?;
    let gd = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    Ok(ExtKind::Sparse { file: add_file(v, p), gd, grain: grain * SECTOR, gtes, compressed })
}

// ---------------------------------------------------------------- reading

impl VDisk {
    pub fn reader(self: &Arc<Self>) -> VDiskReader {
        VDiskReader { disk: self.clone(), pos: 0, files: HashMap::new(), cache: HashMap::new(), order: vec![] }
    }
}

/// `Read + Seek` over the virtual disk.
pub struct VDiskReader {
    disk: Arc<VDisk>,
    pos: u64,
    files: HashMap<usize, File>,
    /// Bitmaps, grain tables and decompressed grains: (kind, file, offset).
    cache: HashMap<(u8, usize, u64), Arc<Vec<u8>>>,
    order: Vec<(u8, usize, u64)>,
}

const CACHE_ITEMS: usize = 256;

impl VDiskReader {
    fn file(&mut self, i: usize) -> io::Result<&mut File> {
        if !self.files.contains_key(&i) {
            let p = self.disk.files.get(i).ok_or_else(|| io::Error::other("bad file index"))?;
            self.files.insert(i, File::open(p)?);
        }
        Ok(self.files.get_mut(&i).unwrap())
    }

    fn cached(&mut self, key: (u8, usize, u64), n: usize, inflate: bool) -> io::Result<Arc<Vec<u8>>> {
        if let Some(b) = self.cache.get(&key) {
            return Ok(b.clone());
        }
        let f = self.file(key.1)?;
        let b = if inflate {
            // Compressed grain: lba (8), size (4), zlib data.
            let head = rd(f, key.2, 12)?;
            let size = le32(&head, 8).min(n as u64 * 2 + 4096) as usize;
            let z = rd(f, key.2 + 12, size)?;
            let mut out = Vec::with_capacity(n);
            flate2::read::ZlibDecoder::new(&z[..]).take(n as u64).read_to_end(&mut out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("compressed grain at {}: {}", key.2, e)))?;
            out
        } else {
            rd(f, key.2, n)?
        };
        let b = Arc::new(b);
        if self.order.len() >= CACHE_ITEMS {
            let old = self.order.remove(0);
            self.cache.remove(&old);
        }
        self.order.push(key);
        self.cache.insert(key, b.clone());
        Ok(b)
    }

    /// Where virtual offset `off` of chain level `lvl` lives, and for how
    /// many bytes (at most `max`) the answer holds.
    fn locate(&mut self, lvl: usize, off: u64, max: u64) -> io::Result<(Loc, u64)> {
        let disk = self.disk.clone();
        let Some(d) = disk.chain.get(lvl) else { return Ok((Loc::Zero, max)) };
        match &d.layer {
            Layer::Vhd { file, bat, block, bitmap, diff } => {
                let (bi, within) = (off / block, off % block);
                let n = (block - within).min(max);
                let entry = bat.get(bi as usize).copied().unwrap_or(u32::MAX);
                if entry == u32::MAX {
                    return Ok((if *diff { Loc::Parent } else { Loc::Zero }, n));
                }
                let base = entry as u64 * SECTOR;
                if !*diff {
                    return Ok((Loc::Data { file: *file, off: base + bitmap + within }, n));
                }
                let bm = self.cached((0, *file, base), *bitmap as usize, false)?;
                let bit = |s: u64| bm.get((s / 8) as usize).map(|b| b & (0x80 >> (s % 8)) != 0).unwrap_or(false);
                let s0 = within / SECTOR;
                let here = bit(s0);
                let mut s = s0 + 1;
                while s * SECTOR < within + n && bit(s) == here {
                    s += 1;
                }
                let run = (s * SECTOR - within).min(n);
                Ok((if here { Loc::Data { file: *file, off: base + bitmap + within } } else { Loc::Parent }, run))
            }
            Layer::Vhdx { file, bat, block, chunk_ratio, sector, diff } => {
                let (bi, within) = (off / block, off % block);
                let n = (block - within).min(max);
                let entry = bat.get((bi + bi / chunk_ratio) as usize).copied().unwrap_or(0);
                let (state, at) = (entry & 7, (entry >> 20) << 20);
                match state {
                    6 => Ok((Loc::Data { file: *file, off: at + within }, n)),
                    7 if *diff => {
                        // Sector bitmap block of this chunk: 1 MiB, a bit per sector.
                        let chunk = bi / chunk_ratio;
                        let be = bat.get((chunk * (chunk_ratio + 1) + chunk_ratio) as usize).copied().unwrap_or(0);
                        if be & 7 != 6 {
                            return Ok((Loc::Parent, n));
                        }
                        let bm = self.cached((1, *file, (be >> 20) << 20), 1 << 20, false)?;
                        let first = (off / sector) % (chunk_ratio * block / sector);
                        let bit = |s: u64| bm.get((s / 8) as usize).map(|b| b >> (s % 8) & 1 == 1).unwrap_or(false);
                        let here = bit(first);
                        let mut s = 1;
                        while (off / sector + s) * sector < off + n && bit(first + s) == here {
                            s += 1;
                        }
                        let run = ((off / sector + s) * sector - off).min(n);
                        Ok((if here { Loc::Data { file: *file, off: at + within } } else { Loc::Parent }, run))
                    }
                    0 | 1 if *diff => Ok((Loc::Parent, n)),
                    _ => Ok((Loc::Zero, n)),
                }
            }
            Layer::Vmdk { extents } => {
                let i = extents.partition_point(|e| e.start + e.len <= off);
                let Some(e) = extents.get(i) else { return Ok((Loc::Zero, max)) };
                let within = off - e.start;
                let n = (e.len - within).min(max);
                match &e.kind {
                    ExtKind::Zero => Ok((Loc::Zero, n)),
                    ExtKind::Flat { file, off: base } => Ok((Loc::Data { file: *file, off: base + within }, n)),
                    ExtKind::Sparse { file, gd, grain, gtes, compressed } => {
                        let g = within / grain;
                        let n = (grain - within % grain).min(n);
                        let gt_sector = gd.get((g / gtes) as usize).copied().unwrap_or(0) as u64;
                        let parent = if lvl + 1 < self.disk.chain.len() { Loc::Parent } else { Loc::Zero };
                        if gt_sector == 0 {
                            return Ok((parent, n));
                        }
                        let gt = self.cached((2, *file, gt_sector * SECTOR), (*gtes * 4) as usize, false)?;
                        let gte = le32(&gt, ((g % gtes) * 4) as usize);
                        match gte {
                            0 => Ok((parent, n)),
                            1 => Ok((Loc::Zero, n)),
                            s if *compressed => Ok((Loc::Grain { file: *file, off: s * SECTOR, grain: *grain, within: within % grain }, n)),
                            s => Ok((Loc::Data { file: *file, off: s * SECTOR + within % grain }, n)),
                        }
                    }
                }
            }
        }
    }

    fn read_level(&mut self, lvl: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = off + done as u64;
            let (loc, n) = self.locate(lvl, at, (buf.len() - done) as u64)?;
            let n = (n.max(1) as usize).min(buf.len() - done);
            let out = &mut buf[done..done + n];
            match loc {
                Loc::Zero => out.fill(0),
                Loc::Parent => self.read_level(lvl + 1, at, out)?,
                Loc::Data { file, off } => {
                    let f = self.file(file)?;
                    let b = rd(f, off, n)?;
                    out[..b.len()].copy_from_slice(&b);
                    out[b.len()..].fill(0);
                }
                Loc::Grain { file, off, grain, within } => {
                    let g = self.cached((3, file, off), grain as usize, true)?;
                    let w = within as usize;
                    let have = g.len().saturating_sub(w).min(n);
                    out[..have].copy_from_slice(&g[w..w + have]);
                    out[have..].fill(0);
                }
            }
            done += n;
        }
        Ok(())
    }
}

impl Read for VDiskReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.disk.size || buf.is_empty() {
            return Ok(0);
        }
        let n = ((self.disk.size - self.pos) as usize).min(buf.len()).min(4 << 20);
        let pos = self.pos;
        self.read_level(0, pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for VDiskReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.disk.size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
    }

    fn whole(name: &str) -> (Vec<u8>, Arc<VDisk>) {
        let d = Arc::new(open(&fixture(name)).unwrap().unwrap_or_else(|| panic!("{} not recognized", name)));
        let mut r = d.reader();
        let mut out = vec![];
        r.read_to_end(&mut out).unwrap();
        (out, d)
    }

    fn expected() -> (Vec<u8>, Vec<u8>) {
        let base = std::fs::read(fixture("disk-fat.img")).unwrap();
        let mut patched = base.clone();
        let at = 0x21200;
        for i in 0..3 * 512 {
            patched[at + i] = ((i * 7 + 3) & 0xFF) as u8;
        }
        (base, patched)
    }

    #[test]
    fn every_format_reads_back_the_disk() {
        if !fixture("vd-dynamic.vhd").exists() {
            return;
        }
        let (base, patched) = expected();
        for (name, want, label) in [
            ("vd-dynamic.vhd", &base, "VHD (dynamic)"),
            ("vd-diff.vhd", &patched, "VHD (differencing) (+1 parent)"),
            ("vd-dynamic.vhdx", &base, "VHDX"),
            ("vd-diff.vhdx", &patched, "VHDX (differencing) (+1 parent)"),
            ("vd-sparse.vmdk", &base, "VMDK (monolithicSparse)"),
            ("vd-stream.vmdk", &base, "VMDK (streamOptimized)"),
            ("vd-flat.vmdk", &base, "VMDK (monolithicFlat)"),
            ("vd-split.vmdk", &base, "VMDK (twoGbMaxExtentSparse)"),
            ("vd-snap.vmdk", &patched, "VMDK (monolithicSparse) (+1 parent)"),
            // Written by VMware ovftool 4.4 (OVF export of vd-sparse.vmdk).
            ("vd-vmware-stream.vmdk", &base, "VMDK (streamOptimized)"),
        ] {
            let (got, d) = whole(name);
            assert_eq!(d.label, label, "{}", name);
            assert_eq!(d.size, base.len() as u64, "{}", name);
            assert!(got == *want, "{}: content differs at {:?}", name, got.iter().zip(want.iter()).position(|(a, b)| a != b));
            assert!(d.notes.is_empty(), "{}: {:?}", name, d.notes);
        }
        // Reads that start and end inside blocks, across the patch.
        let d = Arc::new(open(&fixture("vd-diff.vhdx")).unwrap().unwrap());
        let mut r = d.reader();
        let mut b = vec![0u8; 5000];
        r.seek(SeekFrom::Start(0x21000)).unwrap();
        r.read_exact(&mut b).unwrap();
        assert_eq!(b, patched[0x21000..0x21000 + 5000]);
    }

    #[test]
    fn not_a_virtual_disk() {
        assert!(open(&fixture("disk-fat.img")).unwrap().is_none());
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(guid_text(&guid("2DC27766-F623-4200-9D64-115E9BFD4A08")), "2DC27766-F623-4200-9D64-115E9BFD4A08");
    }
}
