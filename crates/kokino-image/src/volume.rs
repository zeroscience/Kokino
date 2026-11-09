//! Volume systems: bare filesystem, MBR (with extended partitions) and GPT.
//! Gaps between partitions are reported as unallocated regions.

use crate::read_at;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VolumeKind {
    Whole,
    Mbr,
    Gpt,
    Unallocated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FsKind {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ext,
    Apfs,
    HfsPlus,
    BitLocker,
    /// ISO 9660 (CD, DVD, .iso files), with Rock Ridge and Joliet when present.
    Iso9660,
    /// UDF without an ISO 9660 descriptor (most Blu-ray and some DVDs).
    Udf,
    /// A ZIP file added as evidence (triage collections: Velociraptor, KAPE).
    Zip,
    Unknown,
}

impl FsKind {
    pub fn label(&self) -> &'static str {
        match self {
            FsKind::Ntfs => "NTFS",
            FsKind::Fat12 => "FAT12",
            FsKind::Fat16 => "FAT16",
            FsKind::Fat32 => "FAT32",
            FsKind::ExFat => "exFAT",
            FsKind::Ext => "ext2/3/4",
            FsKind::Apfs => "APFS",
            FsKind::HfsPlus => "HFS+",
            FsKind::BitLocker => "BitLocker (encrypted)",
            FsKind::Iso9660 => "ISO 9660",
            FsKind::Udf => "UDF",
            FsKind::Zip => "ZIP",
            FsKind::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub index: usize,
    pub kind: VolumeKind,
    pub start: u64,
    pub length: u64,
    pub description: String,
    pub fs: FsKind,
    pub fs_label: String,
    pub supported: bool,
    /// Set when this volume is a Volume Shadow Copy of another: it is read
    /// through the snapshot, and its bytes have no single place in the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow: Option<ShadowRef>,
    /// Set when this volume is the decrypted view of a BitLocker volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitlocker: Option<BitLockerRef>,
}

impl Volume {
    /// Read through a transformation (shadow copy, decryption): its bytes
    /// are not at one place in the image as they are shown.
    pub fn is_virtual(&self) -> bool {
        self.shadow.is_some() || self.bitlocker.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BitLockerRef {
    /// The encrypted volume.
    pub of_volume: usize,
    pub method: String,
    /// How it was unlocked ("Password", "Recovery password", "Clear key").
    pub protector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowRef {
    /// The volume the shadow copy belongs to.
    pub of_volume: usize,
    /// 1 is the oldest store.
    pub store: usize,
    pub id: String,
    pub created: u64,
}

const SECTOR: u64 = 512;

pub fn detect_fs<R: Read + Seek>(r: &mut R, start: u64) -> FsKind {
    let mut b = [0u8; 2048];
    let n = read_at(r, start, &mut b).unwrap_or(0);
    if n < 512 {
        return FsKind::Unknown;
    }
    if &b[3..11] == b"NTFS    " {
        return FsKind::Ntfs;
    }
    // A ZIP added as evidence (only where the evidence starts).
    if start == 0 && (b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06")) {
        return FsKind::Zip;
    }
    // BitLocker To Go keeps a FAT32 boot record: the GUID tells it apart.
    if crate::bde::is_bitlocker(&b) {
        return FsKind::BitLocker;
    }
    if &b[3..11] == b"EXFAT   " {
        return FsKind::ExFat;
    }
    if &b[82..90] == b"FAT32   " {
        return FsKind::Fat32;
    }
    if &b[54..59] == b"FAT16" {
        return FsKind::Fat16;
    }
    if &b[54..59] == b"FAT12" {
        return FsKind::Fat12;
    }
    if &b[32..36] == b"NXSB" {
        return FsKind::Apfs;
    }
    if n >= 1082 && b[1080] == 0x53 && b[1081] == 0xEF {
        return FsKind::Ext;
    }
    if n >= 1026 && (&b[1024..1026] == b"H+" || &b[1024..1026] == b"HX") {
        return FsKind::HfsPlus;
    }
    // Optical: the volume recognition sequence starts at 32 KiB, one 2 KiB
    // descriptor after another. ISO 9660 has a primary descriptor (CD001);
    // UDF has BEA01, NSR02 or NSR03, TEA01.
    let mut vrs = [0u8; 2048 * 8];
    let got = read_at(r, start + 32768, &mut vrs).unwrap_or(0);
    let ids: Vec<&[u8]> = vrs[..got].chunks(2048).filter(|d| d.len() >= 6).map(|d| &d[1..6]).collect();
    if ids.iter().any(|id| *id == b"CD001") {
        return FsKind::Iso9660;
    }
    if ids.iter().any(|id| *id == b"NSR02" || *id == b"NSR03") && ids.iter().any(|id| *id == b"BEA01") {
        return FsKind::Udf;
    }
    FsKind::Unknown
}

pub(crate) fn mk(index: usize, kind: VolumeKind, start: u64, length: u64, description: String, fs: FsKind) -> Volume {
    Volume {
        index,
        kind,
        start,
        length,
        description,
        fs,
        fs_label: fs.label().to_string(),
        supported: matches!(fs, FsKind::Ntfs | FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 | FsKind::ExFat | FsKind::Ext | FsKind::Iso9660 | FsKind::Udf | FsKind::HfsPlus | FsKind::Apfs),
        shadow: None,
        bitlocker: None,
    }
}

/// Partitions (or a whole-disk file system) and gaps, then the Volume
/// Shadow Copies of each NTFS volume as volumes of their own.
pub fn detect_volumes<R: Read + Seek>(r: &mut R, size: u64) -> Vec<Volume> {
    let mut vols = detect_partitions(r, size);
    // Volume Shadow Copies of NTFS volumes, each as a volume of its own.
    let mut shadows = vec![];
    for v in vols.iter().filter(|v| v.fs == FsKind::Ntfs) {
        let mut sub = crate::SubReader::new(&mut *r, v.start, v.length);
        for s in crate::vss::stores(&mut sub, v.length) {
            let day = chrono::DateTime::from_timestamp(((s.created / 10_000_000) as i64).saturating_sub(11_644_473_600), 0).map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
            let mut sv = mk(0, v.kind, v.start, if s.volume_size > 0 { s.volume_size.min(v.length) } else { v.length }, format!("Shadow copy {} of volume {}, created {}", s.index, v.index, day), FsKind::Ntfs);
            sv.fs_label = "NTFS (shadow copy)".into();
            sv.shadow = Some(ShadowRef { of_volume: v.index, store: s.index, id: s.id.clone(), created: s.created });
            shadows.push(sv);
        }
    }
    let n = vols.len();
    for (k, mut sv) in shadows.into_iter().enumerate() {
        sv.index = n + k;
        vols.push(sv);
    }
    vols
}

fn detect_partitions<R: Read + Seek>(r: &mut R, size: u64) -> Vec<Volume> {
    let mut found: Vec<Volume> = vec![];

    let whole_fs = detect_fs(r, 0);
    if whole_fs != FsKind::Unknown {
        found.push(mk(0, VolumeKind::Whole, 0, size, "Volume (no partition table)".into(), whole_fs));
        return found;
    }

    let mut mbr = [0u8; 512];
    if read_at(r, 0, &mut mbr).unwrap_or(0) == 512 && mbr[510] == 0x55 && mbr[511] == 0xAA {
        let entries = mbr_entries(&mbr);
        if entries.iter().any(|e| e.0 == 0xEE) {
            found.extend(gpt(r, size));
        } else {
            for (ptype, lba, count) in entries {
                if ptype == 0x05 || ptype == 0x0F || ptype == 0x85 {
                    found.extend(ebr_chain(r, lba as u64 * SECTOR));
                } else if ptype != 0 && count > 0 {
                    let start = lba as u64 * SECTOR;
                    let fs = detect_fs(r, start);
                    found.push(mk(0, VolumeKind::Mbr, start, count as u64 * SECTOR, format!("MBR type 0x{:02X} ({})", ptype, mbr_type_name(ptype)), fs));
                }
            }
        }
    }

    found.sort_by_key(|v| v.start);
    found.retain(|v| v.start < size);
    let mut with_gaps = vec![];
    let mut cursor = 0u64;
    for v in found {
        if v.start > cursor && v.start - cursor >= 1024 * 1024 {
            with_gaps.push(mk(0, VolumeKind::Unallocated, cursor, v.start - cursor, "Unallocated".into(), FsKind::Unknown));
        }
        cursor = cursor.max(v.start + v.length);
        with_gaps.push(v);
    }
    if size > cursor && size - cursor >= 1024 * 1024 {
        with_gaps.push(mk(0, VolumeKind::Unallocated, cursor, size - cursor, "Unallocated".into(), FsKind::Unknown));
    }
    for (i, v) in with_gaps.iter_mut().enumerate() {
        v.index = i;
    }
    with_gaps
}

fn mbr_entries(sector: &[u8; 512]) -> Vec<(u8, u32, u32)> {
    (0..4)
        .map(|i| {
            let e = &sector[446 + i * 16..446 + (i + 1) * 16];
            (e[4], u32::from_le_bytes(e[8..12].try_into().unwrap()), u32::from_le_bytes(e[12..16].try_into().unwrap()))
        })
        .collect()
}

fn ebr_chain<R: Read + Seek>(r: &mut R, ext_start: u64) -> Vec<Volume> {
    let mut out = vec![];
    let mut ebr_off = ext_start;
    for _ in 0..128 {
        let mut s = [0u8; 512];
        if read_at(r, ebr_off, &mut s).unwrap_or(0) != 512 || s[510] != 0x55 || s[511] != 0xAA {
            break;
        }
        let e = mbr_entries(&s);
        let (t, lba, cnt) = e[0];
        if t != 0 && cnt > 0 {
            let start = ebr_off + lba as u64 * SECTOR;
            let fs = detect_fs(r, start);
            out.push(mk(0, VolumeKind::Mbr, start, cnt as u64 * SECTOR, format!("Logical, type 0x{:02X} ({})", t, mbr_type_name(t)), fs));
        }
        let (nt, nlba, _) = e[1];
        if nt == 0 || nlba == 0 {
            break;
        }
        ebr_off = ext_start + nlba as u64 * SECTOR;
    }
    out
}

fn gpt<R: Read + Seek>(r: &mut R, size: u64) -> Vec<Volume> {
    let mut out = vec![];
    for sector in [512u64, 4096] {
        let mut h = [0u8; 92];
        if read_at(r, sector, &mut h).unwrap_or(0) != 92 || &h[..8] != b"EFI PART" {
            continue;
        }
        let entries_lba = u64::from_le_bytes(h[72..80].try_into().unwrap());
        let count = u32::from_le_bytes(h[80..84].try_into().unwrap()).min(1024);
        let esize = u32::from_le_bytes(h[84..88].try_into().unwrap()).clamp(128, 4096) as u64;
        let mut table = vec![0u8; (count as u64 * esize) as usize];
        if read_at(r, entries_lba * sector, &mut table).is_err() {
            continue;
        }
        for i in 0..count as usize {
            let e = &table[i * esize as usize..(i + 1) * esize as usize];
            if e[..16].iter().all(|b| *b == 0) {
                continue;
            }
            let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
            let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
            if last < first {
                continue;
            }
            let name: String = char::decode_utf16(e[56..128].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|c| *c != 0))
                .map(|c| c.unwrap_or('?'))
                .collect();
            let start = first * sector;
            if start >= size {
                continue;
            }
            let fs = detect_fs(r, start);
            let label = gpt_type_name(&e[..16]);
            let desc = if name.is_empty() { format!("GPT {}", label) } else { format!("GPT {} \"{}\"", label, name) };
            out.push(mk(0, VolumeKind::Gpt, start, (last - first + 1) * sector, desc, fs));
        }
        break;
    }
    out
}

fn gpt_type_name(guid: &[u8]) -> &'static str {
    // GUIDs are stored mixed-endian; compare against on-disk byte order.
    const BASIC: [u8; 16] = [0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7];
    const ESP: [u8; 16] = [0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B];
    const MSR: [u8; 16] = [0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE];
    const WINRE: [u8; 16] = [0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC];
    match guid {
        g if g == BASIC => "Basic data",
        g if g == ESP => "EFI System",
        g if g == MSR => "Microsoft Reserved",
        g if g == WINRE => "Windows Recovery",
        _ => "partition",
    }
}

fn mbr_type_name(t: u8) -> &'static str {
    match t {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x07 => "NTFS/exFAT",
        0x0B | 0x0C => "FAT32",
        0x27 => "Windows RE",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xAF => "HFS+",
        _ => "other",
    }
}
