//! Windows Prefetch (.pf) files: proof that a program ran, how often, and
//! the last up to eight run times (Windows 8+), plus the files and volumes
//! it touched in its first seconds.
//!
//! Formats: version 17 (XP / 2003), 23 (Vista / 7), 26 (8.1) and 30
//! (10 / 11). Windows 8.1+ files are usually wrapped in "MAM" compression
//! (LZXPRESS Huffman), which is undone first.

use crate::bin::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Prefetch {
    pub version: u32,
    pub compressed: bool,
    pub executable: String,
    /// Path hash in the file name, as 8 hex digits.
    pub hash: String,
    pub run_count: u32,
    /// Newest first, zeros removed.
    pub last_runs: Vec<u64>,
    /// Full path of the executable when one of the referenced files ends with
    /// its name.
    pub path: Option<String>,
    pub files: Vec<String>,
    pub volumes: Vec<PfVolume>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PfVolume {
    pub device: String,
    pub serial: String,
    pub created: u64,
}

pub fn parse(raw: &[u8]) -> anyhow::Result<Prefetch> {
    let (d, compressed) = if raw.starts_with(b"MAM") {
        let algo = raw.get(3).copied().unwrap_or(0) & 0x0F;
        if algo != 4 {
            anyhow::bail!("MAM compression {} not supported", algo);
        }
        let size = u32_at(raw, 4).ok_or_else(|| anyhow::anyhow!("truncated MAM header"))? as usize;
        // Flag 0x80: a CRC32 follows the size (not checked here).
        let start = if raw[3] & 0x80 != 0 { 12 } else { 8 };
        (crate::xpress::decompress(raw.get(start..).unwrap_or(&[]), size)?, true)
    } else {
        (raw.to_vec(), false)
    };
    if d.get(4..8) != Some(b"SCCA") {
        anyhow::bail!("not a Prefetch file (no SCCA signature)");
    }
    let version = u32_at(&d, 0).unwrap_or(0);
    let (last_off, last_n, count_off, vol_entry) = match version {
        17 => (0x78, 1, 0x90, 40),
        23 => (0x80, 1, 0x98, 104),
        26 => (0x80, 8, 0xD0, 104),
        30 | 31 => {
            // Two Windows 10 layouts: newer builds drop 8 bytes before the
            // run count. The metrics array follows the file information, so
            // its offset tells them apart.
            let metrics = u32_at(&d, 0x54).unwrap_or(0);
            (0x80, 8, if metrics == 0x128 { 0xC8 } else { 0xD0 }, 96)
        }
        v => anyhow::bail!("Prefetch version {} not supported", v),
    };
    let mut pf = Prefetch {
        version,
        compressed,
        executable: utf16(slice(&d, 0x10, 60).unwrap_or(&[])),
        hash: format!("{:08X}", u32_at(&d, 0x4C).unwrap_or(0)),
        run_count: u32_at(&d, count_off).unwrap_or(0),
        ..Default::default()
    };
    let mut runs: Vec<u64> = (0..last_n).filter_map(|i| u64_at(&d, last_off + 8 * i)).filter(|&t| plausible(t) > 0).collect();
    runs.sort_unstable_by(|a, b| b.cmp(a));
    pf.last_runs = runs;

    // Referenced file names: a block of NUL-terminated UTF-16 strings.
    let (fo, fs) = (u32_at(&d, 0x64).unwrap_or(0) as usize, u32_at(&d, 0x68).unwrap_or(0) as usize);
    if let Some(block) = slice(&d, fo, fs) {
        let w: Vec<u16> = block.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        pf.files = w.split(|&u| u == 0).filter(|s| !s.is_empty()).take(4096).map(String::from_utf16_lossy).collect();
    }
    let exe = pf.executable.to_ascii_uppercase();
    pf.path = pf.files.iter().find(|f| !exe.is_empty() && f.to_ascii_uppercase().ends_with(&format!("\\{}", exe))).cloned();

    let (vo, vn) = (u32_at(&d, 0x6C).unwrap_or(0) as usize, u32_at(&d, 0x70).unwrap_or(0) as usize);
    for i in 0..vn.min(64) {
        let e = vo + i * vol_entry;
        let (Some(po), Some(pl)) = (u32_at(&d, e), u32_at(&d, e + 4)) else { break };
        pf.volumes.push(PfVolume {
            device: utf16(slice(&d, vo + po as usize, 2 * pl as usize).unwrap_or(&[])),
            created: plausible(u64_at(&d, e + 8).unwrap_or(0)),
            serial: format!("{:08X}", u32_at(&d, e + 16).unwrap_or(0)),
        });
    }
    Ok(pf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<Vec<u8>> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win").join(name)).ok()
    }

    #[test]
    fn win10_compressed_prefetch() {
        let Some(raw) = fixture("SDELETE64.EXE-1A2B3C4D.pf") else { return };
        assert!(raw.starts_with(b"MAM\x04"));
        let pf = parse(&raw).unwrap();
        assert_eq!((pf.version, pf.compressed, pf.executable.as_str(), pf.hash.as_str(), pf.run_count), (30, true, "SDELETE64.EXE", "1A2B3C4D", 3));
        assert_eq!(pf.last_runs.len(), 3);
        assert!(pf.last_runs.windows(2).all(|w| w[0] > w[1]));
        assert_eq!(pf.path.as_deref(), Some("\\VOLUME{01d4a1b2c3d4e5f6-5a6b7c8d}\\USERS\\ALICE\\SDELETE64.EXE"));
        assert_eq!(pf.volumes[0].serial, "5A6B7C8D");
    }

    #[test]
    fn win7_uncompressed_prefetch() {
        let Some(raw) = fixture("CMD.EXE-4A81B364.pf") else { return };
        let pf = parse(&raw).unwrap();
        assert_eq!((pf.version, pf.compressed, pf.executable.as_str(), pf.run_count, pf.last_runs.len()), (23, false, "CMD.EXE", 12, 1));
        assert!(pf.files.iter().any(|f| f.ends_with("\\SYSTEM32\\CMD.EXE")));
    }

    #[test]
    fn rejects_other_files() {
        assert!(parse(b"MZ\x90\0").is_err());
        assert!(parse(b"MAM\x04\x10\0\0\0garbage").is_err());
    }
}
