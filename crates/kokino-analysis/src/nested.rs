//! Disk images stored on the evidence (a VHD on a seized laptop, an E01 on
//! an external disk, an ISO in a download folder): found by their headers,
//! with the other files that belong to them (E02, E03 ... segments, the
//! .002 ... parts of a split raw image, the extents of a VMDK), so they can
//! be extracted and examined as evidence of their own.

use crate::FileRow;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Nested {
    /// The image's first (or only) file, as an index into the file list.
    pub file: u32,
    pub path: String,
    /// "E01", "VHD", "VHDX", "VMDK", "AFF4", "AD1", "ISO 9660", "Raw disk", "QCOW"...
    pub format: String,
    /// Bytes of all its files.
    pub size: u64,
    /// Every file of the image, the first one first.
    pub parts: Vec<u32>,
    pub deleted: bool,
    /// Kokino can open this format once extracted.
    pub supported: bool,
    pub note: String,
}

/// The image format from the start (at least 0x8006 bytes for ISO) and the
/// last 512 bytes of a file. `ext` is the lowercase extension.
pub fn probe(head: &[u8], tail: &[u8], ext: &str) -> Option<(&'static str, bool)> {
    if head.starts_with(b"EVF\x09\x0d\x0a\xff\x00") {
        // Only the first segment names the image.
        return (head.get(9..11) == Some(&[1, 0])).then_some(("E01", true));
    }
    if head.starts_with(b"EVF2\x0d\x0a\x81\x00") {
        // Only the first segment names the image.
        return (head.get(12..16) == Some(&[1, 0, 0, 0])).then_some(("Ex01", true));
    }
    if head.starts_with(b"vhdxfile") {
        return Some(("VHDX", true));
    }
    if head.starts_with(b"KDMV") {
        return Some(("VMDK", true));
    }
    if head.starts_with(b"# Disk DescriptorFile") {
        return Some(("VMDK", true));
    }
    if head.starts_with(b"conectix") || tail.starts_with(b"conectix") {
        return Some(("VHD", true));
    }
    if head.starts_with(b"QFI\xfb") {
        return Some(("QCOW", false));
    }
    if head.starts_with(b"ADSEGMENTEDFILE") {
        // Only the first segment names the image.
        return (head.get(24..28) == Some(&[1, 0, 0, 0])).then_some(("AD1", true));
    }
    if ext == "aff4" && head.starts_with(b"PK") {
        return Some(("AFF4", true));
    }
    if head.get(0x8001..0x8006) == Some(b"CD001") {
        return Some(("ISO 9660", true));
    }
    // Raw images only by their usual extensions, and only with a partition
    // table or a file system boot sector at the start.
    if matches!(ext, "dd" | "raw" | "img" | "001" | "bin" | "ima") {
        let mbr = head.get(510..512) == Some(&[0x55, 0xAA]);
        let fs = head.get(3..11) == Some(b"NTFS    ") || head.get(3..11) == Some(b"EXFAT   ") || head.get(1080..1082) == Some(&[0x53, 0xEF]);
        if mbr || fs {
            return Some(("Raw disk", true));
        }
    }
    None
}

fn ext_of(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

fn stem_of(name: &str) -> String {
    name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name).to_ascii_lowercase()
}

/// The other files of an image in the same folder: E02..EZZ segments,
/// .002.. parts, VMDK extents named after the descriptor.
pub fn parts(files: &[FileRow], first: usize, format: &str) -> Vec<u32> {
    let f = &files[first];
    let stem = stem_of(&f.e.name);
    let mut out = vec![first as u32];
    let mut more: Vec<(String, u32)> = files
        .iter()
        .enumerate()
        .filter(|(i, g)| *i != first && !g.e.is_dir && g.e.parent == f.e.parent && g.e.deleted == f.e.deleted)
        .filter(|(_, g)| {
            let (gs, ge) = (stem_of(&g.e.name), ext_of(&g.e.name));
            match format {
                "E01" => gs == stem && ge.len() == 3 && ge.starts_with('e') && ge != "e01" && ge[1..].chars().all(|c| c.is_ascii_alphanumeric()),
                "Raw disk" if ext_of(&f.e.name) == "001" => gs == stem && ge.len() == 3 && ge.chars().all(|c| c.is_ascii_digit()) && ge != "001",
                "VMDK" => ge == "vmdk" && gs != stem && gs.starts_with(&format!("{}-", stem)),
                "Ex01" => gs == stem && ge.len() == 4 && ge.starts_with('e') && ge != "ex01" && ge[1..].chars().all(|c| c.is_ascii_alphanumeric()),
                "AD1" => gs == stem && ge.starts_with("ad") && ge != "ad1" && ge.len() > 2 && ge[2..].chars().all(|c| c.is_ascii_digit()),
                _ => false,
            }
        })
        .map(|(i, g)| (g.e.name.to_ascii_lowercase(), i as u32))
        .collect();
    more.sort();
    out.extend(more.into_iter().map(|(_, i)| i));
    out
}

/// Disk images among the files. `read(entry, offset, len)` reads file bytes.
pub fn find(files: &[FileRow], read: &mut dyn FnMut(&kokino_ntfs::FsEntry, u64, usize) -> Vec<u8>) -> Vec<Nested> {
    let mut out = vec![];
    for (i, f) in files.iter().enumerate() {
        if f.e.is_dir || f.e.size < 2048 {
            continue;
        }
        let ext = ext_of(&f.e.name);
        let cat = f.sig.as_deref().unwrap_or("");
        let likely = matches!(cat, "vhdx" | "vmdk" | "ewf" | "iso" | "qcow")
            || matches!(ext.as_str(), "vhd" | "vhdx" | "avhdx" | "vmdk" | "e01" | "ex01" | "iso" | "dd" | "raw" | "img" | "001" | "bin" | "ima" | "qcow" | "qcow2" | "ad1" | "aff4");
        if !likely {
            continue;
        }
        let head = read(&f.e, 0, 0x8006.min(f.e.size as usize));
        let tail = if f.e.size >= 512 { read(&f.e, f.e.size - 512, 512) } else { vec![] };
        let Some((format, supported)) = probe(&head, &tail, &ext) else { continue };
        let parts = parts(files, i, format);
        let size = parts.iter().map(|&p| files[p as usize].e.size).sum();
        let mut note = String::new();
        if format == "VMDK" && head.starts_with(b"# Disk DescriptorFile") && parts.len() == 1 {
            note = "a VMDK descriptor without extent files beside it".into();
        }
        if !supported {
            note = format!("{} is not read by Kokino yet", format);
        }
        out.push(Nested { file: i as u32, path: f.e.path.clone(), format: format.into(), size, parts, deleted: f.e.deleted, supported, note });
        if out.len() >= 10_000 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parts() {
        let mut ewf = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00".to_vec();
        ewf.resize(4096, 0);
        assert_eq!(probe(&ewf, &[], "e01"), Some(("E01", true)));
        ewf[9] = 2;
        assert_eq!(probe(&ewf, &[], "e02"), None);
        let mut iso = vec![0u8; 0x8006];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(probe(&iso, &[], "iso"), Some(("ISO 9660", true)));
        assert_eq!(probe(b"plain", b"conectix\0\0", "vhd"), Some(("VHD", true)));
        let mut mbr = vec![0u8; 4096];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(probe(&mbr, &[], "dd"), Some(("Raw disk", true)));
        assert_eq!(probe(&mbr, &[], "txt"), None);
        assert_eq!(probe(b"QFI\xfb rest", &[], "qcow2"), Some(("QCOW", false)));

        let row = |rec: u64, name: &str| {
            let mut r = crate::antiforensics::tests::row(rec, &format!("/Images/{name}"), false, 0, None);
            r.e.parent = 40;
            r.e.size = 10_000;
            r
        };
        let files = vec![row(1, "case.E01"), row(2, "case.E03"), row(3, "case.E02"), row(4, "other.E02"), row(5, "disk.vmdk"), row(6, "disk-flat.vmdk"), row(7, "disk.001"), row(8, "disk.002")];
        assert_eq!(parts(&files, 0, "E01"), vec![0, 2, 1]);
        assert_eq!(parts(&files, 4, "VMDK"), vec![4, 5]);
        assert_eq!(parts(&files, 6, "Raw disk"), vec![6, 7]);
        let mut read = |e: &kokino_ntfs::FsEntry, off: u64, n: usize| -> Vec<u8> {
            if off > 0 {
                return vec![0; n];
            }
            match e.record {
                1 => { let mut h = b"EVF\x09\x0d\x0a\xff\x00\x01\x01\x00".to_vec(); h.resize(n, 0); h }
                5 => { let mut h = b"# Disk DescriptorFile\n".to_vec(); h.resize(n, 0); h }
                7 => mbr.clone(),
                _ => vec![0; n],
            }
        };
        let found: Vec<(String, String, usize, u64)> = find(&files, &mut read).into_iter().map(|n| (n.path, n.format, n.parts.len(), n.size)).collect();
        let want = [("/Images/case.E01", "E01", 3, 30_000), ("/Images/disk.vmdk", "VMDK", 2, 20_000), ("/Images/disk.001", "Raw disk", 2, 20_000)];
        assert_eq!(found, want.iter().map(|(p, f, n, s)| (p.to_string(), f.to_string(), *n, *s)).collect::<Vec<_>>());
    }
}
