//! Windows shortcut (.lnk, [MS-SHLLINK]) files, as created for every file a
//! user opens (Recent folder, Jump Lists, Office recent files).
//!
//! What matters forensically: the target path (local or network), the
//! target's own created / accessed / written times and size at the moment
//! the shortcut was last updated, the volume serial number, label and drive
//! type, and the tracker block with the NetBIOS name and (for time-based
//! object IDs) the MAC address of the machine where the target lived.

use crate::bin::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Lnk {
    pub target: String,
    pub arguments: String,
    pub working_dir: String,
    pub description: String,
    pub relative_path: String,
    pub icon: String,
    pub target_created: u64,
    pub target_accessed: u64,
    pub target_written: u64,
    pub target_size: u32,
    pub target_attributes: u32,
    /// fixed, removable, network, cdrom, ramdisk, unknown
    pub drive_type: String,
    pub volume_serial: String,
    pub volume_label: String,
    pub network_share: String,
    pub machine_id: String,
    pub mac: String,
    pub droid_volume: String,
    pub droid_file: String,
}

const LNK_CLSID: [u8; 16] = [0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];

pub fn is_lnk(d: &[u8]) -> bool {
    u32_at(d, 0) == Some(0x4C) && d.get(4..20) == Some(&LNK_CLSID)
}

pub fn parse(d: &[u8]) -> anyhow::Result<Lnk> {
    if !is_lnk(d) || d.len() < 0x4C {
        anyhow::bail!("not a shortcut (bad or truncated header)");
    }
    let flags = u32_at(d, 20).unwrap_or(0);
    let mut l = Lnk {
        target_attributes: u32_at(d, 24).unwrap_or(0),
        target_created: plausible(u64_at(d, 28).unwrap_or(0)),
        target_accessed: plausible(u64_at(d, 36).unwrap_or(0)),
        target_written: plausible(u64_at(d, 44).unwrap_or(0)),
        target_size: u32_at(d, 52).unwrap_or(0),
        ..Default::default()
    };
    let mut p = 0x4C;
    let mut idlist_path = String::new();
    if flags & 0x01 != 0 {
        let n = u16_at(d, p).unwrap_or(0) as usize;
        idlist_path = shell_items_path(slice(d, p + 2, n).unwrap_or(&[]));
        p += 2 + n;
    }
    let (mut local, mut suffix) = (String::new(), String::new());
    if flags & 0x02 != 0 {
        let li = p;
        let size = u32_at(d, li).unwrap_or(0) as usize;
        let hsize = u32_at(d, li + 4).unwrap_or(0) as usize;
        let lflags = u32_at(d, li + 8).unwrap_or(0);
        let vol = u32_at(d, li + 12).unwrap_or(0) as usize;
        let lbp = u32_at(d, li + 16).unwrap_or(0) as usize;
        let cnr = u32_at(d, li + 20).unwrap_or(0) as usize;
        let cps = u32_at(d, li + 24).unwrap_or(0) as usize;
        if lflags & 1 != 0 && vol > 0 {
            let v = li + vol;
            l.drive_type = match u32_at(d, v + 4).unwrap_or(0) {
                2 => "removable",
                3 => "fixed",
                4 => "network",
                5 => "cdrom",
                6 => "ramdisk",
                _ => "unknown",
            }
            .into();
            l.volume_serial = format!("{:08X}", u32_at(d, v + 8).unwrap_or(0));
            let lo = u32_at(d, v + 12).unwrap_or(0) as usize;
            l.volume_label = if lo == 0x14 { utf16z(d, v + u32_at(d, v + 16).unwrap_or(0) as usize, 260) } else { ansiz(d, v + lo, 260) };
            local = if hsize >= 0x24 && u32_at(d, li + 28).unwrap_or(0) > 0 {
                utf16z(d, li + u32_at(d, li + 28).unwrap_or(0) as usize, 32_767)
            } else {
                ansiz(d, li + lbp, 32_767)
            };
        }
        if lflags & 2 != 0 && cnr > 0 {
            let c = li + cnr;
            let net = u32_at(d, c + 8).unwrap_or(0) as usize;
            l.network_share = ansiz(d, c + net, 32_767);
        }
        if cps > 0 {
            suffix = if hsize >= 0x24 && u32_at(d, li + 32).unwrap_or(0) > 0 {
                utf16z(d, li + u32_at(d, li + 32).unwrap_or(0) as usize, 32_767)
            } else {
                ansiz(d, li + cps, 32_767)
            };
        }
        p += size.max(4);
    }
    let unicode = flags & 0x80 != 0;
    let string = |p: &mut usize| -> String {
        let n = u16_at(d, *p).unwrap_or(0) as usize;
        let bytes = if unicode { 2 * n } else { n };
        let s = slice(d, *p + 2, bytes).map(|b| if unicode { utf16(b) } else { ansi(b) }).unwrap_or_default();
        *p += 2 + bytes;
        s
    };
    if flags & 0x04 != 0 {
        l.description = string(&mut p);
    }
    if flags & 0x08 != 0 {
        l.relative_path = string(&mut p);
    }
    if flags & 0x10 != 0 {
        l.working_dir = string(&mut p);
    }
    if flags & 0x20 != 0 {
        l.arguments = string(&mut p);
    }
    if flags & 0x40 != 0 {
        l.icon = string(&mut p);
    }
    let mut env_target = String::new();
    // Extra data blocks until a terminal block (size < 4).
    for _ in 0..64 {
        let size = u32_at(d, p).unwrap_or(0) as usize;
        if size < 8 {
            break;
        }
        match u32_at(d, p + 4).unwrap_or(0) {
            0xA000_0003 => {
                l.machine_id = ansiz(d, p + 16, 16);
                let droid = slice(d, p + 32, 32).unwrap_or(&[]);
                if droid.len() == 32 {
                    l.droid_volume = guid(&droid[..16]);
                    l.droid_file = guid(&droid[16..]);
                    l.mac = uuid_v1_node(&droid[16..]).unwrap_or_default();
                }
            }
            0xA000_0001 => {
                env_target = utf16z(d, p + 268, 260);
                if env_target.is_empty() {
                    env_target = ansiz(d, p + 8, 260);
                }
            }
            _ => {}
        }
        p += size;
    }
    l.target = if !local.is_empty() {
        if suffix.is_empty() { local } else { format!("{}{}{}", local, if local.ends_with('\\') { "" } else { "\\" }, suffix) }
    } else if !l.network_share.is_empty() {
        format!("{}\\{}", l.network_share, suffix)
    } else if !env_target.is_empty() {
        env_target
    } else if !idlist_path.is_empty() {
        idlist_path
    } else {
        l.relative_path.clone()
    };
    Ok(l)
}

/// Path from a shell item list: drive, folder and file items, or a URI item
/// (documents opened from OneDrive, SharePoint or the web). Other kinds
/// (control panel, network places) are skipped.
pub fn shell_items_path(d: &[u8]) -> String {
    let mut parts: Vec<String> = vec![];
    let mut p = 0;
    for _ in 0..256 {
        let size = u16_at(d, p).unwrap_or(0) as usize;
        if size < 3 || p + size > d.len() {
            break;
        }
        let item = &d[p..p + size];
        let ty = item[2];
        if ty & 0x70 == 0x20 {
            // volume: "C:\"
            let s = ansiz(item, 3, 20);
            if !s.is_empty() {
                parts.clear();
                parts.push(s.trim_end_matches('\\').to_string());
            }
        } else if ty == 0x61 {
            // URI: flags, 32-bit data size, data, then the URI (UTF-16
            // when flag 0x80)
            let flags = item.get(3).copied().unwrap_or(0);
            let at = 8usize.saturating_add(u32_at(item, 4).unwrap_or(0) as usize);
            let uri = if flags & 0x80 != 0 { utf16z(item, at, 4096) } else { ansiz(item, at, 4096) };
            if !uri.is_empty() {
                return uri;
            }
        } else if ty & 0x70 == 0x30 {
            // file or folder: 8.3 name, long name in the 0xBEEF0004 extension
            let short = ansiz(item, 14, 260);
            parts.push(long_name(item).unwrap_or(short));
        }
        p += size;
    }
    parts.join("\\")
}

pub(crate) fn long_name(item: &[u8]) -> Option<String> {
    let at = item.windows(4).position(|w| w == [0x04, 0x00, 0xEF, 0xBE])?.checked_sub(4)?;
    let version = u16_at(item, at + 2)?;
    let off = match version {
        3 => 0x14,
        7 => 0x26,
        8 => 0x2A,
        v if v >= 9 => 0x2E,
        _ => return None,
    };
    let s = utf16z(item, at + off, 260);
    (!s.is_empty() && s.chars().all(|c| !c.is_control())).then_some(s)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Shortcut writer for tests and fixtures: local target with volume info,
    /// a description, arguments and a tracker block.
    pub fn write(target: &str, serial: u32, label: &str, times: [u64; 3], size: u32, machine: &str, object_id: [u8; 16], drive_type: u32) -> Vec<u8> {
        let mut d = vec![0u8; 0x4C];
        d[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        d[4..20].copy_from_slice(&LNK_CLSID);
        let flags: u32 = 0x02 | 0x04 | 0x20 | 0x80;
        d[20..24].copy_from_slice(&flags.to_le_bytes());
        d[24..28].copy_from_slice(&0x20u32.to_le_bytes());
        for (i, t) in times.iter().enumerate() {
            d[28 + 8 * i..36 + 8 * i].copy_from_slice(&t.to_le_bytes());
        }
        d[52..56].copy_from_slice(&size.to_le_bytes());
        // LinkInfo with VolumeID + LocalBasePath (ANSI)
        let mut vol = vec![];
        vol.extend_from_slice(&0u32.to_le_bytes());
        vol.extend_from_slice(&drive_type.to_le_bytes());
        vol.extend_from_slice(&serial.to_le_bytes());
        vol.extend_from_slice(&0x10u32.to_le_bytes());
        vol.extend_from_slice(label.as_bytes());
        vol.push(0);
        let vlen = vol.len() as u32;
        vol[0..4].copy_from_slice(&vlen.to_le_bytes());
        let hsize = 0x1Cusize;
        let vol_off = hsize;
        let lbp_off = vol_off + vol.len();
        let mut li = vec![0u8; hsize];
        li.extend_from_slice(&vol);
        li.extend_from_slice(target.as_bytes());
        li.push(0);
        let cps_off = li.len();
        li.push(0);
        let total = li.len() as u32;
        li[0..4].copy_from_slice(&total.to_le_bytes());
        li[4..8].copy_from_slice(&(hsize as u32).to_le_bytes());
        li[8..12].copy_from_slice(&1u32.to_le_bytes());
        li[12..16].copy_from_slice(&(vol_off as u32).to_le_bytes());
        li[16..20].copy_from_slice(&(lbp_off as u32).to_le_bytes());
        li[24..28].copy_from_slice(&(cps_off as u32).to_le_bytes());
        d.extend_from_slice(&li);
        for s in ["Opened by test", "--secure"] {
            d.extend_from_slice(&(s.encode_utf16().count() as u16).to_le_bytes());
            for u in s.encode_utf16() {
                d.extend_from_slice(&u.to_le_bytes());
            }
        }
        // TrackerDataBlock
        let mut t = vec![0u8; 0x60];
        t[0..4].copy_from_slice(&0x60u32.to_le_bytes());
        t[4..8].copy_from_slice(&0xA000_0003u32.to_le_bytes());
        t[8..12].copy_from_slice(&0x58u32.to_le_bytes());
        t[16..16 + machine.len()].copy_from_slice(machine.as_bytes());
        t[32..48].copy_from_slice(&[0x22; 16]);
        t[48..64].copy_from_slice(&object_id);
        t[64..96].copy_from_slice(&[0x33; 32]);
        d.extend_from_slice(&t);
        d.extend_from_slice(&0u32.to_le_bytes());
        d
    }

    pub const OBJ_V1: [u8; 16] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0x11, 0x80, 0x01, 0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef];

    #[test]
    fn shell_item_paths() {
        let mut ids = vec![];
        let mut item = |body: Vec<u8>| {
            ids.extend_from_slice(&((body.len() + 2) as u16).to_le_bytes());
            ids.extend_from_slice(&body);
        };
        item([vec![0x1F, 0x50], vec![0; 16]].concat()); // My Computer (GUID item, skipped)
        item([vec![0x2F], b"E:\\".to_vec(), vec![0; 19]].concat());
        // folder item with a version 9 long-name extension
        let mut f = vec![0x31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0];
        f.extend_from_slice(b"PROJEC~1\0\0");
        let ext_start = f.len();
        let mut ext = vec![0u8; 0x2E];
        ext[2..4].copy_from_slice(&9u16.to_le_bytes());
        ext[4..8].copy_from_slice(&0xBEEF_0004u32.to_le_bytes());
        for u in "Projects 2026".encode_utf16().chain([0]) {
            ext.extend_from_slice(&u.to_le_bytes());
        }
        let n = ext.len() as u16;
        ext[0..2].copy_from_slice(&n.to_le_bytes());
        f.extend_from_slice(&ext);
        let _ = ext_start;
        item(f);
        item([vec![0x32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0], b"PLAN.TXT\0\0".to_vec()].concat());
        ids.extend_from_slice(&[0, 0]);
        assert_eq!(shell_items_path(&ids), "E:\\Projects 2026\\PLAN.TXT");
        let mut uri = vec![0x1F, 0x50];
        uri.extend_from_slice(&[0; 16]);
        let mut ids = vec![];
        ids.extend_from_slice(&((uri.len() + 2) as u16).to_le_bytes());
        ids.extend_from_slice(&uri);
        let mut u = vec![0x61, 0x80];
        u.extend_from_slice(&4u32.to_le_bytes());
        u.extend_from_slice(&[9; 4]);
        for c in "https://example.test/sites/lab/plan.docx".encode_utf16().chain([0]) {
            u.extend_from_slice(&c.to_le_bytes());
        }
        ids.extend_from_slice(&((u.len() + 2) as u16).to_le_bytes());
        ids.extend_from_slice(&u);
        assert_eq!(shell_items_path(&ids), "https://example.test/sites/lab/plan.docx");
    }

    #[test]
    fn local_target_with_tracker() {
        let t = [133_000_000_000_000_000, 133_100_000_000_000_000, 133_050_000_000_000_000];
        let d = write("E:\\Projects\\nightjar.docx", 0x1234ABCD, "BACKUP", t, 48_213, "lab-pc", OBJ_V1, 2);
        let l = parse(&d).unwrap();
        assert_eq!(l.target, "E:\\Projects\\nightjar.docx");
        assert_eq!((l.drive_type.as_str(), l.volume_serial.as_str(), l.volume_label.as_str()), ("removable", "1234ABCD", "BACKUP"));
        assert_eq!((l.target_created, l.target_accessed, l.target_written, l.target_size), (t[0], t[1], t[2], 48_213));
        assert_eq!((l.description.as_str(), l.arguments.as_str()), ("Opened by test", "--secure"));
        assert_eq!((l.machine_id.as_str(), l.mac.as_str()), ("lab-pc", "00:0c:29:ab:cd:ef"));
        assert!(parse(&d[..40]).is_err());
        // Truncated anywhere after the header: no panic, partial result.
        for n in (0x4C..d.len()).step_by(7) {
            let _ = parse(&d[..n]);
        }
    }
}
