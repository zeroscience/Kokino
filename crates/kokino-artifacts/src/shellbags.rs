//! ShellBags: the folders a user opened in Explorer.
//!
//! Explorer remembers the view settings of every folder a user browses to,
//! in a tree under BagMRU (UsrClass.dat on Windows 7 and later,
//! NTUSER.DAT before). Each key's numbered values are shell items, one path
//! component each, and the subkey with the same number holds that folder's
//! own children, so walking the tree rebuilds full paths. The entries stay
//! after the folder is deleted or the drive removed, which makes them proof
//! that a user looked at a folder on a USB stick, a network share or inside
//! a ZIP file, even long gone.
//!
//! Times: a folder's own key is written when its list of opened subfolders
//! changes; when a folder is first in its parent's MRUListEx, the parent's
//! last write is when it was last opened. File entry items also carry the
//! folder's modified, created and accessed times (FAT format, the
//! computer's local time, 2-second steps) as they were when it was opened,
//! and on Windows 7+ its MFT reference.

use crate::bin::*;
use crate::registry::Key;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShellItem {
    /// "folder", "file", "drive", "network", "root", "zip", "URI",
    /// "control panel" or "other".
    pub kind: String,
    pub name: String,
    /// FAT times of a file entry item, local time as FILETIME (0 = absent).
    pub modified: u64,
    pub created: u64,
    pub accessed: u64,
    /// MFT reference (record, sequence number) from the 0xBEEF0004 block.
    pub mft: Option<(u64, u16)>,
}

impl ShellItem {
    /// A path starts again at drives, shares and web addresses.
    fn is_root(&self) -> bool {
        matches!(self.kind.as_str(), "drive" | "network" | "URI")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bag {
    pub path: String,
    pub kind: String,
    /// Position in the parent's most-recently-used list (0 = newest).
    pub mru: Option<u32>,
    /// Last write of this folder's own BagMRU key.
    pub written: u64,
    /// Last opened: the parent key's last write, when this folder is first
    /// in the parent's MRU list.
    pub opened: u64,
    pub modified: u64,
    pub created: u64,
    pub accessed: u64,
    pub mft: Option<(u64, u16)>,
    /// Registry path of the value, below BagMRU.
    pub key: String,
}

const KNOWN: &[(&str, &str)] = &[
    ("{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "This PC"),
    ("{450D8FBA-AD25-11D0-98A8-0800361B1103}", "My Documents"),
    ("{208D2C60-3AEA-1069-A2D7-08002B30309D}", "My Network Places"),
    ("{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", "Network"),
    ("{645FF040-5081-101B-9F08-00AA002F954E}", "Recycle Bin"),
    ("{26EE0668-A00A-44D7-9371-BEB064C98683}", "Control Panel"),
    ("{21EC2020-3AEA-1069-A2DD-08002B30309D}", "Control Panel (all items)"),
    ("{031E4825-7B94-4DC3-B131-E946B44C8DD5}", "Libraries"),
    ("{59031A47-3F72-44A7-89C5-5595FE6B30EE}", "User folder"),
    ("{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "OneDrive"),
    ("{679F85CB-0220-4080-B29B-5540CC05AAB6}", "Quick access"),
    ("{4234D49B-0245-4DF3-B780-3893943456E1}", "Applications"),
    ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop"),
    ("{D3162B92-9365-467A-956B-92703ACA08AF}", "Documents"),
    ("{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}", "Documents"),
    ("{088E3905-0323-4B02-9826-5D99428E115F}", "Downloads"),
    ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
    ("{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}", "Music"),
    ("{1CF1260C-4DD0-4EBB-811F-33C572699FDE}", "Music"),
    ("{24AD3AD4-A569-4530-98E1-AB02F9417AA8}", "Pictures"),
    ("{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}", "Pictures"),
    ("{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}", "Videos"),
    ("{A0953C92-50DC-43BF-BE83-3742FED03C9C}", "Videos"),
    ("{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}", "3D Objects"),
    ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "User Pinned"),
];

fn known(g: &str) -> String {
    KNOWN.iter().find(|(k, _)| k.eq_ignore_ascii_case(g)).map(|(_, n)| n.to_string()).unwrap_or_else(|| g.to_string())
}

/// FAT date and time (as in shell items: date first) as a FILETIME, 0 when
/// absent or invalid.
pub fn fat_time(d: &[u8], o: usize) -> u64 {
    let (Some(date), Some(time)) = (u16_at(d, o), u16_at(d, o + 2)) else { return 0 };
    if date == 0 {
        return 0;
    }
    let mut st = [0u8; 16];
    let fields = [1980 + (date >> 9), (date >> 5) & 15, 0, date & 31, time >> 11, (time >> 5) & 63, (time & 31) * 2, 0];
    for (i, v) in fields.iter().enumerate() {
        st[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    systemtime(&st).map(plausible).unwrap_or(0)
}

/// Decodes one shell item (with its 2-byte size in front).
pub fn shell_item(item: &[u8]) -> ShellItem {
    let ty = u8_at(item, 2).unwrap_or(0);
    let mut s = ShellItem { kind: "other".into(), ..Default::default() };
    match ty {
        0x1F => {
            s.kind = "root".into();
            s.name = known(&guid(slice(item, 4, 16).unwrap_or(&[])));
        }
        0x20..=0x2F => {
            s.kind = "drive".into();
            let v = ansiz(item, 3, 20);
            s.name = if v.is_empty() { known(&guid(slice(item, 4, 16).unwrap_or(&[]))) } else { v.trim_end_matches('\\').to_string() };
        }
        0x30..=0x3F => file_entry(item, ty, &mut s),
        0x40..=0x4F | 0xC3 => {
            s.kind = "network".into();
            s.name = ansiz(item, 5, 260);
        }
        0x52 => {
            s.kind = "zip".into();
            s.name = utf16z(item, 0x24, 260);
        }
        0x61 => {
            s.kind = "URI".into();
            let flags = u8_at(item, 3).unwrap_or(0);
            let at = 8usize.saturating_add(u32_at(item, 4).unwrap_or(0) as usize);
            s.name = if flags & 0x80 != 0 { utf16z(item, at, 4096) } else { ansiz(item, at, 4096) };
        }
        0x71 => {
            s.kind = "control panel".into();
            s.name = known(&guid(slice(item, 14, 16).unwrap_or(&[])));
        }
        0x74 if slice(item, 6, 4) == Some(b"CFSF") => {
            // Delegate item: a file entry wrapped for the user's folder.
            let sub = item.get(10..).unwrap_or(&[]);
            file_entry(sub, u8_at(sub, 2).unwrap_or(0x31), &mut s);
            if let Some(n) = crate::lnk::long_name(item) {
                s.name = n;
            }
        }
        _ => {}
    }
    if s.name.is_empty() || s.name.chars().any(|c| c.is_control()) {
        s.name = crate::lnk::long_name(item).unwrap_or_else(|| format!("[item type 0x{:02X}]", ty));
    }
    s
}

fn file_entry(item: &[u8], ty: u8, s: &mut ShellItem) {
    s.kind = if ty & 0x01 != 0 { "folder" } else { "file" }.into();
    s.modified = fat_time(item, 8);
    let short = if ty & 0x04 != 0 { utf16z(item, 14, 260) } else { ansiz(item, 14, 260) };
    s.name = crate::lnk::long_name(item).unwrap_or(short);
    if let Some(at) = item.windows(4).position(|w| w == [0x04, 0x00, 0xEF, 0xBE]).and_then(|p| p.checked_sub(4)) {
        s.created = fat_time(item, at + 8);
        s.accessed = fat_time(item, at + 12);
        if u16_at(item, at + 2).unwrap_or(0) >= 7 {
            if let Some(r) = u64_at(item, at + 20).filter(|&r| r != 0) {
                s.mft = Some((r & 0xFFFF_FFFF_FFFF, (r >> 48) as u16));
            }
        }
    }
}

/// MRUListEx order of a key's numbered values.
fn mru(k: &Key) -> Vec<u32> {
    k.value("MRUListEx").map(|v| v.data.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).take_while(|&i| i != u32::MAX).collect()).unwrap_or_default()
}

const MAX_BAGS: usize = 200_000;
const MAX_DEPTH: usize = 64;

/// Every folder under a BagMRU key.
pub fn walk(bagmru: &Key) -> Vec<Bag> {
    let mut out = vec![];
    walk_key(bagmru, "", "", 0, &mut out);
    out
}

fn walk_key(k: &Key, path: &str, key: &str, depth: usize, out: &mut Vec<Bag>) {
    let order = mru(k);
    let mut vals: Vec<(u32, Vec<u8>)> = k.values().into_iter().filter_map(|v| v.name.parse::<u32>().ok().map(|n| (n, v.data))).collect();
    vals.sort_by_key(|v| v.0);
    for (n, data) in vals {
        if out.len() >= MAX_BAGS {
            return;
        }
        let it = shell_item(&data);
        let p = if it.is_root() || path.is_empty() {
            it.name.clone()
        } else if path.ends_with('\\') {
            format!("{}{}", path, it.name)
        } else {
            format!("{}\\{}", path, it.name)
        };
        let pos = order.iter().position(|&x| x == n).map(|x| x as u32);
        let sub = k.subkey(&n.to_string());
        let kp = if key.is_empty() { n.to_string() } else { format!("{}\\{}", key, n) };
        out.push(Bag {
            path: p.clone(),
            kind: it.kind,
            mru: pos,
            written: sub.map(|s| s.last_written()).unwrap_or(0),
            opened: if pos == Some(0) { k.last_written() } else { 0 },
            modified: it.modified,
            created: it.created,
            accessed: it.accessed,
            mft: it.mft,
            key: kp.clone(),
        });
        if let Some(s) = sub {
            if depth < MAX_DEPTH {
                walk_key(&s, &p, &kp, depth + 1, out);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A folder file-entry item with a version 9 extension block holding
    /// the long name, times and MFT reference, as Windows 10 writes it.
    pub fn folder(short: &str, long: &str, mft: (u64, u16)) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[2] = 0x31;
        f[8..10].copy_from_slice(&0x5B65u16.to_le_bytes()); // 2025-11-05
        f[10..12].copy_from_slice(&0x7A40u16.to_le_bytes()); // 15:18:00
        f[12..14].copy_from_slice(&0x10u16.to_le_bytes());
        f.extend_from_slice(short.as_bytes());
        f.push(0);
        if f.len() % 2 == 1 {
            f.push(0);
        }
        let mut ext = vec![0u8; 0x2E];
        ext[2..4].copy_from_slice(&9u16.to_le_bytes());
        ext[4..8].copy_from_slice(&0xBEEF_0004u32.to_le_bytes());
        ext[8..10].copy_from_slice(&0x5B64u16.to_le_bytes()); // created 2025-11-04
        ext[12..14].copy_from_slice(&0x5B65u16.to_le_bytes());
        ext[20..28].copy_from_slice(&(mft.0 | (mft.1 as u64) << 48).to_le_bytes());
        for u in long.encode_utf16().chain([0]) {
            ext.extend_from_slice(&u.to_le_bytes());
        }
        ext.extend_from_slice(&[0, 0]);
        let n = ext.len() as u16;
        ext[0..2].copy_from_slice(&n.to_le_bytes());
        f.extend_from_slice(&ext);
        let n = f.len() as u16;
        f[0..2].copy_from_slice(&n.to_le_bytes());
        f
    }

    #[test]
    fn items() {
        let f = shell_item(&folder("PROJEC~1", "Projects 2026", (1234, 5)));
        assert_eq!((f.kind.as_str(), f.name.as_str(), f.mft), ("folder", "Projects 2026", Some((1234, 5))));
        assert_eq!(crate::bin::plausible(f.modified), f.modified);
        assert!(f.modified > f.created && f.created > 0 && f.accessed > 0);
        let mut pc = vec![0x14, 0, 0x1F, 0x50];
        pc.extend_from_slice(&[0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D]);
        assert_eq!(shell_item(&pc).name, "This PC");
        let mut vol = vec![0x19, 0, 0x2F];
        vol.extend_from_slice(b"E:\\\0");
        vol.resize(0x19, 0);
        assert_eq!((shell_item(&vol).kind.as_str(), shell_item(&vol).name.as_str()), ("drive", "E:"));
        let mut net = vec![0, 0, 0x41, 0x01, 0x00];
        net.extend_from_slice(b"\\\\FILESRV01\\share\0");
        assert_eq!(shell_item(&net).name, "\\\\FILESRV01\\share");
        // Junk and empty items get a placeholder, never a panic.
        assert_eq!(shell_item(&[3, 0, 0x99]).name, "[item type 0x99]");
        assert_eq!(shell_item(&[]).name, "[item type 0x00]");
        for n in 0..64usize {
            let junk: Vec<u8> = (0..n * 7).map(|i| (i * 131 % 251) as u8).collect();
            let _ = shell_item(&junk);
        }
        assert_eq!(fat_time(&[0, 0, 0, 0], 0), 0);
    }
}
