//! Jump Lists: per-application lists of recently and frequently opened
//! items, kept even after the Recent folder is cleaned.
//!
//! Automatic destinations (`<AppID>.automaticDestinations-ms`) are OLE
//! compound files: a "DestList" stream with one entry per item (path, last
//! access time, access count, pinned state, NetBIOS name) and one numbered
//! stream per item holding a full shortcut (LNK). Custom destinations
//! (`<AppID>.customDestinations-ms`) are shortcuts stored back to back.

use crate::bin::*;
use crate::lnk::{self, Lnk};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct JumpList {
    /// The 16 hex digits before the extension: identifies the application.
    pub app_id: String,
    pub custom: bool,
    pub entries: Vec<JumpEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct JumpEntry {
    pub path: String,
    pub last_access: u64,
    pub access_count: u32,
    pub pinned: bool,
    pub hostname: String,
    pub entry: u32,
    pub lnk: Option<Lnk>,
}

pub fn app_id(file_name: &str) -> String {
    file_name.split('.').next().unwrap_or("").to_ascii_lowercase()
}

/// Kind is taken from the content (OLE file = automatic), so temporary and
/// leftover copies (".temp", "~RF...") parse too.
pub fn parse(file_name: &str, d: &[u8]) -> anyhow::Result<JumpList> {
    let custom = !crate::cfb::is_cfb(d);
    let mut jl = JumpList { app_id: app_id(file_name), custom, entries: vec![] };
    if custom {
        // Shortcuts back to back between category headers: find each header.
        let mut p = 0;
        while let Some(i) = d[p..].windows(20).position(lnk::is_lnk) {
            let at = p + i;
            if let Ok(l) = lnk::parse(&d[at..]) {
                jl.entries.push(JumpEntry { path: l.target.clone(), lnk: Some(l), ..Default::default() });
            }
            p = at + 20;
        }
        return Ok(jl);
    }
    let streams = crate::cfb::streams(d, 16 << 20)?;
    let dest = streams.iter().find(|s| s.name.eq_ignore_ascii_case("DestList")).map(|s| s.data.as_slice()).unwrap_or(&[]);
    let version = u32_at(dest, 0).unwrap_or(0);
    let count = u32_at(dest, 4).unwrap_or(0) as usize;
    let mut p = 32;
    for _ in 0..count.min(100_000) {
        let (path_off, fixed) = if version >= 3 { (0x80, 0x82) } else { (0x70, 0x72) };
        let Some(len) = u16_at(dest, p + path_off) else { break };
        let path = utf16(slice(dest, p + fixed, 2 * len as usize).unwrap_or(&[]));
        let entry = u32_at(dest, p + 0x58).unwrap_or(0);
        let pin = i32_at(dest, p + 0x6C).unwrap_or(-1);
        let access_count = if version >= 3 { u32_at(dest, p + 0x74).unwrap_or(0) } else { u32_at(dest, p + 0x60).map(|x| f32::from_bits(x) as u32).unwrap_or(0) };
        jl.entries.push(JumpEntry {
            path,
            last_access: plausible(u64_at(dest, p + 0x64).unwrap_or(0)),
            access_count,
            pinned: pin >= 0,
            hostname: ansiz(dest, p + 0x48, 16),
            entry,
            lnk: None,
        });
        p += fixed + 2 * len as usize + if version >= 3 { 4 } else { 0 };
    }
    // Pair each entry with its stream (named by the entry number in hex).
    for e in &mut jl.entries {
        let name = format!("{:x}", e.entry);
        if let Some(s) = streams.iter().find(|s| s.name.eq_ignore_ascii_case(&name)) {
            e.lnk = lnk::parse(&s.data).ok();
            if e.path.is_empty() {
                e.path = e.lnk.as_ref().map(|l| l.target.clone()).unwrap_or_default();
            }
        }
    }
    // Streams with no DestList entry (DestList damaged or rewritten).
    let known: std::collections::HashSet<String> = jl.entries.iter().map(|e| format!("{:x}", e.entry)).collect();
    for s in &streams {
        if s.name.eq_ignore_ascii_case("DestList") || known.contains(&s.name.to_ascii_lowercase()) {
            continue;
        }
        if let Ok(l) = lnk::parse(&s.data) {
            jl.entries.push(JumpEntry { path: l.target.clone(), entry: u32::from_str_radix(&s.name, 16).unwrap_or(0), lnk: Some(l), ..Default::default() });
        }
    }
    Ok(jl)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// DestList version 4 (Windows 10) with the given (entry, path, time, count, pinned).
    pub fn destlist(items: &[(u32, &str, u64, u32, bool)]) -> Vec<u8> {
        let mut d = vec![0u8; 32];
        d[0..4].copy_from_slice(&4u32.to_le_bytes());
        d[4..8].copy_from_slice(&(items.len() as u32).to_le_bytes());
        for (entry, path, t, count, pinned) in items {
            let mut e = vec![0u8; 0x82];
            e[0x48..0x48 + 6].copy_from_slice(b"lab-pc");
            e[0x58..0x5C].copy_from_slice(&entry.to_le_bytes());
            e[0x64..0x6C].copy_from_slice(&t.to_le_bytes());
            e[0x6C..0x70].copy_from_slice(&(if *pinned { 0i32 } else { -1 }).to_le_bytes());
            e[0x74..0x78].copy_from_slice(&count.to_le_bytes());
            e[0x80..0x82].copy_from_slice(&(path.encode_utf16().count() as u16).to_le_bytes());
            for u in path.encode_utf16() {
                e.extend_from_slice(&u.to_le_bytes());
            }
            e.extend_from_slice(&[0; 4]);
            d.extend_from_slice(&e);
        }
        d
    }

    #[test]
    fn automatic_and_custom() {
        let t = 134_000_000_000_000_000;
        let l1 = crate::lnk::tests::write("E:\\Projects\\nightjar.docx", 0x1234ABCD, "BACKUP", [t; 3], 10, "lab-pc", crate::lnk::tests::OBJ_V1, 2);
        let l2 = crate::lnk::tests::write("C:\\Users\\alice\\Desktop\\keys.txt", 0x5A6B7C8D, "OS", [t; 3], 20, "lab-pc", crate::lnk::tests::OBJ_V1, 3);
        let dl = destlist(&[(1, "E:\\Projects\\nightjar.docx", t + 5, 7, true), (2, "C:\\Users\\alice\\Desktop\\keys.txt", t + 9, 1, false)]);
        let f = crate::cfb::tests::write(&[("1", &l1), ("2", &l2), ("DestList", &dl)]);
        let jl = parse("9b9cdc69c1c24e2b.automaticDestinations-ms", &f).unwrap();
        assert_eq!(jl.app_id, "9b9cdc69c1c24e2b");
        assert_eq!(jl.entries.len(), 2);
        let e = &jl.entries[0];
        assert_eq!((e.path.as_str(), e.last_access, e.access_count, e.pinned, e.hostname.as_str()), ("E:\\Projects\\nightjar.docx", t + 5, 7, true, "lab-pc"));
        assert_eq!(e.lnk.as_ref().unwrap().volume_label, "BACKUP");
        assert!(!jl.entries[1].pinned);

        let mut custom = vec![0xAB; 24];
        custom.extend_from_slice(&l1);
        custom.extend_from_slice(&[0xCD; 12]);
        custom.extend_from_slice(&l2);
        let jl = parse("5d696d521de238c3.customDestinations-ms", &custom).unwrap();
        assert!(jl.custom);
        assert_eq!(jl.entries.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), vec!["E:\\Projects\\nightjar.docx", "C:\\Users\\alice\\Desktop\\keys.txt"]);
    }
}
