//! Windows registry hive (regf) reader.
//!
//! Reads keys (nk), values (vk), every subkey list kind (lf, lh, li, ri) and
//! big data (db) values. A hive whose two sequence numbers differ was not
//! cleanly flushed: recent changes may still sit in its .LOG1 / .LOG2
//! transaction logs, which are not applied here, and the caller is told so.
//! Deleted keys in free cells are not recovered yet.

use crate::bin::*;
use serde::Serialize;

const BASE: usize = 4096;
const MAX_DEPTH: usize = 512;

pub struct Hive {
    data: Vec<u8>,
    root: u32,
    /// Sequence numbers differ: changes may be pending in the .LOG files.
    pub dirty: bool,
    pub last_written: u64,
    /// File name recorded inside the hive (often a full \??\C:\... path).
    pub embedded_name: String,
    pub version: (u32, u32),
}

#[derive(Clone, Copy)]
pub struct Key<'a> {
    hive: &'a Hive,
    off: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Value {
    pub name: String,
    pub kind: u32,
    pub data: Vec<u8>,
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

impl Hive {
    pub fn parse(data: Vec<u8>) -> anyhow::Result<Hive> {
        if data.get(0..4) != Some(b"regf") {
            anyhow::bail!("not a registry hive (no regf signature)");
        }
        let root = u32_at(&data, 36).ok_or_else(|| anyhow::anyhow!("truncated hive header"))?;
        let h = Hive {
            dirty: u32_at(&data, 4) != u32_at(&data, 8),
            last_written: u64_at(&data, 12).unwrap_or(0),
            version: (u32_at(&data, 20).unwrap_or(0), u32_at(&data, 24).unwrap_or(0)),
            embedded_name: utf16(slice(&data, 48, 64).unwrap_or(&[])),
            root,
            data,
        };
        if h.cell(root).map(|c| c.get(0..2) != Some(b"nk")).unwrap_or(true) {
            anyhow::bail!("root key cell is missing or damaged");
        }
        Ok(h)
    }

    /// Cell data (after the size field) at a hive-bins-relative offset.
    fn cell(&self, off: u32) -> Option<&[u8]> {
        if off == 0xFFFF_FFFF {
            return None;
        }
        let p = BASE.checked_add(off as usize)?;
        let size = i32_at(&self.data, p)?;
        let len = (size.unsigned_abs() as usize).checked_sub(4)?;
        slice(&self.data, p + 4, len)
    }

    pub fn root(&self) -> Key<'_> {
        Key { hive: self, off: self.root }
    }

    /// Opens `a\b\c` (case-insensitive) below the root.
    pub fn open(&self, path: &str) -> Option<Key<'_>> {
        let mut k = self.root();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            k = k.subkey(part)?;
        }
        Some(k)
    }
}

impl<'a> Key<'a> {
    fn nk(&self) -> &'a [u8] {
        self.hive.cell(self.off).unwrap_or(&[])
    }

    pub fn name(&self) -> String {
        let d = self.nk();
        let flags = u16_at(d, 2).unwrap_or(0);
        let len = u16_at(d, 72).unwrap_or(0) as usize;
        let raw = slice(d, 76, len).unwrap_or(&[]);
        if flags & 0x20 != 0 { raw.iter().map(|&c| c as char).collect() } else { utf16(raw) }
    }

    pub fn last_written(&self) -> u64 {
        u64_at(self.nk(), 4).unwrap_or(0)
    }

    pub fn subkeys(&self) -> Vec<Key<'a>> {
        let d = self.nk();
        let mut out = vec![];
        if let Some(list) = u32_at(d, 28) {
            self.collect_list(list, &mut out, 0);
        }
        out
    }

    fn collect_list(&self, off: u32, out: &mut Vec<Key<'a>>, depth: usize) {
        let Some(c) = self.hive.cell(off) else { return };
        if depth > 8 || out.len() > 1_000_000 {
            return;
        }
        let n = u16_at(c, 2).unwrap_or(0) as usize;
        match c.get(0..2) {
            Some(b"lf") | Some(b"lh") => {
                for i in 0..n {
                    if let Some(o) = u32_at(c, 4 + 8 * i) {
                        out.push(Key { hive: self.hive, off: o });
                    }
                }
            }
            Some(b"li") => {
                for i in 0..n {
                    if let Some(o) = u32_at(c, 4 + 4 * i) {
                        out.push(Key { hive: self.hive, off: o });
                    }
                }
            }
            Some(b"ri") => {
                for i in 0..n {
                    if let Some(o) = u32_at(c, 4 + 4 * i) {
                        self.collect_list(o, out, depth + 1);
                    }
                }
            }
            _ => {}
        }
        out.retain(|k| k.hive.cell(k.off).map(|c| c.get(0..2) == Some(b"nk")).unwrap_or(false));
    }

    pub fn subkey(&self, name: &str) -> Option<Key<'a>> {
        self.subkeys().into_iter().find(|k| k.name().eq_ignore_ascii_case(name))
    }

    /// Path below this key, e.g. "Microsoft\\Windows NT".
    pub fn open(&self, path: &str) -> Option<Key<'a>> {
        let mut k = *self;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            k = k.subkey(part)?;
        }
        Some(k)
    }

    pub fn values(&self) -> Vec<Value> {
        let d = self.nk();
        let n = u32_at(d, 36).unwrap_or(0) as usize;
        let Some(list) = u32_at(d, 40).and_then(|o| self.hive.cell(o)) else { return vec![] };
        (0..n.min(100_000)).filter_map(|i| u32_at(list, 4 * i)).filter_map(|o| self.value_at(o)).collect()
    }

    fn value_at(&self, off: u32) -> Option<Value> {
        let v = self.hive.cell(off)?;
        if v.get(0..2) != Some(b"vk") {
            return None;
        }
        let nlen = u16_at(v, 2)? as usize;
        let size = u32_at(v, 4)?;
        let doff = u32_at(v, 8)?;
        let kind = u32_at(v, 12)?;
        let flags = u16_at(v, 16)?;
        let raw = slice(v, 20, nlen).unwrap_or(&[]);
        let name = if flags & 1 != 0 { raw.iter().map(|&c| c as char).collect() } else { utf16(raw) };
        let data = if size & 0x8000_0000 != 0 {
            // Up to 4 bytes stored in the offset field itself.
            let n = (size & 0x7FFF_FFFF).min(4) as usize;
            doff.to_le_bytes()[..n].to_vec()
        } else {
            let n = size as usize;
            let cell = self.hive.cell(doff).unwrap_or(&[]);
            if cell.get(0..2) == Some(b"db") && n > 16_344 {
                self.big_data(cell, n)
            } else {
                cell.get(..n.min(cell.len())).unwrap_or(&[]).to_vec()
            }
        };
        Some(Value { name, kind, data })
    }

    fn big_data(&self, db: &[u8], n: usize) -> Vec<u8> {
        let count = u16_at(db, 2).unwrap_or(0) as usize;
        let Some(list) = u32_at(db, 4).and_then(|o| self.hive.cell(o)) else { return vec![] };
        let mut out = Vec::with_capacity(n.min(64 << 20));
        for i in 0..count {
            if let Some(seg) = u32_at(list, 4 * i).and_then(|o| self.hive.cell(o)) {
                out.extend_from_slice(&seg[..seg.len().min(16_344)]);
            }
            if out.len() >= n {
                break;
            }
        }
        out.truncate(n);
        out
    }

    pub fn value(&self, name: &str) -> Option<Value> {
        self.values().into_iter().find(|v| v.name.eq_ignore_ascii_case(name))
    }

    pub fn string(&self, name: &str) -> Option<String> {
        self.value(name).map(|v| v.string()).filter(|s| !s.is_empty())
    }

    pub fn u32(&self, name: &str) -> Option<u32> {
        self.value(name).and_then(|v| v.u32())
    }

    pub fn u64(&self, name: &str) -> Option<u64> {
        self.value(name).and_then(|v| u64_at(&v.data, 0))
    }

    /// Calls `f` for every key below this one (depth-first, bounded). Each
    /// key once: a tampered hive can list a key under itself, which would
    /// otherwise make the walk grow exponentially.
    pub fn walk(&self, f: &mut dyn FnMut(&Key<'a>, usize)) {
        fn go<'a>(k: &Key<'a>, depth: usize, seen: &mut std::collections::HashSet<u32>, f: &mut dyn FnMut(&Key<'a>, usize)) {
            if depth > MAX_DEPTH || !seen.insert(k.off) {
                return;
            }
            f(k, depth);
            for s in k.subkeys() {
                go(&s, depth + 1, seen, f);
            }
        }
        go(self, 0, &mut std::collections::HashSet::new(), f)
    }
}

impl Value {
    /// REG_SZ / REG_EXPAND_SZ (or any UTF-16 payload) as text; DWORDs and
    /// QWORDs as decimal.
    pub fn string(&self) -> String {
        match self.kind {
            REG_DWORD => self.u32().map(|v| v.to_string()).unwrap_or_default(),
            REG_QWORD => u64_at(&self.data, 0).map(|v| v.to_string()).unwrap_or_default(),
            REG_MULTI_SZ => self.multi().join("; "),
            _ => utf16(&self.data),
        }
    }

    pub fn u32(&self) -> Option<u32> {
        u32_at(&self.data, 0)
    }

    pub fn multi(&self) -> Vec<String> {
        let w: Vec<u16> = self.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        w.split(|&u| u == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny hive writer for tests: keys with values, written as one hbin.
    pub(crate) struct W {
        pub cells: Vec<u8>,
    }

    impl W {
        fn new() -> W {
            W { cells: vec![] }
        }
        fn cell(&mut self, body: &[u8]) -> u32 {
            let off = 32 + self.cells.len() as u32; // after the hbin header
            let size = (body.len() + 4 + 7) / 8 * 8;
            self.cells.extend_from_slice(&(-(size as i32)).to_le_bytes());
            self.cells.extend_from_slice(body);
            self.cells.resize(self.cells.len() + size - 4 - body.len(), 0);
            off
        }
        fn value(&mut self, name: &str, kind: u32, data: &[u8]) -> u32 {
            let (size, doff) = if data.len() <= 4 {
                let mut b = [0u8; 4];
                b[..data.len()].copy_from_slice(data);
                (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(b))
            } else {
                (data.len() as u32, self.cell(data))
            };
            let mut v = b"vk".to_vec();
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&doff.to_le_bytes());
            v.extend_from_slice(&kind.to_le_bytes());
            v.extend_from_slice(&1u16.to_le_bytes());
            v.extend_from_slice(&[0, 0]);
            v.extend_from_slice(name.as_bytes());
            self.cell(&v)
        }
        fn key(&mut self, name: &str, ts: u64, subkeys: &[u32], values: &[u32], list: &[u8; 2]) -> u32 {
            let sl = if subkeys.is_empty() {
                0xFFFF_FFFF
            } else {
                let mut l = list.to_vec();
                l.extend_from_slice(&(subkeys.len() as u16).to_le_bytes());
                for s in subkeys {
                    l.extend_from_slice(&s.to_le_bytes());
                    if list != b"li" {
                        l.extend_from_slice(&0u32.to_le_bytes());
                    }
                }
                self.cell(&l)
            };
            let vl = if values.is_empty() { 0xFFFF_FFFF } else { self.cell(&values.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()) };
            let mut k = b"nk".to_vec();
            k.extend_from_slice(&0x20u16.to_le_bytes());
            k.extend_from_slice(&ts.to_le_bytes());
            k.extend_from_slice(&[0; 4]);
            k.extend_from_slice(&0u32.to_le_bytes()); // parent (unused here)
            k.extend_from_slice(&(subkeys.len() as u32).to_le_bytes());
            k.extend_from_slice(&0u32.to_le_bytes());
            k.extend_from_slice(&sl.to_le_bytes());
            k.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            k.extend_from_slice(&(values.len() as u32).to_le_bytes());
            k.extend_from_slice(&vl.to_le_bytes());
            k.extend_from_slice(&[0xFF; 8]);
            k.extend_from_slice(&[0; 20]);
            k.extend_from_slice(&(name.len() as u16).to_le_bytes());
            k.extend_from_slice(&0u16.to_le_bytes());
            k.extend_from_slice(name.as_bytes());
            self.cell(&k)
        }
        fn finish(self, root: u32, dirty: bool) -> Vec<u8> {
            let mut out = vec![0u8; BASE];
            out[0..4].copy_from_slice(b"regf");
            out[4..8].copy_from_slice(&1u32.to_le_bytes());
            out[8..12].copy_from_slice(&(if dirty { 2u32 } else { 1 }).to_le_bytes());
            out[20..24].copy_from_slice(&1u32.to_le_bytes());
            out[24..28].copy_from_slice(&5u32.to_le_bytes());
            out[36..40].copy_from_slice(&root.to_le_bytes());
            let size = (32 + self.cells.len() + 4095) / 4096 * 4096;
            let mut hbin = vec![0u8; size];
            hbin[0..4].copy_from_slice(b"hbin");
            hbin[8..12].copy_from_slice(&(size as u32).to_le_bytes());
            hbin[32..32 + self.cells.len()].copy_from_slice(&self.cells);
            out.extend_from_slice(&hbin);
            out
        }
    }

    fn u16s(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn reads_keys_values_and_list_kinds() {
        let mut w = W::new();
        let v1 = w.value("ProductName", REG_SZ, &u16s("Windows 10 Pro"));
        let v2 = w.value("InstallDate", REG_DWORD, &1_700_000_000u32.to_le_bytes());
        let v3 = w.value("Multi", REG_MULTI_SZ, &[u16s("a"), u16s("bc"), vec![0, 0]].concat());
        let big: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        let seg1 = w.cell(&big[..16_344]);
        let seg2 = w.cell(&big[16_344..]);
        let segs = w.cell(&[seg1.to_le_bytes(), seg2.to_le_bytes()].concat());
        let mut db = b"db".to_vec();
        db.extend_from_slice(&2u16.to_le_bytes());
        db.extend_from_slice(&segs.to_le_bytes());
        let dbc = w.cell(&db);
        let mut vk = b"vk".to_vec();
        vk.extend_from_slice(&3u16.to_le_bytes());
        vk.extend_from_slice(&(big.len() as u32).to_le_bytes());
        vk.extend_from_slice(&dbc.to_le_bytes());
        vk.extend_from_slice(&REG_BINARY.to_le_bytes());
        vk.extend_from_slice(&[1, 0, 0, 0]);
        vk.extend_from_slice(b"Big");
        let v4 = w.cell(&vk);
        let cv = w.key("CurrentVersion", 132_000_000_000_000_000, &[], &[v1, v2, v3, v4], b"lf");
        let a = w.key("A", 0, &[], &[], b"lf");
        let b = w.key("B", 0, &[], &[], b"lf");
        let li = w.key("ListLi", 0, &[a, b], &[], b"li");
        let nt = w.key("Windows NT", 0, &[cv, li], &[], b"lh");
        let ms = w.key("Microsoft", 0, &[nt], &[], b"lf");
        let root = w.key("ROOT", 0, &[ms], &[], b"lf");
        let h = Hive::parse(w.finish(root, true)).unwrap();
        assert!(h.dirty);
        let k = h.open("microsoft\\WINDOWS NT\\CurrentVersion").unwrap();
        assert_eq!(k.last_written(), 132_000_000_000_000_000);
        assert_eq!(k.string("ProductName").unwrap(), "Windows 10 Pro");
        assert_eq!(k.u32("installdate"), Some(1_700_000_000));
        assert_eq!(k.value("Multi").unwrap().multi(), vec!["a", "bc"]);
        assert_eq!(k.value("Big").unwrap().data, big);
        let names: Vec<String> = h.open("Microsoft\\Windows NT\\ListLi").unwrap().subkeys().iter().map(|k| k.name()).collect();
        assert_eq!(names, vec!["A", "B"]);
        let mut n = 0;
        h.root().walk(&mut |_, _| n += 1);
        assert_eq!(n, 7);
        assert!(Hive::parse(b"nope".to_vec()).is_err());
        let mut broken = vec![0u8; 5000];
        broken[..4].copy_from_slice(b"regf");
        broken[36..40].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
        assert!(Hive::parse(broken).is_err());
    }
}
