//! Windows registry hive (regf) reader.
//!
//! Reads keys (nk), values (vk), every subkey list kind (lf, lh, li, ri) and
//! big data (db) values. A hive whose two sequence numbers differ was not
//! cleanly flushed: recent changes may still sit in its .LOG1 / .LOG2
//! transaction logs, which are not applied here, and the caller is told so.
//!
//! Deleted keys and values: when a key or value is deleted, Windows marks
//! its cell free (a positive size) and joins it with free neighbours, but
//! does not clear it. [`Hive::deleted`] looks through the free space of
//! every hive bin for key (nk) and value (vk) cells, rebuilds each deleted
//! key's path through its parent, and reads its values when their cells are
//! still free. Windows also leaves the old copy of a key behind when it
//! moves the key to a bigger cell; such copies are recognized by a live key
//! of the same path, and only the values they hold that the live key no
//! longer has are reported, as deleted values of that key.

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

/// A deleted key found in free space.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedKey {
    /// Cell offset (relative to the first hive bin).
    pub offset: u32,
    /// Path below the root, e.g. `Software\Microsoft\...\RunMRU`.
    pub path: String,
    pub last_written: u64,
    /// The path reaches a live key. False: some parent is gone too, and
    /// the path starts at the oldest parent that was found.
    pub complete_path: bool,
    pub values: Vec<DeletedValue>,
    pub subkey_count: u32,
}

/// A deleted value: of a deleted key, a value an older copy of a live key
/// still holds, or one found on its own.
#[derive(Debug, Clone, Serialize)]
pub struct DeletedValue {
    pub offset: u32,
    /// Key path when known.
    pub key: Option<String>,
    pub value: Value,
    /// The data's cell is in use again: the bytes may belong to newer data.
    pub data_reused: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Deleted {
    pub keys: Vec<DeletedKey>,
    /// Values of live keys that an older copy of the key still holds.
    pub values: Vec<DeletedValue>,
    /// Values found on their own; their key is not known.
    pub orphans: Vec<DeletedValue>,
    /// Old copies of keys that still exist (not reported further).
    pub old_copies: u32,
    pub truncated: bool,
}

const MAX_DELETED: usize = 200_000;
/// Data kept per deleted value, and for all of them together: a crafted
/// hive can point many values at one large cell.
const MAX_DELETED_DATA: usize = 64 << 10;
const DELETED_DATA_BUDGET: usize = 256 << 20;
const MAX_VALUES_PER_DELETED_KEY: usize = 4096;

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

    /// Size field of the cell at `off`: positive when the cell is free.
    fn cell_size(&self, off: u32) -> Option<i32> {
        i32_at(&self.data, BASE.checked_add(off as usize)?)
    }

    /// Key and value cells in free space, with offsets.
    fn free_records(&self) -> (Vec<u32>, Vec<u32>) {
        let (mut nks, mut vks) = (vec![], vec![]);
        let mut bin = BASE;
        while bin + 32 <= self.data.len() && slice(&self.data, bin, 4) == Some(b"hbin") {
            let size = u32_at(&self.data, bin + 8).unwrap_or(0) as usize;
            if size < 32 || size % 4096 != 0 {
                break;
            }
            let end = (bin + size).min(self.data.len());
            let mut p = bin + 32;
            while p + 4 <= end {
                let Some(cs) = i32_at(&self.data, p) else { break };
                let len = cs.unsigned_abs() as usize;
                if len < 8 || len % 8 != 0 || p + len > end {
                    break;
                }
                if cs > 0 {
                    // A free cell, possibly several old cells joined: look at
                    // every 8-byte boundary for the start of an old cell.
                    let mut q = p;
                    while q + 8 <= p + len {
                        let inner = i32_at(&self.data, q).unwrap_or(0).unsigned_abs() as usize;
                        if inner >= 16 && inner % 8 == 0 && q + inner <= p + len {
                            let rel = (q - BASE) as u32;
                            match slice(&self.data, q + 4, 2) {
                                Some(b"nk") => nks.push(rel),
                                Some(b"vk") => vks.push(rel),
                                _ => {}
                            }
                        }
                        q += 8;
                    }
                }
                p += len;
            }
            bin += size;
        }
        (nks, vks)
    }

    /// A key cell in free space that looks real: printable name, plausible
    /// time, fields inside the cell.
    fn deleted_nk(&self, off: u32) -> Option<(String, u64, u32, u32, u32, u32)> {
        let c = self.cell(off)?;
        if c.len() < 80 {
            return None;
        }
        let flags = u16_at(c, 2)?;
        let t = u64_at(c, 4)?;
        let parent = u32_at(c, 16)?;
        let subkeys = u32_at(c, 20)?;
        let nvalues = u32_at(c, 36)?;
        let vlist = u32_at(c, 40)?;
        let len = u16_at(c, 72)? as usize;
        if len == 0 || len > 512 || 76 + len > c.len() || plausible(t) == 0 || subkeys > 1_000_000 || nvalues > 100_000 {
            return None;
        }
        let raw = &c[76..76 + len];
        let name = if flags & 0x20 != 0 { raw.iter().map(|&b| b as char).collect() } else { utf16(raw) };
        if name.chars().any(|ch| ch.is_control()) || name.contains(char::from(92)) || name.chars().count() * if flags & 0x20 != 0 { 1 } else { 2 } != len {
            return None;
        }
        Some((name, t, parent, subkeys, nvalues, vlist))
    }

    /// A value cell, read as a value. `None` when it does not look real.
    fn any_vk(&self, off: u32, budget: &mut usize) -> Option<(Value, bool)> {
        let v = self.cell(off)?;
        if v.get(0..2) != Some(b"vk") || v.len() < 20 {
            return None;
        }
        let nlen = u16_at(v, 2)? as usize;
        let size = u32_at(v, 4)?;
        let doff = u32_at(v, 8)?;
        let kind = u32_at(v, 12)?;
        let flags = u16_at(v, 16)?;
        if 20 + nlen > v.len() || kind > 0xFFFF {
            return None;
        }
        let raw = &v[20..20 + nlen];
        let name = if flags & 1 != 0 { raw.iter().map(|&c| c as char).collect::<String>() } else { utf16(raw) };
        if name.chars().any(|ch| ch.is_control()) {
            return None;
        }
        let mut reused = false;
        let data = if size & 0x8000_0000 != 0 {
            let n = (size & 0x7FFF_FFFF).min(4) as usize;
            doff.to_le_bytes()[..n].to_vec()
        } else {
            let n = (size as usize).min(MAX_DELETED_DATA).min(*budget);
            reused = self.cell_size(doff).is_some_and(|s| s < 0);
            let cell = self.cell(doff).unwrap_or(&[]);
            let d = cell.get(..n.min(cell.len())).unwrap_or(&[]).to_vec();
            *budget -= d.len();
            d
        };
        Some((Value { name, kind, data }, reused))
    }

    /// Deleted keys and values in the hive's free space.
    pub fn deleted(&self) -> Deleted {
        let mut out = Deleted::default();
        let mut budget = DELETED_DATA_BUDGET;
        // Live keys by cell offset, with their paths.
        let mut live: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
        let mut by_path: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut stack: Vec<String> = vec![];
        self.root().walk(&mut |k, depth| {
            stack.truncate(depth);
            stack.push(k.name());
            let p = stack[1..].join("\\");
            by_path.insert(p.to_lowercase(), k.off);
            live.insert(k.off, p);
        });
        let (nks, vks) = self.free_records();
        let mut claimed: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let found: std::collections::HashMap<u32, (String, u64, u32, u32, u32, u32)> = nks.iter().filter(|o| !live.contains_key(o)).filter_map(|&o| self.deleted_nk(o).map(|k| (o, k))).collect();
        let mut offs: Vec<u32> = found.keys().copied().collect();
        offs.sort();
        for off in offs {
            let (name, t, _, subkeys, nvalues, vlist) = found[&off].clone();
            // Path through the parents: live ones end the walk.
            let mut parts = vec![name];
            let mut p = found[&off].2;
            let mut complete = false;
            for _ in 0..MAX_DEPTH {
                if let Some(lp) = live.get(&p) {
                    if !lp.is_empty() {
                        parts.push(lp.clone());
                    }
                    complete = true;
                    break;
                }
                match found.get(&p) {
                    Some(k) if p != off => {
                        parts.push(k.0.clone());
                        p = k.2;
                    }
                    _ => break,
                }
            }
            parts.reverse();
            let path = parts.join("\\");
            // Its values, when the value list and value cells are free.
            let mut values = vec![];
            if nvalues > 0 && self.cell_size(vlist).is_some_and(|s| s > 0) {
                if let Some(list) = self.cell(vlist) {
                    for i in 0..(nvalues as usize).min(list.len() / 4).min(MAX_VALUES_PER_DELETED_KEY) {
                        let Some(vo) = u32_at(list, 4 * i) else { break };
                        if !self.cell_size(vo).is_some_and(|s| s > 0) {
                            continue;
                        }
                        if let Some((value, reused)) = self.any_vk(vo, &mut budget) {
                            claimed.insert(vo);
                            values.push(DeletedValue { offset: vo, key: Some(path.clone()), value, data_reused: reused });
                        }
                    }
                }
            }
            if complete && by_path.contains_key(&path.to_lowercase()) {
                // An old copy of a key that still exists: report only the
                // values the live key no longer has.
                out.old_copies += 1;
                let lk = Key { hive: self, off: by_path[&path.to_lowercase()] };
                let names: std::collections::HashSet<String> = lk.values().into_iter().map(|v| v.name.to_lowercase()).collect();
                for v in values {
                    if !names.contains(&v.value.name.to_lowercase()) && !out.values.iter().any(|x| x.key == v.key && x.value.name.eq_ignore_ascii_case(&v.value.name)) {
                        out.values.push(v);
                    }
                }
                continue;
            }
            if out.keys.len() >= MAX_DELETED {
                out.truncated = true;
                break;
            }
            out.keys.push(DeletedKey { offset: off, path, last_written: t, complete_path: complete, values, subkey_count: subkeys });
        }
        // Several old copies of one deleted key: keep the newest.
        out.keys.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()).then(b.last_written.cmp(&a.last_written)));
        out.keys.dedup_by(|b, a| a.path.eq_ignore_ascii_case(&b.path) && a.complete_path == b.complete_path);
        for &vo in &vks {
            if claimed.contains(&vo) || out.orphans.len() >= MAX_DELETED {
                continue;
            }
            if let Some((value, reused)) = self.any_vk(vo, &mut budget) {
                out.orphans.push(DeletedValue { offset: vo, key: None, value, data_reused: reused });
            }
        }
        out
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
    /// `free` marks a cell free and `parent` sets a key's parent field.
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
        fn free(&mut self, off: u32) {
            let p = off as usize - 32;
            let s = i32::from_le_bytes(self.cells[p..p + 4].try_into().unwrap()).abs();
            self.cells[p..p + 4].copy_from_slice(&s.to_le_bytes());
        }
        fn parent(&mut self, key: u32, parent: u32) {
            let p = key as usize - 32 + 4 + 16;
            self.cells[p..p + 4].copy_from_slice(&parent.to_le_bytes());
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

    #[test]
    fn deleted_keys_and_values() {
        let t = 133_000_000_000_000_000u64;
        let mut w = W::new();
        // Live: ROOT\Software\RunMRU with value a.
        let a = w.value("a", REG_SZ, &u16s("notepad.exe"));
        let run = w.key("RunMRU", t, &[], &[a], b"lf");
        // The old copy of RunMRU still has value b, deleted since.
        let a_old = w.value("a", REG_SZ, &u16s("notepad.exe"));
        let b_old = w.value("b", REG_SZ, &u16s("cmd /c del evidence.txt"));
        let run_old = w.key("RunMRU", t - 1, &[], &[a_old, b_old], b"lf");
        // A deleted key with a value, and a deleted key below it.
        let x = w.value("Tool", REG_SZ, &u16s("C:\\Users\\alice\\wipe.exe"));
        let gone = w.key("Wiper", t + 5, &[], &[x], b"lf");
        let child = w.key("Settings", t + 6, &[], &[], b"lf");
        // A value found on its own.
        let lone = w.value("Lonely", REG_DWORD, &7u32.to_le_bytes());
        let sw = w.key("Software", t, &[run], &[], b"lf");
        let root = w.key("ROOT", t, &[sw], &[], b"lf");
        w.parent(run_old, sw);
        w.parent(gone, sw);
        w.parent(child, gone);
        for c in [a_old, b_old, run_old, x, gone, child, lone] {
            w.free(c);
        }
        // The value lists of the freed keys are the cells after their values.
        let data = w.finish(root, false);
        let mut h = Hive::parse(data).unwrap();
        // Free the old value lists too (the cell just before each nk).
        for k in [run_old, gone] {
            let mut p = 32usize;
            let mut last = 0u32;
            while (p as u32) < k {
                last = p as u32;
                let s = i32_at(&h.data, BASE + p).unwrap().unsigned_abs() as usize;
                p += s;
            }
            let at = BASE + last as usize;
            let s = i32_at(&h.data, at).unwrap().abs();
            h.data[at..at + 4].copy_from_slice(&s.to_le_bytes());
        }
        let d = h.deleted();
        let keys: Vec<(&str, bool, usize)> = d.keys.iter().map(|k| (k.path.as_str(), k.complete_path, k.values.len())).collect();
        assert_eq!(keys, vec![("Software\\Wiper", true, 1), ("Software\\Wiper\\Settings", true, 0)]);
        assert_eq!(d.keys[0].values[0].value.string(), "C:\\Users\\alice\\wipe.exe");
        assert_eq!(d.keys[0].last_written, t + 5);
        assert_eq!(d.old_copies, 1);
        let vals: Vec<(Option<&str>, &str, String)> = d.values.iter().map(|v| (v.key.as_deref(), v.value.name.as_str(), v.value.string())).collect();
        assert_eq!(vals, vec![(Some("Software\\RunMRU"), "b", "cmd /c del evidence.txt".to_string())]);
        assert_eq!(d.orphans.len(), 1);
        assert_eq!((d.orphans[0].value.name.as_str(), d.orphans[0].value.u32()), ("Lonely", Some(7)));
        // A live hive with nothing free has nothing deleted.
        let mut w = W::new();
        let r = w.key("ROOT", t, &[], &[], b"lf");
        let d = Hive::parse(w.finish(r, false)).unwrap().deleted();
        assert!(d.keys.is_empty() && d.values.is_empty() && d.orphans.is_empty());
    }
}
