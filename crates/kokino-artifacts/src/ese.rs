//! Extensible Storage Engine (ESE, "Jet Blue") database reader.
//!
//! Windows keeps several artifacts in ESE databases: SRUM (SRUDB.dat), the
//! Windows Search index, WebCache, Active Directory (ntds.dit). This reader
//! is read-only and works on the file's bytes:
//!
//! - file header: page size, format revision, state (clean or dirty);
//! - pages: header (40 bytes, or 80 for 16 and 32 KiB pages), tags at the
//!   end of the page, each a slice of the page with flags (in the tag for
//!   small pages, in the first key-size word for large ones);
//! - B+ trees: branch entries end in a child page number, leaf entries hold
//!   a key (with an optional prefix shared with the page) and the data;
//! - the catalog (MSysObjectsShadow is not used; MSysObjects at page 4)
//!   lists tables, their columns (id, type, code page) and long-value trees;
//! - records: fixed columns (ids 1-127) with a null bitmap, variable ones
//!   (128-255) with an end-offset array, tagged ones (256 and up) with an
//!   id/offset array, multi-valued and long values, and the compression
//!   Windows 8 added (7-bit text and XPRESS).
//!
//! A database copied while in use is "dirty": its newest changes may still
//! be only in the transaction logs (*.log), which are not replayed here.
//! Every read is bounds-checked and every walk limited, so a damaged or
//! hostile file only yields fewer rows.

use crate::bin::*;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const STATE_CLEAN: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    UInt(u64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
}

impl Value {
    pub fn i64(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            Value::UInt(v) => i64::try_from(*v).ok(),
            Value::Float(f) => Some(*f as i64),
            _ => None,
        }
    }
    pub fn f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(v) => Some(*v as f64),
            Value::UInt(v) => Some(*v as f64),
            _ => None,
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            Value::Text(t) => Some(t.as_bytes()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Column {
    pub id: u32,
    pub name: String,
    pub coltyp: u32,
    /// Code page of text columns (1200 = UTF-16).
    pub codepage: u32,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub objid: u32,
    pub root: u32,
    pub columns: Vec<Column>,
    /// Root page of the table's long-value tree.
    pub lv_root: Option<u32>,
}

pub struct Db<'a> {
    d: &'a [u8],
    pub page_size: usize,
    pub revision: u32,
    pub state: u32,
    pub tables: Vec<Table>,
}

pub const JET_BIT: u32 = 1;
const MAX_PAGES_WALKED: usize = 1 << 20;
const MAX_DEPTH: usize = 64;

/// Size of a fixed column of each type (0 = variable or tagged).
fn fixed_size(coltyp: u32) -> usize {
    match coltyp {
        1 | 2 => 1,
        3 | 17 => 2,
        4 | 6 | 14 => 4,
        5 | 7 | 8 | 15 => 8,
        16 => 16,
        _ => 0,
    }
}

struct Entry<'p> {
    key: Vec<u8>,
    data: &'p [u8],
}

impl<'a> Db<'a> {
    pub fn open(d: &'a [u8]) -> anyhow::Result<Db<'a>> {
        if u32_at(d, 4) != Some(0x89AB_CDEF) {
            anyhow::bail!("not an ESE database (no 0x89ABCDEF signature)");
        }
        let page_size = u32_at(d, 0xEC).unwrap_or(0) as usize;
        if ![2048, 4096, 8192, 16384, 32768].contains(&page_size) {
            anyhow::bail!("unsupported ESE page size {}", page_size);
        }
        let mut db = Db { d, page_size, revision: u32_at(d, 0xE8).unwrap_or(0), state: u32_at(d, 0x34).unwrap_or(0), tables: vec![] };
        db.catalog();
        Ok(db)
    }

    /// The database was not cleanly shut down: recent changes may be only
    /// in its transaction logs.
    pub fn dirty(&self) -> bool {
        self.state != STATE_CLEAN
    }

    fn large(&self) -> bool {
        self.page_size >= 16384
    }

    fn page(&self, n: u32) -> Option<&'a [u8]> {
        let ps = self.page_size;
        let off = (n as usize).checked_add(1)?.checked_mul(ps)?;
        self.d.get(off..off.checked_add(ps)?)
    }

    fn flags(&self, p: &[u8]) -> u32 {
        u32_at(p, 0x24).unwrap_or(0)
    }

    /// The page's tags as (data, tag flags).
    fn tags<'p>(&self, p: &'p [u8]) -> Vec<(&'p [u8], u16)> {
        let ps = self.page_size;
        let hdr = if self.large() { 80 } else { 40 };
        let n = u16_at(p, 0x22).unwrap_or(0) as usize;
        let mut out = vec![];
        for i in 0..n.min(ps / 4) {
            let at = ps - 4 * (i + 1);
            let (Some(size), Some(off)) = (u16_at(p, at), u16_at(p, at + 2)) else { break };
            let (size, off, mut fl) = if self.large() { (size & 0x7FFF, off & 0x7FFF, 0) } else { (size & 0x1FFF, off & 0x1FFF, off >> 13) };
            let start = hdr + off as usize;
            let Some(v) = p.get(start..start + size as usize) else {
                out.push((&p[0..0], 0));
                continue;
            };
            if self.large() && i > 0 && v.len() >= 2 {
                fl = u16_at(v, 0).unwrap_or(0) >> 13;
            }
            out.push((v, fl));
        }
        out
    }

    /// Entries of a leaf or branch page, with their full keys.
    fn entries<'p>(&self, p: &'p [u8]) -> Vec<Entry<'p>> {
        let tags = self.tags(p);
        let Some(&(prefix, _)) = tags.first() else { return vec![] };
        let root = self.flags(p) & 1 != 0;
        let mut out = vec![];
        for &(v, fl) in tags.iter().skip(1) {
            if fl & 0x2 != 0 || v.is_empty() {
                continue; // defunct
            }
            let mut at = 0;
            let mut common = 0;
            if fl & 0x4 != 0 {
                common = (u16_at(v, 0).unwrap_or(0) & 0x1FFF) as usize;
                at = 2;
            }
            let Some(local) = u16_at(v, at) else { continue };
            let local = (local & 0x1FFF) as usize;
            at += 2;
            let Some(k) = v.get(at..at + local) else { continue };
            // On a root page tag 0 is the root header, not a key prefix.
            let mut key = if root { vec![] } else { prefix.get(..common.min(prefix.len())).unwrap_or(&[]).to_vec() };
            key.extend_from_slice(k);
            out.push(Entry { key, data: &v[at + local..] });
        }
        out
    }

    /// Every leaf entry of the B+ tree rooted at `root`, in key order.
    fn walk(&self, root: u32, f: &mut dyn FnMut(&[u8], &[u8])) {
        let mut seen = HashSet::new();
        let Some(objid) = self.page(root).and_then(|p| u32_at(p, 0x18)) else { return };
        self.walk_page(root, objid, 0, &mut seen, f);
    }

    fn walk_page(&self, n: u32, objid: u32, depth: usize, seen: &mut HashSet<u32>, f: &mut dyn FnMut(&[u8], &[u8])) {
        if depth > MAX_DEPTH || seen.len() > MAX_PAGES_WALKED || !seen.insert(n) {
            return;
        }
        let Some(p) = self.page(n) else { return };
        // Every page of a tree carries the tree's object id; a page of
        // another tree (reused or stale) is not followed.
        if u32_at(p, 0x18) != Some(objid) {
            return;
        }
        let flags = self.flags(p);
        if flags & 0x2 != 0 {
            for e in self.entries(p) {
                f(&e.key, e.data);
            }
        } else if flags & 0x8 == 0 {
            // A branch page. Only those right above the leaves carry 0x4
            // ("parent of leaf"); higher ones carry neither flag.
            for e in self.entries(p) {
                if let Some(child) = e.data.len().checked_sub(4).and_then(|o| u32_at(e.data, o)) {
                    self.walk_page(child, objid, depth + 1, seen, f);
                }
            }
        }
    }

    fn catalog(&mut self) {
        let mut tables: BTreeMap<u32, Table> = BTreeMap::new();
        let mut cols: Vec<(u32, Column)> = vec![];
        let mut lvs: Vec<(u32, u32)> = vec![];
        // MSysObjects' own layout: fixed ObjidTable (4), Type (2), Id (4),
        // ColtypOrPgnoFDP (4), SpaceUsage (4), Flags (4), PagesOrLocale (4);
        // Name is the first variable column.
        self.walk(4, &mut |_, rec| {
            let last_fixed = u8_at(rec, 0).unwrap_or(0);
            if last_fixed < 7 {
                return;
            }
            let objid = u32_at(rec, 4).unwrap_or(0);
            let ty = u16_at(rec, 8).unwrap_or(0);
            let id = u32_at(rec, 10).unwrap_or(0);
            let coltyp_or_root = u32_at(rec, 14).unwrap_or(0);
            let locale = u32_at(rec, 26).unwrap_or(0);
            let name = record_var(rec, 128).map(ansi).unwrap_or_default();
            match ty {
                1 => {
                    tables.insert(objid, Table { name, objid, root: coltyp_or_root, columns: vec![], lv_root: None });
                }
                2 => cols.push((objid, Column { id, name, coltyp: coltyp_or_root, codepage: locale })),
                4 => lvs.push((objid, coltyp_or_root)),
                _ => {}
            }
        });
        for (t, c) in cols {
            if let Some(tb) = tables.get_mut(&t) {
                tb.columns.push(c);
            }
        }
        for (t, root) in lvs {
            if let Some(tb) = tables.get_mut(&t) {
                tb.lv_root = Some(root);
            }
        }
        for t in tables.values_mut() {
            t.columns.sort_by_key(|c| c.id);
        }
        self.tables = tables.into_values().collect();
    }

    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name.eq_ignore_ascii_case(name))
    }

    /// Every row of a table: column name to value. `limit` caps the rows.
    pub fn rows(&self, t: &Table, limit: usize) -> Vec<HashMap<String, Value>> {
        let lv = t.lv_root.map(|r| self.long_values(r)).unwrap_or_default();
        let mut out = vec![];
        self.walk(t.root, &mut |_, rec| {
            if out.len() < limit {
                out.push(self.record(t, rec, &lv));
            }
        });
        out
    }

    /// Long values of a table: id -> bytes (segments joined in order).
    fn long_values(&self, root: u32) -> HashMap<u32, Vec<u8>> {
        let mut parts: BTreeMap<(u32, u32), Vec<u8>> = BTreeMap::new();
        let mut total = 0usize;
        self.walk(root, &mut |key, data| {
            if key.len() == 8 && total < (256 << 20) {
                let id = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
                let off = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
                total += data.len();
                parts.insert((id, off), data.to_vec());
            }
        });
        let mut out: HashMap<u32, Vec<u8>> = HashMap::new();
        for ((id, _), d) in parts {
            out.entry(id).or_default().extend_from_slice(&d);
        }
        out
    }

    fn record(&self, t: &Table, rec: &[u8], lv: &HashMap<u32, Vec<u8>>) -> HashMap<String, Value> {
        let mut row = HashMap::new();
        let last_fixed = u8_at(rec, 0).unwrap_or(0) as u32;
        let last_var = u8_at(rec, 1).unwrap_or(0) as u32;
        let var_off = u16_at(rec, 2).unwrap_or(0) as usize;
        // Fixed columns, in id order, then their null bitmap.
        let mut at = 4usize;
        let fixed: Vec<&Column> = t.columns.iter().filter(|c| c.id <= 127 && c.id <= last_fixed).collect();
        let nbits = at + fixed.iter().map(|c| fixed_size(c.coltyp)).sum::<usize>();
        for (i, c) in fixed.iter().enumerate() {
            let size = fixed_size(c.coltyp);
            let null = u8_at(rec, nbits + i / 8).map(|b| b >> (i % 8) & 1 == 1).unwrap_or(true);
            let v = match rec.get(at..at + size) {
                Some(b) if !null => decode(c, b),
                _ => Value::Null,
            };
            row.insert(c.name.clone(), v);
            at += size;
        }
        // Variable columns: an array of end offsets after `var_off`.
        let nvar = last_var.saturating_sub(127) as usize;
        let vstart = var_off + 2 * nvar;
        let mut prev = 0usize;
        let mut vend = vstart;
        for i in 0..nvar {
            let Some(raw) = u16_at(rec, var_off + 2 * i) else { break };
            let end = (raw & 0x7FFF) as usize;
            let id = 128 + i as u32;
            if raw & 0x8000 == 0 {
                if let (Some(c), Some(b)) = (t.columns.iter().find(|c| c.id == id), rec.get(vstart + prev..vstart + end)) {
                    row.insert(c.name.clone(), decode(c, b));
                }
            }
            prev = end;
            vend = vstart + end;
        }
        // Tagged columns: (id, offset) pairs, then the data.
        // Large pages use 15-bit offsets and always lead the data with a
        // flags byte; small pages mark that byte with offset bit 0x4000.
        let tagged = rec.get(vend..).unwrap_or(&[]);
        let mask = if self.large() { 0x7FFF } else { 0x3FFF };
        if tagged.len() >= 4 {
            let first = (u16_at(tagged, 2).unwrap_or(0) & mask) as usize;
            let n = (first / 4).min(tagged.len() / 4);
            for i in 0..n {
                let id = u16_at(tagged, 4 * i).unwrap_or(0) as u32;
                let raw = u16_at(tagged, 4 * i + 2).unwrap_or(0);
                let start = (raw & mask) as usize;
                let end = if i + 1 < n { (u16_at(tagged, 4 * i + 6).unwrap_or(0) & mask) as usize } else { tagged.len() };
                let Some(mut b) = tagged.get(start..end.max(start)) else { continue };
                let Some(c) = t.columns.iter().find(|c| c.id == id) else { continue };
                // Extended info: a flags byte leads the data.
                let mut fl = 0u8;
                if self.large() || raw & 0x4000 != 0 {
                    fl = b.first().copied().unwrap_or(0);
                    b = b.get(1..).unwrap_or(&[]);
                }
                let v = if fl & 0x04 != 0 {
                    // Long value: the data is the long value's id.
                    let id = b.get(..4).map(|k| u32::from_be_bytes([k[0], k[1], k[2], k[3]])).unwrap_or(0);
                    lv.get(&id).map(|d| decode(c, &uncompress(d))).unwrap_or(Value::Null)
                } else if fl & 0x08 != 0 {
                    // Multi-valued: an offset array; the first value is kept.
                    let o = u16_at(b, 0).unwrap_or(0) as usize & 0x7FFF;
                    let e = u16_at(b, 2).map(|x| x as usize & 0x7FFF).filter(|&e| e > o && o >= 2).unwrap_or(b.len());
                    decode(c, &uncompress(b.get(o..e).unwrap_or(&[])))
                } else if fl & 0x02 != 0 || c.coltyp == 11 || c.coltyp == 12 {
                    decode(c, &uncompress(b))
                } else {
                    decode(c, b)
                };
                row.insert(c.name.clone(), v);
            }
        }
        row
    }
}

/// The bytes of variable column `id` in a record (used for the catalog,
/// whose layout is fixed).
fn record_var(rec: &[u8], id: u32) -> Option<&[u8]> {
    let last_var = u8_at(rec, 1)? as u32;
    let var_off = u16_at(rec, 2)? as usize;
    let nvar = last_var.checked_sub(127)? as usize;
    let i = id.checked_sub(128)? as usize;
    if i >= nvar {
        return None;
    }
    let vstart = var_off + 2 * nvar;
    let start = if i == 0 { 0 } else { (u16_at(rec, var_off + 2 * (i - 1))? & 0x7FFF) as usize };
    let raw = u16_at(rec, var_off + 2 * i)?;
    if raw & 0x8000 != 0 {
        return None;
    }
    rec.get(vstart + start..vstart + (raw & 0x7FFF) as usize)
}

fn decode(c: &Column, b: &[u8]) -> Value {
    match c.coltyp {
        1 | 2 => Value::UInt(b.first().copied().unwrap_or(0) as u64),
        3 => Value::Int(u16_at(b, 0).unwrap_or(0) as i16 as i64),
        17 => Value::UInt(u16_at(b, 0).unwrap_or(0) as u64),
        4 => Value::Int(i32_at(b, 0).unwrap_or(0) as i64),
        14 => Value::UInt(u32_at(b, 0).unwrap_or(0) as u64),
        5 | 15 => Value::Int(u64_at(b, 0).unwrap_or(0) as i64),
        6 => Value::Float(u32_at(b, 0).map(f32::from_bits).unwrap_or(0.0) as f64),
        7 | 8 => Value::Float(u64_at(b, 0).map(f64::from_bits).unwrap_or(0.0)),
        10 | 12 if c.codepage == 1200 => Value::Text(utf16(b)),
        // Programs also store UTF-16 in columns declared as ANSI (SRUM
        // does): two or more characters, every second byte zero.
        10 | 12 if looks_utf16(b) => Value::Text(utf16(b)),
        10 | 12 => Value::Text(ansi(b)),
        _ => Value::Bytes(b.to_vec()),
    }
}

fn looks_utf16(b: &[u8]) -> bool {
    b.len() >= 4 && b.len().is_multiple_of(2) && b[0] != 0 && b.chunks(2).all(|c| c[1] == 0)
}

/// Undoes ESE column compression (Windows 8 and later). The first byte
/// names the method in its top 5 bits: 1 = 7-bit ASCII, 2 = 7-bit UTF-16,
/// 3 = XPRESS (plain LZ77). Anything else is returned as stored.
pub fn uncompress(b: &[u8]) -> Vec<u8> {
    let Some(&h) = b.first() else { return vec![] };
    match h >> 3 {
        1 | 2 if b.len() >= 2 => {
            // 7-bit: packed little-endian bit stream of 7-bit characters.
            let wide = h >> 3 == 2;
            // The low 3 bits of the header are the bits used in the last
            // byte, minus one.
            let n = ((b.len() - 2) * 8 + (h & 7) as usize + 1) / 7;
            let mut out = Vec::with_capacity(n * if wide { 2 } else { 1 });
            let (mut acc, mut nacc, mut p) = (0u32, 0u32, 1usize);
            for _ in 0..n {
                while nacc < 7 && p < b.len() {
                    acc |= (b[p] as u32) << nacc;
                    nacc += 8;
                    p += 1;
                }
                if nacc < 7 {
                    break;
                }
                let c = (acc & 0x7F) as u8;
                acc >>= 7;
                nacc -= 7;
                out.push(c);
                if wide {
                    out.push(0);
                }
            }
            out
        }
        3 if b.len() >= 3 => {
            let size = u16_at(b, 1).unwrap_or(0) as usize;
            xpress_plain(b.get(3..).unwrap_or(&[]), size)
        }
        _ => b.to_vec(),
    }
}

/// LZ77 "plain" XPRESS ([MS-XCA] 2.4), as ESE uses for column compression.
pub fn xpress_plain(src: &[u8], size: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(size.min(1 << 20));
    let (mut flags, mut nflags, mut p, mut nibble_at): (u32, u32, usize, Option<usize>) = (0, 0, 0, None);
    while out.len() < size && p < src.len() {
        if nflags == 0 {
            let Some(f) = u32_at(src, p) else { break };
            flags = f;
            nflags = 32;
            p += 4;
        }
        nflags -= 1;
        if flags >> nflags & 1 == 0 {
            let Some(&c) = src.get(p) else { break };
            out.push(c);
            p += 1;
            continue;
        }
        let Some(m) = u16_at(src, p) else { break };
        p += 2;
        let off = (m >> 3) as usize + 1;
        let mut len = (m & 7) as usize;
        if len == 7 {
            let n = match nibble_at.take() {
                Some(at) => (src.get(at).copied().unwrap_or(0) >> 4) as usize,
                None => {
                    nibble_at = Some(p);
                    let v = src.get(p).copied().unwrap_or(0) & 15;
                    p += 1;
                    v as usize
                }
            };
            len = n;
            if len == 15 {
                len = src.get(p).copied().unwrap_or(0) as usize;
                p += 1;
                if len == 255 {
                    len = u16_at(src, p).unwrap_or(0) as usize;
                    p += 2;
                    if len == 0 {
                        len = u32_at(src, p).unwrap_or(0) as usize;
                        p += 4;
                    }
                    if len < 22 {
                        break;
                    }
                    len -= 22;
                }
                len += 15;
            }
            len += 7;
        }
        len += 3;
        if off > out.len() {
            break;
        }
        for _ in 0..len.min(size - out.len()) {
            let c = out[out.len() - off];
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<Vec<u8>> {
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/win/").to_string() + name).ok()
    }

    /// Databases written by Windows' own esent.dll (scripts/make_srum_fixture.py).
    #[test]
    fn reads_srum_fixtures() {
        for name in ["SRUDB.dat", "SRUDB-4k.dat"] {
            let Some(d) = fixture(name) else { continue };
            let db = Db::open(&d).unwrap();
            assert!(!db.dirty(), "{}", name);
            let names: Vec<&str> = db.tables.iter().map(|t| t.name.as_str()).collect();
            for t in ["MSysObjects", "SruDbIdMapTable", "{973F5D5C-1D90-4944-BE8E-24B94231A174}", "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "{DD6636C4-8929-4683-974E-22C046A43763}"] {
                assert!(names.contains(&t), "{} missing in {}: {:?}", t, name, names);
            }
            let ids = db.rows(db.table("SruDbIdMapTable").unwrap(), usize::MAX);
            assert_eq!(ids.len(), 7, "{}", name);
            // Not 7-bit text: Windows keeps it uncompressed (only the 7-bit
            // path is exercised by Windows' own data; XPRESS by the vector below).
            let long = ids.iter().find(|r| r["IdIndex"] == Value::Int(7)).unwrap();
            let u = char::from_u32(0xFC).unwrap();
            let want = format!(r"\Device\HarddiskVolume3\Users\alice\Documents\M{u}ller Projekte\M{u}ller Projekte Archiv\M{u}ller Projekte Archiv 2026\backup-tool.exe");
            assert_eq!(utf16(long["IdBlob"].bytes().unwrap()), want, "{}", name);
            let rclone = ids.iter().find(|r| r["IdIndex"] == Value::Int(1)).unwrap();
            assert_eq!(utf16(rclone["IdBlob"].bytes().unwrap()), r"\Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\rclone.exe", "{}", name);
            let sid = ids.iter().find(|r| r["IdIndex"] == Value::Int(4)).unwrap();
            assert_eq!(crate::bin::sid(sid["IdBlob"].bytes().unwrap()).unwrap(), "S-1-5-21-1111111111-2222222222-3333333333-1001");
            let net = db.rows(db.table("{973F5D5C-1D90-4944-BE8E-24B94231A174}").unwrap(), usize::MAX);
            assert_eq!(net.len(), 303, "{}", name);
            let sent: i64 = net.iter().filter(|r| r["AppId"] == Value::Int(1)).map(|r| r["BytesSent"].i64().unwrap()).sum();
            assert_eq!(sent, 2_147_483_648);
            assert!(net.iter().all(|r| r["TimeStamp"].f64().unwrap() > 46_000.0));
            let usage = db.rows(db.table("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}").unwrap(), usize::MAX);
            assert_eq!(usage.iter().map(|r| r["ForegroundBytesRead"].i64().unwrap()).sum::<i64>(), 2_147_483_648);
        }
    }

    /// A tree of three levels (scripts/make_srum_fixture.py deep): branch
    /// pages above the parents of leaves carry neither page flag, as in
    /// Windows' own SRUM databases with many ids. Also UTF-16 text in a
    /// column declared as code page 1252.
    #[test]
    fn deep_tree_and_utf16_in_ansi() {
        let Some(d) = fixture("ese-deep.dat") else { return };
        let db = Db::open(&d).unwrap();
        let t = db.table("Deep").unwrap();
        let rows = db.rows(t, usize::MAX);
        assert_eq!(rows.len(), 400);
        for (i, r) in rows.iter().enumerate() {
            assert_eq!(r["N"], Value::Int(i as i64));
            assert_eq!(r["Note"], Value::Text(format!("row {}", i)));
        }
    }

    #[test]
    fn junk_and_compression() {
        assert!(Db::open(&[0u8; 100]).is_err());
        let mut d = vec![0u8; 8192 * 8];
        d[4..8].copy_from_slice(&0x89AB_CDEFu32.to_le_bytes());
        d[0xEC..0xF0].copy_from_slice(&8192u32.to_le_bytes());
        for (i, b) in d.iter_mut().enumerate().skip(8192 * 5) {
            *b = (i.wrapping_mul(2654435761) >> 13) as u8;
        }
        let db = Db::open(&d).unwrap();
        for t in &db.tables {
            let _ = db.rows(t, 1000);
        }
        // 7-bit ASCII: "ABC" packed.
        let packed = {
            let (a, b, c) = (b'A' as u32, b'B' as u32, b'C' as u32);
            let v = a | b << 7 | c << 14;
            vec![0x08 | 4, v as u8, (v >> 8) as u8, (v >> 16) as u8]
        };
        assert_eq!(uncompress(&packed), b"ABC");
        // Plain XPRESS: literals then a match of 6 at distance 3.
        let mut x = vec![];
        x.extend_from_slice(&(1u32 << 28).to_le_bytes());
        x.extend_from_slice(b"abc");
        x.extend_from_slice(&((2u16 << 3) | 3).to_le_bytes());
        assert_eq!(xpress_plain(&x, 9), b"abcabcabc");
        for n in 0..64usize {
            let junk: Vec<u8> = (0..n * 5).map(|i| (i * 37 % 256) as u8).collect();
            let _ = uncompress(&junk);
            let _ = xpress_plain(&junk, 4096);
        }
    }
}
