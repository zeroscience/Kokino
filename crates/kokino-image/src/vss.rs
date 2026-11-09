//! Volume Shadow Copies (VSS) on NTFS volumes.
//!
//! A shadow copy keeps, for each 16 KiB block that changed after the
//! snapshot, the block as it was. The volume header at 0x1E00 points to a
//! catalog listing the stores (oldest first) with their creation times and
//! block lists. A snapshot is rebuilt by reading each block from the first
//! store, at or after the snapshot's own, that holds it; blocks no store
//! holds are read from the live volume. Overlay entries replace single
//! 512-byte sectors of a block; forwarders say a block is to be read at
//! another offset of the next store.
//!
//! Structures as documented by Joachim Metz (libvshadow); checked against
//! the dfvfs test image `vss.raw`.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom};

pub const VSS_ID: [u8; 16] = [0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52];
const HEADER_AT: u64 = 0x1E00;
const BLOCK: u64 = 0x4000;
const MAX_STORES: usize = 512;
const MAX_CATALOG_BLOCKS: usize = 4096;
const MAX_LIST_BLOCKS: usize = 1 << 20;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct StoreInfo {
    /// 1 is the oldest.
    pub index: usize,
    pub id: String,
    pub created: u64,
    pub volume_size: u64,
    block_list: u64,
}

#[derive(Debug, Clone, Default)]
pub struct StoreMap {
    full: HashMap<u64, u64>,
    overlay: HashMap<u64, Vec<(u64, u32)>>,
    forward: HashMap<u64, u64>,
}

fn rd<R: Read + Seek>(r: &mut R, off: u64, n: usize) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; n];
    let mut got = 0;
    while got < n {
        let k = r.read(&mut b[got..])?;
        if k == 0 {
            break;
        }
        got += k;
    }
    b.truncate(got);
    Ok(b)
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32_at(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// The shadow copy stores of an NTFS volume (`r` reads the volume), oldest
/// first. Empty when the volume has none.
pub fn stores<R: Read + Seek>(r: &mut R, vol_len: u64) -> Vec<StoreInfo> {
    let Ok(h) = rd(r, HEADER_AT, 128) else { return vec![] };
    if h.get(0..16) != Some(&VSS_ID[..]) || u32_at(&h, 20) != 1 {
        return vec![];
    }
    let mut off = u64_at(&h, 48);
    let mut info: Vec<StoreInfo> = vec![];
    let mut lists: HashMap<String, u64> = HashMap::new();
    let mut seen = 0;
    while off != 0 && off.checked_add(BLOCK).is_some_and(|e| e <= vol_len) && seen < MAX_CATALOG_BLOCKS {
        seen += 1;
        let Ok(b) = rd(r, off, BLOCK as usize) else { break };
        if b.get(0..16) != Some(&VSS_ID[..]) || u32_at(&b, 20) != 2 {
            break;
        }
        for e in b[128..].chunks_exact(128) {
            match u64_at(e, 0) {
                2 => info.push(StoreInfo { index: 0, id: guid(&e[16..32]), created: u64_at(e, 48), volume_size: u64_at(e, 8), block_list: 0 }),
                3 => {
                    lists.insert(guid(&e[16..32]), u64_at(e, 8));
                }
                _ => {}
            }
        }
        off = u64_at(&b, 40);
    }
    info.retain(|s| s.created != 0 && lists.contains_key(&s.id));
    for s in &mut info {
        s.block_list = lists[&s.id];
    }
    info.sort_by_key(|s| s.created);
    // Windows keeps at most 512 shadow copies per volume.
    info.truncate(MAX_STORES);
    for (i, s) in info.iter_mut().enumerate() {
        s.index = i + 1;
    }
    info
}

/// The block list of one store.
pub fn store_map<R: Read + Seek>(r: &mut R, s: &StoreInfo, vol_len: u64) -> io::Result<StoreMap> {
    let mut m = StoreMap::default();
    let mut off = s.block_list;
    let mut n = 0;
    while off != 0 && off.checked_add(BLOCK).is_some_and(|e| e <= vol_len) && n < MAX_LIST_BLOCKS {
        n += 1;
        let b = rd(r, off, BLOCK as usize)?;
        if b.get(0..16) != Some(&VSS_ID[..]) || u32_at(&b, 20) != 3 {
            break;
        }
        for e in b[128..].chunks_exact(32) {
            let (orig, rel, data, flags, bitmap) = (u64_at(e, 0), u64_at(e, 8), u64_at(e, 16), u32_at(e, 24), u32_at(e, 28));
            if orig == 0 && rel == 0 && data == 0 && flags == 0 {
                continue;
            }
            if orig % BLOCK != 0 || orig >= vol_len {
                continue;
            }
            if flags & 4 != 0 {
                continue; // not used
            }
            if flags & 1 != 0 {
                m.forward.insert(orig, rel);
            } else if flags & 2 != 0 {
                m.overlay.entry(orig).or_default().push((data, bitmap));
            } else {
                m.full.insert(orig, data);
            }
        }
        off = u64_at(&b, 40);
    }
    Ok(m)
}

/// A shadow copy as a volume: read it like the volume it was.
pub struct ShadowReader<R: Read + Seek> {
    inner: R,
    /// The stores from this snapshot's own to the newest.
    maps: Vec<StoreMap>,
    size: u64,
    pos: u64,
}

impl<R: Read + Seek> ShadowReader<R> {
    /// `inner` reads the live volume; `index` is the store (1 = oldest).
    pub fn new(mut inner: R, vol_len: u64, index: usize) -> io::Result<Self> {
        let all = stores(&mut inner, vol_len);
        let me = all.iter().find(|s| s.index == index).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such shadow copy"))?;
        let size = if me.volume_size == 0 { vol_len } else { me.volume_size.min(vol_len) };
        let mut maps = vec![];
        for s in all.iter().filter(|s| s.index >= index) {
            maps.push(store_map(&mut inner, s, vol_len)?);
        }
        Ok(ShadowReader { inner, maps, size, pos: 0 })
    }

    /// One block as the snapshot saw it: the first store from this
    /// snapshot's own that copied it (following forwarders), else the live
    /// volume; then the sectors each store overlaid, the newest store first.
    fn block(&mut self, orig: u64) -> io::Result<Vec<u8>> {
        let mut cur = orig;
        let mut src = None;
        // (store, block address there) for each store passed, for overlays.
        let mut passed: Vec<(usize, u64)> = vec![];
        for (k, m) in self.maps.iter().enumerate() {
            passed.push((k, cur));
            if let Some(&to) = m.forward.get(&cur) {
                cur = to;
            } else if let Some(&at) = m.full.get(&cur) {
                src = Some(at);
                break;
            }
        }
        let mut data = rd(&mut self.inner, src.unwrap_or(cur), BLOCK as usize)?;
        data.resize(BLOCK as usize, 0);
        for &(k, o) in passed.iter().rev() {
            let Some(ov) = self.maps[k].overlay.get(&o).cloned() else { continue };
            for (at, bitmap) in ov {
                let b = rd(&mut self.inner, at, BLOCK as usize)?;
                for s in 0..32 {
                    if bitmap >> s & 1 == 1 {
                        let o = s * 512;
                        if let Some(src) = b.get(o..o + 512) {
                            data[o..o + 512].copy_from_slice(src);
                        }
                    }
                }
            }
        }
        Ok(data)
    }
}

impl<R: Read + Seek> Read for ShadowReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let start = self.pos / BLOCK * BLOCK;
        let block = self.block(start)?;
        let o = (self.pos - start) as usize;
        let n = buf.len().min(BLOCK as usize - o).min((self.size - self.pos) as usize);
        buf[..n].copy_from_slice(&block[o..o + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for ShadowReader<R> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.pos = match p {
            SeekFrom::Start(x) => x,
            SeekFrom::End(x) => (self.size as i64).saturating_add(x).max(0) as u64,
            SeekFrom::Current(x) => (self.pos.min(i64::MAX as u64) as i64).saturating_add(x).max(0) as u64,
        };
        Ok(self.pos)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn put64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// A 1 MiB "volume" with two stores. Block 0x10000: store 1 holds it whole.
    /// Block 0x14000: store 1 overlays sector 2 on store 2's copy. Block
    /// 0x18000: store 1 forwards to 0x1c000 in store 2. Everything else: live.
    pub(crate) fn synthetic() -> Vec<u8> {
        let len = 1 << 20;
        let mut v = vec![0u8; len];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i / BLOCK as usize) as u8; // live data: block number
        }
        let header = |b: &mut [u8], ty: u32, next: u64| {
            b[0..16].copy_from_slice(&VSS_ID);
            b[16..20].copy_from_slice(&1u32.to_le_bytes());
            b[20..24].copy_from_slice(&ty.to_le_bytes());
            put64(b, 40, next);
        };
        // Volume header -> catalog at 0x40000.
        let mut h = [0u8; 128];
        h[0..16].copy_from_slice(&VSS_ID);
        h[16..20].copy_from_slice(&1u32.to_le_bytes());
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        put64(&mut h, 48, 0x40000);
        v[0x1E00..0x1E80].copy_from_slice(&h);
        let mut cat = vec![0u8; BLOCK as usize];
        header(&mut cat, 2, 0);
        let ids = [[1u8; 16], [2u8; 16]];
        for (k, (id, created, list)) in [(ids[0], 100u64, 0x44000u64), (ids[1], 200, 0x48000)].iter().enumerate() {
            let e = 128 + k * 256;
            put64(&mut cat, e, 2);
            put64(&mut cat, e + 8, len as u64);
            cat[e + 16..e + 32].copy_from_slice(id);
            put64(&mut cat, e + 48, *created);
            put64(&mut cat, e + 128, 3);
            put64(&mut cat, e + 136, *list);
            cat[e + 144..e + 160].copy_from_slice(id);
        }
        v[0x40000..0x44000].copy_from_slice(&cat);
        let list = |entries: &[(u64, u64, u64, u32, u32)]| {
            let mut b = vec![0u8; BLOCK as usize];
            header(&mut b, 3, 0);
            for (i, (o, r, d, f, bm)) in entries.iter().enumerate() {
                let p = 128 + i * 32;
                put64(&mut b, p, *o);
                put64(&mut b, p + 8, *r);
                put64(&mut b, p + 16, *d);
                b[p + 24..p + 28].copy_from_slice(&f.to_le_bytes());
                b[p + 28..p + 32].copy_from_slice(&bm.to_le_bytes());
            }
            b
        };
        // Store data blocks at 0x50000.. filled with marker bytes.
        let fill = |v: &mut Vec<u8>, at: usize, x: u8| v[at..at + BLOCK as usize].fill(x);
        fill(&mut v, 0x50000, 0xA1); // store 1 full copy of 0x10000
        fill(&mut v, 0x54000, 0xA2); // store 1 overlay data for 0x14000
        fill(&mut v, 0x58000, 0xB1); // store 2 full copy of 0x14000
        fill(&mut v, 0x5C000, 0xB2); // store 2 full copy of 0x1c000
        let l1 = list(&[(0x10000, 0, 0x50000, 0, 0), (0x14000, 0, 0x54000, 2, 0b100), (0x18000, 0x1c000, 0, 1, 0)]);
        let l2 = list(&[(0x14000, 0, 0x58000, 0, 0), (0x1c000, 0, 0x5C000, 0, 0)]);
        v[0x44000..0x48000].copy_from_slice(&l1);
        v[0x48000..0x4C000].copy_from_slice(&l2);
        v
    }

    #[test]
    fn rebuilds_snapshots() {
        let len = 1 << 20;
        let mut r = std::io::Cursor::new(synthetic());
        let st = stores(&mut r, len as u64);
        assert_eq!(st.iter().map(|s| (s.index, s.created)).collect::<Vec<_>>(), vec![(1, 100), (2, 200)]);
        let read = |store: usize, off: u64, n: usize| {
            let mut s = ShadowReader::new(r.clone(), len as u64, store).unwrap();
            s.seek(SeekFrom::Start(off)).unwrap();
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).unwrap();
            b
        };
        assert_eq!(read(1, 0x10000, 4), [0xA1; 4]); // store 1's own copy
        assert_eq!(read(2, 0x10000, 4), [4; 4]); // store 2 never saw it change: live
        assert_eq!(read(1, 0x14000 + 1024, 4), [0xA2; 4]); // overlaid sector 2
        assert_eq!(read(1, 0x14000, 4), [0xB1; 4]); // the rest from store 2
        assert_eq!(read(1, 0x18000, 4), [0xB2; 4]); // forwarded to 0x1c000 in store 2
        assert_eq!(read(1, 0x20000, 4), [8; 4]); // live
        assert!(ShadowReader::new(r.clone(), len as u64, 3).is_err());
    }
}
