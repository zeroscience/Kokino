//! Outlook PST and OST files (MS-PST): ANSI (Outlook 97-2002), Unicode
//! (2003 and later) and the 4 KiB-page OST of Outlook 2013 and later, with
//! its compressed blocks; no, "compressible" and "high" encryption.
//!
//! Layers, as the specification names them:
//! - NDB: the header, the node and block B-trees (NBT, BBT), blocks
//!   (decoded and inflated), data trees (XBLOCK, XXBLOCK) and subnode
//!   trees (SLBLOCK, SIBLOCK);
//! - LTP: the heap on a node, property contexts and table contexts;
//! - messaging: folders, messages, recipients and attachments.
//!
//! Deleted messages come back two ways: message nodes left in the unused
//! slots of node index pages, and message property contexts found in the
//! file's free space by their block trailers (size, signature, CRC, block
//! id) whose blocks the index no longer lists.
//!
//! The file is read through `Read + Seek`, block by block, so large files
//! are never held in memory. Every message node is listed, also one whose
//! folder is gone. A message is rendered as an RFC 822 message (headers,
//! text, attachments as MIME parts, attached messages as message/rfc822)
//! so the mail code can show, search and export it like any other.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::io::{Read, Seek, SeekFrom};

// MS-PST 5.1 (mpbbCrypt): the three 256-byte parts of the permutation
// table. I decodes compressible encryption; R, S and I together the
// cyclic (high) encryption.
const CRYPT_R: [u8; 256] = [
    0x41, 0x36, 0x13, 0x62, 0xa8, 0x21, 0x6e, 0xbb, 0xf4, 0x16, 0xcc, 0x04, 0x7f, 0x64, 0xe8, 0x5d,
    0x1e, 0xf2, 0xcb, 0x2a, 0x74, 0xc5, 0x5e, 0x35, 0xd2, 0x95, 0x47, 0x9e, 0x96, 0x2d, 0x9a, 0x88,
    0x4c, 0x7d, 0x84, 0x3f, 0xdb, 0xac, 0x31, 0xb6, 0x48, 0x5f, 0xf6, 0xc4, 0xd8, 0x39, 0x8b, 0xe7,
    0x23, 0x3b, 0x38, 0x8e, 0xc8, 0xc1, 0xdf, 0x25, 0xb1, 0x20, 0xa5, 0x46, 0x60, 0x4e, 0x9c, 0xfb,
    0xaa, 0xd3, 0x56, 0x51, 0x45, 0x7c, 0x55, 0x00, 0x07, 0xc9, 0x2b, 0x9d, 0x85, 0x9b, 0x09, 0xa0,
    0x8f, 0xad, 0xb3, 0x0f, 0x63, 0xab, 0x89, 0x4b, 0xd7, 0xa7, 0x15, 0x5a, 0x71, 0x66, 0x42, 0xbf,
    0x26, 0x4a, 0x6b, 0x98, 0xfa, 0xea, 0x77, 0x53, 0xb2, 0x70, 0x05, 0x2c, 0xfd, 0x59, 0x3a, 0x86,
    0x7e, 0xce, 0x06, 0xeb, 0x82, 0x78, 0x57, 0xc7, 0x8d, 0x43, 0xaf, 0xb4, 0x1c, 0xd4, 0x5b, 0xcd,
    0xe2, 0xe9, 0x27, 0x4f, 0xc3, 0x08, 0x72, 0x80, 0xcf, 0xb0, 0xef, 0xf5, 0x28, 0x6d, 0xbe, 0x30,
    0x4d, 0x34, 0x92, 0xd5, 0x0e, 0x3c, 0x22, 0x32, 0xe5, 0xe4, 0xf9, 0x9f, 0xc2, 0xd1, 0x0a, 0x81,
    0x12, 0xe1, 0xee, 0x91, 0x83, 0x76, 0xe3, 0x97, 0xe6, 0x61, 0x8a, 0x17, 0x79, 0xa4, 0xb7, 0xdc,
    0x90, 0x7a, 0x5c, 0x8c, 0x02, 0xa6, 0xca, 0x69, 0xde, 0x50, 0x1a, 0x11, 0x93, 0xb9, 0x52, 0x87,
    0x58, 0xfc, 0xed, 0x1d, 0x37, 0x49, 0x1b, 0x6a, 0xe0, 0x29, 0x33, 0x99, 0xbd, 0x6c, 0xd9, 0x94,
    0xf3, 0x40, 0x54, 0x6f, 0xf0, 0xc6, 0x73, 0xb8, 0xd6, 0x3e, 0x65, 0x18, 0x44, 0x1f, 0xdd, 0x67,
    0x10, 0xf1, 0x0c, 0x19, 0xec, 0xae, 0x03, 0xa1, 0x14, 0x7b, 0xa9, 0x0b, 0xff, 0xf8, 0xa3, 0xc0,
    0xa2, 0x01, 0xf7, 0x2e, 0xbc, 0x24, 0x68, 0x75, 0x0d, 0xfe, 0xba, 0x2f, 0xb5, 0xd0, 0xda, 0x3d,
];
const CRYPT_S: [u8; 256] = [
    0x14, 0x53, 0x0f, 0x56, 0xb3, 0xc8, 0x7a, 0x9c, 0xeb, 0x65, 0x48, 0x17, 0x16, 0x15, 0x9f, 0x02,
    0xcc, 0x54, 0x7c, 0x83, 0x00, 0x0d, 0x0c, 0x0b, 0xa2, 0x62, 0xa8, 0x76, 0xdb, 0xd9, 0xed, 0xc7,
    0xc5, 0xa4, 0xdc, 0xac, 0x85, 0x74, 0xd6, 0xd0, 0xa7, 0x9b, 0xae, 0x9a, 0x96, 0x71, 0x66, 0xc3,
    0x63, 0x99, 0xb8, 0xdd, 0x73, 0x92, 0x8e, 0x84, 0x7d, 0xa5, 0x5e, 0xd1, 0x5d, 0x93, 0xb1, 0x57,
    0x51, 0x50, 0x80, 0x89, 0x52, 0x94, 0x4f, 0x4e, 0x0a, 0x6b, 0xbc, 0x8d, 0x7f, 0x6e, 0x47, 0x46,
    0x41, 0x40, 0x44, 0x01, 0x11, 0xcb, 0x03, 0x3f, 0xf7, 0xf4, 0xe1, 0xa9, 0x8f, 0x3c, 0x3a, 0xf9,
    0xfb, 0xf0, 0x19, 0x30, 0x82, 0x09, 0x2e, 0xc9, 0x9d, 0xa0, 0x86, 0x49, 0xee, 0x6f, 0x4d, 0x6d,
    0xc4, 0x2d, 0x81, 0x34, 0x25, 0x87, 0x1b, 0x88, 0xaa, 0xfc, 0x06, 0xa1, 0x12, 0x38, 0xfd, 0x4c,
    0x42, 0x72, 0x64, 0x13, 0x37, 0x24, 0x6a, 0x75, 0x77, 0x43, 0xff, 0xe6, 0xb4, 0x4b, 0x36, 0x5c,
    0xe4, 0xd8, 0x35, 0x3d, 0x45, 0xb9, 0x2c, 0xec, 0xb7, 0x31, 0x2b, 0x29, 0x07, 0x68, 0xa3, 0x0e,
    0x69, 0x7b, 0x18, 0x9e, 0x21, 0x39, 0xbe, 0x28, 0x1a, 0x5b, 0x78, 0xf5, 0x23, 0xca, 0x2a, 0xb0,
    0xaf, 0x3e, 0xfe, 0x04, 0x8c, 0xe7, 0xe5, 0x98, 0x32, 0x95, 0xd3, 0xf6, 0x4a, 0xe8, 0xa6, 0xea,
    0xe9, 0xf3, 0xd5, 0x2f, 0x70, 0x20, 0xf2, 0x1f, 0x05, 0x67, 0xad, 0x55, 0x10, 0xce, 0xcd, 0xe3,
    0x27, 0x3b, 0xda, 0xba, 0xd7, 0xc2, 0x26, 0xd4, 0x91, 0x1d, 0xd2, 0x1c, 0x22, 0x33, 0xf8, 0xfa,
    0xf1, 0x5a, 0xef, 0xcf, 0x90, 0xb6, 0x8b, 0xb5, 0xbd, 0xc0, 0xbf, 0x08, 0x97, 0x1e, 0x6c, 0xe2,
    0x61, 0xe0, 0xc6, 0xc1, 0x59, 0xab, 0xbb, 0x58, 0xde, 0x5f, 0xdf, 0x60, 0x79, 0x7e, 0xb2, 0x8a,
];
const CRYPT_I: [u8; 256] = [
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
    0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
    0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
    0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
    0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
    0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
    0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
    0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
    0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
    0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
    0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
    0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
    0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
    0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
    0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
    0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec,
];

const MAX_NODES: usize = 4_000_000;
/// Deleted messages recovered from one file, at most.
const MAX_RECOVERED: usize = 10_000;
const MAX_DATA: usize = 256 << 20;
/// How much of a file is searched for blocks by their trailers.
const MAX_SCAN: u64 = 16 << 30;
/// Blocks found in free space that are looked at, at most.
const MAX_ORPHANS: usize = 500_000;

/// MS-PST 5.3: CRC-32 (reflected 0xEDB88320) from 0, not inverted.
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn pst_crc(d: &[u8]) -> u32 {
    d.iter().fold(0u32, |c, &b| CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8))
}

/// MS-PST 5.5: the block signature, from where the block is and its id.
fn block_sig(ib: u64, bid: u64) -> u16 {
    let x = ib ^ bid;
    ((x >> 16) ^ x) as u16
}
const MAX_DEPTH: usize = 8;

fn u16_at(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]])).unwrap_or(0)
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}

/// Whether the bytes start like a PST or OST file.
pub fn is_pst(head: &[u8]) -> bool {
    head.len() >= 12 && head.starts_with(b"!BDN") && matches!(&head[8..10], b"SM" | b"SO" | b"AB")
}

#[derive(Debug, Clone, Copy)]
struct BlockRef {
    ib: u64,
    cb: u32,
    /// Uncompressed size (4 KiB-page OST); equal to `cb` otherwise.
    inflated: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Node {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
    pub parent: u32,
}

/// A property value as stored.
#[derive(Debug, Clone)]
pub struct Prop {
    pub ptype: u16,
    pub data: Vec<u8>,
}

impl Prop {
    pub fn text(&self) -> String {
        match self.ptype {
            0x001F => utf16(&self.data),
            0x001E | 0x0102 => {
                let end = self.data.iter().position(|&c| c == 0).unwrap_or(self.data.len());
                match std::str::from_utf8(&self.data[..end]) {
                    Ok(s) => s.to_string(),
                    Err(_) => self.data[..end].iter().map(|&c| crate::oletext::cp1252(c)).collect(),
                }
            }
            _ => String::new(),
        }
    }
    pub fn int(&self) -> u64 {
        match self.data.len() {
            1 => self.data[0] as u64,
            2 => u16_at(&self.data, 0) as u64,
            4 => u32_at(&self.data, 0) as u64,
            n if n >= 8 => u64_at(&self.data, 0),
            _ => 0,
        }
    }
}

fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let s = String::from_utf16_lossy(&w);
    s.trim_end_matches('\0').to_string()
}

pub type Props = HashMap<u16, Prop>;

pub struct Pst<R> {
    r: R,
    len: u64,
    /// 64-bit identifiers (Unicode); 32-bit for ANSI.
    wide: bool,
    /// 4 KiB pages and compressible blocks (OST 2013 and later).
    big: bool,
    crypt: u8,
    pub version: u16,
    pub ost: bool,
    bbt: Arc<HashMap<u64, BlockRef>>,
    pub nodes: Arc<BTreeMap<u32, Node>>,
    /// Messages found only in the unused slots of node index pages: deleted
    /// from the index, their data still in the file.
    pub recovered: Arc<std::collections::BTreeSet<u32>>,
    /// Of those, the ones found in the file's free space by their block
    /// trailers (their folder is not known).
    pub free_space: Arc<std::collections::BTreeSet<u32>>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Folder {
    pub nid: u32,
    pub name: String,
    pub path: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Recipient {
    pub kind: u32,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Default)]
pub struct Attach {
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// An attached message (its node in the message's subnodes).
    pub embedded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MessageInfo {
    pub nid: u32,
    pub folder: String,
    pub class: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub date: u64,
    pub created: u64,
    pub modified: u64,
    pub message_id: String,
    pub flags: u32,
    pub body: String,
    /// HTML body as stored, and its character set.
    pub html: Vec<u8>,
    pub html_charset: String,
    /// The RTF body (decompressed), read only when there is no other body.
    pub rtf: Vec<u8>,
    pub headers: String,
    pub attachments: Vec<Attach>,
}

impl<R> Pst<R> {
    /// The same file through another reader, sharing the indexes (no
    /// re-reading of the B-trees).
    pub fn with_reader<R2>(&self, r: R2) -> Pst<R2> {
        Pst { r, len: self.len, wide: self.wide, big: self.big, crypt: self.crypt, version: self.version, ost: self.ost, bbt: self.bbt.clone(), nodes: self.nodes.clone(), recovered: self.recovered.clone(), free_space: self.free_space.clone(), notes: self.notes.clone() }
    }
}

impl<R: Read + Seek> Pst<R> {
    pub fn open(mut r: R, len: u64) -> anyhow::Result<Pst<R>> {
        let mut h = vec![0u8; 576];
        r.seek(SeekFrom::Start(0))?;
        let n = read_full(&mut r, &mut h)?;
        if n < 512 || !is_pst(&h) {
            anyhow::bail!("not a PST or OST file");
        }
        let version = u16_at(&h, 10);
        let (wide, big) = match version {
            14 | 15 => (false, false),
            21 | 23 => (true, false),
            36 => (true, true),
            v => anyhow::bail!("PST format version {} is not supported", v),
        };
        let (nbt, bbt, crypt) = if wide { (u64_at(&h, 224), u64_at(&h, 240), h[513]) } else { (u32_at(&h, 188) as u64, u32_at(&h, 196) as u64, h[461]) };
        let mut p = Pst { r, len, wide, big, crypt, version, ost: &h[8..10] == b"SO", bbt: Arc::new(HashMap::new()), nodes: Arc::new(BTreeMap::new()), recovered: Arc::default(), free_space: Arc::default(), notes: vec![] };
        if crypt > 2 {
            anyhow::bail!("unknown PST encryption {}", crypt);
        }
        let mut leaves = vec![];
        let mut stale = vec![];
        p.walk(bbt, 0x80, 0, &mut leaves, &mut stale)?;
        let es = if wide { 8 } else { 4 };
        let block_ref = |e: &[u8]| -> (u64, BlockRef) {
            let bid = if wide { u64_at(e, 0) } else { u32_at(e, 0) as u64 };
            let ib = if wide { u64_at(e, 8) } else { u32_at(e, 4) as u64 };
            let cb = u16_at(e, 2 * es) as u32;
            let inflated = if big { u16_at(e, 2 * es + 2) as u32 } else { cb };
            (bid & !1, BlockRef { ib, cb, inflated })
        };
        let mut bmap = HashMap::with_capacity(leaves.len());
        for e in &leaves {
            let (bid, b) = block_ref(e);
            bmap.insert(bid, b);
        }
        // Blocks only in the unused slots of block index pages: their entries
        // were removed, the bytes may still be there. Used only for nodes
        // recovered the same way.
        for e in &stale {
            let (bid, b) = block_ref(e);
            if bid != 0 && b.cb > 0 && b.ib.checked_add(b.cb as u64).is_some_and(|x| x <= len) {
                bmap.entry(bid).or_insert(b);
            }
        }
        p.bbt = Arc::new(bmap);
        let mut leaves = vec![];
        let mut stale = vec![];
        p.walk(nbt, 0x81, 0, &mut leaves, &mut stale)?;
        let node = |e: &[u8]| {
            if wide {
                Node { nid: u32_at(e, 0), data: u64_at(e, 8), sub: u64_at(e, 16), parent: u32_at(e, 24) }
            } else {
                Node { nid: u32_at(e, 0), data: u32_at(e, 4) as u64, sub: u32_at(e, 8) as u64, parent: u32_at(e, 12) }
            }
        };
        let mut nmap = BTreeMap::new();
        for e in &leaves {
            let n = node(e);
            nmap.insert(n.nid, n);
        }
        p.nodes = Arc::new(nmap);
        if p.nodes.is_empty() {
            anyhow::bail!("the PST node index is empty or unreadable");
        }
        // Deleted messages: message nodes left in the unused slots of node
        // index pages, no longer in the index, whose data is still a
        // property context.
        let mut found = std::collections::BTreeSet::new();
        let mut extra = vec![];
        for e in &stale {
            let n = node(e);
            if n.nid & 0x1F != 4 || n.data == 0 || p.nodes.contains_key(&n.nid) || found.contains(&n.nid) || found.len() >= MAX_RECOVERED {
                continue;
            }
            let pc = p.blocks(n.data).ok().and_then(|b| Self::hn(&b)).is_some_and(|(sig, _)| sig == 0xBC);
            if pc {
                found.insert(n.nid);
                extra.push(n);
            }
        }
        if !found.is_empty() {
            let mut nmap = (*p.nodes).clone();
            for n in extra {
                nmap.insert(n.nid, n);
            }
            p.nodes = Arc::new(nmap);
            p.notes.push(format!("{} deleted message(s) recovered from unused entries of the node index", found.len()));
            p.recovered = Arc::new(found);
        }
        p.from_free_space()?;
        Ok(p)
    }

    /// Every block in the file found by its trailer: the block's size,
    /// signature (from its place and id) and CRC must all agree.
    fn trailer_blocks(&mut self) -> anyhow::Result<Vec<(u64, BlockRef)>> {
        let (al, tl) = if self.big { (512u64, 24usize) } else if self.wide { (64, 16) } else { (64, 12) };
        let max_slot: u64 = if self.big { 65_536 + 512 } else { 8_192 + 64 };
        const CHUNK: u64 = 4 << 20;
        let scan_end = self.len.min(MAX_SCAN);
        if self.len > MAX_SCAN {
            self.notes.push(format!("free space searched for deleted messages in the first {} GB only", MAX_SCAN >> 30));
        }
        let mut out = vec![];
        let mut buf: Vec<u8> = vec![];
        let mut pos = 0u64;
        while pos < scan_end {
            // The end of the previous chunk stays: a block may start there.
            let keep = buf.len().min(max_slot as usize);
            buf.drain(..buf.len() - keep);
            let base = pos - keep as u64;
            let old = buf.len();
            let n = CHUNK.min(scan_end - pos) as usize;
            buf.resize(old + n, 0);
            self.r.seek(SeekFrom::Start(pos))?;
            let got = read_full(&mut self.r, &mut buf[old..])?;
            buf.truncate(old + got);
            let mut end = (pos / al + 1) * al;
            while end <= pos + got as u64 {
                let t = (end - base) as usize - tl;
                end += al;
                let tr = &buf[t..t + tl];
                let (cb, sig) = (u16_at(tr, 0) as u64, u16_at(tr, 2));
                let (crc, bid, inflated) = match (self.big, self.wide) {
                    (true, _) => (u32_at(tr, 4), u64_at(tr, 8), u16_at(tr, 18) as u32),
                    (false, true) => (u32_at(tr, 4), u64_at(tr, 8), cb as u32),
                    (false, false) => (u32_at(tr, 8), u32_at(tr, 4) as u64, cb as u32),
                };
                if cb == 0 || bid == 0 {
                    continue;
                }
                let slot = (cb + tl as u64).div_ceil(al) * al;
                let block_end = end - al;
                let Some(ib) = block_end.checked_sub(slot) else { continue };
                if slot > max_slot || ib < base || block_sig(ib, bid) != sig {
                    continue;
                }
                let s = (ib - base) as usize;
                if pst_crc(&buf[s..s + cb as usize]) != crc {
                    continue;
                }
                out.push((bid & !1, BlockRef { ib, cb: cb as u32, inflated: inflated.max(cb as u32) }));
            }
            if got < n {
                break;
            }
            pos += got as u64;
        }
        Ok(out)
    }

    /// Who a message is, to tell an old copy of one still in the file from
    /// a deleted one: its search key, else its Internet message id, else
    /// subject, sender and times.
    fn identity(p: &Props) -> String {
        if let Some(k) = p.get(&0x300B).filter(|x| !x.data.is_empty()) {
            return format!("k:{:?}", k.data);
        }
        let s = |id: u16| p.get(&id).map(|x| x.text()).unwrap_or_default();
        let t = |id: u16| p.get(&id).map(|x| x.int()).unwrap_or(0);
        match s(0x1035) {
            m if !m.is_empty() => format!("m:{}", m),
            _ => format!("t:{}|{}|{}|{}", s(0x0037), s(0x0C1A), t(0x0E06), t(0x0039)),
        }
    }

    /// Subnode ids a property context names (values kept in subnodes).
    fn subnode_refs(&self, blocks: &[Vec<u8>]) -> Vec<u32> {
        let Some((_, root)) = Self::hn(blocks) else { return vec![] };
        let mut out: Vec<u32> = self
            .bth(blocks, root)
            .into_iter()
            .filter(|(k, v)| k.len() == 2 && v.len() >= 6)
            .filter_map(|(_, v)| {
                let (ptype, val) = (u16_at(&v, 0), u32_at(&v, 2));
                let fixed = matches!(ptype, 0x0002 | 0x0003 | 0x0004 | 0x000A | 0x000B);
                (!fixed && val & 0x1F != 0).then_some(val)
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Deleted messages in the file's free space: message property
    /// contexts in blocks the block index no longer lists, found by their
    /// trailers. A message whose values are in subnodes gets them only when
    /// exactly one such subnode block names every one of them. Old copies
    /// of messages still in the file (Outlook writes a changed message
    /// anew) are left out, and of several copies of one deleted message the
    /// newest is kept.
    fn from_free_space(&mut self) -> anyhow::Result<()> {
        let found = self.trailer_blocks()?;
        let mut orphans: BTreeMap<u64, BlockRef> = BTreeMap::new();
        for (bid, b) in found {
            if !self.bbt.contains_key(&bid) && orphans.len() < MAX_ORPHANS {
                orphans.entry(bid).or_insert(b);
            }
        }
        if orphans.is_empty() {
            return Ok(());
        }
        let mut bmap = (*self.bbt).clone();
        for (bid, b) in &orphans {
            bmap.insert(*bid, *b);
        }
        self.bbt = Arc::new(bmap);
        // Data trees and subnode blocks among them.
        let mut children = std::collections::HashSet::new();
        let mut trees = vec![];
        let mut sls: Vec<(u64, HashMap<u32, Node>)> = vec![];
        for &bid in orphans.keys() {
            if bid & 2 == 0 {
                continue;
            }
            let Ok(d) = self.block(bid) else { continue };
            match (d.first(), d.get(1)) {
                (Some(1), Some(1)) => {
                    let w = if self.wide { 8 } else { 4 };
                    for i in 0..u16_at(&d, 2) as usize {
                        let o = 8 + i * w;
                        if o + w > d.len() {
                            break;
                        }
                        children.insert(if self.wide { u64_at(&d, o) } else { u32_at(&d, o) as u64 } & !1);
                    }
                    trees.push(bid);
                }
                (Some(2), Some(0)) => {
                    if let Ok(s) = self.subnodes(bid) {
                        if s.values().all(|n| self.bbt.contains_key(&(n.data & !1))) {
                            sls.push((bid, s));
                        }
                    }
                }
                _ => {}
            }
        }
        let mut candidates: Vec<u64> = orphans.keys().copied().filter(|b| b & 2 == 0 && !children.contains(b)).collect();
        candidates.extend(trees);
        // Who the messages still in the file are.
        let mut known = std::collections::HashSet::new();
        let mut live_messages: Vec<Node> = self.nodes.values().filter(|n| n.nid & 0x1F == 4).copied().collect();
        let mut keyed: BTreeMap<String, (u64, u64)> = BTreeMap::new(); // identity -> (data, sub)
        for data in candidates {
            if keyed.len() >= MAX_RECOVERED {
                break;
            }
            let Ok(blocks) = self.blocks(data) else { continue };
            if Self::hn(&blocks).is_none_or(|(sig, _)| sig != 0xBC) {
                continue;
            }
            let Ok(p) = self.props_in(&blocks, &HashMap::new()) else { continue };
            // A message (not an attachment, not a calendar exception).
            let class = p.get(&0x001A).map(|c| c.text().to_ascii_uppercase()).unwrap_or_default();
            if !class.starts_with("IPM.") || class.starts_with("IPM.OLE.CLASS") || p.contains_key(&0x3705) {
                continue;
            }
            if known.is_empty() {
                for n in live_messages.drain(..) {
                    if let Ok(lp) = self.props(n.data, 0) {
                        known.insert(Self::identity(&lp));
                    }
                }
                known.insert(String::new());
            }
            let id = Self::identity(&p);
            if known.contains(&id) {
                continue;
            }
            let refs = self.subnode_refs(&blocks);
            // Something to show: an empty draft or a hidden item is not.
            let said = [0x0037u16, 0x0C1A, 0x0C1F, 0x0E04, 0x1000, 0x1013, 0x1009].iter().any(|id| p.get(id).is_some_and(|x| !x.data.is_empty()));
            if !said && refs.is_empty() {
                continue;
            }
            let mut sub = 0;
            if !refs.is_empty() {
                let fits: Vec<u64> = sls.iter().filter(|(_, s)| refs.iter().all(|r| s.contains_key(r))).map(|x| x.0).collect();
                if fits.len() == 1 {
                    sub = fits[0];
                }
            }
            // Block ids grow with every write: the highest is the newest copy.
            let e = keyed.entry(id).or_insert((data, sub));
            if data > e.0 {
                *e = (data, sub);
            }
        }
        if keyed.is_empty() {
            return Ok(());
        }
        let mut nmap = (*self.nodes).clone();
        let mut recovered = (*self.recovered).clone();
        let mut free = std::collections::BTreeSet::new();
        let mut index = 0x0400_0000u32;
        let mut entries: Vec<(u64, u64)> = keyed.into_values().collect();
        entries.sort_unstable();
        for (data, sub) in entries {
            while nmap.contains_key(&((index << 5) | 4)) {
                index += 1;
            }
            let nid = (index << 5) | 4;
            index += 1;
            nmap.insert(nid, Node { nid, data, sub, parent: 0 });
            recovered.insert(nid);
            free.insert(nid);
        }
        self.notes.push(format!("{} deleted message(s) recovered from the file's free space by their block trailers", free.len()));
        self.nodes = Arc::new(nmap);
        self.recovered = Arc::new(recovered);
        self.free_space = Arc::new(free);
        Ok(())
    }

    fn page_size(&self) -> usize {
        if self.big {
            4096
        } else {
            512
        }
    }

    /// Leaf entries of a B-tree page and the pages below it, and in `stale`
    /// the entries left in the unused slots of leaf pages.
    fn walk(&mut self, ib: u64, ptype: u8, depth: usize, out: &mut Vec<Vec<u8>>, stale: &mut Vec<Vec<u8>>) -> anyhow::Result<()> {
        if depth > MAX_DEPTH || out.len() > MAX_NODES {
            return Ok(());
        }
        let ps = self.page_size();
        if ib.checked_add(ps as u64).is_none_or(|e| e > self.len) {
            self.notes.push(format!("B-tree page at {} is outside the file", ib));
            return Ok(());
        }
        let mut pg = vec![0u8; ps];
        self.r.seek(SeekFrom::Start(ib))?;
        read_full(&mut self.r, &mut pg)?;
        let (c, cb, level, t) = match (self.big, self.wide) {
            (true, _) => (u16_at(&pg, 4056) as usize, pg[4060] as usize, pg[4061], pg[4072]),
            (false, true) => (pg[488] as usize, pg[490] as usize, pg[491], pg[496]),
            (false, false) => (pg[496] as usize, pg[498] as usize, pg[499], pg[500]),
        };
        if t != ptype {
            self.notes.push(format!("B-tree page at {} has type {:#x}, not {:#x}; skipped", ib, t, ptype));
            return Ok(());
        }
        let area = if self.big { 4056 } else if self.wide { 488 } else { 496 };
        if cb == 0 || c * cb > area {
            self.notes.push(format!("B-tree page at {} is damaged; skipped", ib));
            return Ok(());
        }
        for i in 0..c {
            let e = pg[i * cb..(i + 1) * cb].to_vec();
            if level == 0 {
                out.push(e);
            } else {
                let child = if self.wide { u64_at(&e, 16) } else { u32_at(&e, 8) as u64 };
                self.walk(child, ptype, depth + 1, out, stale)?;
            }
        }
        if level == 0 && stale.len() < MAX_NODES {
            for i in c..area / cb {
                let e = &pg[i * cb..(i + 1) * cb];
                if e.iter().any(|&b| b != 0) {
                    stale.push(e.to_vec());
                }
            }
        }
        Ok(())
    }

    /// One block's data: read, inflated (4 KiB-page OST) and decoded.
    fn block(&mut self, bid: u64) -> anyhow::Result<Vec<u8>> {
        let b = *self.bbt.get(&(bid & !1)).ok_or_else(|| anyhow::anyhow!("block {:#x} is not in the block index", bid))?;
        if b.ib.checked_add(b.cb as u64).is_none_or(|e| e > self.len) {
            anyhow::bail!("block {:#x} lies outside the file", bid);
        }
        let mut d = vec![0u8; b.cb as usize];
        self.r.seek(SeekFrom::Start(b.ib))?;
        read_full(&mut self.r, &mut d)?;
        if self.big && b.inflated > b.cb {
            let mut out = Vec::with_capacity(b.inflated as usize);
            let ok = flate2::read::ZlibDecoder::new(&d[..]).take(b.inflated as u64).read_to_end(&mut out).is_ok() && out.len() == b.inflated as usize;
            if !ok {
                out.clear();
                flate2::read::DeflateDecoder::new(&d[..]).take(b.inflated as u64).read_to_end(&mut out).map_err(|e| anyhow::anyhow!("block {:#x}: {}", bid, e))?;
            }
            d = out;
        }
        // Internal blocks (data trees, subnode trees) are never encoded.
        if bid & 2 == 0 {
            match self.crypt {
                1 => d.iter_mut().for_each(|c| *c = CRYPT_I[*c as usize]),
                2 => {
                    let key = bid as u32;
                    let mut salt = ((key >> 16) ^ (key & 0xFFFF)) as u16;
                    for c in d.iter_mut() {
                        let (lo, hi) = (salt as u8, (salt >> 8) as u8);
                        let mut i = c.wrapping_add(lo);
                        i = CRYPT_R[i as usize];
                        i = i.wrapping_add(hi);
                        i = CRYPT_S[i as usize];
                        i = i.wrapping_sub(hi);
                        i = CRYPT_I[i as usize];
                        *c = i.wrapping_sub(lo);
                        salt = salt.wrapping_add(1);
                    }
                }
                _ => {}
            }
        }
        Ok(d)
    }

    /// The data blocks of a node, in order (a data tree is followed).
    pub fn blocks(&mut self, bid: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = vec![];
        let mut total = 0usize;
        self.blocks_into(bid, 0, &mut out, &mut total)?;
        Ok(out)
    }

    fn blocks_into(&mut self, bid: u64, depth: usize, out: &mut Vec<Vec<u8>>, total: &mut usize) -> anyhow::Result<()> {
        if bid == 0 {
            return Ok(());
        }
        let d = self.block(bid)?;
        if bid & 2 != 0 && d.first() == Some(&1) && depth < 3 {
            // XBLOCK (level 1) or XXBLOCK (level 2): block ids of the parts.
            let n = u16_at(&d, 2) as usize;
            let w = if self.wide { 8 } else { 4 };
            for i in 0..n {
                let o = 8 + i * w;
                let Some(_) = d.get(o..o + w) else { break };
                let child = if self.wide { u64_at(&d, o) } else { u32_at(&d, o) as u64 };
                self.blocks_into(child, depth + 1, out, total)?;
                if *total > MAX_DATA {
                    anyhow::bail!("node data larger than {} bytes", MAX_DATA);
                }
            }
            return Ok(());
        }
        *total += d.len();
        out.push(d);
        Ok(())
    }

    pub fn data(&mut self, bid: u64) -> anyhow::Result<Vec<u8>> {
        Ok(self.blocks(bid)?.concat())
    }

    /// The subnodes of a node (its SLBLOCK / SIBLOCK tree).
    pub fn subnodes(&mut self, bid: u64) -> anyhow::Result<HashMap<u32, Node>> {
        let mut out = HashMap::new();
        self.sub_into(bid, 0, &mut out)?;
        Ok(out)
    }

    fn sub_into(&mut self, bid: u64, depth: usize, out: &mut HashMap<u32, Node>) -> anyhow::Result<()> {
        if bid == 0 || depth > 3 || out.len() > MAX_NODES {
            return Ok(());
        }
        let d = self.block(bid)?;
        if d.first() != Some(&2) {
            anyhow::bail!("subnode block {:#x} has the wrong type", bid);
        }
        let (level, n) = (d.get(1).copied().unwrap_or(0), u16_at(&d, 2) as usize);
        let (head, w) = if self.wide { (8, 8) } else { (4, 4) };
        let es = if level == 0 { 3 * w } else { 2 * w };
        for i in 0..n {
            let o = head + i * es;
            if o + es > d.len() {
                break;
            }
            let nid = u32_at(&d, o);
            let id = |k: usize| if self.wide { u64_at(&d, o + k * w) } else { u32_at(&d, o + k * w) as u64 };
            if level == 0 {
                out.insert(nid, Node { nid, data: id(1), sub: id(2), parent: 0 });
            } else {
                let child = id(1);
                self.sub_into(child, depth + 1, out)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ LTP

    /// A heap item (HID) in the node's blocks.
    fn heap(&self, blocks: &[Vec<u8>], hid: u32) -> Option<Vec<u8>> {
        if hid & 0x1F != 0 {
            return None;
        }
        let (index, bi) = if self.big { (((hid >> 5) & 0x3FFF) as usize, (hid >> 19) as usize) } else { (((hid >> 5) & 0x7FF) as usize, (hid >> 16) as usize) };
        let b = blocks.get(bi)?;
        let map = u16_at(b, 0) as usize;
        let count = u16_at(b, map) as usize;
        if index == 0 || index > count {
            return None;
        }
        let start = u16_at(b, map + 4 + (index - 1) * 2) as usize;
        let end = u16_at(b, map + 4 + index * 2) as usize;
        b.get(start..end).map(|x| x.to_vec())
    }

    /// The value an HNID names: a heap item, or a subnode's data.
    fn hnid(&mut self, blocks: &[Vec<u8>], subs: &HashMap<u32, Node>, hnid: u32) -> Option<Vec<u8>> {
        if hnid == 0 {
            return Some(vec![]);
        }
        if hnid & 0x1F == 0 {
            return self.heap(blocks, hnid);
        }
        let n = subs.get(&hnid)?;
        self.data(n.data).ok()
    }

    /// Records of a B-tree on the heap: (key, data).
    fn bth(&self, blocks: &[Vec<u8>], hid: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
        let Some(h) = self.heap(blocks, hid) else { return vec![] };
        if h.len() < 8 || h[0] != 0xB5 {
            return vec![];
        }
        let (kb, eb, levels, root) = (h[1] as usize, h[2] as usize, h[3] as usize, u32_at(&h, 4));
        if kb == 0 || kb > 16 || eb > 32 {
            return vec![];
        }
        let mut out = vec![];
        let mut todo = vec![(root, levels)];
        let mut steps = 0;
        while let Some((hid, lvl)) = todo.pop() {
            steps += 1;
            if hid == 0 || steps > 100_000 {
                continue;
            }
            let Some(d) = self.heap(blocks, hid) else { continue };
            if lvl == 0 {
                for rec in d.chunks_exact(kb + eb) {
                    out.push((rec[..kb].to_vec(), rec[kb..].to_vec()));
                }
            } else {
                for rec in d.chunks_exact(kb + 4).rev() {
                    todo.push((u32_at(rec, kb), lvl - 1));
                }
            }
        }
        out
    }

    /// The heap's client signature and user root.
    fn hn(blocks: &[Vec<u8>]) -> Option<(u8, u32)> {
        let b = blocks.first()?;
        (b.len() >= 12 && b[2] == 0xEC).then(|| (b[3], u32_at(b, 4)))
    }

    /// A property context (the properties of a folder, message or attachment).
    pub fn props(&mut self, data: u64, sub: u64) -> anyhow::Result<Props> {
        let blocks = self.blocks(data)?;
        let subs = self.subnodes(sub).unwrap_or_default();
        self.props_in(&blocks, &subs)
    }

    fn props_in(&mut self, blocks: &[Vec<u8>], subs: &HashMap<u32, Node>) -> anyhow::Result<Props> {
        let (sig, root) = Self::hn(blocks).ok_or_else(|| anyhow::anyhow!("not a heap"))?;
        if sig != 0xBC {
            anyhow::bail!("not a property context ({:#x})", sig);
        }
        let mut out = HashMap::new();
        for (k, v) in self.bth(blocks, root) {
            if k.len() != 2 || v.len() < 6 {
                continue;
            }
            let (id, ptype, val) = (u16_at(&k, 0), u16_at(&v, 0), u32_at(&v, 2));
            let data = match ptype {
                0x0002 => val.to_le_bytes()[..2].to_vec(),
                0x0003 | 0x0004 | 0x000A => val.to_le_bytes().to_vec(),
                0x000B => vec![val as u8],
                0x000D => {
                    // An object: the heap item names a subnode (nid, size).
                    match self.hnid(blocks, subs, val) {
                        Some(x) if x.len() >= 4 => u32_at(&x, 0).to_le_bytes().to_vec(),
                        _ => continue,
                    }
                }
                _ => match self.hnid(blocks, subs, val) {
                    Some(x) => x,
                    None => continue,
                },
            };
            out.insert(id, Prop { ptype, data });
        }
        Ok(out)
    }

    /// The rows of a table context (recipients, attachments).
    pub fn table(&mut self, data: u64, sub: u64) -> anyhow::Result<Vec<Props>> {
        let blocks = self.blocks(data)?;
        let subs = self.subnodes(sub).unwrap_or_default();
        let (sig, root) = Self::hn(&blocks).ok_or_else(|| anyhow::anyhow!("not a heap"))?;
        if sig != 0x7C {
            anyhow::bail!("not a table context ({:#x})", sig);
        }
        let t = self.heap(&blocks, root).ok_or_else(|| anyhow::anyhow!("table header missing"))?;
        if t.len() < 22 || t[0] != 0x7C {
            anyhow::bail!("table header damaged");
        }
        let cols = t[1] as usize;
        let (ceb, rowsize) = (u16_at(&t, 6) as usize, u16_at(&t, 8) as usize);
        let rows_hnid = u32_at(&t, 14);
        let mut desc = vec![];
        for i in 0..cols {
            let o = 22 + i * 8;
            if o + 8 > t.len() {
                break;
            }
            desc.push((u16_at(&t, o), u16_at(&t, o + 2), u16_at(&t, o + 4) as usize, t[o + 6] as usize, t[o + 7] as usize));
        }
        if rowsize == 0 || rows_hnid == 0 {
            return Ok(vec![]);
        }
        // Row data: a heap item, or a subnode whose blocks hold whole rows.
        let row_blocks: Vec<Vec<u8>> = if rows_hnid & 0x1F == 0 {
            self.heap(&blocks, rows_hnid).into_iter().collect()
        } else {
            match subs.get(&rows_hnid) {
                Some(n) => self.blocks(n.data)?,
                None => vec![],
            }
        };
        let mut out = vec![];
        for b in &row_blocks {
            for row in b.chunks_exact(rowsize) {
                let mut props = HashMap::new();
                for &(ptype, id, ib, cb, bit) in &desc {
                    let exists = row.get(ceb + bit / 8).is_some_and(|x| x & (0x80 >> (bit % 8)) != 0);
                    if !exists || ib + cb > row.len() {
                        continue;
                    }
                    let cell = &row[ib..ib + cb];
                    let data = match ptype {
                        0x0002 | 0x0003 | 0x000B | 0x0014 | 0x0040 | 0x0005 | 0x0004 | 0x000A => cell.to_vec(),
                        _ => match self.hnid(&blocks, &subs, u32_at(cell, 0)) {
                            Some(x) => x,
                            None => continue,
                        },
                    };
                    props.insert(id, Prop { ptype, data });
                }
                out.push(props);
                if out.len() > 100_000 {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------- messaging

    /// Every folder, with its path from the root.
    pub fn folders(&mut self) -> Vec<Folder> {
        let ids: Vec<Node> = self.nodes.values().filter(|n| n.nid & 0x1F == 2).copied().collect();
        let mut names: HashMap<u32, (String, u32, u32)> = HashMap::new();
        for n in &ids {
            let p = self.props(n.data, n.sub).unwrap_or_default();
            names.insert(n.nid, (p.get(&0x3001).map(|x| x.text()).unwrap_or_default(), n.parent, p.get(&0x3602).map(|x| x.int() as u32).unwrap_or(0)));
        }
        ids.iter()
            .map(|n| {
                let mut parts = vec![];
                let mut cur = n.nid;
                for _ in 0..64 {
                    let Some((name, parent, _)) = names.get(&cur) else { break };
                    if !name.is_empty() {
                        parts.push(name.clone());
                    }
                    if *parent == cur || *parent == 0 {
                        break;
                    }
                    cur = *parent;
                }
                parts.reverse();
                let (name, _, count) = names[&n.nid].clone();
                Folder { nid: n.nid, name, path: parts.join("/"), count }
            })
            .collect()
    }

    /// Node ids of every message (recovered deleted ones included; see
    /// `recovered`).
    pub fn message_ids(&self) -> Vec<u32> {
        self.nodes.values().filter(|n| n.nid & 0x1F == 4).map(|n| n.nid).collect()
    }

    /// A message's properties, recipients and attachments.
    pub fn message(&mut self, nid: u32) -> anyhow::Result<(MessageInfo, Props)> {
        let n = *self.nodes.get(&nid).ok_or_else(|| anyhow::anyhow!("no message {:#x}", nid))?;
        let blocks = self.blocks(n.data)?;
        let subs = self.subnodes(n.sub).unwrap_or_default();
        let p = self.props_in(&blocks, &subs)?;
        let mut m = self.info(nid, &p);
        self.recipients_and_attachments(&subs, &mut m);
        Ok((m, p))
    }

    fn info(&self, nid: u32, p: &Props) -> MessageInfo {
        let s = |id: u16| p.get(&id).map(|x| x.text()).unwrap_or_default();
        let t = |id: u16| p.get(&id).filter(|x| x.ptype == 0x0040).map(|x| x.int()).unwrap_or(0);
        // A subject may start with a control prefix (0x01, length).
        let mut subject = s(0x0037);
        if subject.starts_with('\u{1}') {
            subject = subject.chars().skip(2).collect();
        }
        let addr = |name: String, mail: String| match (name.is_empty(), mail.is_empty() || mail.eq_ignore_ascii_case(&name)) {
            (_, true) => name,
            (true, false) => mail,
            (false, false) => format!("{} <{}>", name, mail),
        };
        let smtp = |a: String, b: String| if !b.is_empty() && !b.starts_with('/') { b } else if a.starts_with('/') { String::new() } else { a };
        let cp = p.get(&0x3FDE).map(|x| x.int() as u32).unwrap_or(0);
        let (html, html_charset) = match p.get(&0x1013) {
            Some(x) if x.ptype == 0x001F => (x.text().into_bytes(), "utf-8".to_string()),
            Some(x) => (x.data.clone(), match cp {
                0 | 65001 => "utf-8".to_string(),
                28591 => "iso-8859-1".to_string(),
                20127 => "us-ascii".to_string(),
                c => format!("windows-{}", c),
            }),
            None => (vec![], String::new()),
        };
        MessageInfo {
            nid,
            class: s(0x001A),
            subject,
            from: addr(s(0x0C1A), smtp(s(0x0C1F), s(0x5D01))),
            to: s(0x0E04),
            cc: s(0x0E03),
            bcc: s(0x0E02),
            date: [t(0x0E06), t(0x0039), t(0x3007)].into_iter().find(|&x| x > 0).unwrap_or(0),
            created: t(0x3007),
            modified: t(0x3008),
            message_id: s(0x1035),
            flags: p.get(&0x0E07).map(|x| x.int() as u32).unwrap_or(0),
            body: s(0x1000),
            html,
            html_charset,
            rtf: if p.contains_key(&0x1000) || p.contains_key(&0x1013) { vec![] } else { p.get(&0x1009).and_then(|x| lzfu(&x.data)).unwrap_or_default() },
            headers: s(0x007D),
            ..Default::default()
        }
    }

    fn recipients_and_attachments(&mut self, subs: &HashMap<u32, Node>, m: &mut MessageInfo) {
        if let Some(t) = subs.get(&0x692).copied() {
            if let Ok(rows) = self.table(t.data, t.sub) {
                let mut by: [Vec<String>; 3] = Default::default();
                for r in rows {
                    let kind = r.get(&0x0C15).map(|x| x.int() as u32).unwrap_or(1);
                    let name = r.get(&0x3001).map(|x| x.text()).unwrap_or_default();
                    let mail = [0x39FE, 0x3003].iter().filter_map(|id| r.get(id).map(|x| x.text())).find(|x| !x.is_empty() && !x.starts_with('/')).unwrap_or_default();
                    let a = if mail.is_empty() || mail == name { name } else if name.is_empty() { mail } else { format!("{} <{}>", name, mail) };
                    if (1..=3).contains(&kind) && !a.is_empty() {
                        by[kind as usize - 1].push(a);
                    }
                }
                for (k, field) in [&mut m.to, &mut m.cc, &mut m.bcc].into_iter().enumerate() {
                    if !by[k].is_empty() {
                        *field = by[k].join(", ");
                    }
                }
            }
        }
        let mut att: Vec<Node> = subs.values().filter(|n| n.nid & 0x1F == 5).copied().collect();
        att.sort_by_key(|n| n.nid);
        for a in att.into_iter().take(1000) {
            let Ok(p) = self.props(a.data, a.sub) else { continue };
            let s = |id: u16| p.get(&id).map(|x| x.text()).unwrap_or_default();
            let method = p.get(&0x3705).map(|x| x.int()).unwrap_or(1);
            let name = [s(0x3707), s(0x3704), s(0x3001)].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "(unnamed)".into());
            let size = p.get(&0x3701).map(|x| if x.ptype == 0x0102 { x.data.len() as u64 } else { 0 }).filter(|&x| x > 0).or_else(|| p.get(&0x0E20).map(|x| x.int())).unwrap_or(0);
            m.attachments.push(Attach { name, mime: s(0x370E), size, embedded: method == 5 });
        }
    }

    /// Attachment bytes, or an attached message rendered, by position.
    fn attachment_parts(&mut self, nid: u32, depth: usize) -> Vec<(Attach, Vec<u8>)> {
        let Some(n) = self.nodes.get(&nid).copied() else { return vec![] };
        self.attachment_parts_of(n.sub, depth)
    }

    fn attachment_parts_of(&mut self, sub: u64, depth: usize) -> Vec<(Attach, Vec<u8>)> {
        let subs = self.subnodes(sub).unwrap_or_default();
        let mut att: Vec<Node> = subs.values().filter(|n| n.nid & 0x1F == 5).copied().collect();
        att.sort_by_key(|n| n.nid);
        let mut out = vec![];
        for a in att.into_iter().take(1000) {
            let Ok(ablocks) = self.blocks(a.data) else { continue };
            let asubs = self.subnodes(a.sub).unwrap_or_default();
            let Ok(p) = self.props_in(&ablocks, &asubs) else { continue };
            let s = |id: u16| p.get(&id).map(|x| x.text()).unwrap_or_default();
            let name = [s(0x3707), s(0x3704), s(0x3001)].into_iter().find(|x| !x.is_empty()).unwrap_or_else(|| "(unnamed)".into());
            let method = p.get(&0x3705).map(|x| x.int()).unwrap_or(1);
            match p.get(&0x3701) {
                Some(x) if x.ptype == 0x000D && method == 5 && depth < 4 => {
                    // An attached message: a message in the attachment's subnodes.
                    let inner = u32_at(&x.data, 0);
                    let Some(node) = asubs.get(&inner).copied() else { continue };
                    let Ok(ib) = self.blocks(node.data) else { continue };
                    let isubs = self.subnodes(node.sub).unwrap_or_default();
                    let Ok(ip) = self.props_in(&ib, &isubs) else { continue };
                    let mut m = self.info(inner, &ip);
                    self.recipients_and_attachments(&isubs, &mut m);
                    let parts = self.attachment_parts_of(node.sub, depth + 1);
                    let eml = render(&m, &parts);
                    let lower = name.to_ascii_lowercase();
                    let name = if lower.ends_with(".eml") || lower.ends_with(".msg") { name } else { format!("{}.eml", name) };
                    out.push((Attach { name, mime: "message/rfc822".into(), size: eml.len() as u64, embedded: true }, eml));
                }
                Some(x) => out.push((Attach { name, mime: s(0x370E), size: x.data.len() as u64, embedded: false }, x.data.clone())),
                None => out.push((Attach { name, mime: s(0x370E), size: 0, embedded: false }, vec![])),
            }
        }
        out
    }

    /// The message as an RFC 822 message with its attachments.
    pub fn eml(&mut self, nid: u32) -> anyhow::Result<Vec<u8>> {
        let (m, _) = self.message(nid)?;
        let parts = self.attachment_parts(nid, 0);
        Ok(render(&m, &parts))
    }
}

/// MS-OXRTFCP: the dictionary every compressed RTF starts from (207 bytes).
const LZFU_DICT: &[u8] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

/// Compressed RTF (PidTagRtfCompressed, MS-OXRTFCP): "LZFu" compressed or
/// "MELA" stored. `None` when it is neither or damaged.
pub fn lzfu(d: &[u8]) -> Option<Vec<u8>> {
    if d.len() < 16 {
        return None;
    }
    let (comp, raw) = (u32_at(d, 0) as usize, (u32_at(d, 4) as usize).min(64 << 20));
    let body = d.get(16..(comp + 4).min(d.len()))?;
    match &d[8..12] {
        b"MELA" => return Some(body[..body.len().min(raw)].to_vec()),
        b"LZFu" => {}
        _ => return None,
    }
    let mut dict = [b' '; 4096];
    dict[..LZFU_DICT.len()].copy_from_slice(LZFU_DICT);
    let mut w = LZFU_DICT.len();
    let mut out = Vec::with_capacity(raw.min(16 << 20));
    let mut i = 0;
    'outer: while i < body.len() {
        let flags = body[i];
        i += 1;
        for bit in 0..8 {
            if flags >> bit & 1 == 1 {
                let Some(t) = body.get(i..i + 2) else { break 'outer };
                i += 2;
                let token = u16::from_be_bytes([t[0], t[1]]) as usize;
                let (off, len) = (token >> 4, (token & 15) + 2);
                if off == w {
                    break 'outer;
                }
                for k in 0..len {
                    let c = dict[(off + k) % 4096];
                    out.push(c);
                    dict[w] = c;
                    w = (w + 1) % 4096;
                }
            } else {
                let Some(&c) = body.get(i) else { break 'outer };
                i += 1;
                out.push(c);
                dict[w] = c;
                w = (w + 1) % 4096;
            }
            if out.len() >= raw.max(1) {
                break 'outer;
            }
        }
    }
    out.truncate(raw);
    Some(out)
}

impl MessageInfo {
    /// The message text: the plain body, or the HTML without its markup.
    pub fn text(&self) -> String {
        if self.body.is_empty() && self.html.is_empty() && !self.rtf.is_empty() {
            return crate::oletext::rtf(&self.rtf);
        }
        if !self.body.is_empty() || self.html.is_empty() {
            return self.body.clone();
        }
        let h = match std::str::from_utf8(&self.html) {
            Ok(s) => s.to_string(),
            Err(_) => self.html.iter().map(|&c| crate::oletext::cp1252(c)).collect(),
        };
        crate::doctext::xml_text(&h)
    }
}

fn read_full<R: Read>(r: &mut R, b: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < b.len() {
        let n = r.read(&mut b[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(got)
}

fn b64(d: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(d.len() * 4 / 3 + d.len() / 57 * 2 + 4);
    for (i, c) in d.chunks(3).enumerate() {
        if i > 0 && i % 19 == 0 {
            out.push_str("\r\n");
        }
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= c.len() {
                out.push(T[(n >> (18 - 6 * k)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A header value safe on one line (RFC 2047 when it is not ASCII).
fn hval(s: &str) -> String {
    let s: String = s.chars().map(|c| if c == '\r' || c == '\n' { ' ' } else { c }).collect();
    if s.is_ascii() {
        s
    } else {
        format!("=?UTF-8?B?{}?=", b64(s.as_bytes()).replace("\r\n", ""))
    }
}

/// An RFC 2231 file name parameter.
fn fname(s: &str) -> String {
    let enc: String = s.bytes().map(|b| if b.is_ascii_alphanumeric() || b".-_".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) }).collect();
    format!("filename*=UTF-8''{}", enc)
}

/// RFC 822 rendering: the transport headers Outlook kept (without their
/// MIME lines) or headers made from the properties, then the text and the
/// attachments as MIME parts.
pub fn render(m: &MessageInfo, parts: &[(Attach, Vec<u8>)]) -> Vec<u8> {
    let mut h = String::new();
    let kept: Vec<&str> = m.headers.split("\r\n").flat_map(|l| l.split('\n')).collect();
    let mut skip = false;
    let had = |name: &str| kept.iter().any(|l| l.len() > name.len() && l.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes()) && l.as_bytes()[name.len()] == b':');
    if !m.headers.trim().is_empty() {
        for l in &kept {
            if l.trim().is_empty() {
                break;
            }
            let cont = l.starts_with(' ') || l.starts_with('\t');
            if !cont {
                let low = l.to_ascii_lowercase();
                skip = low.starts_with("content-") || low.starts_with("mime-version:");
            }
            if !skip {
                h.push_str(l);
                h.push_str("\r\n");
            }
        }
    }
    let date = if m.date > 0 { chrono::DateTime::from_timestamp(((m.date / 10_000_000) as i64).saturating_sub(11_644_473_600), 0).filter(|d| (1..=9999).contains(&chrono::Datelike::year(d))).map(|d| d.to_rfc2822()).unwrap_or_default() } else { String::new() };
    for (name, v) in [("Date", date), ("From", m.from.clone()), ("To", m.to.clone()), ("Cc", m.cc.clone()), ("Bcc", m.bcc.clone()), ("Subject", m.subject.clone()), ("Message-ID", m.message_id.clone())] {
        if !v.is_empty() && !had(name) {
            h.push_str(&format!("{}: {}\r\n", name, hval(&v)));
        }
    }
    if !m.class.is_empty() {
        h.push_str(&format!("X-Outlook-Message-Class: {}\r\n", hval(&m.class)));
    }
    let boundary = format!("=_kokino_{:08x}", m.nid);
    h.push_str(&format!("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n", boundary));
    let mut out = h.into_bytes();
    let part = |head: String, body: &[u8], out: &mut Vec<u8>| {
        out.extend(format!("--{}\r\n{}\r\n", boundary, head).as_bytes());
        out.extend(body);
        out.extend(b"\r\n");
    };
    if !m.body.is_empty() {
        part("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n".into(), b64(m.body.as_bytes()).as_bytes(), &mut out);
    } else if !m.html.is_empty() {
        part(format!("Content-Type: text/html; charset={}\r\nContent-Transfer-Encoding: base64\r\n", m.html_charset), b64(&m.html).as_bytes(), &mut out);
    } else if !m.rtf.is_empty() {
        part("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n".into(), b64(m.text().as_bytes()).as_bytes(), &mut out);
    }
    for (a, d) in parts {
        if a.mime == "message/rfc822" {
            part(format!("Content-Type: message/rfc822\r\nContent-Disposition: attachment; {}\r\n", fname(&a.name)), d, &mut out);
        } else {
            let ct = if a.mime.is_empty() { "application/octet-stream".to_string() } else { a.mime.replace(['\r', '\n', ';'], "") };
            part(format!("Content-Type: {}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; {}\r\n", ct, fname(&a.name)), b64(d).as_bytes(), &mut out);
        }
    }
    out.extend(format!("--{}--\r\n", boundary).as_bytes());
    out
}

/// Local validation (public sample files, not in the repository): runs
/// only when `target/validation/pst/` holds them.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a small Unicode PST the way Outlook lays one out: blocks
    /// encoded with compressible encryption, two-level node and block
    /// B-trees, heaps with property and table contexts, subnodes, and a
    /// data tree (XBLOCK) for an attachment larger than one block.
    pub(crate) struct Builder {
        file: Vec<u8>,
        bbt: Vec<(u64, u64, u16)>,
        nbt: Vec<(u32, u64, u64, u32)>,
        next_bid: u64,
    }

    pub(crate) enum V<'a> {
        S(&'a str),
        I(u32),
        T(u64),
        B(Vec<u8>),
    }

    fn le(v: &mut Vec<u8>, x: u64, n: usize) {
        v.extend_from_slice(&x.to_le_bytes()[..n]);
    }

    /// A heap: items (1-based HIDs in block 0) and the page map.
    fn heap(sig: u8, items: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0u8; 12];
        let mut offs = vec![12u16];
        for it in items {
            b.extend(it);
            offs.push(b.len() as u16);
        }
        if b.len() % 2 == 1 {
            b.push(0);
        }
        let map = b.len() as u16;
        le(&mut b, items.len() as u64, 2);
        le(&mut b, 0, 2);
        for o in offs {
            le(&mut b, o as u64, 2);
        }
        b[0..2].copy_from_slice(&map.to_le_bytes());
        b[2] = 0xEC;
        b[3] = sig;
        b[4..8].copy_from_slice(&0x20u32.to_le_bytes()); // user root: HID 1
        b
    }

    fn hid(k: usize) -> u32 {
        (k as u32) << 5
    }

    impl Builder {
        pub(crate) fn new() -> Self {
            Builder { file: vec![0u8; 0x4400], bbt: vec![], nbt: vec![], next_bid: 4 }
        }

        /// Adds a block; internal ones (data trees, subnodes) are not encoded.
        pub(crate) fn block(&mut self, data: &[u8], internal: bool) -> u64 {
            let bid = self.next_bid | if internal { 2 } else { 0 };
            self.next_bid += 4;
            let mut enc = data.to_vec();
            if !internal {
                let mut inv = [0u8; 256];
                for (i, &v) in CRYPT_I.iter().enumerate() {
                    inv[v as usize] = i as u8;
                }
                enc.iter_mut().for_each(|c| *c = inv[*c as usize]);
            }
            while self.file.len() % 64 != 0 {
                self.file.push(0);
            }
            let ib = self.file.len() as u64;
            let slot = (enc.len() + 16).div_ceil(64) * 64;
            self.file.extend(&enc);
            self.file.resize(ib as usize + slot - 16, 0);
            le(&mut self.file, enc.len() as u64, 2);
            le(&mut self.file, block_sig(ib, bid) as u64, 2);
            le(&mut self.file, pst_crc(&enc) as u64, 4);
            le(&mut self.file, bid, 8);
            self.bbt.push((bid, ib, data.len() as u16));
            bid
        }

        /// Takes the last block out of the block index (its bytes stay).
        pub(crate) fn forget_last(&mut self) {
            self.bbt.pop();
        }

        /// A property context in one block (values over 3 KB in subnodes,
        /// which `subs` collects as (nid, data bid)).
        pub(crate) fn pc(&mut self, props: &[(u16, V)], subs: &mut Vec<(u32, u64, u64)>) -> u64 {
            let mut items: Vec<Vec<u8>> = vec![vec![], vec![]];
            let mut recs: Vec<(u16, u16, u32)> = vec![];
            for (id, v) in props {
                let (ptype, val) = match v {
                    V::I(x) => (0x0003u16, *x),
                    V::S(t) => {
                        items.push(t.encode_utf16().flat_map(|c| c.to_le_bytes()).collect());
                        (0x001F, hid(items.len()))
                    }
                    V::T(t) => {
                        items.push(t.to_le_bytes().to_vec());
                        (0x0040, hid(items.len()))
                    }
                    V::B(d) if d.len() > 3000 => {
                        let nid = 0x8000_001F | ((subs.len() as u32 + 1) << 5);
                        let bid = self.data(d);
                        subs.push((nid, bid, 0));
                        (0x0102, nid)
                    }
                    V::B(d) => {
                        items.push(d.clone());
                        (0x0102, hid(items.len()))
                    }
                };
                recs.push((*id, ptype, val));
            }
            recs.sort_by_key(|r| r.0);
            let mut bth = vec![0xB5, 2, 6, 0];
            le(&mut bth, hid(2) as u64, 4);
            items[0] = bth;
            items[1] = recs.iter().flat_map(|(id, t, v)| [id.to_le_bytes().to_vec(), t.to_le_bytes().to_vec(), v.to_le_bytes().to_vec()].concat()).collect();
            let h = heap(0xBC, &items);
            self.block(&h, false)
        }

        /// Data of any size: one block, or an XBLOCK over 8176-byte blocks.
        pub(crate) fn data(&mut self, d: &[u8]) -> u64 {
            if d.len() <= 8176 {
                return self.block(d, false);
            }
            let parts: Vec<u64> = d.chunks(8176).map(|c| self.block(c, false)).collect();
            let mut x = vec![1u8, 1];
            le(&mut x, parts.len() as u64, 2);
            le(&mut x, d.len() as u64, 4);
            for b in parts {
                le(&mut x, b, 8);
            }
            self.block(&x, true)
        }

        /// A recipient table: (type, name, address) rows.
        pub(crate) fn recipients(&mut self, rows: &[(u32, &str, &str)]) -> u64 {
            let mut items: Vec<Vec<u8>> = vec![vec![], vec![]];
            let cols: [(u16, u16, u16, u8); 5] = [(0x0003, 0x67F2, 0, 0), (0x0003, 0x67F3, 4, 1), (0x0003, 0x0C15, 8, 2), (0x001F, 0x3001, 12, 3), (0x001F, 0x3003, 16, 4)];
            let mut row_data = vec![];
            for (k, (t, name, mail)) in rows.iter().enumerate() {
                items.push(name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect());
                let hn = hid(items.len());
                items.push(mail.encode_utf16().flat_map(|c| c.to_le_bytes()).collect());
                let hm = hid(items.len());
                le(&mut row_data, k as u64, 4);
                le(&mut row_data, 0, 4);
                le(&mut row_data, *t as u64, 4);
                le(&mut row_data, hn as u64, 4);
                le(&mut row_data, hm as u64, 4);
                row_data.push(0xF8); // all five cells exist
            }
            items[1] = row_data;
            let mut t = vec![0x7C, cols.len() as u8];
            for v in [20u64, 20, 20, 21] {
                le(&mut t, v, 2);
            }
            le(&mut t, 0, 4); // row index (not read)
            le(&mut t, hid(2) as u64, 4);
            le(&mut t, 0, 4);
            for (ty, id, ib, bit) in cols {
                le(&mut t, ty as u64, 2);
                le(&mut t, id as u64, 2);
                le(&mut t, ib as u64, 2);
                t.push(4);
                t.push(bit);
            }
            items[0] = t;
            let h = heap(0x7C, &items);
            self.block(&h, false)
        }

        /// A subnode block (SLBLOCK) for (nid, data, sub) entries.
        pub(crate) fn subnodes(&mut self, entries: &[(u32, u64, u64)]) -> u64 {
            if entries.is_empty() {
                return 0;
            }
            let mut b = vec![2u8, 0];
            le(&mut b, entries.len() as u64, 2);
            le(&mut b, 0, 4);
            for (nid, d, s) in entries {
                le(&mut b, *nid as u64, 8);
                le(&mut b, *d, 8);
                le(&mut b, *s, 8);
            }
            self.block(&b, true)
        }

        pub(crate) fn node(&mut self, nid: u32, data: u64, sub: u64, parent: u32) {
            self.nbt.push((nid, data, sub, parent));
        }

        /// A two-level B-tree: leaf pages under one branch page.
        fn btree(&mut self, ptype: u8, entries: Vec<(u64, Vec<u8>)>, per_page: usize, size: u8) -> u64 {
            let page = |file: &mut Vec<u8>, ents: &[Vec<u8>], level: u8, cb: u8| -> u64 {
                while file.len() % 512 != 0 {
                    file.push(0);
                }
                let ib = file.len() as u64;
                let mut p = vec![0u8; 512];
                for (i, e) in ents.iter().enumerate() {
                    p[i * cb as usize..(i + 1) * cb as usize].copy_from_slice(e);
                }
                p[488] = ents.len() as u8;
                p[489] = (488 / cb as usize) as u8;
                p[490] = cb;
                p[491] = level;
                p[496] = ptype;
                p[497] = ptype;
                file.extend(p);
                ib
            };
            let mut branch = vec![];
            for chunk in entries.chunks(per_page) {
                let ents: Vec<Vec<u8>> = chunk.iter().map(|e| e.1.clone()).collect();
                let ib = page(&mut self.file, &ents, 0, size);
                let mut be = vec![];
                le(&mut be, chunk[0].0, 8);
                le(&mut be, 0, 8);
                le(&mut be, ib, 8);
                branch.push(be);
            }
            page(&mut self.file, &branch, 1, 24)
        }

        pub(crate) fn finish(mut self) -> Vec<u8> {
            let mut b: Vec<(u64, Vec<u8>)> = self.bbt.iter().map(|&(bid, ib, cb)| {
                let mut e = vec![];
                le(&mut e, bid, 8);
                le(&mut e, ib, 8);
                le(&mut e, cb as u64, 2);
                le(&mut e, 1, 2);
                le(&mut e, 0, 4);
                (bid, e)
            }).collect();
            b.sort_by_key(|x| x.0);
            let mut n: Vec<(u64, Vec<u8>)> = self.nbt.iter().map(|&(nid, d, s, parent)| {
                let mut e = vec![];
                le(&mut e, nid as u64, 8);
                le(&mut e, d, 8);
                le(&mut e, s, 8);
                le(&mut e, parent as u64, 4);
                le(&mut e, 0, 4);
                (nid as u64, e)
            }).collect();
            n.sort_by_key(|x| x.0);
            let bbt = self.btree(0x80, b, 7, 24);
            let nbt = self.btree(0x81, n, 5, 32);
            let f = &mut self.file;
            f[0..4].copy_from_slice(b"!BDN");
            f[8..10].copy_from_slice(b"SM");
            f[10..12].copy_from_slice(&23u16.to_le_bytes());
            f[12..14].copy_from_slice(&19u16.to_le_bytes());
            let len = f.len() as u64;
            f[184..192].copy_from_slice(&len.to_le_bytes());
            f[224..232].copy_from_slice(&nbt.to_le_bytes());
            f[240..248].copy_from_slice(&bbt.to_le_bytes());
            f[512] = 0x80;
            f[513] = 1; // compressible encryption
            self.file
        }
    }

    #[test]
    fn compressed_rtf() {
        assert_eq!(LZFU_DICT.len(), 207);
        // MS-OXRTFCP's example: compressed, then stored.
        let c = b"-\x00\x00\x00+\x00\x00\x00LZFu\xf1\xc5\xc7\xa7\x03\x00\n\x00rcpg125B2\n\xf3 hel\t\x00 bw\x05\xb0ld}\n\x80\x0f\xa0";
        assert_eq!(lzfu(c).unwrap(), b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n");
        let m = b".\x00\x00\x00\"\x00\x00\x00MELA\x00\x00\x00\x00{\\rtf1\\ansi\\ansicpg1252\\pard test}";
        assert_eq!(lzfu(m).unwrap(), b"{\\rtf1\\ansi\\ansicpg1252\\pard test}");
        assert!(lzfu(b"short").is_none());
        let msg = MessageInfo { rtf: lzfu(c).unwrap(), ..Default::default() };
        assert_eq!(msg.text().trim(), "hello world");
    }

    pub(crate) const FT: u64 = 134_064_000_000_000_000; // 2025-10-31 (FILETIME)

    /// The test mailbox: Inbox with two messages (one with a 20,000-byte
    /// attachment and a recipient table) and Deleted Items with one.
    pub(crate) fn sample() -> Vec<u8> {
        let mut b = Builder::new();
        let mut none = vec![];
        let root = b.pc(&[(0x3001, V::S(""))], &mut none);
        b.node(0x122, root, 0, 0x122);
        let top = b.pc(&[(0x3001, V::S("Top of Personal Folders"))], &mut none);
        b.node(0x8022, top, 0, 0x122);
        let inbox = b.pc(&[(0x3001, V::S("Inbox")), (0x3602, V::I(2))], &mut none);
        b.node(0x8082, inbox, 0, 0x8022);
        let del = b.pc(&[(0x3001, V::S("Deleted Items")), (0x3602, V::I(1))], &mut none);
        b.node(0x8062, del, 0, 0x8022);

        // Message 1: recipients, an attachment over three blocks.
        let report: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let mut asubs = vec![];
        let att = b.pc(&[(0x3707, V::S("q3-ledger.bin")), (0x3705, V::I(1)), (0x370E, V::S("application/octet-stream")), (0x3701, V::B(report))], &mut asubs);
        let att_sub = b.subnodes(&asubs);
        let rcpt = b.recipients(&[(1, "Bob Lab", "bob@lab.test"), (2, "Carol Lab", "carol@lab.test")]);
        let msub = b.subnodes(&[(0x692, rcpt, 0), (0x8025, att, att_sub)]);
        let mut none2 = vec![];
        let m1 = b.pc(
            &[
                (0x001A, V::S("IPM.Note")),
                (0x0037, V::S("Q3 numbers \u{2013} confidential")),
                (0x0C1A, V::S("Alice Lab")),
                (0x0C1F, V::S("alice@lab.test")),
                (0x0E04, V::S("Bob Lab")),
                (0x0E06, V::T(FT)),
                (0x1000, V::S("Bob, the ledger is attached. Delete after reading.")),
                (0x1035, V::S("<q3@lab.test>")),
                (0x0E07, V::I(1)),
            ],
            &mut none2,
        );
        b.node(0x200024, m1, msub, 0x8082);
        // Message 2: HTML only.
        let m2 = b.pc(&[(0x001A, V::S("IPM.Note")), (0x0037, V::S("Lunch")), (0x0C1A, V::S("Bob Lab")), (0x0E06, V::T(FT + 36_000_000_000)), (0x1013, V::B(b"<html><body><p>Lunch at <b>noon</b>?</p></body></html>".to_vec()))], &mut none2);
        b.node(0x200044, m2, 0, 0x8082);
        // Message 3, in Deleted Items.
        let m3 = b.pc(&[(0x001A, V::S("IPM.Note")), (0x0037, V::S("wipe the laptop")), (0x0C1A, V::S("Alice Lab")), (0x0E06, V::T(FT + 72_000_000_000)), (0x1000, V::S("Use sdelete on everything."))], &mut none2);
        b.node(0x200064, m3, 0, 0x8062);
        b.finish()
    }

    #[test]
    fn reads_a_built_pst() {
        let d = sample();
        // KOKINO_WRITE_SEEDS=1 also saves it as a fuzz seed.
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/pst");
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("lab.pst"), &d).unwrap();
        }
        let mut p = Pst::open(std::io::Cursor::new(&d), d.len() as u64).unwrap();
        let mut folders: Vec<String> = p.folders().into_iter().map(|f| f.path).collect();
        folders.sort();
        assert_eq!(folders, ["", "Top of Personal Folders", "Top of Personal Folders/Deleted Items", "Top of Personal Folders/Inbox"]);
        assert_eq!(p.message_ids(), [0x200024, 0x200044, 0x200064]);
        let (m, _) = p.message(0x200024).unwrap();
        assert_eq!(m.subject, "Q3 numbers \u{2013} confidential");
        assert_eq!(m.from, "Alice Lab <alice@lab.test>");
        assert_eq!((m.to.as_str(), m.cc.as_str()), ("Bob Lab <bob@lab.test>", "Carol Lab <carol@lab.test>"));
        assert_eq!(m.date, FT);
        assert_eq!(m.attachments.len(), 1);
        assert_eq!((m.attachments[0].name.as_str(), m.attachments[0].size), ("q3-ledger.bin", 20_000));
        // Rendered as RFC 822 and read back: headers, text, attachment bytes.
        let eml = p.eml(0x200024).unwrap();
        let x = crate::mail::parse(&eml);
        assert_eq!(crate::mail::decode_words(&x.header("Subject")), "Q3 numbers \u{2013} confidential");
        assert!(x.text.contains("ledger is attached"));
        assert_eq!(x.attachments[0].1, (0..20_000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>());
        let (m2, _) = p.message(0x200044).unwrap();
        // HTML only: its text without the markup.
        let t = m2.text();
        assert!(t.contains("Lunch at") && t.contains("noon") && !t.contains('<'), "{:?}", t);
        assert!(crate::mail::parse(&p.eml(0x200044).unwrap()).text.contains("Lunch at"));
    }

    /// Message 3 deleted the way Outlook does it: the node index page holds
    /// one entry less, the entry itself stays in the page's unused slot.
    #[test]
    fn recovers_deleted_messages_from_the_node_index() {
        let mut d = sample();
        // Down the node index to the leaf with the highest node ids.
        let mut pg = u64_at(&d, 224) as usize;
        while d[pg + 491] > 0 {
            let (c, cb) = (d[pg + 488] as usize, d[pg + 490] as usize);
            pg = u64_at(&d, pg + (c - 1) * cb + 16) as usize;
        }
        let (c, cb) = (d[pg + 488] as usize, d[pg + 490] as usize);
        assert_eq!(u32_at(&d, pg + (c - 1) * cb), 0x200064, "message 3 is the last entry of its page");
        d[pg + 488] = (c - 1) as u8;
        let mut p = Pst::open(std::io::Cursor::new(&d), d.len() as u64).unwrap();
        assert_eq!(p.recovered.iter().copied().collect::<Vec<_>>(), [0x200064]);
        assert_eq!(p.message_ids(), [0x200024, 0x200044, 0x200064]);
        let (m, _) = p.message(0x200064).unwrap();
        assert_eq!(m.subject, "wipe the laptop");
        assert!(m.body.contains("sdelete"));
        assert_eq!(p.nodes[&0x200064].parent, 0x8062, "still tied to Deleted Items");
        assert!(p.notes.iter().any(|n| n.starts_with("1 deleted message(s) recovered")));
        // The untouched file has nothing to recover.
        let d = sample();
        let p = Pst::open(std::io::Cursor::new(&d), d.len() as u64).unwrap();
        assert!(p.recovered.is_empty());
    }

    /// Message 3 deleted with nothing left in the index: neither its node
    /// nor its blocks. An old copy of message 1 (same message id) is in free
    /// space too, and must not come back as a deleted message.
    #[test]
    fn recovers_deleted_messages_from_free_space() {
        let mut b = Builder::new();
        let mut none = vec![];
        let root = b.pc(&[(0x3001, V::S(""))], &mut none);
        b.node(0x122, root, 0, 0x122);
        let inbox = b.pc(&[(0x3001, V::S("Inbox"))], &mut none);
        b.node(0x8082, inbox, 0, 0x122);
        let m1 = [(0x001A, V::S("IPM.Note")), (0x0037, V::S("Q3 numbers")), (0x0C1A, V::S("Alice Lab")), (0x0E06, V::T(FT)), (0x1035, V::S("<q3@lab.test>"))];
        let old = b.pc(&m1, &mut none);
        b.forget_last();
        let _ = old;
        let live = b.pc(&m1, &mut none);
        b.node(0x200024, live, 0, 0x8082);
        // Message 3: its HTML body in a subnode, all of it forgotten.
        let html: Vec<u8> = format!("<html><body>{}</body></html>", "Use sdelete on everything. ".repeat(160)).into_bytes();
        let mut subs = vec![];
        let m3 = b.pc(&[(0x001A, V::S("IPM.Note")), (0x0037, V::S("wipe the laptop")), (0x0C1A, V::S("Alice Lab")), (0x0E06, V::T(FT + 72_000_000_000)), (0x1013, V::B(html.clone()))], &mut subs);
        b.forget_last();
        let _ = m3;
        // The HTML data block came before the PC; forget it too.
        let html_bid = subs[0].1;
        b.bbt.retain(|x| x.0 != html_bid);
        let _sl = b.subnodes(&subs);
        b.forget_last();
        let d = b.finish();
        if std::env::var_os("KOKINO_WRITE_SEEDS").is_some() {
            let seeds = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/pst");
            std::fs::write(seeds.join("free-space.pst"), &d).unwrap();
        }
        let mut p = Pst::open(std::io::Cursor::new(&d), d.len() as u64).unwrap();
        assert_eq!(p.free_space.len(), 1, "{:?}", p.notes);
        let nid = *p.free_space.iter().next().unwrap();
        assert!(p.recovered.contains(&nid));
        assert_eq!(p.message_ids().len(), 2);
        let (m, _) = p.message(nid).unwrap();
        assert_eq!(m.subject, "wipe the laptop");
        assert_eq!(m.html, html, "the body from its subnode");
        assert_eq!(p.nodes[&nid].parent, 0);
        assert!(p.notes.iter().any(|n| n.starts_with("1 deleted message(s) recovered from the file's free space")));
        // The ordinary sample has nothing in free space.
        let d = sample();
        let p = Pst::open(std::io::Cursor::new(&d), d.len() as u64).unwrap();
        assert!(p.free_space.is_empty());
    }

    #[test]
    fn block_trailers_check_out() {
        assert_eq!(pst_crc(b""), 0);
        assert_eq!(block_sig(0x23000, 0x2496), 0x1494, "from a real 2013 OST");
    }

    #[test]
    fn damaged_files_are_refused_or_skipped() {
        let mut d = sample();
        assert!(Pst::open(std::io::Cursor::new(&d[..400]), 400).is_err());
        // A node B-tree page of the wrong type: skipped with a note.
        let nbt = u64_at(&d, 224) as usize;
        d[nbt + 496] = 0x99;
        assert!(Pst::open(std::io::Cursor::new(&d), d.len() as u64).is_err());
    }
}

#[cfg(test)]
mod validation {
    use super::*;

    #[test]
    fn sample_files() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/pst");
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let f = std::fs::File::open(&p).unwrap();
            let len = f.metadata().unwrap().len();
            let mut pst = match Pst::open(std::io::BufReader::new(f), len) {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("{}: {}", p.display(), err);
                    continue;
                }
            };
            let folders = pst.folders();
            let ids = pst.message_ids();
            eprintln!("== {} version {} crypt {} nodes {} folders {} messages {} notes {:?}", p.display(), pst.version, pst.crypt, pst.nodes.len(), folders.len(), ids.len(), pst.notes);
            for f in folders.iter().take(30) {
                eprintln!("   folder {:#x} {:?} ({} items)", f.nid, f.path, f.count);
            }
            let mut errors = 0;
            for (k, &id) in ids.iter().enumerate() {
                match pst.message(id) {
                    Ok((m, _)) => {
                        if k < 3 {
                            eprintln!("   msg {:#x} {:?} from {:?} to {:?} date {} atts {:?} text {:?}", id, m.subject, m.from, m.to, m.date, m.attachments.iter().map(|a| (&a.name, a.size)).collect::<Vec<_>>(), m.text().chars().take(60).collect::<String>());
                        }
                        let eml = pst.eml(id).unwrap();
                        let parsed = crate::mail::parse(&eml);
                        assert_eq!(parsed.attachments.len(), m.attachments.len(), "{:#x}", id);
                    }
                    Err(err) => {
                        errors += 1;
                        if errors < 5 {
                            eprintln!("   msg {:#x}: {}", id, err);
                        }
                    }
                }
            }
            eprintln!("   {} messages unreadable, {} from free space", errors, pst.free_space.len());
            for id in pst.free_space.clone().iter().copied().take(5) {
                if let Ok((m, _)) = pst.message(id) {
                    eprintln!("   free {:#x} {:?} {:?} from {:?} date {} msgid {:?} sub {:#x} atts {} text {:?}", id, m.class, m.subject, m.from, m.date, m.message_id, pst.nodes[&id].sub, m.attachments.len(), m.text().chars().take(60).collect::<String>());
                }
            }
        }
    }
}
