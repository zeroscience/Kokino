//! Transparent file compression of HFS+ and APFS (decmpfs).
//!
//! A compressed file has an empty data fork and an extended attribute
//! `com.apple.decmpfs`: a 16-byte header ("fpmc", the method, the size)
//! followed by the data when it is small, or by nothing when the data is in
//! the resource fork (`com.apple.ResourceFork` on APFS) in 64 KiB chunks.
//!
//! Methods read: 3 and 4 (zlib), 7 and 8 (LZVN), 9 and 10 (stored).
//! LZFSE (11, 12) and LZBITMAP (13, 14) are reported, not decoded yet.

use std::io::Read;

pub const XATTR: &str = "com.apple.decmpfs";
pub const RSRC: &str = "com.apple.ResourceFork";
const CHUNK: usize = 64 << 10;
/// Largest file decompressed in one go.
pub const MAX_SIZE: u64 = 1 << 30;

fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn be32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}

/// (method, uncompressed size) from the attribute, if it is one.
pub fn header(attr: &[u8]) -> Option<(u32, u64)> {
    (attr.len() >= 16 && &attr[0..4] == b"fpmc").then(|| (le32(attr, 4) as u32, le64(attr, 8)))
}

pub fn method_name(m: u32) -> &'static str {
    match m {
        3 | 4 => "zlib",
        7 | 8 => "LZVN",
        9 | 10 => "stored",
        11 | 12 => "LZFSE",
        13 | 14 => "LZBITMAP",
        _ => "unknown",
    }
}

/// The whole uncompressed file. `rsrc` is the resource fork (needed for
/// the even-numbered methods).
pub fn decompress(attr: &[u8], rsrc: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
    let (method, size) = header(attr).ok_or_else(|| anyhow::anyhow!("not a decmpfs attribute"))?;
    if size > MAX_SIZE {
        anyhow::bail!("compressed file of {} bytes is larger than the {} byte limit", size, MAX_SIZE);
    }
    let size = size as usize;
    let inline = &attr[16..];
    let mut out = match method {
        3 => block(inline, size, Codec::Zlib)?,
        7 => block(inline, size, Codec::Lzvn)?,
        9 => inline.to_vec(),
        4 => {
            // Resource fork: 256-byte header, then the data: length (BE),
            // block count (LE) and (offset, size) pairs (LE) from 0x104.
            let r = rsrc.ok_or_else(|| anyhow::anyhow!("resource fork missing"))?;
            let base = (be32(r, 0) + 4) as usize;
            let n = le32(r, base) as usize;
            let mut out = Vec::with_capacity(size.min(64 << 20));
            for i in 0..n.min(size.div_ceil(CHUNK) + 1) {
                let (o, l) = (le32(r, base + 4 + 8 * i) as usize, le32(r, base + 8 + 8 * i) as usize);
                let d = r.get(base + o..base + o + l).ok_or_else(|| anyhow::anyhow!("compressed chunk {} outside the resource fork", i))?;
                out.extend(block(d, CHUNK.min(size - out.len().min(size)), Codec::Zlib)?);
                if out.len() >= size {
                    break;
                }
            }
            out
        }
        8 | 10 => {
            // Resource fork: a table of little-endian offsets, one per chunk
            // plus the end.
            let r = rsrc.ok_or_else(|| anyhow::anyhow!("resource fork missing"))?;
            let first = le32(r, 0) as usize;
            let n = (first / 4).saturating_sub(1);
            let mut out = Vec::with_capacity(size.min(64 << 20));
            for i in 0..n.min(size.div_ceil(CHUNK) + 1) {
                let (a, b) = (le32(r, 4 * i) as usize, le32(r, 4 * i + 4) as usize);
                let d = r.get(a..b).ok_or_else(|| anyhow::anyhow!("compressed chunk {} outside the resource fork", i))?;
                let want = CHUNK.min(size - out.len().min(size));
                out.extend(if method == 8 { block(d, want, Codec::Lzvn)? } else { d.to_vec() });
                if out.len() >= size {
                    break;
                }
            }
            out
        }
        m => anyhow::bail!("compression method {} ({}) is not decoded yet", m, method_name(m)),
    };
    out.truncate(size);
    Ok(out)
}

#[derive(Clone, Copy)]
enum Codec {
    Zlib,
    Lzvn,
}

/// One compressed block. A first byte of 0xFF (zlib) or 0x06 (LZVN) means
/// the rest is stored as is.
fn block(d: &[u8], want: usize, c: Codec) -> anyhow::Result<Vec<u8>> {
    match (c, d.first()) {
        (Codec::Zlib, Some(0xFF)) | (Codec::Lzvn, Some(0x06)) => Ok(d[1..d.len().min(want + 1)].to_vec()),
        (Codec::Zlib, _) => {
            let mut out = Vec::with_capacity(want);
            flate2::read::ZlibDecoder::new(d).take(want as u64).read_to_end(&mut out)?;
            Ok(out)
        }
        (Codec::Lzvn, _) => lzvn(d, want),
    }
}

/// LZVN, Apple's byte-oriented LZ77 variant (the format of lzvn_decode in
/// Apple's LZFSE reference code).
pub fn lzvn(src: &[u8], want: usize) -> anyhow::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(want.min(64 << 20));
    let mut p = 0usize;
    let mut d_prev = 0usize;
    let get = |i: usize| -> anyhow::Result<usize> { src.get(i).map(|&b| b as usize).ok_or_else(|| anyhow::anyhow!("LZVN data ends early")) };
    while out.len() < want {
        let op = get(p)?;
        // (literal count, match length, distance, opcode length)
        let (l, m, d, n) = match op {
            0x06 => break, // end of stream
            0x0E | 0x16 => (0, 0, d_prev, 1),
            0x70..=0x7F | 0xD0..=0xDF => anyhow::bail!("bad LZVN opcode 0x{:02x}", op),
            0x1E | 0x26 | 0x2E | 0x36 | 0x3E => anyhow::bail!("bad LZVN opcode 0x{:02x}", op),
            0xA0..=0xBF => {
                let w = get(p + 1)? | get(p + 2)? << 8;
                ((op >> 3) & 3, (((op & 7) << 2) | (w & 3)) + 3, w >> 2, 3)
            }
            0xE0 => (get(p + 1)? + 16, 0, d_prev, 2),
            0xE1..=0xEF => (op & 0xF, 0, d_prev, 1),
            0xF0 => (0, get(p + 1)? + 16, d_prev, 2),
            0xF1..=0xFF => (0, op & 0xF, d_prev, 1),
            _ => match op & 7 {
                6 => (op >> 6, ((op >> 3) & 7) + 3, d_prev, 1),
                7 => (op >> 6, ((op >> 3) & 7) + 3, get(p + 1)? | get(p + 2)? << 8, 3),
                _ => (op >> 6, ((op >> 3) & 7) + 3, (op & 7) << 8 | get(p + 1)?, 2),
            },
        };
        p += n;
        let lits = src.get(p..p + l).ok_or_else(|| anyhow::anyhow!("LZVN literals past the end"))?;
        out.extend_from_slice(lits);
        p += l;
        if m > 0 {
            if d == 0 || d > out.len() {
                anyhow::bail!("LZVN match distance {} outside the output", d);
            }
            let start = out.len() - d;
            for i in 0..m {
                let b = out[start + i];
                out.push(b);
            }
            d_prev = d;
        }
    }
    out.truncate(want);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzvn_basics() {
        // E3 "abc" (three literals), then a 6-byte match at distance 3
        // (sml_d: 00 011 000 / 03), then end of stream.
        let src = [0xE3, b'a', b'b', b'c', 0x18, 0x03, 0x06];
        assert_eq!(lzvn(&src, 9).unwrap(), b"abcabcabc");
        assert!(lzvn(&[0x70], 4).is_err());
        assert!(lzvn(&[0x00, 0x05], 4).is_err()); // distance past the output
    }
}
