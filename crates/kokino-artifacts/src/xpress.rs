//! LZXPRESS Huffman decompression ([MS-XCA] 2.2), as used by Windows 8.1+
//! Prefetch files ("MAM\x04" header) and other compressed system data.

/// Decompresses `src` into exactly `out_len` bytes.
pub fn decompress(src: &[u8], out_len: usize) -> anyhow::Result<Vec<u8>> {
    if out_len > 256 << 20 {
        anyhow::bail!("declared size {} is implausible", out_len);
    }
    let mut out = Vec::with_capacity(out_len);
    let mut pos = 0usize;
    let rd16 = |p: usize| -> u32 { src.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32).unwrap_or(0) };
    while out.len() < out_len {
        let table = src.get(pos..pos + 256).ok_or_else(|| anyhow::anyhow!("truncated Huffman table"))?;
        let mut lens = [0u8; 512];
        for (i, b) in table.iter().enumerate() {
            lens[2 * i] = b & 0x0F;
            lens[2 * i + 1] = b >> 4;
        }
        let decode = build_table(&lens)?;
        pos += 256;
        let mut bits: u32 = (rd16(pos) << 16) | rd16(pos + 2);
        pos += 4;
        let mut extra: i32 = 16;
        let chunk_end = (out.len() + 65_536).min(out_len);
        while out.len() < chunk_end {
            let (sym, len) = decode[(bits >> 17) as usize];
            if len == 0 {
                anyhow::bail!("invalid Huffman code");
            }
            bits <<= len;
            extra -= len as i32;
            if extra < 0 {
                bits |= rd16(pos) << (-extra);
                extra += 16;
                pos += 2;
            }
            if sym < 256 {
                out.push(sym as u8);
                continue;
            }
            let s = sym - 256;
            let mut mlen = (s & 15) as usize;
            let obits = (s >> 4) as u32;
            if mlen == 15 {
                mlen = *src.get(pos).ok_or_else(|| anyhow::anyhow!("truncated length"))? as usize;
                pos += 1;
                if mlen == 255 {
                    mlen = rd16(pos) as usize;
                    pos += 2;
                    if mlen == 0 {
                        mlen = src.get(pos..pos + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize).unwrap_or(0);
                        pos += 4;
                    }
                    if mlen < 15 {
                        anyhow::bail!("invalid match length");
                    }
                    mlen -= 15;
                }
                mlen += 15;
            }
            mlen += 3;
            let mut off = if obits == 0 { 0 } else { (bits >> (32 - obits)) as usize };
            off += 1usize << obits;
            if obits > 0 {
                bits = if obits >= 32 { 0 } else { bits << obits };
                extra -= obits as i32;
                if extra < 0 {
                    bits |= rd16(pos) << (-extra);
                    extra += 16;
                    pos += 2;
                }
            }
            if off > out.len() {
                anyhow::bail!("match points before the start of the output");
            }
            let start = out.len() - off;
            for i in 0..mlen.min(out_len - out.len()) {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    Ok(out)
}

/// Canonical Huffman decode table indexed by the next 15 bits.
fn build_table(lens: &[u8; 512]) -> anyhow::Result<Vec<(u16, u8)>> {
    let mut table = vec![(0u16, 0u8); 1 << 15];
    let mut code: u32 = 0;
    for bl in 1..=15u8 {
        for (sym, &l) in lens.iter().enumerate() {
            if l != bl {
                continue;
            }
            let span = 1u32 << (15 - bl);
            let start = code << (15 - bl);
            if start + span > 1 << 15 {
                anyhow::bail!("over-subscribed Huffman table");
            }
            for e in &mut table[start as usize..(start + span) as usize] {
                *e = (sym as u16, bl);
            }
            code += 1;
        }
        code <<= 1;
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Option<Vec<u8>> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win").join(name)).ok()
    }

    /// Vectors made by Windows itself (RtlCompressBuffer with
    /// COMPRESSION_FORMAT_XPRESS_HUFF), see scripts/fixture_windows.py.
    #[test]
    fn matches_windows_compressor() {
        for name in ["xpress-text", "xpress-random", "xpress-long"] {
            let (Some(raw), Some(comp)) = (fixture(&format!("{}.raw", name)), fixture(&format!("{}.xph", name))) else { return };
            assert_eq!(decompress(&comp, raw.len()).unwrap(), raw, "{}", name);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(decompress(&[0u8; 10], 100).is_err());
        assert!(decompress(&[0xFFu8; 300], 100).is_err());
    }
}
