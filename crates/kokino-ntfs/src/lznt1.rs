//! LZNT1 decompression ([MS-XCA] 2.5), the format of NTFS compressed files.
//!
//! A compressed stream is a series of chunks, each up to 4096 bytes once
//! decompressed, with a 2-byte header: bit 15 says whether the chunk is
//! compressed, the low 12 bits give its stored size minus 3. Compressed
//! chunks hold groups of 8 tokens behind a flag byte; a token is a literal
//! byte or a 16-bit back-reference whose split between offset and length
//! depends on how far into the chunk it is.

const CHUNK: usize = 4096;

/// Decompresses `src` into at most `max` bytes. A zero chunk header (or the
/// end of `src`) ends the stream.
pub fn decompress(src: &[u8], max: usize) -> anyhow::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(max.min(1 << 20));
    let mut p = 0;
    while p + 2 <= src.len() && out.len() < max {
        let h = u16::from_le_bytes([src[p], src[p + 1]]);
        if h == 0 {
            break;
        }
        let size = (h & 0x0FFF) as usize + 1;
        p += 2;
        let chunk = src.get(p..p + size).ok_or_else(|| anyhow::anyhow!("LZNT1 chunk runs past the end of the data"))?;
        p += size;
        if h & 0x8000 == 0 {
            out.extend_from_slice(chunk);
            continue;
        }
        let start = out.len();
        let mut i = 0;
        while i < chunk.len() {
            let flags = chunk[i];
            i += 1;
            for bit in 0..8 {
                if i >= chunk.len() {
                    break;
                }
                if (flags >> bit) & 1 == 0 {
                    out.push(chunk[i]);
                    i += 1;
                } else {
                    let tok = chunk.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| anyhow::anyhow!("LZNT1 back-reference cut short"))?;
                    i += 2;
                    let pos = out.len() - start;
                    if pos == 0 {
                        anyhow::bail!("LZNT1 back-reference at the start of a chunk");
                    }
                    // The further into the chunk, the more bits go to the offset.
                    let mut shift = 12;
                    let mut q = pos - 1;
                    while q >= 0x10 {
                        q >>= 1;
                        shift -= 1;
                    }
                    let disp = (tok >> shift) as usize + 1;
                    let len = (tok & ((1u16 << shift) - 1)) as usize + 3;
                    if disp > pos {
                        anyhow::bail!("LZNT1 back-reference before the start of the chunk");
                    }
                    for _ in 0..len {
                        let b = out[out.len() - disp];
                        out.push(b);
                    }
                }
                if out.len() - start > CHUNK {
                    anyhow::bail!("LZNT1 chunk decompresses to more than {} bytes", CHUNK);
                }
            }
        }
    }
    out.truncate(max);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win").join(name)).unwrap()
    }

    #[test]
    fn matches_windows_compressor() {
        for name in ["text", "long", "mixed"] {
            let raw = fixture(&format!("lznt1-{}.raw", name));
            let comp = fixture(&format!("lznt1-{}.lznt", name));
            assert_eq!(decompress(&comp, usize::MAX).unwrap(), raw, "{}", name);
            assert_eq!(decompress(&comp, 100).unwrap(), raw[..100.min(raw.len())], "{}", name);
        }
    }

    #[test]
    fn hostile_input_is_refused_not_trusted() {
        // Back-reference as the first token of a compressed chunk.
        assert!(decompress(&[0x02, 0xB0, 0x01, 0x00, 0x00], usize::MAX).is_err());
        // Header claims more data than there is.
        assert!(decompress(&[0xFF, 0xBF, 0x00], usize::MAX).is_err());
        // Uncompressed chunk passes through.
        assert_eq!(decompress(&[0x02, 0x30, b'a', b'b', b'c'], usize::MAX).unwrap(), b"abc");
    }
}
