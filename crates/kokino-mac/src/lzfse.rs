//! LZFSE, Apple's compression (decmpfs methods 11 and 12, and .aar and
//! other Apple archives), decoded in safe Rust after the format of Apple's
//! reference code (lzfse_decode_base.c, lzfse_fse.h; BSD).
//!
//! A stream is a run of blocks, each starting with a four-byte magic:
//! "bvx-" stored, "bvxn" LZVN, "bvx1" and "bvx2" LZFSE (version 1 with its
//! frequency tables as is, version 2 with them packed), "bvx$" the end.
//! An LZFSE block holds literals coded with four interleaved FSE (tANS)
//! states, then (literal length, match length, distance) triples coded with
//! three more; both bit streams are read backwards from their ends.

use crate::decmpfs::lzvn;

const MAGIC_END: u32 = 0x2478_7662; // "bvx$"
const MAGIC_RAW: u32 = 0x2D78_7662; // "bvx-"
const MAGIC_V1: u32 = 0x3178_7662; // "bvx1"
const MAGIC_V2: u32 = 0x3278_7662; // "bvx2"
const MAGIC_LZVN: u32 = 0x6E78_7662; // "bvxn"

const MATCHES_PER_BLOCK: u64 = 10_000;
const LITERALS_PER_BLOCK: u64 = 4 * MATCHES_PER_BLOCK;
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LITERAL_STATES: usize = 1024;
const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LITERAL_SYMBOLS: usize = 256;

const L_EXTRA_BITS: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [i32; 20] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60];
const M_EXTRA_BITS: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [i32; 20] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312];
const D_EXTRA_BITS: [u8; 64] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
];
const D_BASE: [i32; 64] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956,
    49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

fn le16(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as u64).unwrap_or(0)
}
fn le32(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64).unwrap_or(0)
}
fn le64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0)
}
/// Up to 8 bytes from `o`, zeros past the end (bit-stream reads).
fn load(b: &[u8], o: usize) -> u64 {
    let mut x = [0u8; 8];
    let n = b.len().saturating_sub(o).min(8);
    x[..n].copy_from_slice(&b[o..o + n]);
    u64::from_le_bytes(x)
}
fn bits(v: u64, at: u32, n: u32) -> u64 {
    (v >> at) & ((1 << n) - 1)
}

/// Decodes a whole LZFSE stream; `want` bounds the output (the decmpfs
/// size), and decoding stops there.
pub fn decode(src: &[u8], want: usize) -> anyhow::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(want.min(64 << 20));
    let mut p = 0usize;
    while out.len() < want {
        if src.len() < p + 4 {
            anyhow::bail!("LZFSE stream ends without its end marker");
        }
        let magic = le32(src, p);
        match magic as u32 {
            MAGIC_END => break,
            MAGIC_RAW => {
                let n = le32(src, p + 4) as usize;
                let d = src.get(p + 8..p + 8 + n).ok_or_else(|| anyhow::anyhow!("stored LZFSE block past the end"))?;
                out.extend_from_slice(&d[..n.min(want - out.len())]);
                p += 8 + n;
            }
            MAGIC_LZVN => {
                let (raw, payload) = (le32(src, p + 4) as usize, le32(src, p + 8) as usize);
                let d = src.get(p + 12..p + 12 + payload).ok_or_else(|| anyhow::anyhow!("LZVN block past the end"))?;
                let b = lzvn(d, raw.min(want - out.len()))?;
                out.extend_from_slice(&b);
                p += 12 + payload;
            }
            MAGIC_V1 | MAGIC_V2 => {
                let h = Header::parse(src, p, magic as u32)?;
                let end = h.decode(src, &mut out, want)?;
                p = end;
            }
            m => anyhow::bail!("not an LZFSE block (magic 0x{:08x})", m),
        }
    }
    out.truncate(want);
    Ok(out)
}

/// An LZFSE block header, either version, unpacked.
struct Header {
    n_raw: u64,
    n_literals: u64,
    n_matches: u64,
    n_lit_payload: u64,
    n_lmd_payload: u64,
    literal_bits: i32,
    literal_state: [u64; 4],
    lmd_bits: i32,
    l_state: u64,
    m_state: u64,
    d_state: u64,
    /// L, M, D and literal frequencies, in that order (20 + 20 + 64 + 256).
    freq: Vec<u16>,
    /// Where the payload starts.
    payload: usize,
}

impl Header {
    fn parse(src: &[u8], p: usize, magic: u32) -> anyhow::Result<Header> {
        let mut freq = vec![0u16; L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS];
        let h = if magic == MAGIC_V1 {
            // The C struct as written, 772 bytes with its padding.
            let b = src.get(p..p + 772).ok_or_else(|| anyhow::anyhow!("LZFSE block header past the end"))?;
            for (i, f) in freq.iter_mut().enumerate() {
                *f = le16(b, 50 + 2 * i) as u16;
            }
            Header {
                n_raw: le32(b, 4),
                n_literals: le32(b, 12),
                n_matches: le32(b, 16),
                n_lit_payload: le32(b, 20),
                n_lmd_payload: le32(b, 24),
                literal_bits: le32(b, 28) as u32 as i32,
                literal_state: [le16(b, 32), le16(b, 34), le16(b, 36), le16(b, 38)],
                lmd_bits: le32(b, 40) as u32 as i32,
                l_state: le16(b, 44),
                m_state: le16(b, 46),
                d_state: le16(b, 48),
                freq,
                payload: p + 772,
            }
        } else {
            let b = src.get(p..p + 32).ok_or_else(|| anyhow::anyhow!("LZFSE block header past the end"))?;
            let (v0, v1, v2) = (le64(b, 8), le64(b, 16), le64(b, 24));
            let header_size = bits(v2, 0, 32) as usize;
            let tables = src.get(p + 32..p + header_size.max(32)).ok_or_else(|| anyhow::anyhow!("LZFSE block header past the end"))?;
            if header_size < 32 {
                anyhow::bail!("LZFSE block header too short");
            }
            unpack_freq(tables, &mut freq)?;
            Header {
                n_raw: le32(b, 4),
                n_literals: bits(v0, 0, 20),
                n_lit_payload: bits(v0, 20, 20),
                n_matches: bits(v0, 40, 20),
                literal_bits: bits(v0, 60, 3) as i32 - 7,
                literal_state: [bits(v1, 0, 10), bits(v1, 10, 10), bits(v1, 20, 10), bits(v1, 30, 10)],
                n_lmd_payload: bits(v1, 40, 20),
                lmd_bits: bits(v1, 60, 3) as i32 - 7,
                l_state: bits(v2, 32, 10),
                m_state: bits(v2, 42, 10),
                d_state: bits(v2, 52, 10),
                freq,
                payload: p + header_size,
            }
        };
        if h.n_literals > LITERALS_PER_BLOCK || h.n_matches > MATCHES_PER_BLOCK {
            anyhow::bail!("LZFSE block claims too many literals or matches");
        }
        if h.literal_state.iter().any(|&s| s >= LITERAL_STATES as u64) || h.l_state >= L_STATES as u64 || h.m_state >= M_STATES as u64 || h.d_state >= D_STATES as u64 {
            anyhow::bail!("LZFSE block state out of range");
        }
        if !(-7..=0).contains(&h.literal_bits) || !(-7..=0).contains(&h.lmd_bits) {
            anyhow::bail!("LZFSE block bit count out of range");
        }
        Ok(h)
    }

    /// Decodes the block onto `out`; returns where the next block starts.
    fn decode(&self, src: &[u8], out: &mut Vec<u8>, want: usize) -> anyhow::Result<usize> {
        let (lf, rest) = self.freq.split_at(L_SYMBOLS);
        let (mf, rest) = rest.split_at(M_SYMBOLS);
        let (df, litf) = rest.split_at(D_SYMBOLS);
        let lit_table = decoder_table(LITERAL_STATES, litf)?;
        let l_table = value_table(L_STATES, lf, &L_EXTRA_BITS, &L_BASE)?;
        let m_table = value_table(M_STATES, mf, &M_EXTRA_BITS, &M_BASE)?;
        let d_table = value_table(D_STATES, df, &D_EXTRA_BITS, &D_BASE)?;

        let lit_end = self.payload + self.n_lit_payload as usize;
        let lmd_end = lit_end + self.n_lmd_payload as usize;
        if lmd_end > src.len() {
            anyhow::bail!("LZFSE block payload past the end");
        }
        // Literals: four states in turn, read backwards from the end of
        // their payload (8-byte reads may reach back into the header, as in
        // the reference decoder).
        let mut literals = vec![0u8; self.n_literals.next_multiple_of(4) as usize];
        let mut inp = BitIn::new(src, lit_end, self.literal_bits)?;
        let mut st = self.literal_state;
        for chunk in literals.chunks_mut(4) {
            inp.flush()?;
            for (k, b) in chunk.iter_mut().enumerate() {
                let e = lit_table[st[k] as usize];
                *b = e.symbol;
                st[k] = (e.delta as i64 + inp.pull(e.k as u32)? as i64) as u64;
                if st[k] >= LITERAL_STATES as u64 {
                    anyhow::bail!("LZFSE literal state out of range");
                }
            }
        }
        // Literal length, match length and distance triples.
        let mut inp = BitIn::new(src, lmd_end, self.lmd_bits)?;
        let (mut ls, mut ms, mut ds) = (self.l_state as usize, self.m_state as usize, self.d_state as usize);
        let mut lit = 0usize;
        let mut d: i64 = -1;
        let start = out.len();
        for _ in 0..self.n_matches {
            inp.flush()?;
            let l = value(&l_table, &mut ls, &mut inp, L_STATES)? as usize;
            let m = value(&m_table, &mut ms, &mut inp, M_STATES)? as usize;
            let nd = value(&d_table, &mut ds, &mut inp, D_STATES)?;
            if nd != 0 {
                d = nd as i64;
            }
            let lits = literals.get(lit..lit + l).ok_or_else(|| anyhow::anyhow!("LZFSE literal run past the decoded literals"))?;
            out.extend_from_slice(lits);
            lit += l;
            if m > 0 {
                if d <= 0 || d as usize > out.len() {
                    anyhow::bail!("LZFSE match distance {} outside the output", d);
                }
                let from = out.len() - d as usize;
                for i in 0..m {
                    let b = out[from + i];
                    out.push(b);
                }
            }
            if out.len() >= want {
                break;
            }
        }
        if out.len() - start < self.n_raw as usize && out.len() < want {
            anyhow::bail!("LZFSE block decoded to {} of {} bytes", out.len() - start, self.n_raw);
        }
        out.truncate(start + (self.n_raw as usize).min(out.len() - start));
        Ok(lmd_end)
    }
}

/// Version 2 headers pack the 360 frequencies in a variable-length code.
fn unpack_freq(b: &[u8], freq: &mut [u16]) -> anyhow::Result<()> {
    const NBITS: [u32; 32] = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14];
    const VALUE: [u16; 32] = [0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3, 1, 0];
    let mut acc: u32 = 0;
    let mut nacc: u32 = 0;
    let mut p = 0usize;
    for f in freq.iter_mut() {
        while nacc + 8 <= 32 && p < b.len() {
            acc |= (b[p] as u32) << nacc;
            nacc += 8;
            p += 1;
        }
        let i = (acc & 31) as usize;
        let n = NBITS[i];
        let v = match n {
            8 => 8 + ((acc >> 4) & 0xF) as u16,
            14 => 24 + ((acc >> 4) & 0x3FF) as u16,
            _ => VALUE[i],
        };
        if n > nacc {
            anyhow::bail!("LZFSE frequency table ends early");
        }
        *f = v;
        acc >>= n;
        nacc -= n;
    }
    // The tables end exactly at the end of the header.
    if nacc >= 8 || p != b.len() {
        anyhow::bail!("LZFSE frequency table does not fill its header");
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct Entry {
    k: i8,
    symbol: u8,
    delta: i16,
}

#[derive(Clone, Copy, Default)]
struct ValueEntry {
    total_bits: u8,
    value_bits: u8,
    delta: i32,
    vbase: i32,
}

/// Leading zeros of a 32-bit value, as the reference code counts them.
fn clz(v: usize) -> i32 {
    (v as u32).leading_zeros() as i32
}

fn decoder_table(nstates: usize, freq: &[u16]) -> anyhow::Result<Vec<Entry>> {
    let mut t = Vec::with_capacity(nstates);
    let n_clz = clz(nstates);
    let mut sum = 0usize;
    for (sym, &f) in freq.iter().enumerate() {
        let f = f as usize;
        if f == 0 {
            continue;
        }
        sum += f;
        if sum > nstates {
            anyhow::bail!("LZFSE frequencies add up to more than the states");
        }
        let k = clz(f) - n_clz;
        let j0 = ((2 * nstates) >> k) - f;
        for j in 0..f {
            t.push(if j < j0 {
                Entry { k: k as i8, symbol: sym as u8, delta: (((f + j) << k) as i64 - nstates as i64) as i16 }
            } else {
                Entry { k: (k - 1) as i8, symbol: sym as u8, delta: ((j - j0) << (k - 1)) as i16 }
            });
        }
    }
    t.resize(nstates, Entry::default());
    Ok(t)
}

fn value_table(nstates: usize, freq: &[u16], vbits: &[u8], vbase: &[i32]) -> anyhow::Result<Vec<ValueEntry>> {
    let mut t = Vec::with_capacity(nstates);
    let n_clz = clz(nstates);
    let mut sum = 0usize;
    for (sym, &f) in freq.iter().enumerate() {
        let f = f as usize;
        if f == 0 {
            continue;
        }
        sum += f;
        if sum > nstates {
            anyhow::bail!("LZFSE frequencies add up to more than the states");
        }
        let k = clz(f) - n_clz;
        let j0 = ((2 * nstates) >> k) - f;
        let vb = vbits[sym];
        for j in 0..f {
            t.push(if j < j0 {
                ValueEntry { total_bits: k as u8 + vb, value_bits: vb, delta: (((f + j) << k) as i64 - nstates as i64) as i32, vbase: vbase[sym] }
            } else {
                ValueEntry { total_bits: (k - 1) as u8 + vb, value_bits: vb, delta: ((j - j0) << (k - 1)) as i32, vbase: vbase[sym] }
            });
        }
    }
    t.resize(nstates, ValueEntry::default());
    Ok(t)
}

fn value(t: &[ValueEntry], state: &mut usize, inp: &mut BitIn, nstates: usize) -> anyhow::Result<i32> {
    let e = t[*state];
    let sv = inp.pull(e.total_bits as u32)?;
    let next = e.delta as i64 + (sv >> e.value_bits) as i64;
    if !(0..nstates as i64).contains(&next) {
        anyhow::bail!("LZFSE state out of range");
    }
    *state = next as usize;
    Ok(e.vbase + (sv & ((1u64 << e.value_bits) - 1)) as i32)
}

/// FSE's backward bit reader (the reference's 64-bit stream): bytes are
/// taken from `pos` down towards the start of `src`.
struct BitIn<'a> {
    src: &'a [u8],
    pos: usize,
    acc: u64,
    n: u32,
}

impl<'a> BitIn<'a> {
    fn new(src: &'a [u8], end: usize, nbits: i32) -> anyhow::Result<BitIn<'a>> {
        let (take, n) = if nbits != 0 { (8, (nbits + 64) as u32) } else { (7, 56) };
        let pos = end.checked_sub(take).ok_or_else(|| anyhow::anyhow!("LZFSE bit stream starts before the data"))?;
        let mut acc = load(src, pos);
        if take == 7 {
            acc &= 0x00FF_FFFF_FFFF_FFFF;
        }
        if !(56..64).contains(&n) || acc >> n != 0 {
            anyhow::bail!("LZFSE bit stream start is damaged");
        }
        Ok(BitIn { src, pos, acc, n })
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        let nbits = (63 - self.n) & !7;
        if nbits == 0 {
            return Ok(());
        }
        let nbytes = (nbits >> 3) as usize;
        self.pos = self.pos.checked_sub(nbytes).ok_or_else(|| anyhow::anyhow!("LZFSE bit stream runs past its start"))?;
        let incoming = load(self.src, self.pos) & ((1u64 << nbits) - 1);
        self.acc = (self.acc << nbits) | incoming;
        self.n += nbits;
        Ok(())
    }

    fn pull(&mut self, k: u32) -> anyhow::Result<u64> {
        if k > self.n {
            anyhow::bail!("LZFSE bit stream exhausted");
        }
        self.n -= k;
        let r = self.acc >> self.n;
        self.acc &= if self.n == 0 { 0 } else { (1u64 << self.n) - 1 };
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Packs version 2 frequencies: 0 as two zero bits, anything from 24
    /// up as fourteen bits (1111, then the value less 24).
    fn pack_freq(freq: &[u16]) -> Vec<u8> {
        let (mut out, mut acc, mut n) = (vec![], 0u64, 0u32);
        for &f in freq {
            let (code, bits) = match f {
                0 => (0u64, 2),
                f if f >= 24 => (0b1111 | ((f as u64 - 24) << 4), 14),
                _ => panic!("not packed by this test"),
            };
            acc |= code << n;
            n += bits;
            while n >= 8 {
                out.push(acc as u8);
                acc >>= 8;
                n -= 8;
            }
        }
        if n > 0 {
            out.push(acc as u8);
        }
        out
    }

    /// One version 2 block whose tables each hold a single symbol: every
    /// literal is 'A', and one triple (L 4, M 8, D 4) makes 12 bytes.
    fn single_symbol_block() -> Vec<u8> {
        let mut freq = vec![0u16; 360];
        freq[4] = 64; // L = 4
        freq[20 + 8] = 64; // M = 8
        freq[40 + 4] = 256; // D symbol 4: base 4, one extra bit
        freq[104 + b'A' as usize] = 1024;
        let tables = pack_freq(&freq);
        let header_size = 32 + tables.len() as u64;
        let mut b = vec![];
        b.extend_from_slice(b"bvx2");
        b.extend_from_slice(&12u32.to_le_bytes());
        let v0 = 4 | (8 << 20) | (1 << 40) | (7 << 60); // literals, literal payload, matches, literal_bits 0
        let v1 = 8u64 << 40; // lmd payload; lmd_bits 0 here means -7
        let v2 = header_size;
        for v in [v0, v1, v2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&tables);
        b.extend_from_slice(&[0; 16]);
        b.extend_from_slice(b"bvx$");
        b
    }

    #[test]
    fn single_symbol_tables() {
        assert_eq!(decode(&single_symbol_block(), 12).unwrap(), b"AAAAAAAAAAAA");
        assert_eq!(decode(&single_symbol_block(), 5).unwrap(), b"AAAAA");
    }

    #[test]
    fn stored_and_lzvn_blocks() {
        let mut s = vec![];
        s.extend_from_slice(b"bvx-");
        s.extend_from_slice(&3u32.to_le_bytes());
        s.extend_from_slice(b"xyz");
        s.extend_from_slice(b"bvxn");
        s.extend_from_slice(&9u32.to_le_bytes());
        s.extend_from_slice(&7u32.to_le_bytes());
        s.extend_from_slice(&[0xE3, b'a', b'b', b'c', 0x18, 0x03, 0x06]);
        s.extend_from_slice(b"bvx$");
        assert_eq!(decode(&s, 100).unwrap(), b"xyzabcabcabc");
    }

    /// Writes the fuzzing seeds. Run with --ignored after changing them.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kokino-fuzz/seeds/lzfse");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("single-symbol.lzfse"), single_symbol_block()).unwrap();
    }

    /// Streams made by Apple's reference encoder (lzfse -encode, from
    /// github.com/lzfse/lzfse) from generated test data: LZFSE version 2
    /// blocks, an LZVN block (inputs under 4 KiB) and a stream of eight
    /// blocks. Checked by the original's size and SHA-256.
    #[test]
    fn reference_encoder_streams() {
        use sha2::{Digest, Sha256};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/lzfse");
        for (name, size, sha) in [
            ("small.txt", 1_000, "e0fd14066e1acd479d3526d8bf89772418d101613bfd1da2d6cdbb7413c7d1f3"),
            ("text.txt", 200_000, "6032819a9118929eec231fd32448371db0dfca6bcba506a3c09441eff3f1490d"),
            ("binary.bin", 300_000, "ff1f65037a759cde176dc63bfdb29a7b4325d1cf8125364df348eff7d9b164ba"),
            ("random.bin", 20_000, "4f4f20352cd7d69498f266219777029de1ccea957041f43cd5a2836a0cf7d2c8"),
            ("long-runs.bin", 262_400, "d8ba59e266a899d4ae78b4df28cbecf682d51df09b3d756567c64f13e4616ecf"),
            ("multi-block.bin", 1_200_000, "cb889743094e1509645d3b8926657b4d32e10a9951b3df20d2ad91885cf92883"),
        ] {
            let src = std::fs::read(dir.join(format!("{}.lzfse", name))).unwrap();
            let out = decode(&src, usize::MAX).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert_eq!(out.len(), size, "{}", name);
            let got: String = Sha256::digest(&out).iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(got, sha, "{}", name);
            // Stopping early gives the start.
            assert_eq!(decode(&src, 777).unwrap(), out[..777]);
        }
    }

    #[test]
    fn rejects_damage() {
        assert!(decode(b"bvx", 10).is_err());
        assert!(decode(b"nope", 10).is_err());
        let good = single_symbol_block();
        for i in 0..good.len() {
            for v in [0x00, 0xFF, 0x80] {
                let mut b = good.clone();
                b[i] = v;
                let _ = decode(&b, 64);
            }
        }
    }
}
