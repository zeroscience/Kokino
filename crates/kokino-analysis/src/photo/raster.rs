//! Lossless images (PNG, BMP): structure, where the file really ends, text
//! chunks, and the 8-bit sample values for the LSB test.

use serde::Serialize;
use std::io::Read;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Raster {
    pub format: &'static str,
    pub width: u32,
    pub height: u32,
    /// "RGB", "RGBA", "Gray", "Gray+Alpha", "Palette"...
    pub color: String,
    pub bit_depth: u8,
    pub interlaced: bool,
    /// PNG chunk types in order (repeated IDATs shown once with a count).
    pub chunks: Vec<String>,
    /// PNG tEXt / iTXt / zTXt entries (keyword, start of the text).
    pub text: Vec<(String, String)>,
    /// Offset just after IEND (PNG) or the declared file size (BMP).
    pub end: usize,
    /// Channels per pixel in `samples`, for the bit-plane statistics.
    #[serde(skip)]
    pub channels: usize,
    /// Every 8-bit color sample (alpha left out), row by row.
    #[serde(skip)]
    pub samples: Vec<u8>,
    pub note: String,
}

fn be32(d: &[u8], i: usize) -> usize {
    u32::from_be_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as usize
}

fn le32(d: &[u8], i: usize) -> usize {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as usize
}

/// Decodes samples only up to this many pixels (the LSB test needs a sample, not everything).
const MAX_PIXELS: usize = 40_000_000;

pub fn png(d: &[u8]) -> anyhow::Result<Raster> {
    if !d.starts_with(b"\x89PNG\r\n\x1a\n") {
        anyhow::bail!("not a PNG");
    }
    let mut r = Raster { format: "PNG", end: d.len(), ..Default::default() };
    let (mut i, mut idat, mut ctype) = (8usize, Vec::new(), 0u8);
    let mut idat_count = 0;
    while i + 12 <= d.len() {
        let len = be32(d, i);
        let typ = String::from_utf8_lossy(&d[i + 4..i + 8]).to_string();
        if i + 12 + len > d.len() {
            r.note = format!("chunk {} runs past the end of the file", typ);
            break;
        }
        let body = &d[i + 8..i + 8 + len];
        match typ.as_str() {
            "IHDR" if len >= 13 => {
                r.width = be32(body, 0) as u32;
                r.height = be32(body, 4) as u32;
                r.bit_depth = body[8];
                ctype = body[9];
                r.interlaced = body[12] == 1;
                r.color = match ctype {
                    0 => "Gray",
                    2 => "RGB",
                    3 => "Palette",
                    4 => "Gray+Alpha",
                    6 => "RGBA",
                    _ => "unknown",
                }
                .into();
            }
            "IDAT" => {
                idat_count += 1;
                if idat.len() < 512 << 20 {
                    idat.extend_from_slice(body);
                }
            }
            "tEXt" => {
                let k = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                r.text.push((String::from_utf8_lossy(&body[..k]).into(), String::from_utf8_lossy(body.get(k + 1..).unwrap_or(&[])).chars().take(500).collect()));
            }
            "iTXt" | "zTXt" => {
                let k = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                let compressed = if typ == "zTXt" { true } else { body.get(k + 1).copied() == Some(1) };
                let rest = if typ == "zTXt" { body.get(k + 2..).unwrap_or(&[]) } else {
                    // iTXt: flag, method, language\0, translated keyword\0, text
                    let mut p = k + 3;
                    for _ in 0..2 {
                        p += body.get(p..).and_then(|s| s.iter().position(|&b| b == 0)).map(|x| x + 1).unwrap_or(0);
                    }
                    body.get(p..).unwrap_or(&[])
                };
                let text = if compressed {
                    let mut s = String::new();
                    let _ = flate2::read::ZlibDecoder::new(rest).take(64 * 1024).read_to_string(&mut s);
                    s
                } else {
                    String::from_utf8_lossy(rest).into()
                };
                r.text.push((String::from_utf8_lossy(&body[..k]).into(), text.chars().take(500).collect()));
            }
            _ => {}
        }
        if typ != "IDAT" || idat_count == 1 {
            r.chunks.push(typ.clone());
        }
        i += 12 + len;
        if typ == "IEND" {
            r.end = i;
            break;
        }
    }
    if idat_count > 1 {
        if let Some(c) = r.chunks.iter_mut().find(|c| *c == "IDAT") {
            *c = format!("IDAT x{}", idat_count);
        }
    }
    let channels = match ctype {
        0 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => 0,
    };
    let pixels = r.width as usize * r.height as usize;
    if channels == 0 || r.bit_depth != 8 || r.interlaced || pixels == 0 || pixels > MAX_PIXELS {
        if r.note.is_empty() {
            r.note = "pixel statistics need a non-interlaced 8-bit gray or RGB(A) PNG".into();
        }
        return Ok(r);
    }
    let stride = r.width as usize * channels;
    let mut raw = Vec::with_capacity((stride + 1) * r.height as usize);
    flate2::read::ZlibDecoder::new(&idat[..]).take(((stride + 1) * r.height as usize) as u64).read_to_end(&mut raw)?;
    let rows = raw.len() / (stride + 1);
    let mut prev = vec![0u8; stride];
    let mut cur = vec![0u8; stride];
    let color = if channels == 2 || channels == 4 { channels - 1 } else { channels };
    r.channels = color;
    r.samples.reserve(rows * r.width as usize * color);
    for y in 0..rows {
        let line = &raw[y * (stride + 1)..(y + 1) * (stride + 1)];
        let f = line[0];
        for x in 0..stride {
            let a = if x >= channels { cur[x - channels] as i32 } else { 0 };
            let b = prev[x] as i32;
            let c = if x >= channels { prev[x - channels] as i32 } else { 0 };
            let v = line[1 + x] as i32;
            cur[x] = match f {
                0 => v,
                1 => v + a,
                2 => v + b,
                3 => v + (a + b) / 2,
                4 => {
                    let p = a + b - c;
                    let (pa, pb, pc) = ((p - a).abs(), (p - b).abs(), (p - c).abs());
                    v + if pa <= pb && pa <= pc { a } else if pb <= pc { b } else { c }
                }
                _ => anyhow::bail!("bad PNG filter {}", f),
            } as u8;
        }
        for px in cur.chunks_exact(channels) {
            r.samples.extend_from_slice(&px[..color]);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    if rows < r.height as usize {
        r.note = format!("image data ends after {} of {} rows", rows, r.height);
    }
    Ok(r)
}

pub fn bmp(d: &[u8]) -> anyhow::Result<Raster> {
    if d.len() < 54 || &d[..2] != b"BM" {
        anyhow::bail!("not a BMP");
    }
    let size = le32(d, 2);
    let data = le32(d, 10);
    let w = le32(d, 18) as i32;
    let h = le32(d, 22) as i32;
    let bpp = u16::from_le_bytes([d[28], d[29]]);
    let comp = le32(d, 30);
    let mut r = Raster { format: "BMP", width: w.unsigned_abs(), height: h.unsigned_abs(), bit_depth: bpp as u8, end: size.min(d.len()).max(54), ..Default::default() };
    r.color = match bpp {
        24 => "RGB",
        32 => "RGBA",
        8 => "Palette",
        _ => "other",
    }
    .into();
    if !(bpp == 24 || bpp == 32) || comp != 0 || w <= 0 || h == 0 || (w as usize) * (h.unsigned_abs() as usize) > MAX_PIXELS {
        r.note = "pixel statistics need an uncompressed 24- or 32-bit BMP".into();
        return Ok(r);
    }
    let bytes = bpp as usize / 8;
    let stride = (w as usize * bytes).div_ceil(4) * 4;
    r.channels = 3;
    for y in 0..h.unsigned_abs() as usize {
        let o = data + y * stride;
        let Some(row) = d.get(o..o + w as usize * bytes) else {
            r.note = format!("pixel data ends after {} rows", y);
            break;
        };
        for px in row.chunks_exact(bytes) {
            r.samples.extend_from_slice(&px[..3]);
        }
    }
    Ok(r)
}

/// Chi-square attack on the least significant bit (Westfeld and Pfitzmann).
/// Embedding a message in the LSBs evens out the counts of each value pair
/// (2k, 2k+1); natural images keep them uneven. The p-value is the
/// probability the pairs are this even by chance of embedding: near 1 means
/// "consistent with LSB embedding". It is computed on growing runs from the
/// start and from the end of the pixel data, because tools fill in order.
#[derive(Debug, Clone, Serialize)]
pub struct LsbTest {
    /// (share of the samples tested, p-value)
    pub prefix: Vec<(f64, f64)>,
    /// Largest prefix whose p-value is at least `LSB_THRESHOLD`.
    pub embedded_share: f64,
    /// The run was found from the end of the pixel data (BMP rows are
    /// stored bottom-up, and some tools fill from the end).
    pub from_end: bool,
    pub detected: bool,
    /// Share of ones in the LSB plane (0.5 for random data).
    pub ones: f64,
}

/// p-value at or above which a prefix counts as embedded.
pub const LSB_THRESHOLD: f64 = 0.99;
/// Smallest prefix share that is reported (shorter runs are noise).
pub const LSB_MIN_SHARE: f64 = 0.05;

pub fn lsb(samples: &[u8]) -> Option<LsbTest> {
    if samples.len() < 4096 {
        return None;
    }
    let shares = [0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
    let n = samples.len();
    let curve = |from_end: bool| -> Vec<(f64, f64)> {
        shares
            .iter()
            .map(|&s| {
                let k = ((n as f64 * s) as usize).max(1);
                (s, run_p(if from_end { &samples[n - k..] } else { &samples[..k] }))
            })
            .collect()
    };
    let share = |c: &[(f64, f64)]| c.iter().filter(|(s, p)| *s >= LSB_MIN_SHARE && *p >= LSB_THRESHOLD).map(|x| x.0).fold(0.0, f64::max);
    let (head, tail) = (curve(false), curve(true));
    let (prefix, embedded_share, from_end) = if share(&tail) > share(&head) { let s = share(&tail); (tail, s, true) } else { let s = share(&head); (head, s, false) };
    let ones = samples.iter().filter(|&&b| b & 1 == 1).count() as f64 / n as f64;
    Some(LsbTest { prefix, embedded_share, from_end, detected: embedded_share > 0.0, ones: (ones * 1000.0).round() / 1000.0 })
}

/// p-value of the pairs (2k, 2k+1), or of the shifted pairs (2k+1, 2k+2)
/// when `shift` is 1.
fn chi_square_p(s: &[u8], shift: usize) -> f64 {
    let mut h = [0u64; 257];
    for &b in s {
        h[b as usize] += 1;
    }
    let (mut chi, mut df) = (0f64, 0i32);
    for k in 0..128 - shift {
        let (a, b) = (h[2 * k + shift] as f64, h[2 * k + 1 + shift] as f64);
        let e = (a + b) / 2.0;
        if e > 4.0 {
            chi += (a - e) * (a - e) / e;
            df += 1;
        }
    }
    if df < 2 {
        return 0.0;
    }
    // P(X >= chi) for chi-square with df-1 degrees of freedom.
    gamma_q((df - 1) as f64 / 2.0, chi / 2.0)
}

/// An embedded run evens out the true pairs only. A histogram that is
/// smooth by nature (noise over flat areas) evens out the shifted pairs as
/// well, so a run counts only while those stay uneven.
const CONTROL_MAX: f64 = 0.5;

fn run_p(s: &[u8]) -> f64 {
    if chi_square_p(s, 1) > CONTROL_MAX {
        0.0
    } else {
        chi_square_p(s, 0)
    }
}

/// Regularized upper incomplete gamma Q(a, x).
fn gamma_q(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    let gln = ln_gamma(a);
    if x < a + 1.0 {
        let (mut sum, mut del, mut ap) = (1.0 / a, 1.0 / a, a);
        for _ in 0..1000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-14 {
                break;
            }
        }
        1.0 - (sum * (-x + a * x.ln() - gln).exp())
    } else {
        let (mut b, mut c, mut d) = (x + 1.0 - a, 1.0 / 1e-300, 1.0 / (x + 1.0 - a));
        let mut h = d;
        for i in 1..1000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < 1e-300 {
                d = 1e-300;
            }
            c = b + an / c;
            if c.abs() < 1e-300 {
                c = 1e-300;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-14 {
                break;
            }
        }
        (-x + a * x.ln() - gln).exp() * h
    }
}

fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 6] = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = tmp - (x + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for c in C {
        y += 1.0;
        ser += c / y;
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gamma_matches_known_values() {
        // Chi-square, 2 degrees of freedom: Q = exp(-x/2).
        assert!((gamma_q(1.0, 1.5) - (-1.5f64).exp()).abs() < 1e-9);
        // 10 degrees of freedom at 18.307 is the 0.05 critical value.
        assert!((gamma_q(5.0, 18.307 / 2.0) - 0.05).abs() < 1e-3);
    }

    #[test]
    fn lsb_test_separates_smooth_and_embedded() {
        // A smooth gradient with uneven pairs, then the same with random LSBs.
        let mut s: Vec<u8> = (0..200_000u32).map(|i| ((i % 640) / 5) as u8 & 0xFE | ((i / 640) % 3 == 0) as u8).collect();
        let clean = lsb(&s).unwrap();
        assert!(!clean.detected, "{:?}", clean.prefix);
        let mut x = 0x1234_5678u32;
        for b in s.iter_mut().take(100_000) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (*b & 0xFE) | (x & 1) as u8;
        }
        let t = lsb(&s).unwrap();
        assert!(t.detected && (0.4..=0.5).contains(&t.embedded_share), "{:?}", t.prefix);
    }
}
