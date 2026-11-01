//! Looking at raw bytes: printable strings with their offsets, and a byte
//! map (in the spirit of binvis.io) that summarizes each slice of a file or
//! disk by entropy and byte classes, for drawing as a picture.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Str {
    /// Offset of the first byte, relative to the data's `base`.
    pub offset: u64,
    /// "ascii", "utf8" or "utf16le"
    pub enc: &'static str,
    pub text: String,
}

/// Longest text kept per string (longer runs are cut, with their full length lost).
const MAX_CHARS: usize = 1000;

fn printable(c: char) -> bool {
    c == '\t' || (!c.is_control() && c != '\u{fffd}' && !('\u{fff0}'..='\u{ffff}').contains(&c))
}

/// Characters accepted in UTF-16 strings: printable ASCII, Latin-1 and
/// Latin Extended, Greek, Cyrillic, Hebrew and Arabic. CJK is left out:
/// pairs of ASCII bytes would otherwise read as CJK text everywhere.
fn utf16_char(c: char) -> bool {
    matches!(c as u32, 0x20..=0x7e | 0x09 | 0xa0..=0x24f | 0x370..=0x52f | 0x590..=0x6ff) && printable(c)
}

/// Text-like, not binary that happens to decode: an ASCII run passes; one
/// with other characters must be at least 90% letters, digits and spaces,
/// with every non-ASCII letter from one 256-character block (one script),
/// as real Cyrillic, Greek or accented Latin text is, and not one or two
/// characters repeated (binary tables decode to runs like that).
fn plausible(s: &str) -> bool {
    if s.is_ascii() {
        return true;
    }
    let (mut n, mut good, mut block) = (0usize, 0usize, None);
    for c in s.chars() {
        n += 1;
        if c.is_alphanumeric() || c == ' ' {
            good += 1;
        }
        if !c.is_ascii() {
            if !c.is_alphabetic() {
                return false;
            }
            let b = c as u32 >> 8;
            if *block.get_or_insert(b) != b {
                return false;
            }
        }
    }
    let mut distinct: Vec<char> = s.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    good * 10 >= n * 9 && distinct.len() * 2 >= n.min(12)
}

/// Runs of at least `min` printable characters: UTF-8 (ASCII included) and
/// UTF-16LE at both byte alignments (scripts in `utf16_char`), ordered by
/// offset.
pub fn strings(d: &[u8], base: u64, min: usize) -> Vec<Str> {
    let min = min.max(2);
    let mut out = vec![];
    // UTF-8 / ASCII.
    let mut i = 0;
    let (mut start, mut text, mut n, mut ascii) = (0usize, String::new(), 0usize, true);
    let flush = |start: usize, text: &mut String, n: &mut usize, ascii: &mut bool, out: &mut Vec<Str>| {
        if *n >= min && plausible(text) {
            out.push(Str { offset: base + start as u64, enc: if *ascii { "ascii" } else { "utf8" }, text: std::mem::take(text) });
        }
        text.clear();
        *n = 0;
        *ascii = true;
    };
    while i < d.len() {
        let b = d[i];
        let w = match b {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let ch = if w > 0 && i + w <= d.len() { std::str::from_utf8(&d[i..i + w]).ok().and_then(|s| s.chars().next()) } else { None };
        match ch.filter(|&c| printable(c)) {
            Some(c) => {
                if n == 0 {
                    start = i;
                }
                if n < MAX_CHARS {
                    text.push(c);
                }
                n += 1;
                ascii &= w == 1;
                i += w;
            }
            None => {
                flush(start, &mut text, &mut n, &mut ascii, &mut out);
                i += 1;
            }
        }
    }
    flush(start, &mut text, &mut n, &mut ascii, &mut out);
    // UTF-16LE at even and odd offsets.
    for align in 0..2 {
        let (mut start, mut text, mut n) = (0usize, String::new(), 0usize);
        let mut j = align;
        let emit = |start: usize, text: &mut String, n: &mut usize, out: &mut Vec<Str>| {
            if *n >= min && plausible(text) {
                out.push(Str { offset: base + start as u64, enc: "utf16le", text: std::mem::take(text) });
            }
            text.clear();
            *n = 0;
        };
        while j + 1 < d.len() {
            let u = u16::from_le_bytes([d[j], d[j + 1]]);
            let ok = char::from_u32(u as u32).filter(|&c| utf16_char(c));
            match ok {
                Some(c) => {
                    if n == 0 {
                        start = j;
                    }
                    if n < MAX_CHARS {
                        text.push(c);
                    }
                    n += 1;
                }
                None => emit(start, &mut text, &mut n, &mut out),
            }
            j += 2;
        }
        emit(start, &mut text, &mut n, &mut out);
    }
    out.sort_by_key(|s| s.offset);
    out
}

/// One slice of the byte map: entropy and the share of 0x00 bytes, 0xFF
/// bytes (erased flash, some wipes), text (printable ASCII and whitespace),
/// other low (control) bytes and other high bytes (0x80 to 0xFE), each
/// scaled to 0..255.
pub fn cell(d: &[u8]) -> [u8; 6] {
    if d.is_empty() {
        return [0; 6];
    }
    let mut hist = [0u32; 256];
    for &b in d {
        hist[b as usize] += 1;
    }
    let n = d.len() as f64;
    let ent: f64 = hist.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum();
    let share = |r: std::ops::RangeInclusive<usize>, extra: &[usize]| (r.map(|i| hist[i]).sum::<u32>() + extra.iter().map(|&i| hist[i]).sum::<u32>()) as f64 / n;
    let zero = hist[0] as f64 / n;
    let text = share(0x20..=0x7e, &[9, 10, 13]);
    let ff = hist[255] as f64 / n;
    let high = share(0x80..=0xfe, &[]);
    let low = (1.0 - zero - ff - text - high).max(0.0);
    let s = |v: f64| (v * 255.0).round().clamp(0.0, 255.0) as u8;
    [s(ent / 8.0), s(zero), s(ff), s(text), s(low), s(high)]
}

/// Cells for a byte map of `size` bytes: a power of 4 (so a Hilbert curve
/// fills a square), at most `want`, never more than there are bytes.
pub fn cell_count(size: u64, want: usize) -> usize {
    let want = want.clamp(16, 65536);
    let mut c = 16usize;
    while c * 4 <= want && (c * 4) as u64 <= size.max(16) {
        c *= 4;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_utf8_and_utf16() {
        let mut d = b"\x00\x01Hello world\x00\xff".to_vec();
        d.extend("\u{41a}\u{43e}\u{43a}\u{438}\u{43d}\u{43e} FTK".as_bytes()); // Kokino FTK in Cyrillic
        d.push(0);
        let utf16: Vec<u8> = "Password1".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d.push(0x99); // odd alignment
        d.extend(&utf16);
        d.extend([0, 0, 7, 3]);
        let s = strings(&d, 1000, 4);
        let found: Vec<(&str, &str, u64)> = s.iter().map(|x| (x.enc, x.text.as_str(), x.offset)).collect();
        assert!(found.contains(&("ascii", "Hello world", 1002)), "{:?}", found);
        assert!(found.iter().any(|f| f.0 == "utf8" && f.1 == "\u{41a}\u{43e}\u{43a}\u{438}\u{43d}\u{43e} FTK"), "{:?}", found);
        assert!(found.iter().any(|f| f.0 == "utf16le" && f.1 == "Password1"), "{:?}", found);
        assert!(strings(b"abc\x00de", 0, 4).is_empty());
        // Binary that decodes to accented and mixed-script letters is dropped.
        assert!(!plausible("\u{db}C\u{103}\u{201}\u{102}\u{203}"));
        assert!(!plausible("\u{200}\u{201}\u{404}\u{403}\u{507}"));
        assert!(plausible("Caf\u{e9} cr\u{e8}me"));
        assert!(!plausible("\u{103}\u{101}\u{101}\u{101}\u{101}"));
        assert!(!plausible("\u{3ff}oS_E"));
        // Random high bytes do not turn into long UTF-16 runs.
        let noise: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert!(strings(&noise, 0, 8).iter().all(|x| x.enc != "utf16le"));
    }

    #[test]
    fn cells_classify_bytes() {
        assert_eq!(cell(&[0u8; 512]), [0, 255, 0, 0, 0, 0]);
        assert_eq!(cell(&[0xffu8; 512]), [0, 0, 255, 0, 0, 0]);
        let t = cell(b"plain text plain text plain text");
        assert_eq!(t[3], 255);
        assert!(t[0] < 128);
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let r = cell(&all);
        assert_eq!(r[0], 255);
        assert_eq!(r[5], 127);
        assert_eq!(cell_count(720, 4096), 256);
        assert_eq!(cell_count(10, 4096), 16);
        assert_eq!(cell_count(1 << 30, 4096), 4096);
        assert_eq!(cell_count(1 << 30, 5000), 4096);
    }
}
