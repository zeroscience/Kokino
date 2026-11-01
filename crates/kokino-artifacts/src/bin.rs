//! Bounds-checked little-endian readers and Windows value formats shared by
//! the artifact parsers. Every read returns None past the end, so a damaged
//! or hostile file can never panic a parser.

pub fn u8_at(d: &[u8], o: usize) -> Option<u8> {
    d.get(o).copied()
}
pub fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
pub fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn i32_at(d: &[u8], o: usize) -> Option<i32> {
    u32_at(d, o).map(|v| v as i32)
}
pub fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o.checked_add(8)?).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}
pub fn slice(d: &[u8], o: usize, n: usize) -> Option<&[u8]> {
    d.get(o..o.checked_add(n)?)
}

/// UTF-16LE text, cut at the first NUL.
pub fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&w)
}

/// NUL-terminated UTF-16LE string starting at `o`, at most `max` characters.
pub fn utf16z(d: &[u8], o: usize, max: usize) -> String {
    let mut w = vec![];
    let mut p = o;
    while w.len() < max {
        match u16_at(d, p) {
            Some(0) | None => break,
            Some(u) => w.push(u),
        }
        p += 2;
    }
    String::from_utf16_lossy(&w)
}

/// Single-byte text (Windows-1252 subset), cut at the first NUL.
pub fn ansi(b: &[u8]) -> String {
    b.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect()
}

/// NUL-terminated single-byte string starting at `o`.
pub fn ansiz(d: &[u8], o: usize, max: usize) -> String {
    d.get(o..).map(|b| ansi(&b[..b.len().min(max)])).unwrap_or_default()
}

/// {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} from the 16-byte mixed-endian form.
pub fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// For a version 1 (time-based) UUID, the node field: usually the MAC
/// address of the machine that made it.
pub fn uuid_v1_node(b: &[u8]) -> Option<String> {
    if b.len() < 16 || (b[7] >> 4) != 1 {
        return None;
    }
    Some(b[10..16].iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(":"))
}

/// Binary SID to S-1-5-21-... form.
pub fn sid(b: &[u8]) -> Option<String> {
    let rev = *b.first()?;
    let n = *b.get(1)? as usize;
    let auth = b.get(2..8)?.iter().fold(0u64, |a, &x| (a << 8) | x as u64);
    let mut s = format!("S-{}-{}", rev, auth);
    for i in 0..n {
        s.push_str(&format!("-{}", u32_at(b, 8 + 4 * i)?));
    }
    Some(s)
}

/// FILETIME of a SYSTEMTIME structure (16 bytes), as used by NetworkList.
pub fn systemtime(b: &[u8]) -> Option<u64> {
    let f = |i: usize| u16_at(b, 2 * i).map(|v| v as u32);
    let (y, mo, d, h, mi, s, ms) = (f(0)?, f(1)?, f(3)?, f(4)?, f(5)?, f(6)?, f(7)?);
    if !(1601..=30827).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    // days from 1601-01-01 (civil-from-days inverse)
    let (yy, mm) = if mo <= 2 { (y as i64 - 1, mo as i64 + 9) } else { (y as i64, mo as i64 - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_unix = era * 146_097 + doe - 719_468;
    let secs = days_unix * 86_400 + h as i64 * 3600 + mi as i64 * 60 + s as i64;
    unix_to_filetime(secs).map(|ft| ft + ms as u64 * 10_000)
}

pub const UNIX_EPOCH_FT: u64 = 116_444_736_000_000_000;

pub fn unix_to_filetime(secs: i64) -> Option<u64> {
    let v = secs.checked_mul(10_000_000)?.checked_add(UNIX_EPOCH_FT as i64)?;
    (v > 0).then_some(v as u64)
}

/// A FILETIME that is plausible as a real date (1980..2100), else 0.
pub fn plausible(ft: u64) -> u64 {
    if (119_600_064_000_000_000..157_766_400_000_000_000).contains(&ft) { ft } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let g = [0x26, 0x63, 0xda, 0x83, 0xa6, 0x97, 0x88, 0x40, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29];
        assert_eq!(guid(&g), "{83DA6326-97A6-4088-9453-A1923F573B29}");
        let s = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe9, 3, 0, 0];
        assert_eq!(sid(&s).unwrap(), "S-1-5-21-1-2-3-1001");
        // 2026-10-20 09:30:15.250 UTC
        let st: Vec<u8> = [2026u16, 10, 2, 20, 9, 30, 15, 250].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(systemtime(&st), Some(unix_to_filetime(1_792_488_615).unwrap() + 2_500_000));
        assert_eq!(utf16z(&[b'a', 0, b'b', 0, 0, 0, b'c', 0], 0, 10), "ab");
        assert_eq!(u32_at(&[1, 2, 3], 0), None);
        assert_eq!(u32_at(&[1, 2, 3], usize::MAX), None);
    }
}
