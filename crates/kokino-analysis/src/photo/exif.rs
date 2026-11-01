//! EXIF (TIFF) metadata: camera, software, dates, GPS and the embedded
//! thumbnail. Bounds-checked; a damaged directory only loses its own tags.

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Exif {
    pub make: String,
    pub model: String,
    pub software: String,
    pub serial: String,
    pub lens: String,
    pub artist: String,
    /// EXIF date strings as stored ("YYYY:MM:DD HH:MM:SS", local, no zone).
    pub datetime: String,
    pub original: String,
    pub digitized: String,
    pub offset_time: String,
    pub orientation: u16,
    pub width: u32,
    pub height: u32,
    pub gps: Option<Gps>,
    /// Thumbnail location relative to the TIFF data.
    #[serde(skip)]
    pub thumb: Option<(usize, usize)>,
    pub thumb_len: usize,
    pub tags: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Gps {
    pub lat: f64,
    pub lon: f64,
    pub alt: Option<f64>,
    pub time: String,
}

struct Tiff<'a> {
    d: &'a [u8],
    le: bool,
}

impl<'a> Tiff<'a> {
    fn u16(&self, o: usize) -> Option<u32> {
        let b = self.d.get(o..o + 2)?;
        Some(if self.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) } as u32)
    }

    fn u32(&self, o: usize) -> Option<u32> {
        let b = self.d.get(o..o + 4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Some(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }

    /// (tag, type, count, value offset or inline position) of each entry.
    fn ifd(&self, off: usize) -> Vec<(u32, u32, u32, usize)> {
        let Some(n) = self.u16(off) else { return vec![] };
        (0..n.min(512) as usize)
            .filter_map(|k| {
                let e = off + 2 + 12 * k;
                let (tag, typ, count) = (self.u16(e)?, self.u16(e + 2)?, self.u32(e + 4)?);
                let size = match typ {
                    1 | 2 | 6 | 7 => 1,
                    3 | 8 => 2,
                    4 | 9 | 11 => 4,
                    5 | 10 | 12 => 8,
                    _ => return None,
                } * count as usize;
                let at = if size <= 4 { e + 8 } else { self.u32(e + 8)? as usize };
                (at.checked_add(size)? <= self.d.len()).then_some((tag, typ, count, at))
            })
            .collect()
    }

    fn next(&self, off: usize) -> Option<usize> {
        let n = self.u16(off)? as usize;
        self.u32(off + 2 + 12 * n).map(|v| v as usize).filter(|&v| v != 0 && v < self.d.len())
    }

    fn text(&self, at: usize, count: u32) -> String {
        let b = &self.d[at..at + count as usize];
        String::from_utf8_lossy(b).trim_end_matches('\0').trim().chars().filter(|c| !c.is_control()).take(200).collect()
    }

    fn int(&self, typ: u32, at: usize) -> Option<u32> {
        match typ {
            3 => self.u16(at),
            4 => self.u32(at),
            1 => self.d.get(at).map(|&b| b as u32),
            _ => None,
        }
    }

    fn rational(&self, at: usize) -> Option<f64> {
        let (n, d) = (self.u32(at)?, self.u32(at + 4)?);
        (d != 0).then(|| n as f64 / d as f64)
    }
}

/// Parses TIFF-structured EXIF data (the APP1 payload after "Exif\0\0").
pub fn parse(d: &[u8]) -> Option<Exif> {
    let le = match d.get(..4)? {
        b"II*\0" => true,
        b"MM\0*" => false,
        _ => return None,
    };
    let t = Tiff { d, le };
    let ifd0 = t.u32(4)? as usize;
    let mut x = Exif::default();
    let mut sub = vec![];
    for (tag, typ, count, at) in t.ifd(ifd0) {
        x.tags += 1;
        match tag {
            0x010F => x.make = t.text(at, count),
            0x0110 => x.model = t.text(at, count),
            0x0131 => x.software = t.text(at, count),
            0x0132 => x.datetime = t.text(at, count),
            0x013B => x.artist = t.text(at, count),
            0x0112 => x.orientation = t.int(typ, at).unwrap_or(0) as u16,
            0x8769 | 0x8825 => sub.push((tag, t.u32(at).unwrap_or(0) as usize)),
            _ => {}
        }
    }
    for (kind, off) in sub {
        if off == 0 || off >= d.len() {
            continue;
        }
        let entries = t.ifd(off);
        if kind == 0x8769 {
            for (tag, typ, count, at) in entries {
                x.tags += 1;
                match tag {
                    0x9003 => x.original = t.text(at, count),
                    0x9004 => x.digitized = t.text(at, count),
                    0x9011 => x.offset_time = t.text(at, count),
                    0xA002 => x.width = t.int(typ, at).unwrap_or(0),
                    0xA003 => x.height = t.int(typ, at).unwrap_or(0),
                    0xA431 => x.serial = t.text(at, count),
                    0xA434 => x.lens = t.text(at, count),
                    _ => {}
                }
            }
        } else {
            let (mut lat, mut lon, mut alt, mut lat_ref, mut lon_ref, mut alt_ref, mut time, mut date) = (None, None, None, 'N', 'E', 0u8, String::new(), String::new());
            let dms = |at: usize| Some(t.rational(at)? + t.rational(at + 8)? / 60.0 + t.rational(at + 16)? / 3600.0);
            for (tag, typ, count, at) in entries {
                x.tags += 1;
                match (tag, typ) {
                    (1, 2) => lat_ref = d[at] as char,
                    (2, 5) if count >= 3 => lat = dms(at),
                    (3, 2) => lon_ref = d[at] as char,
                    (4, 5) if count >= 3 => lon = dms(at),
                    (5, 1) => alt_ref = d[at],
                    (6, 5) => alt = t.rational(at),
                    (7, 5) if count >= 3 => {
                        if let (Some(h), Some(m), Some(s)) = (t.rational(at), t.rational(at + 8), t.rational(at + 16)) {
                            time = format!("{:02}:{:02}:{:02}", h as u32, m as u32, s as u32);
                        }
                    }
                    (0x1D, 2) => date = t.text(at, count),
                    _ => {}
                }
            }
            if let (Some(a), Some(b)) = (lat, lon) {
                let (a, b) = (if lat_ref == 'S' { -a } else { a }, if lon_ref == 'W' { -b } else { b });
                // 0,0 is what an unset receiver writes; not a location.
                if (a != 0.0 || b != 0.0) && a.abs() <= 90.0 && b.abs() <= 180.0 {
                    x.gps = Some(Gps { lat: a, lon: b, alt: alt.map(|v| if alt_ref == 1 { -v } else { v }), time: format!("{} {}", date, time).trim().to_string() });
                }
            }
        }
    }
    // IFD1: the thumbnail.
    if let Some(ifd1) = t.next(ifd0) {
        let (mut off, mut len) = (None, None);
        for (tag, typ, _, at) in t.ifd(ifd1) {
            match tag {
                0x0201 => off = t.int(typ, at),
                0x0202 => len = t.int(typ, at),
                _ => {}
            }
        }
        if let (Some(o), Some(l)) = (off, len) {
            let (o, l) = (o as usize, l as usize);
            if l > 0 && o.checked_add(l).map(|e| e <= d.len()).unwrap_or(false) {
                x.thumb = Some((o, l));
                x.thumb_len = l;
            }
        }
    }
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Little-endian TIFF with Make, a GPS IFD and a thumbnail pointer.
    #[test]
    fn reads_make_gps_and_thumbnail() {
        let mut d = b"II*\0\x08\0\0\0".to_vec();
        // IFD0 at 8: 2 entries (Make, GPS pointer), next IFD at 38.
        let ifd = |entries: &[(u16, u16, u32, u32)], next: u32| {
            let mut v = (entries.len() as u16).to_le_bytes().to_vec();
            for e in entries {
                v.extend(e.0.to_le_bytes());
                v.extend(e.1.to_le_bytes());
                v.extend(e.2.to_le_bytes());
                v.extend(e.3.to_le_bytes());
            }
            v.extend(next.to_le_bytes());
            v
        };
        d.extend(ifd(&[(0x010F, 2, 4, u32::from_le_bytes(*b"Lab\0")), (0x8825, 4, 1, 68)], 38));
        // IFD1 at 38: thumbnail at 120, 4 bytes.
        d.extend(ifd(&[(0x0201, 4, 1, 120), (0x0202, 4, 1, 4)], 0));
        assert_eq!(d.len(), 68);
        // GPS IFD at 68: N, 41 deg 59' 24", E, 21 deg 25' 48".
        d.extend(ifd(&[(1, 2, 2, u32::from_le_bytes(*b"N\0\0\0")), (2, 5, 3, 200), (3, 2, 2, u32::from_le_bytes(*b"E\0\0\0")), (4, 5, 3, 224)], 0));
        d.resize(200, 0);
        for v in [41u32, 1, 59, 1, 24, 1, 21, 1, 25, 1, 48, 1] {
            d.extend(v.to_le_bytes());
        }
        d[120..124].copy_from_slice(b"\xFF\xD8\xFF\xD9");
        let x = parse(&d).unwrap();
        assert_eq!(x.make, "Lab");
        let g = x.gps.unwrap();
        assert!((g.lat - 41.99).abs() < 1e-9 && (g.lon - 21.43).abs() < 1e-9, "{:?}", g);
        assert_eq!(x.thumb, Some((120, 4)));
    }
}
