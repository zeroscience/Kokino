//! OLE Compound File Binary ([MS-CFB]) reader: the container behind
//! automatic Jump Lists, legacy Office documents (DOC, XLS, PPT), MSI files
//! and Outlook MSG. Gives every stream by name.

use crate::bin::*;

pub struct Stream {
    /// Path from the root, '/'-separated.
    pub name: String,
    pub data: Vec<u8>,
    pub modified: u64,
}

const FREE: u32 = 0xFFFF_FFFF;
const END: u32 = 0xFFFF_FFFE;

pub fn is_cfb(d: &[u8]) -> bool {
    d.get(0..8) == Some(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// All streams, each at most `max_stream` bytes.
pub fn streams(d: &[u8], max_stream: usize) -> anyhow::Result<Vec<Stream>> {
    if !is_cfb(d) {
        anyhow::bail!("not an OLE compound file");
    }
    let shift = u16_at(d, 30).unwrap_or(9);
    if !(9..=16).contains(&shift) {
        anyhow::bail!("bad sector size");
    }
    let ss = 1usize << shift;
    let mss = 1usize << u16_at(d, 32).unwrap_or(6).min(12);
    let sector = |n: u32| -> Option<&[u8]> { slice(d, (n as usize + 1).checked_mul(ss)?, ss) };

    // FAT sector list: 109 in the header, the rest in DIFAT sectors.
    let mut fat_sectors: Vec<u32> = (0..109).filter_map(|i| u32_at(d, 76 + 4 * i)).filter(|&s| s != FREE).collect();
    let mut difat = u32_at(d, 68).unwrap_or(END);
    // A file cannot have more FAT sectors than sectors: more means the
    // DIFAT repeats itself.
    let sectors = d.len() / ss;
    let mut guard = 0;
    while difat != END && difat != FREE && guard < 10_000 && fat_sectors.len() <= sectors {
        let Some(s) = sector(difat) else { break };
        let per = ss / 4 - 1;
        fat_sectors.extend((0..per).filter_map(|i| u32_at(s, 4 * i)).filter(|&x| x != FREE));
        difat = u32_at(s, 4 * per).unwrap_or(END);
        guard += 1;
    }
    fat_sectors.truncate(sectors);
    let fat: Vec<u32> = fat_sectors.iter().filter_map(|&s| sector(s)).flat_map(|s| s.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap()))).collect();
    let chain = |start: u32, max: usize| -> Vec<u8> {
        let mut out = vec![];
        let mut s = start;
        // Each sector once: a chain that loops back would repeat forever.
        let mut seen = vec![false; fat.len()];
        while s != END && s != FREE && (s as usize) < fat.len() && out.len() < max && !seen[s as usize] {
            seen[s as usize] = true;
            match sector(s) {
                Some(b) => out.extend_from_slice(b),
                None => break,
            }
            s = fat[s as usize];
        }
        out.truncate(max);
        out
    };

    let dir = chain(u32_at(d, 48).unwrap_or(END), 64 << 20);
    let entries: Vec<&[u8]> = dir.chunks_exact(128).collect();
    let root = entries.first().ok_or_else(|| anyhow::anyhow!("no directory"))?;
    let mini_stream = chain(u32_at(root, 116).unwrap_or(END), u64_at(root, 120).unwrap_or(0) as usize);
    let minifat_bytes = chain(u32_at(d, 60).unwrap_or(END), 64 << 20);
    let minifat: Vec<u32> = minifat_bytes.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    // Always 4096 in the specification; a larger value would send big streams
    // through the mini stream.
    let cutoff = (u32_at(d, 56).unwrap_or(4096) as u64).min(4096);

    // Walk the red-black tree from the root's child to build full names.
    let mut out = vec![];
    let mut stack: Vec<(u32, String)> = vec![(u32_at(root, 76).unwrap_or(FREE), String::new())];
    let mut seen = std::collections::HashSet::new();
    // Many entries can name the same sectors; bound what is copied in all.
    let mut total = 0usize;
    while let Some((id, prefix)) = stack.pop() {
        if total > 256 << 20 {
            break;
        }
        if id == FREE || !seen.insert(id) {
            continue;
        }
        let Some(e) = entries.get(id as usize) else { continue };
        let nlen = (u16_at(e, 64).unwrap_or(0) as usize).min(64);
        let name = utf16(&e[..nlen]);
        stack.push((u32_at(e, 68).unwrap_or(FREE), prefix.clone()));
        stack.push((u32_at(e, 72).unwrap_or(FREE), prefix.clone()));
        let full = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
        match e[66] {
            1 => stack.push((u32_at(e, 76).unwrap_or(FREE), full)),
            2 => {
                let size = (u64_at(e, 120).unwrap_or(0) & 0xFFFF_FFFF) as usize;
                let start = u32_at(e, 116).unwrap_or(END);
                let data = if (size as u64) < cutoff {
                    let mut v = vec![];
                    let mut s = start;
                    let mut seen_mini = std::collections::HashSet::new();
                    while s != END && s != FREE && v.len() < size && seen_mini.insert(s) {
                        match slice(&mini_stream, s as usize * mss, mss) {
                            Some(b) => v.extend_from_slice(b),
                            None => break,
                        }
                        s = minifat.get(s as usize).copied().unwrap_or(END);
                    }
                    v.truncate(size);
                    v
                } else {
                    chain(start, size.min(max_stream))
                };
                total += data.len();
                out.push(Stream { name: full, data, modified: plausible(u64_at(e, 108).unwrap_or(0)) });
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Writes a version 3 compound file (512-byte sectors) with flat streams.
    /// Small streams go to the mini stream, like real writers do.
    pub fn write(streams: &[(&str, &[u8])]) -> Vec<u8> {
        let ss = 512;
        let mut sectors: Vec<Vec<u8>> = vec![];
        let mut fat: Vec<u32> = vec![];
        let alloc = |data: &[u8], sectors: &mut Vec<Vec<u8>>, fat: &mut Vec<u32>| -> u32 {
            if data.is_empty() {
                return END;
            }
            let start = sectors.len() as u32;
            let n = (data.len() + ss - 1) / ss;
            for i in 0..n {
                let mut s = data[i * ss..((i + 1) * ss).min(data.len())].to_vec();
                s.resize(ss, 0);
                sectors.push(s);
                fat.push(if i + 1 == n { END } else { start + i as u32 + 1 });
            }
            start
        };
        let mut mini = vec![];
        let mut minifat: Vec<u32> = vec![];
        let mut dir_entries: Vec<(String, u8, u32, u64)> = vec![("Root Entry".into(), 5, END, 0)];
        let mut big: Vec<(usize, Vec<u8>)> = vec![];
        for (name, data) in streams {
            if data.len() < 4096 {
                let start = (mini.len() / 64) as u32;
                let n = (data.len() + 63) / 64;
                for i in 0..n {
                    minifat.push(if i + 1 == n { END } else { start + i as u32 + 1 });
                }
                mini.extend_from_slice(data);
                mini.resize(mini.len() + (64 - data.len() % 64) % 64, 0);
                dir_entries.push((name.to_string(), 2, if n == 0 { END } else { start }, data.len() as u64));
            } else {
                big.push((dir_entries.len(), data.to_vec()));
                dir_entries.push((name.to_string(), 2, 0, data.len() as u64));
            }
        }
        for (i, data) in big {
            dir_entries[i].2 = alloc(&data, &mut sectors, &mut fat);
        }
        let ms = alloc(&mini, &mut sectors, &mut fat);
        dir_entries[0].2 = ms;
        dir_entries[0].3 = mini.len() as u64;
        let mf: Vec<u8> = minifat.iter().flat_map(|v| v.to_le_bytes()).collect();
        let mf_start = alloc(&mf, &mut sectors, &mut fat);
        // Directory: root's child is entry 1; streams chained via right sibling.
        let mut dir = vec![];
        for (i, (name, ty, start, size)) in dir_entries.iter().enumerate() {
            let mut e = vec![0u8; 128];
            let w: Vec<u8> = name.encode_utf16().chain([0]).flat_map(|u| u.to_le_bytes()).collect();
            e[..w.len()].copy_from_slice(&w);
            e[64..66].copy_from_slice(&(w.len() as u16).to_le_bytes());
            e[66] = *ty;
            e[67] = 1;
            e[68..72].copy_from_slice(&FREE.to_le_bytes());
            let right = if i > 0 && i + 1 < dir_entries.len() { (i + 1) as u32 } else { FREE };
            e[72..76].copy_from_slice(&right.to_le_bytes());
            let child = if i == 0 && dir_entries.len() > 1 { 1 } else { FREE };
            e[76..80].copy_from_slice(&child.to_le_bytes());
            e[116..120].copy_from_slice(&start.to_le_bytes());
            e[120..128].copy_from_slice(&size.to_le_bytes());
            dir.extend_from_slice(&e);
        }
        let dir_start = alloc(&dir, &mut sectors, &mut fat);
        // FAT sectors themselves (one is enough for tests up to 127 sectors).
        let fat_sector = sectors.len() as u32;
        fat.push(0xFFFF_FFFD);
        assert!(fat.len() <= 128);
        let mut fs: Vec<u8> = fat.iter().flat_map(|v| v.to_le_bytes()).collect();
        fs.resize(ss, 0xFF);
        sectors.push(fs);
        let mut h = vec![0u8; 512];
        h[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        h[24..26].copy_from_slice(&0x3Eu16.to_le_bytes());
        h[26..28].copy_from_slice(&3u16.to_le_bytes());
        h[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        h[30..32].copy_from_slice(&9u16.to_le_bytes());
        h[32..34].copy_from_slice(&6u16.to_le_bytes());
        h[44..48].copy_from_slice(&1u32.to_le_bytes());
        h[48..52].copy_from_slice(&dir_start.to_le_bytes());
        h[56..60].copy_from_slice(&4096u32.to_le_bytes());
        h[60..64].copy_from_slice(&mf_start.to_le_bytes());
        h[64..68].copy_from_slice(&(((mf.len() + 511) / 512) as u32).to_le_bytes());
        h[68..72].copy_from_slice(&END.to_le_bytes());
        for i in 0..109 {
            h[76 + 4 * i..80 + 4 * i].copy_from_slice(&FREE.to_le_bytes());
        }
        h[76..80].copy_from_slice(&fat_sector.to_le_bytes());
        let mut out = h;
        for s in sectors {
            out.extend_from_slice(&s);
        }
        out
    }

    #[test]
    fn mini_and_regular_streams() {
        let big: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let f = write(&[("1", b"small stream"), ("DestList", &big), ("a", b"")]);
        let s = streams(&f, usize::MAX).unwrap();
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["1", "DestList", "a"]);
        assert_eq!(s[0].data, b"small stream");
        assert_eq!(s[1].data, big);
        assert!(s[2].data.is_empty());
        assert!(streams(b"not ole", 10).is_err());
        for n in [512, 700, 1500] {
            let _ = streams(&f[..n.min(f.len())], 1 << 20);
        }
    }
}
