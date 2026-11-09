//! macOS FSEvents (`/.fseventsd/<event id>`): the file system's change log,
//! one gzip file per batch. Each file holds pages ("1SLD", "2SLD" from High
//! Sierra, "3SLD" from Sonoma); a page holds records: the path (NUL
//! terminated), the event id, the flags and, from version 2, the file's
//! node id (version 3 adds the user id).
//!
//! Records carry no time. The file they are in was written when its batch
//! was flushed, so its modification time is the latest a record can be.
//! Flag names follow FSEventsParser (David Cowen, Apache-2.0).

use std::io::Read;

const MAX_GZ: u64 = 256 << 20;
const MAX_RECORDS: usize = 2_000_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub path: String,
    pub id: u64,
    pub flags: u32,
    pub node: Option<u64>,
}

const FLAGS: &[(u32, &str)] = &[
    (0x0100_0000, "Created"),
    (0x0200_0000, "Removed"),
    (0x0800_0000, "Renamed"),
    (0x1000_0000, "Modified"),
    (0x0400_0000, "InodeMetaMod"),
    (0x8000_0000, "FolderCreated"),
    (0x0001_0000, "PermissionChange"),
    (0x0002_0000, "ExtendedAttrModified"),
    (0x0004_0000, "ExtendedAttrRemoved"),
    (0x4000_0000, "FinderInfoMod"),
    (0x2000_0000, "Exchange"),
    (0x0040_0000, "ItemCloned"),
    (0x0010_0000, "DocumentRevisioning"),
    (0x0000_1000, "HardLink"),
    (0x0000_0800, "LastHardLinkRemoved"),
    (0x0000_4000, "SymbolicLink"),
    (0x0000_0002, "Mount"),
    (0x0000_0004, "Unmount"),
    (0x0000_0020, "EndOfTransaction"),
];

impl Record {
    /// "Created, Modified" (what happened), without the kind flags.
    pub fn changes(&self) -> String {
        FLAGS.iter().filter(|(b, _)| self.flags & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
    }
    pub fn is_dir(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// Every record in one FSEvents file (gzip, or already inflated).
pub fn parse(d: &[u8]) -> anyhow::Result<Vec<Record>> {
    let data = if d.starts_with(&[0x1F, 0x8B]) {
        let mut out = vec![];
        flate2::read::MultiGzDecoder::new(d).take(MAX_GZ).read_to_end(&mut out)?;
        out
    } else {
        d.to_vec()
    };
    let mut out = vec![];
    let mut p = 0usize;
    while p + 12 <= data.len() && out.len() < MAX_RECORDS {
        let magic = &data[p..p + 4];
        let tail = match magic {
            b"1SLD" => 12,
            b"2SLD" => 20,
            b"3SLD" => 24,
            _ => {
                if out.is_empty() {
                    anyhow::bail!("not an FSEvents file");
                }
                break;
            }
        };
        let len = u32::from_le_bytes(data[p + 8..p + 12].try_into().unwrap()) as usize;
        if len < 12 {
            break;
        }
        let end = p.saturating_add(len).min(data.len());
        let mut q = p + 12;
        while q < end && out.len() < MAX_RECORDS {
            let Some(nul) = data[q..end].iter().position(|&c| c == 0) else { break };
            let path = String::from_utf8_lossy(&data[q..q + nul]).replace('\t', "");
            let b = q + nul + 1;
            let Some(rec) = data.get(b..b + tail) else { break };
            if b + tail > end {
                break;
            }
            out.push(Record {
                path,
                id: u64::from_le_bytes(rec[0..8].try_into().unwrap()),
                flags: u32::from_be_bytes(rec[8..12].try_into().unwrap()),
                node: (tail >= 20).then(|| u64::from_le_bytes(rec[12..20].try_into().unwrap())),
            });
            q = b + tail;
        }
        p = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn page(version: u8, recs: &[(&str, u64, u32, u64)]) -> Vec<u8> {
        let mut body = vec![];
        for (path, id, flags, node) in recs {
            body.extend(path.as_bytes());
            body.push(0);
            body.extend(id.to_le_bytes());
            body.extend(flags.to_be_bytes());
            if version >= 2 {
                body.extend(node.to_le_bytes());
            }
            if version >= 3 {
                body.extend(501u32.to_le_bytes());
            }
        }
        let mut p = format!("{}SLD", version).into_bytes();
        p.extend(0u32.to_le_bytes());
        p.extend(((body.len() + 12) as u32).to_le_bytes());
        p.extend(body);
        p
    }

    #[test]
    fn pages_of_every_version() {
        let mut d = page(1, &[("Users/alice/notes.txt", 100, 0x0100_8000 | 0x1000_0000, 0)]);
        d.extend(page(2, &[("Users/alice/Documents", 101, 0x8000_0001, 77), ("Users/alice/plan.txt", 102, 0x0200_8000, 78)]));
        d.extend(page(3, &[("private/var/log/x", 103, 0x0800_8000, 79)]));
        let mut gz = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
        gz.write_all(&d).unwrap();
        let r = parse(&gz.finish().unwrap()).unwrap();
        assert_eq!(r.len(), 4);
        assert_eq!((r[0].path.as_str(), r[0].id, r[0].changes().as_str(), r[0].node), ("Users/alice/notes.txt", 100, "Created, Modified", None));
        assert!(r[1].is_dir() && r[1].changes() == "FolderCreated" && r[1].node == Some(77));
        assert_eq!(r[2].changes(), "Removed");
        assert_eq!((r[3].changes().as_str(), r[3].node), ("Renamed", Some(79)));
        assert!(parse(b"not fsevents at all").is_err());
        // A page cut short ends the file, it does not fail it.
        let cut = &d[..d.len() - 10];
        assert_eq!(parse(cut).unwrap().len(), 3);
    }
}
