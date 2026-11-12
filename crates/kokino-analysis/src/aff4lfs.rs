//! AFF4-L logical images as a file system: the files and folders the
//! container lists, with their original names, times (UTC) and recorded
//! hashes; content from ZIP members or AFF4 image streams. The reading
//! itself is in `kokino_image::aff4`.

use kokino_image::aff4::{Aff4Logical, Cache};
use kokino_ntfs::{Extent, FsEntry, NtfsVolumeInfo, Stream, Times};
use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};

const FIRST_RECORD: u64 = 64;

pub struct Aff4LVolume {
    img: Aff4Logical,
    /// Record number to file index.
    files: HashMap<u64, usize>,
    listing: Vec<FsEntry>,
    pub notes: Vec<String>,
    size: u64,
    state: Mutex<(Cache, Option<(usize, Arc<Vec<u8>>)>)>,
}

pub fn open<R: Read + Seek>(r: &mut R, len: u64) -> anyhow::Result<Aff4LVolume> {
    let img = kokino_image::aff4::open_logical(r, len)?;
    let mk = |record: u64, parent: u64, name: &str, path: &str, is_dir: bool, size: u64, times: Option<Times>| FsEntry {
        record,
        seq: 1,
        parent,
        parent_seq: 1,
        name: name.to_string(),
        dos_name: None,
        path: path.to_string(),
        is_dir,
        deleted: false,
        orphan: false,
        size,
        alloc_size: size,
        resident: false,
        attributes: if is_dir { 0x10 } else { 0 },
        hard_links: 1,
        usn: None,
        si: times,
        fname: None,
        streams: if is_dir { vec![] } else { vec![Stream { name: String::new(), size, resident: false, first_offset: None }] },
        has_reparse: false,
        record_offset: 0,
        error: None,
        unix: None,
        name_only: None,
    };
    let mut listing = vec![mk(kokino_ntfs::ROOT_RECORD, kokino_ntfs::ROOT_RECORD, "", "/", true, 0, None)];
    let mut dirs: HashMap<String, u64> = HashMap::from([(String::new(), kokino_ntfs::ROOT_RECORD)]);
    let mut files = HashMap::new();
    let mut next = FIRST_RECORD;
    // Folders first, so their times stay with them.
    let mut order: Vec<usize> = (0..img.files.len()).collect();
    order.sort_by_key(|&i| (!img.files[i].is_dir, img.files[i].path.matches('/').count()));
    for i in order {
        let f = &img.files[i];
        let times = Times { created: f.created, modified: f.modified, accessed: f.accessed, mft_modified: f.changed };
        let t = (f.created | f.modified | f.accessed) != 0;
        let parts: Vec<&str> = f.path.split('/').filter(|s| !s.is_empty()).collect();
        let mut parent = kokino_ntfs::ROOT_RECORD;
        let mut path = String::new();
        for (k, part) in parts.iter().enumerate() {
            let last = k + 1 == parts.len();
            let p = format!("{}/{}", path, part);
            if last && !f.is_dir {
                path = p;
                break;
            }
            parent = match dirs.get(&p) {
                Some(&rec) => rec,
                None => {
                    let rec = next;
                    next += 1;
                    listing.push(mk(rec, parent, part, &p, true, 0, (last && t).then_some(times)));
                    dirs.insert(p.clone(), rec);
                    rec
                }
            };
            path = p;
        }
        if f.is_dir || parts.is_empty() {
            continue;
        }
        let rec = next;
        next += 1;
        listing.push(mk(rec, parent, parts[parts.len() - 1], &path, false, f.size, t.then_some(times)));
        files.insert(rec, i);
    }
    let notes = img.notes.clone();
    Ok(Aff4LVolume { img, files, listing, notes, size: len, state: Mutex::new((Cache::default(), None)) })
}

impl Aff4LVolume {
    pub fn info(&self) -> NtfsVolumeInfo {
        NtfsVolumeInfo {
            label: String::new(),
            serial: String::new(),
            version: "AFF4-L (logical image)".into(),
            cluster_size: 0,
            sector_size: 0,
            record_size: 0,
            volume_size: self.size,
            mft_records: self.listing.len() as u64,
            mft_offset: 0,
            dirty: false,
        }
    }

    pub fn entries(&self) -> Vec<FsEntry> {
        self.listing.clone()
    }

    /// Hashes the container recorded for a file: (algorithm, hex).
    pub fn recorded(&self, record: u64) -> Vec<(String, String)> {
        self.files.get(&record).map(|&i| self.img.files[i].hashes.clone()).unwrap_or_default()
    }

    pub fn read<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let &i = self.files.get(&fe.record).ok_or_else(|| anyhow::anyhow!("not a file"))?;
        let mut st = self.state.lock().unwrap();
        let (cache, whole) = &mut *st;
        self.img.read(r, i, offset, len, cache, whole)
    }

    pub fn extents<R: Read + Seek>(&self, r: &mut R, fe: &FsEntry) -> Vec<Extent> {
        match self.files.get(&fe.record).and_then(|&i| self.img.extent(r, i)) {
            Some((at, n)) if n > 0 => vec![Extent { offset: 0, len: n, vol: Some(at) }],
            _ => vec![],
        }
    }
}
