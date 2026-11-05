//! NTFS volume walker.
//!
//! Visits every MFT record (allocated and deleted), and for each one records
//! both $STANDARD_INFORMATION and $FILE_NAME timestamps, data streams (ADS),
//! sizes, flags and the byte offsets needed to jump to the raw record and the
//! first data cluster. Paths are rebuilt from $FILE_NAME parent references;
//! entries whose parent chain is broken or reused become orphans.

#![forbid(unsafe_code)]

use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace, NtfsStandardInformation};
pub use ntfs::Ntfs;
use ntfs::{NtfsAttribute, NtfsAttributeFlags, NtfsAttributeType, NtfsFile, NtfsFileFlags, NtfsReadSeek};

pub mod indx;
pub mod lznt1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

pub const ROOT_RECORD: u64 = 5;
pub const ORPHAN_ROOT: &str = "$OrphanFiles";

/// The four NTFS timestamps as raw FILETIMEs (0 = absent).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Times {
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub mft_modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    pub name: String,
    pub size: u64,
    pub resident: bool,
    /// Volume-relative byte offset of the first non-sparse data run.
    pub first_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    pub record: u64,
    pub seq: u16,
    pub parent: u64,
    pub parent_seq: u16,
    pub name: String,
    pub dos_name: Option<String>,
    pub path: String,
    pub is_dir: bool,
    pub deleted: bool,
    pub orphan: bool,
    pub size: u64,
    pub alloc_size: u64,
    pub resident: bool,
    pub attributes: u32,
    pub hard_links: u16,
    pub usn: Option<u64>,
    pub si: Option<Times>,
    pub fname: Option<Times>,
    /// Data streams; the unnamed stream has name "".
    pub streams: Vec<Stream>,
    pub has_reparse: bool,
    /// Volume-relative byte offset of the MFT record.
    pub record_offset: u64,
    pub error: Option<String>,
    /// Owner, mode and inode on Unix file systems (ext2/3/4); None elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix: Option<UnixMeta>,
    /// Set for NTFS names recovered from a folder index ($I30) or $LogFile
    /// rather than from an MFT record; such entries have no content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_only: Option<NameOnly>,
}

/// Where a name without an MFT record came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameOnly {
    /// The file's own MFT reference, when known.
    pub mft_record: Option<u64>,
    pub mft_seq: u16,
    /// "$I30 slack", "$I30 of a deleted folder" or "$LogFile".
    pub source: String,
}

/// Names without an MFT record get record numbers from here up (MFT
/// references are 48-bit), so they never collide with real records.
pub const NAME_ONLY_BASE: u64 = 1 << 48;

/// What a Unix inode adds to an entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnixMeta {
    pub inode: u64,
    /// st_mode: file type and permission bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Deletion time (FILETIME), 0 when not set.
    #[serde(default)]
    pub deleted_time: u64,
    /// Volume byte offset of the inode the content is read through: the
    /// inode table, or a copy of the inode kept in the file-system journal.
    pub inode_offset: u64,
    /// Journal transaction the inode copy came from, when recovered from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_seq: Option<u32>,
    /// Symbolic link target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
}

impl UnixMeta {
    /// "-rw-r--r--" style, as ls prints it.
    pub fn mode_string(&self) -> String {
        let t = match self.mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '-',
        };
        let mut s = String::from(t);
        for (i, c) in "rwxrwxrwx".chars().enumerate() {
            s.push(if self.mode & (0o400 >> i) != 0 { c } else { '-' });
        }
        let special = |s: &mut String, at: usize, bit: u32, on: char, off: char| {
            if self.mode & bit != 0 {
                let x = if s.as_bytes()[at] == b'x' { on } else { off };
                s.replace_range(at..at + 1, &x.to_string());
            }
        };
        special(&mut s, 3, 0o4000, 's', 'S');
        special(&mut s, 6, 0o2000, 's', 'S');
        special(&mut s, 9, 0o1000, 't', 'T');
        s
    }
}

impl FsEntry {
    pub fn data_offset(&self) -> Option<u64> {
        self.streams.iter().find(|s| s.name.is_empty()).and_then(|s| s.first_offset)
    }
    pub fn ads(&self) -> impl Iterator<Item = &Stream> {
        self.streams.iter().filter(|s| !s.name.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfsVolumeInfo {
    pub label: String,
    pub serial: String,
    pub version: String,
    pub cluster_size: u32,
    pub sector_size: u16,
    pub record_size: u32,
    pub volume_size: u64,
    pub mft_records: u64,
    pub mft_offset: u64,
    pub dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfsScan {
    pub volume: NtfsVolumeInfo,
    pub entries: Vec<FsEntry>,
    /// Records that had a valid header but could not be parsed.
    pub unreadable: Vec<UnreadableRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreadableRecord {
    pub record: u64,
    pub reason: String,
}

fn times_si(si: &NtfsStandardInformation) -> Times {
    Times {
        created: si.creation_time().nt_timestamp(),
        modified: si.modification_time().nt_timestamp(),
        accessed: si.access_time().nt_timestamp(),
        mft_modified: si.mft_record_modification_time().nt_timestamp(),
    }
}

fn times_fn(f: &NtfsFileName) -> Times {
    Times {
        created: f.creation_time().nt_timestamp(),
        modified: f.modification_time().nt_timestamp(),
        accessed: f.access_time().nt_timestamp(),
        mft_modified: f.mft_record_modification_time().nt_timestamp(),
    }
}

/// Runs code that calls into the `ntfs` crate, which panics (with
/// `unreachable!`) on some malformed structures instead of returning an
/// error. A panic becomes an error, so one bad structure cannot stop a scan.
fn guarded<T>(f: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| Err(anyhow::anyhow!("malformed NTFS structure (the parser refused it)")))
}

pub fn open_ntfs<R: Read + Seek>(r: &mut R) -> anyhow::Result<Ntfs> {
    guarded(|| open_ntfs_inner(r))
}

fn open_ntfs_inner<R: Read + Seek>(r: &mut R) -> anyhow::Result<Ntfs> {
    // The ntfs crate panics on a boot sector that is cut short; refuse first.
    let len = r.seek(std::io::SeekFrom::End(0))?;
    r.seek(std::io::SeekFrom::Start(0))?;
    if len < 512 {
        anyhow::bail!("volume too small for NTFS ({} bytes)", len);
    }
    let mut ntfs = Ntfs::new(r)?;
    ntfs.read_upcase_table(r)?;
    Ok(ntfs)
}

/// Walks the whole MFT. `progress(done, total)` may return false to cancel.
pub fn scan<R: Read + Seek>(r: &mut R, progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<NtfsScan> {
    let ntfs = open_ntfs(r)?;
    scan_with(&ntfs, r, progress)
}

pub fn scan_with<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<NtfsScan> {
    guarded(|| scan_inner(ntfs, r, progress))
}

fn scan_inner<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, mut progress: impl FnMut(u64, u64) -> bool) -> anyhow::Result<NtfsScan> {
    let record_size = ntfs.file_record_size();
    let mft = ntfs.file(r, 0)?;
    let mft_len = match mft.data(r, "") {
        Some(item) => item?.to_attribute()?.value_length(),
        None => anyhow::bail!("$MFT has no $DATA attribute"),
    };
    // The MFT's declared size is only trusted as far as the volume reaches:
    // a tampered $MFT could otherwise claim billions of records.
    let vol_len = r.seek(std::io::SeekFrom::End(0))?;
    let total = (mft_len / record_size.max(1) as u64).min(vol_len / record_size.max(1) as u64);

    let (label, version, dirty) = guarded(|| Ok(volume_details(ntfs, r))).unwrap_or_default();
    let volume = NtfsVolumeInfo {
        label,
        serial: format!("{:016X}", ntfs.serial_number()),
        version,
        cluster_size: ntfs.cluster_size(),
        sector_size: ntfs.sector_size(),
        record_size,
        volume_size: ntfs.size(),
        mft_records: total,
        mft_offset: ntfs.mft_position().value().map(|v| v.get()).unwrap_or(0),
        dirty,
    };

    let mut entries = Vec::with_capacity(total.min(1 << 20) as usize);
    let mut indexes: Vec<FolderIndex> = vec![];
    // Every (parent, name, record) a $FILE_NAME gives, hard links included.
    let mut links: Vec<(u64, String, u64)> = vec![];
    let mut unreadable = vec![];
    for rec in 0..total {
        if rec % 2048 == 0 && !progress(rec, total) {
            anyhow::bail!("scan cancelled");
        }
        let file = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ntfs.file(r, rec))) {
            Err(_) => {
                unreadable.push(UnreadableRecord { record: rec, reason: "malformed record (the parser refused it)".into() });
                continue;
            }
            Ok(f) => f,
        };
        let file = match file {
            Ok(f) => f,
            // Never-used slots have no FILE signature. Anything else is a real
            // record we failed to parse (corrupt, wiped mid-record, or a record
            // straddling non-contiguous MFT clusters) and must be reported.
            Err(ntfs::NtfsError::InvalidFileSignature { .. }) => continue,
            Err(err) => {
                unreadable.push(UnreadableRecord { record: rec, reason: err.to_string() });
                continue;
            }
        };
        match guarded(|| entry_from_file(&file, r)) {
            Ok(Some((e, mut ix))) => {
                links.extend(ix.names.drain(..).map(|(p, n)| (p, n, e.record)));
                if !ix.runs.is_empty() || !ix.root.is_empty() {
                    indexes.push(FolderIndex { record: e.record, ..ix });
                }
                entries.push(e)
            }
            Ok(None) => {}
            Err(e) => {
                unreadable.push(UnreadableRecord { record: rec, reason: e.to_string() });
                tracing::debug!("record {}: {}", rec, e);
            }
        }
    }
    progress(total, total);
    note_reused_clusters(ntfs, r, &mut entries);
    resolve_paths(&mut entries);
    index_names(ntfs, r, &mut entries, indexes, links, total, &unreadable);
    Ok(NtfsScan { volume, entries, unreadable })
}

/// Deleted files that claim the same space: at most one of them can still
/// hold its own content there (the later one overwrote the other, and was
/// deleted in turn, so the space shows as free). `ranges` are (entry index,
/// start, end) in volume bytes. Notes each such entry that has no note yet.
pub fn note_shared_space(entries: &mut [FsEntry], mut ranges: Vec<(usize, u64, u64)>) {
    ranges.sort_by_key(|x| x.1);
    let mut shared: HashMap<usize, (u64, usize)> = HashMap::new();
    let mut active: Vec<(u64, usize)> = vec![];
    for (i, s, e) in ranges {
        active.retain(|&(end, _)| end > s);
        for &(end, j) in &active {
            if j != i {
                let n = end.min(e) - s;
                shared.entry(i).or_insert((0, j)).0 += n;
                shared.entry(j).or_insert((0, i)).0 += n;
            }
        }
        if active.len() < 1024 {
            active.push((e, i));
        }
    }
    for (i, (bytes, j)) in shared {
        if entries[i].error.is_none() {
            let other = entries[j].name.clone();
            entries[i].error = Some(format!("{} bytes of its space are also claimed by the deleted file {}: one overwrote the other, so the content may be that file's", bytes, other));
        }
    }
}

/// Deleted files whose clusters $Bitmap now marks as in use: their content
/// may have been overwritten by another file, so say so (as for FAT). Then
/// deleted files that overlap each other.
fn note_reused_clusters<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, entries: &mut [FsEntry]) {
    if !entries.iter().any(|e| e.deleted && !e.is_dir && !e.resident) {
        return;
    }
    let cs = (ntfs.cluster_size() as u64).max(1);
    let Ok(vol_len) = r.seek(SeekFrom::End(0)) else { return };
    let clusters = ntfs.size().min(vol_len) / cs;
    let Ok(bitmap) = read_stream_with(ntfs, r, 6, "", 0, clusters.div_ceil(8) as usize) else { return };
    let used = |c: u64| bitmap.get((c / 8) as usize).map(|b| b >> (c % 8) & 1 == 1).unwrap_or(false);
    let mut ranges = vec![];
    for (i, e) in entries.iter_mut().enumerate().filter(|(_, e)| e.deleted && !e.is_dir && !e.resident && e.size > 0) {
        let Ok(ext) = stream_extents(ntfs, r, e.record, "") else { continue };
        let (mut n, mut busy) = (0u64, 0u64);
        for x in ext.iter().filter(|x| x.offset < e.size) {
            let Some(v) = x.vol else { continue };
            let len = x.len.min(e.size - x.offset);
            ranges.push((i, v, v + len));
            for c in v / cs..(v + len).div_ceil(cs) {
                n += 1;
                busy += used(c) as u64;
                if n > 1 << 24 {
                    break;
                }
            }
        }
        if busy > 0 && e.error.is_none() {
            e.error = Some(format!("{} of its {} clusters are in use again: recovered content may belong to another file", busy, n));
        }
    }
    note_shared_space(entries, ranges);
}

fn volume_details<R: Read + Seek>(ntfs: &Ntfs, r: &mut R) -> (String, String, bool) {
    let label = ntfs.volume_name(r).and_then(|v| v.ok()).map(|v| v.name().to_string_lossy()).unwrap_or_default();
    match ntfs.volume_info(r) {
        Ok(vi) => (
            label,
            format!("{}.{}", vi.major_version(), vi.minor_version()),
            vi.flags().bits() & 0x0001 != 0,
        ),
        Err(_) => (label, String::new(), false),
    }
}

/// Most attributes taken from one file record and its extension records.
const MAX_ATTRIBUTES: usize = 65_536;

/// Where a folder's index lives: $INDEX_ALLOCATION:$I30 runs as (volume
/// offset or None for sparse, length), and for deleted folders the
/// $INDEX_ROOT value.
#[derive(Default)]
struct FolderIndex {
    record: u64,
    runs: Vec<(Option<u64>, u64)>,
    root: Vec<u8>,
    /// Every name the record's $FILE_NAMEs give: (parent record, lowercase).
    names: Vec<(u64, String)>,
}

fn entry_from_file<R: Read + Seek>(file: &NtfsFile, r: &mut R) -> anyhow::Result<Option<(FsEntry, FolderIndex)>> {
    let flags = file.flags();
    let in_use = flags.contains(NtfsFileFlags::IN_USE);
    let mut e = FsEntry {
        record: file.file_record_number(),
        seq: file.sequence_number(),
        parent: 0,
        parent_seq: 0,
        name: String::new(),
        dos_name: None,
        path: String::new(),
        is_dir: flags.contains(NtfsFileFlags::IS_DIRECTORY),
        deleted: !in_use,
        orphan: false,
        size: 0,
        alloc_size: 0,
        resident: false,
        attributes: 0,
        hard_links: file.hard_link_count(),
        usn: None,
        si: None,
        fname: None,
        streams: vec![],
        has_reparse: false,
        record_offset: file.position().value().map(|v| v.get()).unwrap_or(0),
        error: None,
        unix: None,
        name_only: None,
    };
    let mut best_ns: i32 = -1;
    let mut ix = FolderIndex::default();

    // In-use records may spread attributes across extension records via an
    // $ATTRIBUTE_LIST; deleted records are read in place since their extension
    // records may already be reused.
    if in_use {
        let mut iter = file.attributes();
        // A crafted $ATTRIBUTE_LIST can send the iterator round in circles;
        // real records, extension records included, stay far below this.
        let mut n = 0;
        while let Some(item) = iter.next(r) {
            n += 1;
            if n > MAX_ATTRIBUTES {
                e.error = Some(format!("more than {} attributes (attribute list loops or is corrupt)", MAX_ATTRIBUTES));
                break;
            }
            let item = match item {
                Ok(i) => i,
                Err(err) => {
                    e.error = Some(err.to_string());
                    break;
                }
            };
            if let Ok(attr) = item.to_attribute() {
                take_attribute(&attr, r, &mut e, &mut best_ns, &mut ix);
            }
        }
    } else {
        for attr in file.attributes_raw() {
            match attr {
                Ok(attr) => take_attribute(&attr, r, &mut e, &mut best_ns, &mut ix),
                Err(err) => {
                    e.error = Some(err.to_string());
                    break;
                }
            }
        }
    }

    // Extension records (base record reference != 0) carry no name; skip them.
    if e.name.is_empty() && e.si.is_none() {
        return Ok(None);
    }
    if let Some(s) = e.streams.iter().find(|s| s.name.is_empty()) {
        e.size = s.size;
        e.resident = s.resident;
    }
    if !e.is_dir || !e.deleted {
        ix.root.clear();
    }
    Ok(Some((e, ix)))
}

fn take_attribute<R: Read + Seek>(attr: &NtfsAttribute, r: &mut R, e: &mut FsEntry, best_ns: &mut i32, ix: &mut FolderIndex) {
    let Ok(ty) = attr.ty() else { return };
    match ty {
        NtfsAttributeType::StandardInformation => {
            if let Ok(si) = attr.structured_value::<_, NtfsStandardInformation>(r) {
                e.si = Some(times_si(&si));
                e.attributes = si.file_attributes().bits();
                e.usn = si.usn();
            }
        }
        NtfsAttributeType::FileName => {
            if let Ok(f) = attr.structured_value::<_, NtfsFileName>(r) {
                let ns = f.namespace();
                let name = f.name().to_string_lossy();
                ix.names.push((f.parent_directory_reference().file_record_number(), name.to_lowercase()));
                if ns == NtfsFileNamespace::Dos {
                    e.dos_name = Some(name.clone());
                }
                // Prefer Win32 / Win32AndDos / Posix long names over 8.3 names.
                let rank = match ns {
                    NtfsFileNamespace::Win32AndDos => 3,
                    NtfsFileNamespace::Win32 => 3,
                    NtfsFileNamespace::Posix => 2,
                    NtfsFileNamespace::Dos => 1,
                };
                if rank > *best_ns {
                    *best_ns = rank;
                    e.name = name;
                    let pref = f.parent_directory_reference();
                    e.parent = pref.file_record_number();
                    e.parent_seq = pref.sequence_number();
                    e.fname = Some(times_fn(&f));
                    if e.alloc_size == 0 {
                        e.alloc_size = f.allocated_size();
                    }
                }
            }
        }
        NtfsAttributeType::Data => {
            let name = attr.name().map(|n| n.to_string_lossy()).unwrap_or_default();
            let mut s = Stream { name, size: attr.value_length(), resident: attr.is_resident(), first_offset: None };
            if let Ok(NtfsAttributeValue::NonResident(v)) = attr.value(r) {
                // Stop at the first bad run: the iterator may keep returning
                // the same error without moving on.
                for run in v.data_runs().take(MAX_ATTRIBUTES).map_while(Result::ok) {
                    if let Some(p) = run.data_position().value() {
                        s.first_offset = Some(p.get());
                        break;
                    }
                }
            }
            if s.name.is_empty() && !s.resident {
                // allocated size of the unnamed stream lives in the attribute header
                e.alloc_size = e.alloc_size.max(s.size);
            }
            // An attribute list may yield the same stream more than once (one
            // per extent); keep the first.
            if !e.streams.iter().any(|x| x.name == s.name) {
                e.streams.push(s);
            }
        }
        NtfsAttributeType::ReparsePoint => e.has_reparse = true,
        NtfsAttributeType::IndexAllocation | NtfsAttributeType::IndexRoot if attr.name().map(|n| n.to_string_lossy()).unwrap_or_default() == "$I30" => match attr.value(r) {
            Ok(NtfsAttributeValue::NonResident(v)) if ty == NtfsAttributeType::IndexAllocation => {
                for run in v.data_runs().take(MAX_ATTRIBUTES).map_while(Result::ok) {
                    ix.runs.push((run.data_position().value().map(|p| p.get()), run.allocated_size()));
                }
            }
            Ok(NtfsAttributeValue::Resident(v)) if ty == NtfsAttributeType::IndexRoot => ix.root = v.data().to_vec(),
            _ => {}
        },
        _ => {}
    }
}

/// Most index bytes read from one folder, and from $LogFile.
const MAX_INDEX: u64 = 64 << 20;
const MAX_LOG: u64 = 256 << 20;

/// Reads runs of (volume offset or None for sparse, length) into one
/// buffer, with a map of (buffer offset, volume offset, length).
fn read_runs<R: Read + Seek>(r: &mut R, runs: &[(Option<u64>, u64)], max: u64) -> (Vec<u8>, Vec<(usize, u64, u64)>) {
    let mut data = vec![];
    let mut map = vec![];
    for (vol, len) in runs {
        if data.len() as u64 + len > max {
            break;
        }
        let at = data.len();
        data.resize(at + *len as usize, 0);
        if let Some(v) = vol {
            if r.seek(SeekFrom::Start(*v)).is_err() || r.read_exact(&mut data[at..]).is_err() {
                data.truncate(at);
                break;
            }
            map.push((at, *v, *len));
        }
    }
    (data, map)
}

fn map_back(map: &[(usize, u64, u64)], off: usize) -> Option<u64> {
    map.iter().find(|(at, _, len)| off >= *at && ((off - at) as u64) < *len).map(|(at, v, _)| v + (off - at) as u64)
}

/// Names that no MFT record accounts for, from the slack of every folder's
/// INDX records, the whole index of deleted folders, and $LogFile. A name
/// is dropped when an entry in that folder already has it with the same
/// MFT record (the index tree moves entries around and leaves copies, and
/// the log repeats them). Renamed and moved files keep their old names this
/// way, and deleted files whose MFT record was reused keep their name,
/// times and size.
#[allow(clippy::too_many_arguments)]
fn index_names<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, entries: &mut Vec<FsEntry>, indexes: Vec<FolderIndex>, links: Vec<(u64, String, u64)>, mft_records: u64, unreadable: &[UnreadableRecord]) {
    let by_rec: HashMap<u64, usize> = entries.iter().enumerate().map(|(i, e)| (e.record, i)).collect();
    let mut names: HashMap<u64, Vec<(String, u64)>> = HashMap::new();
    for (parent, name, rec) in links {
        names.entry(parent).or_default().push((name, rec));
    }
    let mut got: Vec<(indx::IndexName, Option<u64>)> = vec![];
    for ix in indexes {
        let Some(dir) = by_rec.get(&ix.record).map(|&i| &entries[i]).filter(|d| d.is_dir) else { continue };
        let key = (dir.record, dir.seq);
        if !ix.runs.is_empty() {
            let (mut data, map) = read_runs(r, &ix.runs, MAX_INDEX);
            for n in indx::scan_allocation(&mut data, key, dir.deleted) {
                let vol = map_back(&map, n.offset);
                got.push((n, vol));
            }
        }
        if !ix.root.is_empty() {
            got.extend(indx::scan_root(&ix.root, key).into_iter().map(|n| (n, None)));
        }
    }
    if let Ok(ext) = stream_extents(ntfs, r, 2, "") {
        let runs: Vec<(Option<u64>, u64)> = ext.iter().map(|x| (x.vol, x.len)).collect();
        let (mut data, map) = read_runs(r, &runs, MAX_LOG);
        let dirs: std::collections::HashSet<(u64, u16)> = entries.iter().filter(|e| e.is_dir).map(|e| (e.record, e.seq)).collect();
        for n in indx::scan_logfile(&mut data, &|p| dirs.contains(&p)) {
            let vol = map_back(&map, n.offset);
            got.push((n, vol));
        }
    }
    // Names whose record is known first: a later copy without one is then
    // recognized as the same file.
    got.sort_by_key(|(n, _)| n.file.is_none_or(|f| f.0 >= mft_records));
    let mut found = vec![];
    for (n, vol) in got {
        // 8.3 names repeat a long name's entry; the first 24 records are
        // NTFS's own files, whose names change only when it is formatted.
        if n.namespace == 2 || n.file.is_some_and(|f| f.0 < 24) {
            continue;
        }
        let Some(dir) = by_rec.get(&n.parent.0).map(|&i| &entries[i]) else { continue };
        // A reference past the end of the MFT means the header in front was
        // not this entry's.
        let file = n.file.filter(|f| f.0 < mft_records);
        let lname = n.name.to_lowercase();
        let rec = file.map(|f| f.0);
        if names.get(&dir.record).is_some_and(|v| v.iter().any(|(nm, r)| *nm == lname && (rec.is_none() || rec == Some(*r)))) {
            continue;
        }
        names.entry(dir.record).or_default().push((lname, rec.unwrap_or(u64::MAX)));
        let src = n.source.label();
        let note = match file {
            None => format!("Name found in {} with its times and size; which MFT record it had is not known, so there is no content.", src),
            Some((rec, seq)) => match by_rec.get(&rec).map(|&i| &entries[i]) {
                Some(o) if o.seq == seq => format!("Earlier name of MFT record {}, now {}: the file was renamed or moved (name found in {}).", rec, o.path, src),
                Some(o) => format!("MFT record {} now holds another file ({}): this file's own record was reused, so its content cannot be read through the file system (carving may still find it). Name, times and size are from {}.", rec, o.path, src),
                None if unreadable.iter().any(|u| u.record == rec) => format!("Name of MFT record {}, which could not be parsed (see the unreadable records); name, times and size are from {}.", rec, src),
                None => format!("MFT record {} holds no file now: name, times and size are from {}; there is no content.", rec, src),
            },
        };
        let path = if dir.path == "/" { format!("/{}", n.name) } else { format!("{}/{}", dir.path, n.name) };
        found.push(FsEntry {
            record: NAME_ONLY_BASE + found.len() as u64,
            seq: file.map(|f| f.1).unwrap_or(0),
            parent: dir.record,
            parent_seq: dir.seq,
            is_dir: n.is_dir(),
            deleted: true,
            orphan: dir.orphan,
            size: n.size,
            alloc_size: n.alloc_size,
            resident: false,
            attributes: n.flags & 0xFFFF,
            hard_links: 0,
            usn: None,
            si: None,
            fname: Some(n.times),
            streams: vec![],
            has_reparse: false,
            record_offset: vol.unwrap_or(0),
            error: Some(note),
            unix: None,
            name_only: Some(NameOnly { mft_record: file.map(|f| f.0), mft_seq: file.map(|f| f.1).unwrap_or(0), source: src.to_string() }),
            name: n.name,
            dos_name: None,
            path,
        });
    }
    entries.extend(found);
}

fn resolve_paths(entries: &mut [FsEntry]) {
    let index: HashMap<u64, usize> = entries.iter().enumerate().map(|(i, e)| (e.record, i)).collect();
    let mut cache: HashMap<u64, (String, bool)> = HashMap::new();

    fn build(rec: u64, entries: &[FsEntry], index: &HashMap<u64, usize>, cache: &mut HashMap<u64, (String, bool)>, depth: u32) -> (String, bool) {
        if rec == ROOT_RECORD {
            return (String::new(), false);
        }
        if let Some(c) = cache.get(&rec) {
            return c.clone();
        }
        let Some(&i) = index.get(&rec) else { return (ORPHAN_ROOT.to_string(), true) };
        let e = &entries[i];
        if depth > 256 || e.parent == rec {
            return (format!("{}/{}", ORPHAN_ROOT, e.name), true);
        }
        let parent_ok = match index.get(&e.parent) {
            Some(&pi) => {
                let p = &entries[pi];
                e.parent == ROOT_RECORD || (p.is_dir && (p.seq == e.parent_seq || e.parent_seq == 0))
            }
            None => false,
        };
        let res = if parent_ok {
            let (pp, porphan) = build(e.parent, entries, index, cache, depth + 1);
            (format!("{}/{}", pp, e.name), porphan)
        } else {
            (format!("{}/{}", ORPHAN_ROOT, e.name), true)
        };
        cache.insert(rec, res.clone());
        res
    }

    let resolved: Vec<(String, bool)> = (0..entries.len()).map(|i| build(entries[i].record, entries, &index, &mut cache, 0)).collect();
    for (e, (p, orphan)) in entries.iter_mut().zip(resolved) {
        e.path = if e.record == ROOT_RECORD { "/".into() } else { p };
        e.orphan = orphan;
    }
}

/// Reads up to `len` bytes of a stream starting at `offset`. Works for deleted
/// records as long as the record and its clusters were not reused.
pub fn read_stream<R: Read + Seek>(r: &mut R, record: u64, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
    let ntfs = open_ntfs(r)?;
    read_stream_with(&ntfs, r, record, stream, offset, len)
}

pub fn read_stream_with<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, record: u64, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
    guarded(|| read_stream_with_inner(ntfs, r, record, stream, offset, len))
}

fn read_stream_with_inner<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, record: u64, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
    let file = ntfs.file(r, record)?;
    let in_use = file.flags().contains(NtfsFileFlags::IN_USE);
    // Grown as bytes arrive: `len` and the stream's declared size can both
    // be far larger than what the volume holds.
    let mut out = vec![];

    let read_attr = |attr: NtfsAttribute, r: &mut R, out: &mut Vec<u8>| -> anyhow::Result<usize> {
        if attr.flags().contains(NtfsAttributeFlags::COMPRESSED) && !attr.is_resident() {
            return read_compressed(ntfs, &attr, r, offset, len, out);
        }
        let mut v = attr.value(r)?;
        let vlen = v.len();
        if offset >= vlen {
            return Ok(0);
        }
        v.seek(r, SeekFrom::Start(offset))?;
        let want = (vlen - offset).min(len as u64) as usize;
        let mut got = 0;
        while got < want {
            if out.len() == got {
                out.resize(got + (want - got).min(1 << 20), 0);
            }
            let n = v.read(r, &mut out[got..])?;
            if n == 0 {
                break;
            }
            got += n;
        }
        Ok(got)
    };

    let got = if in_use {
        let item = file.data(r, stream).ok_or_else(|| anyhow::anyhow!("stream not found"))??;
        read_attr(item.to_attribute()?, r, &mut out)?
    } else {
        let mut found = None;
        for attr in file.attributes_raw().take(MAX_ATTRIBUTES).map_while(Result::ok) {
            if attr.ty().ok() == Some(NtfsAttributeType::Data)
                && attr.name().map(|n| n.to_string_lossy()).unwrap_or_default() == stream
            {
                found = Some(attr);
                break;
            }
        }
        let attr = found.ok_or_else(|| anyhow::anyhow!("stream not found in deleted record"))?;
        read_attr(attr, r, &mut out)?
    };
    out.truncate(got);
    Ok(out)
}

/// Little-endian value of `n` bytes at `off` in an attribute's header.
fn header_value<R: Read + Seek>(r: &mut R, attr: &NtfsAttribute, off: u64, n: usize) -> Option<u64> {
    let p = attr.position().value()?.get();
    let mut b = [0u8; 8];
    r.seek(SeekFrom::Start(p + off)).ok()?;
    r.read_exact(&mut b[..n]).ok()?;
    Some(u64::from_le_bytes(b))
}

/// Reads part of an NTFS-compressed stream, one compression unit at a time.
/// A unit whose clusters are all stored is raw, one with fewer is LZNT1 data
/// followed by sparse clusters (the last unit is padded to a whole unit the
/// same way), one with none is zeros. The value reader maps each cluster, whatever the layout
/// (including a stream split over an attribute list).
fn read_compressed<R: Read + Seek>(ntfs: &Ntfs, attr: &NtfsAttribute, r: &mut R, offset: u64, len: usize, out: &mut Vec<u8>) -> anyhow::Result<usize> {
    let vlen = attr.value_length();
    if offset >= vlen || len == 0 {
        return Ok(0);
    }
    let want = (vlen - offset).min(len as u64);
    let cs = (ntfs.cluster_size() as u64).max(1);
    // Clusters per unit: 2^n from the attribute header (offset 0x22); 16 on
    // every volume Windows creates.
    let exp = header_value(r, attr, 0x22, 2).filter(|e| (1..=8).contains(e)).unwrap_or(4);
    let per = 1u64 << exp;
    let unit = cs * per;
    let mut v = attr.value(r)?;
    let mut got = 0u64;
    let first = offset / unit;
    let last = (offset + want - 1) / unit;
    for u in first..=last {
        let us = u * unit;
        let mut stored: Vec<(u64, u64)> = vec![];
        for c in 0..per {
            // Past the end of the data counts as sparse if the reader will
            // not go there.
            if v.seek(r, SeekFrom::Start(us + c * cs)).is_err() {
                continue;
            }
            if let Some(p) = v.data_position().value() {
                match stored.last_mut() {
                    Some(x) if x.0 + x.1 == p.get() => x.1 += cs,
                    _ => stored.push((p.get(), cs)),
                }
            }
        }
        let total: u64 = stored.iter().map(|x| x.1).sum();
        let data = if total == 0 {
            vec![0u8; unit as usize]
        } else {
            let mut raw = Vec::with_capacity(total as usize);
            for (p, n) in stored {
                r.seek(SeekFrom::Start(p))?;
                let mut b = vec![0u8; n as usize];
                r.read_exact(&mut b)?;
                raw.extend_from_slice(&b);
            }
            if total >= unit {
                raw
            } else {
                let mut d = lznt1::decompress(&raw, unit as usize)?;
                d.resize(unit as usize, 0);
                d
            }
        };
        let from = if u == first { (offset - us) as usize } else { 0 };
        let take = ((want - got) as usize).min(data.len().saturating_sub(from));
        out.extend_from_slice(&data[from..from + take]);
        got += take as u64;
    }
    Ok(got as usize)
}

/// One piece of a stream: `len` bytes at stream offset `offset`, stored at
/// volume offset `vol` (None for sparse runs or layouts we cannot map).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
    pub vol: Option<u64>,
}

/// Where a stream's bytes live on the volume. Resident data maps into the MFT
/// record; streams split over an attribute list come back empty (unmapped).
pub fn stream_extents<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, record: u64, stream: &str) -> anyhow::Result<Vec<Extent>> {
    guarded(|| stream_extents_inner(ntfs, r, record, stream))
}

fn stream_extents_inner<R: Read + Seek>(ntfs: &Ntfs, r: &mut R, record: u64, stream: &str) -> anyhow::Result<Vec<Extent>> {
    let file = ntfs.file(r, record)?;
    let in_use = file.flags().contains(NtfsFileFlags::IN_USE);
    let to_extents = |attr: NtfsAttribute, r: &mut R| -> anyhow::Result<Vec<Extent>> {
        // Compressed data does not map byte for byte onto the volume.
        if attr.flags().contains(NtfsAttributeFlags::COMPRESSED) && !attr.is_resident() {
            return Ok(vec![]);
        }
        Ok(match attr.value(r)? {
            NtfsAttributeValue::Resident(v) => vec![Extent { offset: 0, len: v.len(), vol: v.data_position().value().map(|p| p.get()) }],
            NtfsAttributeValue::NonResident(v) => {
                let mut out = vec![];
                let mut off = 0;
                for run in v.data_runs() {
                    let run = run?;
                    let len = run.allocated_size();
                    out.push(Extent { offset: off, len, vol: run.data_position().value().map(|p| p.get()) });
                    off = off.saturating_add(len);
                }
                out
            }
            NtfsAttributeValue::AttributeListNonResident(_) => vec![],
        })
    };
    if in_use {
        let item = file.data(r, stream).ok_or_else(|| anyhow::anyhow!("stream not found"))??;
        to_extents(item.to_attribute()?, r)
    } else {
        for attr in file.attributes_raw().take(MAX_ATTRIBUTES).map_while(Result::ok) {
            if attr.ty().ok() == Some(NtfsAttributeType::Data) && attr.name().map(|n| n.to_string_lossy()).unwrap_or_default() == stream {
                return to_extents(attr, r);
            }
        }
        anyhow::bail!("stream not found in deleted record")
    }
}

/// Maps a stream offset to a volume offset using `extents`.
pub fn map_offset(extents: &[Extent], offset: u64) -> Option<u64> {
    extents.iter().find(|e| offset >= e.offset && offset < e.offset + e.len).and_then(|e| e.vol.map(|v| v + (offset - e.offset)))
}

/// Unallocated cluster runs as (volume byte offset, byte length), read from
/// $Bitmap (record 6). Clusters past the end of the volume are ignored.
pub fn free_runs<R: Read + Seek>(ntfs: &Ntfs, r: &mut R) -> anyhow::Result<Vec<(u64, u64)>> {
    guarded(|| free_runs_inner(ntfs, r))
}

fn free_runs_inner<R: Read + Seek>(ntfs: &Ntfs, r: &mut R) -> anyhow::Result<Vec<(u64, u64)>> {
    let cs = (ntfs.cluster_size() as u64).max(1);
    let vol_len = r.seek(SeekFrom::End(0))?;
    let clusters = ntfs.size().min(vol_len) / cs;
    let bitmap = read_stream_with(ntfs, r, 6, "", 0, clusters.div_ceil(8) as usize)?;
    let mut out = vec![];
    let mut start: Option<u64> = None;
    for c in 0..clusters {
        let used = bitmap.get((c / 8) as usize).map(|b| b >> (c % 8) & 1 == 1).unwrap_or(true);
        match (used, start) {
            (false, None) => start = Some(c),
            (true, Some(s)) => {
                out.push((s * cs, (c - s) * cs));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s * cs, (clusters - s) * cs));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn fixture() -> Option<File> {
        File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/testfs1")).ok()
    }

    #[test]
    fn scans_testfs1() {
        let Some(f) = fixture() else { return };
        let mut r = std::io::BufReader::new(f);
        let scan = scan(&mut r, |_, _| true).unwrap();
        assert_eq!(scan.volume.label, "mylabel");
        let e = scan.entries.iter().find(|e| e.path == "/file-with-12345").unwrap();
        assert_eq!(e.size, 5);
        assert!(e.resident);
        let data = read_stream(&mut r, e.record, "", 0, 64).unwrap();
        assert_eq!(data, b"12345");
        let big = scan.entries.iter().find(|e| e.path == "/1000-bytes-file").unwrap();
        assert_eq!(big.size, 1000);
        assert!(!big.resident);
        assert!(big.data_offset().is_some());
        let sub = scan.entries.iter().filter(|e| e.path.starts_with("/many_subdirs/")).count();
        // testfs1 uses 512-byte clusters; one 1 KiB record straddles two
        // non-contiguous MFT runs, which the ntfs crate cannot read. It must
        // be reported, not silently dropped.
        assert_eq!(sub, 512);
        assert_eq!(scan.unreadable.len(), 1);
        // Its name survives in the folder's index.
        let named = scan.entries.iter().find(|e| e.name_only.is_some()).unwrap();
        assert_eq!((named.path.as_str(), named.name_only.as_ref().unwrap().mft_record), ("/many_subdirs/187", Some(scan.unreadable[0].record)));
        assert!(named.error.as_ref().unwrap().contains("could not be parsed"));
        assert_eq!(scan.entries.iter().filter(|e| e.name_only.is_some()).count(), 1);
        let mt = scan.entries.iter().find(|e| e.path == "/empty-file").unwrap();
        assert_eq!(kokino_core::time::filetime_to_iso(mt.si.unwrap().modified), "2021-01-01T12:37:00.0000000Z"); // touch -t ran in UTC+1
    }
}
