use kokino_analysis::timeline::{self, TimelineEvent};
use kokino_analysis::fs::Fs;
use kokino_analysis::Analysis;
use kokino_ntfs::FsEntry;
use kokino_core::case::{read_json, Case};
use kokino_image::Evidence;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::auth::Sessions;
use kokino_analysis::hashsets::{FileHashes, SetKind};
use crate::jobs::Job;
use kokino_core::users::UserStore;

/// Synthetic directory key for orphaned entries.
pub const ORPHAN_KEY: u64 = u64::MAX;

pub struct FsIndex {
    pub timeline: Vec<TimelineEvent>,
    /// Directory record -> child indices (dirs first, then by name).
    pub children: HashMap<u64, Vec<u32>>,
}

pub struct Loaded {
    pub analysis: Analysis,
    pub evidence: Evidence,
    pub fs: Vec<FsIndex>,
    /// Opened file systems by volume index (a FAT is read once, not per request).
    handles: Mutex<HashMap<usize, Arc<Fs>>>,
    /// Indexes of PST and OST mailboxes by (file system, file), read once.
    pub pst: Mutex<HashMap<(usize, u32), Arc<kokino_analysis::pst::Pst<()>>>>,
}

impl Loaded {
    /// Up to `len` bytes of a file stream, through its file system.
    pub fn read_file(&self, fi: usize, e: &FsEntry, stream: &str, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let fsa = self.analysis.filesystems.get(fi).ok_or_else(|| anyhow::anyhow!("no such filesystem"))?;
        let mut r = kokino_analysis::volume_reader(&self.evidence, &fsa.volume)?;
        let cached = self.handles.lock().unwrap().get(&fi).cloned();
        let fs = match cached {
            Some(fs) => fs,
            None => {
                let fs = Arc::new(Fs::open(&mut r, &fsa.volume)?);
                self.handles.lock().unwrap().insert(fi, fs.clone());
                fs
            }
        };
        fs.read(&mut r, e, stream, offset, len)
    }
}

pub struct AppState {
    pub root: PathBuf,
    /// One-time secret for creating the first admin account.
    pub setup_token: String,
    pub port: u16,
    pub tls: bool,
    /// Extra DNS names accepted in the Host header (besides loopback and IP literals).
    pub hostnames: Vec<String>,
    pub users: Arc<UserStore>,
    pub sessions: Sessions,
    pub jobs: Mutex<HashMap<String, Arc<Job>>>,
    /// Serializes bookmark file updates (read-modify-write).
    pub bookmarks: Mutex<()>,
    /// Hash sets shared by every case (`<root>/.kokino/hashsets`).
    pub hashsets: kokino_analysis::hashsets::Store,
    cache: Mutex<HashMap<String, Arc<Loaded>>>,
    hash_cache: Mutex<HashMap<String, Arc<HashStatus>>>,
    /// The folder of plugins the administrator allowed (`serve --plugins`).
    pub plugins: Option<PathBuf>,
}

/// Hash analysis of one evidence item, indexed for file listings.
pub struct HashStatus {
    pub fh: FileHashes,
    /// (file system, record) -> index into `fh.files`.
    pub by_file: HashMap<(usize, u64), usize>,
    /// Index into `fh.files` -> set indexes and algorithms that matched.
    pub hits: HashMap<usize, Vec<(usize, String)>>,
}

impl HashStatus {
    pub fn new(fh: FileHashes) -> Self {
        let by_file = fh.files.iter().enumerate().map(|(i, f)| ((f.fi, f.record), i)).collect();
        let mut hits: HashMap<usize, Vec<(usize, String)>> = HashMap::new();
        for h in &fh.hits {
            hits.entry(h.file).or_default().push((h.set, h.algo.clone()));
        }
        HashStatus { fh, by_file, hits }
    }

    /// "notable", "known" or "" for a file index; notable wins when both match.
    pub fn kind_of(&self, i: usize) -> &'static str {
        let Some(sets) = self.hits.get(&i) else { return "" };
        let has = |k: SetKind| sets.iter().any(|(s, _)| self.fh.sets.get(*s).map(|x| x.kind == k).unwrap_or(false));
        if has(SetKind::Notable) {
            "notable"
        } else if has(SetKind::Known) {
            "known"
        } else {
            ""
        }
    }

    pub fn kind(&self, fi: usize, record: u64) -> &'static str {
        self.by_file.get(&(fi, record)).map(|&i| self.kind_of(i)).unwrap_or("")
    }
}

impl AppState {
    pub fn new(root: PathBuf, port: u16, tls: bool, hostnames: Vec<String>) -> anyhow::Result<Self> {
        Ok(Self {
            users: Arc::new(UserStore::open(&root)?),
            hashsets: kokino_analysis::hashsets::Store::open(root.join(".kokino").join("hashsets")),
            hash_cache: Mutex::default(),
            root,
            setup_token: random_token(),
            port,
            tls,
            hostnames,
            sessions: Sessions::default(),
            jobs: Mutex::default(),
            bookmarks: Mutex::default(),
            cache: Mutex::default(),
            plugins: None,
        })
    }

    pub fn case(&self, cid: &str) -> anyhow::Result<Case> {
        Case::open(&self.root.join(kokino_core::case::safe_id(cid)?))
    }

    /// Drops every cached analysis of a case.
    pub fn invalidate_case(&self, cid: &str) {
        let prefix = format!("{}/", cid);
        self.cache.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
        self.hash_cache.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
    }

    pub fn invalidate(&self, cid: &str, eid: &str) {
        self.cache.lock().unwrap().remove(&format!("{}/{}", cid, eid));
        self.hash_cache.lock().unwrap().remove(&format!("{}/{}", cid, eid));
    }

    /// Hash analysis of an evidence item, if it has one (cached).
    pub fn hash_status(&self, cid: &str, eid: &str) -> Option<Arc<HashStatus>> {
        let key = format!("{}/{}", cid, eid);
        if let Some(h) = self.hash_cache.lock().unwrap().get(&key) {
            return Some(h.clone());
        }
        let p = self.case(cid).ok()?.hashes_path(eid).ok()?;
        let fh: FileHashes = read_json(&p).ok().filter(|f: &FileHashes| f.schema == kokino_analysis::hashsets::FILEHASH_SCHEMA)?;
        let h = Arc::new(HashStatus::new(fh));
        self.hash_cache.lock().unwrap().insert(key, h.clone());
        Some(h)
    }

    pub fn put_hashes(&self, cid: &str, eid: &str, fh: FileHashes) {
        self.hash_cache.lock().unwrap().insert(format!("{}/{}", cid, eid), Arc::new(HashStatus::new(fh)));
    }

    pub fn put(&self, cid: &str, eid: &str, analysis: Analysis, evidence: Evidence) -> Arc<Loaded> {
        let l = Arc::new(index(analysis, evidence));
        self.cache.lock().unwrap().insert(format!("{}/{}", cid, eid), l.clone());
        l
    }

    /// Cached analysis, loading it from the case directory when needed.
    pub fn loaded(&self, cid: &str, eid: &str) -> anyhow::Result<Arc<Loaded>> {
        if let Some(l) = self.cache.lock().unwrap().get(&format!("{}/{}", cid, eid)) {
            return Ok(l.clone());
        }
        let case = self.case(cid)?;
        let rec = case.evidence_by_id(eid)?;
        let p = case.analysis_path(eid)?;
        if !p.exists() {
            anyhow::bail!("evidence has not been analyzed yet");
        }
        let analysis: Analysis = read_json(&p)?;
        let evidence = open_evidence(&case, &rec)?;
        Ok(self.put(cid, eid, analysis, evidence))
    }
}

/// A BitLocker key kept with the case, found with a password or recovery
/// password the examiner gave (the secret itself is not kept).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredKey {
    pub volume_start: u64,
    pub key: kokino_image::bde::Key,
    pub by: String,
    pub at: String,
}

pub fn stored_keys(case: &Case, eid: &str) -> Vec<StoredKey> {
    case.keys_path(eid).ok().filter(|p| p.exists()).and_then(|p| read_json(&p).ok()).unwrap_or_default()
}

pub fn save_keys(case: &Case, eid: &str, keys: &[StoredKey]) -> anyhow::Result<()> {
    let p = case.keys_path(eid)?;
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    kokino_core::case::write_json(&p, &keys)
}

/// The evidence with the BitLocker keys the case holds for it.
pub fn open_evidence(case: &Case, rec: &kokino_core::case::EvidenceRecord) -> anyhow::Result<Evidence> {
    let mut ev = Evidence::open(&rec.path)?;
    for k in stored_keys(case, &rec.id) {
        ev = ev.with_bitlocker_key(k.volume_start, k.key);
    }
    Ok(ev)
}

fn index(analysis: Analysis, evidence: Evidence) -> Loaded {
    let fs = analysis
        .filesystems
        .iter()
        .map(|fsa| {
            let files = &fsa.files;
            let by_rec: HashMap<u64, usize> = files.iter().enumerate().map(|(i, f)| (f.e.record, i)).collect();
            let mut children: HashMap<u64, Vec<u32>> = HashMap::new();
            for (i, f) in files.iter().enumerate() {
                if f.e.record == kokino_ntfs::ROOT_RECORD {
                    continue;
                }
                let parent_ok = by_rec
                    .get(&f.e.parent)
                    .map(|&pi| {
                        let p = &files[pi];
                        p.e.is_dir && (p.e.path == "/" || f.e.path.starts_with(&format!("{}/", p.e.path)))
                    })
                    .unwrap_or(false);
                let key = if parent_ok { f.e.parent } else { ORPHAN_KEY };
                children.entry(key).or_default().push(i as u32);
            }
            for v in children.values_mut() {
                v.sort_by(|a, b| {
                    let (a, b) = (&files[*a as usize].e, &files[*b as usize].e);
                    b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
            }
            FsIndex { timeline: timeline::build(files, &fsa.web, &fsa.windows, &fsa.linux.timeline), children }
        })
        .collect();
    Loaded { analysis, evidence, fs, handles: Mutex::default(), pst: Mutex::default() }
}

pub fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Constant-time comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
