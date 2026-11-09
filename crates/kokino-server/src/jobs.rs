//! Background jobs (hashing, analysis, text indexing) with progress the GUI can poll.

use crate::state::AppState;
use kokino_core::case::write_json;
use kokino_image::Evidence;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: String,
    pub kind: String,
    pub case: String,
    pub evidence: String,
    pub user: String,
    pub stage: String,
    pub done: u64,
    pub total: u64,
    pub state: String,
    pub error: Option<String>,
    pub started: String,
    pub finished: Option<String>,
}

pub struct Job {
    pub view: Mutex<JobView>,
    pub cancel: AtomicBool,
}

impl Job {
    fn progress(&self, stage: &str, done: u64, total: u64) -> bool {
        let mut v = self.view.lock().unwrap();
        v.stage = stage.to_string();
        v.done = done;
        v.total = total;
        !self.cancel.load(Ordering::Relaxed)
    }

    fn finish(&self, res: &anyhow::Result<()>) {
        // Still usable if a panic poisoned it mid-update.
        let mut v = self.view.lock().unwrap_or_else(|e| e.into_inner());
        v.finished = Some(kokino_core::time::now_iso());
        match res {
            Ok(()) => {
                v.state = "done".into();
                v.done = v.total.max(1);
                v.total = v.total.max(1);
            }
            Err(e) => {
                v.state = if self.cancel.load(Ordering::Relaxed) { "cancelled".into() } else { "error".into() };
                v.error = Some(format!("{:#}", e));
            }
        }
    }
}

fn new_job(st: &AppState, kind: &str, user: &str, cid: &str, eid: &str) -> Arc<Job> {
    let job = Arc::new(Job {
        view: Mutex::new(JobView {
            id: uuid::Uuid::new_v4().simple().to_string()[..12].to_string(),
            kind: kind.into(),
            case: cid.to_string(),
            evidence: eid.to_string(),
            user: user.to_string(),
            stage: "Queued".into(),
            done: 0,
            total: 1,
            state: "running".into(),
            error: None,
            started: kokino_core::time::now_iso(),
            finished: None,
        }),
        cancel: AtomicBool::new(false),
    });
    let id = job.view.lock().unwrap().id.clone();
    st.jobs.lock().unwrap().insert(id, job.clone());
    job
}

/// Runs a job body, turning a panic (a parser bug on some input) into an
/// error, so the job ends as failed instead of showing as running for ever.
fn guarded(f: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|p| {
        let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
        tracing::error!("job panicked: {}", msg);
        Err(anyhow::anyhow!("internal error while processing the evidence ({}). Please report it to lab@zeroscience.mk with the Kokino version.", msg))
    })
}

/// Hash (unless already hashed and `rehash` is false), analyze, then build
/// the text index when the analysis is new or the index is missing.
pub fn spawn_ingest(st: Arc<AppState>, user: &str, cid: String, eid: String, rehash: bool, reanalyze: bool) -> Arc<Job> {
    let job = new_job(&st, "ingest", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| run_ingest(&st, &j, &user, &cid, &eid, rehash, reanalyze));
        j.finish(&res);
    });
    job
}

/// Extracts a disk image found on the evidence (all of its files) into the
/// case folder, registers it as new evidence with where it came from, and
/// hashes and analyzes it. The copy is checked against the bytes read.
pub fn spawn_extract(st: Arc<AppState>, user: &str, cid: String, eid: String, fi: usize, file: usize) -> Arc<Job> {
    let job = new_job(&st, "extract", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| {
            let new_id = run_extract(&st, &j, &user, &cid, &eid, fi, file)?;
            {
                let mut v = j.view.lock().unwrap();
                v.evidence = new_id.clone();
            }
            run_ingest(&st, &j, &user, &cid, &new_id, true, true)
        });
        j.finish(&res);
    });
    job
}

fn run_extract(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str, fi: usize, file: usize) -> anyhow::Result<String> {
    let l = st.loaded(cid, eid)?;
    let case = st.case(cid)?;
    let src = case.evidence_by_id(eid)?;
    let fsa = l.analysis.filesystems.get(fi).ok_or_else(|| anyhow::anyhow!("no such file system"))?;
    let first = fsa.files.get(file).ok_or_else(|| anyhow::anyhow!("no such file"))?;
    let mut read = |e: &kokino_ntfs::FsEntry, off: u64, n: usize| l.read_file(fi, e, "", off, n).unwrap_or_default();
    let found = kokino_analysis::nested::find(std::slice::from_ref(first), &mut read);
    let format = found.first().map(|n| n.format.clone()).ok_or_else(|| anyhow::anyhow!("{} is not a disk image Kokino recognizes", first.e.path))?;
    let parts = kokino_analysis::nested::parts(&fsa.files, file, &format);
    let tag = format!("[from {}:{}:{}]", eid, fi, first.e.record);
    if case.evidence().iter().any(|r| r.notes.contains(&tag)) {
        anyhow::bail!("this image was already extracted into the case");
    }
    let new_id = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
    let dir = case.dir.join("derived").join(&new_id);
    std::fs::create_dir_all(&dir)?;
    let total: u64 = parts.iter().map(|&p| fsa.files[p as usize].e.size).sum();
    let mut done = 0u64;
    let mut copied = vec![];
    const CHUNK: u64 = 16 << 20;
    for &p in &parts {
        let e = &fsa.files[p as usize].e;
        let safe: String = e.name.chars().map(|c| if c.is_alphanumeric() || ".-_ ()[]".contains(c) { c } else { '_' }).collect();
        let dest = dir.join(&safe);
        let mut out = std::io::BufWriter::new(std::fs::File::create(&dest)?);
        let mut hasher = kokino_core::hashing::MultiHasher::default();
        let mut off = 0u64;
        while off < e.size {
            let n = (e.size - off).min(CHUNK) as usize;
            let b = l.read_file(fi, e, "", off, n)?;
            if b.len() != n {
                anyhow::bail!("{}: could not read {} bytes at offset {}", e.path, n, off);
            }
            std::io::Write::write_all(&mut out, &b)?;
            hasher.update(&b);
            off += n as u64;
            done += n as u64;
            if !job.progress(&format!("Extracting {}", e.name), done, total) {
                anyhow::bail!("extraction cancelled");
            }
        }
        std::io::Write::flush(&mut out)?;
        drop(out);
        let read_hashes = hasher.finish();
        // The copy on disk must hash the same as the bytes read.
        let (copy_hashes, _) = kokino_core::hashing::hash_reader(std::fs::File::open(&dest)?, |_| true)?;
        if copy_hashes.sha256 != read_hashes.sha256 {
            anyhow::bail!("{}: the copy does not match the bytes read", e.path);
        }
        copied.push(serde_json::json!({"path": e.path, "mft_record": e.record, "deleted": e.deleted, "bytes": e.size, "saved_as": dest.display().to_string(), "hashes": read_hashes}));
    }
    let first_dest = dir.join(fsa.files[parts[0] as usize].e.name.chars().map(|c| if c.is_alphanumeric() || ".-_ ()[]".contains(c) { c } else { '_' }).collect::<String>());
    let ev = Evidence::open(&first_dest).map_err(|e| anyhow::anyhow!("extracted, but it does not open as an image: {:#} (a differencing disk needs its parent extracted too)", e))?;
    let rec = kokino_core::case::EvidenceRecord {
        id: new_id.clone(),
        name: first.e.name.clone(),
        path: first_dest.display().to_string(),
        format: ev.format_label(),
        size: ev.size,
        added: kokino_core::time::now_iso(),
        notes: format!("Extracted from evidence \"{}\" ({}), file {}{} on volume {} {}", src.name, eid, first.e.path, if first.e.deleted { " (deleted)" } else { "" }, fsa.volume.index, tag),
        hashes: None,
        hashed_at: None,
        expected: None,
        embedded: ev.ewf_info().filter(|i| i.md5.is_some() || i.sha1.is_some()).map(|i| kokino_core::hashing::Hashes { md5: i.md5.clone().unwrap_or_default(), sha1: i.sha1.clone().unwrap_or_default(), sha256: String::new() }),
        acquisition: ev.ewf_info().map(serde_json::to_value).transpose()?,
    };
    case.save_evidence(&rec)?;
    case.audit.append(user, "evidence.extract", serde_json::json!({"from_evidence": eid, "fs": fi, "format": format, "files": copied, "record": rec}))?;
    Ok(new_id)
}

/// Carve unallocated space, then rebuild the text index so carved
/// documents become searchable.
pub fn spawn_carve(st: Arc<AppState>, user: &str, cid: String, eid: String) -> Arc<Job> {
    let job = new_job(&st, "carve", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| run_carve(&st, &j, &user, &cid, &eid).and_then(|_| run_index(&st, &j, &user, &cid, &eid)).and_then(|_| run_photos(&st, &j, &user, &cid, &eid)));
        j.finish(&res);
    });
    job
}

/// (Re)analyze the pictures of analyzed evidence.
pub fn spawn_photos(st: Arc<AppState>, user: &str, cid: String, eid: String) -> Arc<Job> {
    let job = new_job(&st, "photos", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| run_photos(&st, &j, &user, &cid, &eid));
        j.finish(&res);
    });
    job
}

pub fn load_photos(case: &kokino_core::case::Case, eid: &str) -> Option<kokino_analysis::photo::PhotoScan> {
    let p = case.photos_path(eid).ok()?;
    kokino_core::case::read_json::<kokino_analysis::photo::PhotoScan>(&p).ok().filter(|c| c.schema == kokino_analysis::photo::PHOTO_SCHEMA)
}

fn run_photos(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str) -> anyhow::Result<()> {
    let case = st.case(cid)?;
    let l = st.loaded(cid, eid)?;
    let carved = load_carved(&case, eid);
    let res = kokino_analysis::photo::scan(&l.evidence, &l.analysis, carved.as_ref(), &mut |s, d, t| job.progress(s, d, t))?;
    let path = case.photos_path(eid)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_json(&path, &res)?;
    let mut found: std::collections::BTreeMap<&str, u64> = Default::default();
    for f in res.images.iter().flat_map(|i| &i.findings) {
        *found.entry(f.id.as_str()).or_default() += 1;
    }
    case.audit.append(user, "evidence.photos", serde_json::json!({"evidence": eid, "images": res.images.len(), "flagged": res.images.iter().filter(|i| i.flagged()).count(), "findings": found, "skipped": res.skipped}))?;
    Ok(())
}

pub fn load_carved(case: &kokino_core::case::Case, eid: &str) -> Option<kokino_analysis::carve::CarveResult> {
    let p = case.carved_path(eid).ok()?;
    kokino_core::case::read_json::<kokino_analysis::carve::CarveResult>(&p).ok().filter(|c| (1..=kokino_analysis::carve::CARVE_SCHEMA).contains(&c.schema))
}

fn run_carve(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str) -> anyhow::Result<()> {
    let case = st.case(cid)?;
    let l = st.loaded(cid, eid)?;
    let res = kokino_analysis::carve::carve(&l.evidence, &l.analysis, &mut |s, d, t| job.progress(s, d, t))?;
    let path = case.carved_path(eid)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_json(&path, &res)?;
    let mut kinds: std::collections::BTreeMap<&str, u64> = Default::default();
    for f in &res.files {
        *kinds.entry(f.kind.as_str()).or_default() += 1;
    }
    case.audit.append(user, "evidence.carve", serde_json::json!({"evidence": eid, "files": res.files.len(), "kinds": kinds, "scanned_bytes": res.scanned_bytes, "truncated": res.truncated}))?;
    Ok(())
}

/// (Re)build only the text index of analyzed evidence.
pub fn spawn_index(st: Arc<AppState>, user: &str, cid: String, eid: String) -> Arc<Job> {
    let job = new_job(&st, "index", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| run_index(&st, &j, &user, &cid, &eid));
        j.finish(&res);
    });
    job
}

fn run_index(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str) -> anyhow::Result<()> {
    let case = st.case(cid)?;
    let l = st.loaded(cid, eid)?;
    let path = case.index_path(eid)?;
    let carved = load_carved(&case, eid);
    let stats = kokino_analysis::textindex::build(&l.evidence, &l.analysis, carved.as_ref(), &path, &mut |s, d, t| job.progress(s, d, t))?;
    case.audit.append(user, "evidence.index", serde_json::json!({"evidence": eid, "stats": stats}))?;
    Ok(())
}

fn run_ingest(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str, rehash: bool, reanalyze: bool) -> anyhow::Result<()> {
    let case = st.case(cid)?;
    let mut rec = case.evidence_by_id(eid)?;
    let ev = Evidence::open(&rec.path)?;

    if rehash || rec.hashes.is_none() {
        let total = ev.size;
        let (hashes, n) = kokino_core::hashing::hash_reader(ev.reader()?, |d| job.progress("Hashing (MD5, SHA-1, SHA-256)", d, total))?;
        let check = |x: &kokino_core::hashing::Hashes| {
            (x.md5.is_empty() || x.md5.eq_ignore_ascii_case(&hashes.md5))
                && (x.sha1.is_empty() || x.sha1.eq_ignore_ascii_case(&hashes.sha1))
                && (x.sha256.is_empty() || x.sha256.eq_ignore_ascii_case(&hashes.sha256))
        };
        let verified = rec.expected.as_ref().map(check);
        let embedded = rec.embedded.as_ref().map(check);
        case.audit.append(
            user,
            "evidence.hash",
            serde_json::json!({"evidence": eid, "bytes": n, "hashes": hashes, "matches_expected": verified, "matches_embedded": embedded}),
        )?;
        if rec.size != n {
            // The file changed size since it was added: record it, the audit
            // entry above already holds the new hashes.
            case.audit.append(user, "evidence.size_changed", serde_json::json!({"evidence": eid, "was": rec.size, "now": n}))?;
            rec.size = n;
        }
        rec.hashes = Some(hashes);
        rec.hashed_at = Some(kokino_core::time::now_iso());
        case.save_evidence(&rec)?;
    }

    let path = case.analysis_path(eid)?;
    if reanalyze || !path.exists() {
        st.invalidate(cid, eid);
        let analysis = kokino_analysis::analyze(&ev, &mut |s, d, t| job.progress(s, d, t))?;
        job.progress("Saving results", 0, 1);
        write_json(&path, &analysis)?;
        let summary: Vec<serde_json::Value> = analysis
            .filesystems
            .iter()
            .map(|f| serde_json::json!({"volume": f.volume.index, "entries": f.files.len(), "likelihood": f.score.likelihood, "indicators": f.indicators.iter().map(|i| (&i.id, i.count)).collect::<Vec<_>>()}))
            .collect();
        case.audit.append(
            user,
            "evidence.analyze",
            serde_json::json!({"evidence": eid, "schema": analysis.schema, "filesystems": summary, "errors": analysis.errors}),
        )?;
        st.put(cid, eid, analysis, ev);
        let _ = std::fs::remove_file(case.index_path(eid)?);
        let _ = std::fs::remove_file(case.carved_path(eid)?);
        let _ = std::fs::remove_file(case.photos_path(eid)?);
        let _ = std::fs::remove_file(case.hashes_path(eid)?);
    }
    if !case.carved_path(eid)?.exists() {
        run_carve(st, job, user, cid, eid)?;
    }
    if !case.index_path(eid)?.exists() {
        run_index(st, job, user, cid, eid)?;
    }
    if !case.photos_path(eid)?.exists() {
        run_photos(st, job, user, cid, eid)?;
    }
    if !case.hashes_path(eid)?.exists() {
        run_filehash(st, job, user, cid, eid, false)?;
    }
    Ok(())
}

/// Hash analysis: hash every file (unless done and `rehash` is false),
/// then look the hashes up in the enabled hash sets.
pub fn spawn_filehash(st: Arc<AppState>, user: &str, cid: String, eid: String, rehash: bool) -> Arc<Job> {
    let job = new_job(&st, "hashes", user, &cid, &eid);
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| run_filehash(&st, &j, &user, &cid, &eid, rehash));
        j.finish(&res);
    });
    job
}

fn run_filehash(st: &AppState, job: &Job, user: &str, cid: &str, eid: &str, rehash: bool) -> anyhow::Result<()> {
    use kokino_analysis::hashsets::{self, SetKind};
    let case = st.case(cid)?;
    let path = case.hashes_path(eid)?;
    let old = if rehash { None } else { st.hash_status(cid, eid).map(|h| h.fh.clone()) };
    let fresh = old.is_none();
    let mut fh = match old {
        Some(f) => f,
        None => {
            let l = st.loaded(cid, eid)?;
            hashsets::hash_files(&l.evidence, &l.analysis, &mut |s, d, t| job.progress(s, d, t))?
        }
    };
    let m = st.hashsets.matcher()?;
    hashsets::match_sets(&mut fh, &m, &mut |s, d, t| job.progress(s, d, t))?;
    drop(m);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Compact JSON: a large disk has hundreds of thousands of files.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&fh)?)?;
    std::fs::rename(&tmp, &path)?;
    let sets: Vec<serde_json::Value> = fh.sets.iter().map(|s| serde_json::json!({"id": s.id, "name": s.name, "kind": s.kind, "source": s.source, "source_sha256": s.source_sha256})).collect();
    case.audit.append(
        user,
        "evidence.filehash",
        serde_json::json!({"evidence": eid, "hashed": if fresh { "now" } else { "earlier" }, "files": fh.files.len(), "bytes": fh.bytes, "unreadable": fh.errors(), "known": fh.count(SetKind::Known), "notable": fh.count(SetKind::Notable), "sets": sets}),
    )?;
    st.put_hashes(cid, eid, fh);
    Ok(())
}

/// Imports a hash set (system-wide; the job belongs to no case).
pub fn spawn_hashset_import(st: Arc<AppState>, user: &str, src: std::path::PathBuf, name: String, kind: kokino_analysis::hashsets::SetKind, description: String) -> Arc<Job> {
    let job = new_job(&st, "hashset", user, "", "");
    let j = job.clone();
    tokio::task::spawn_blocking(move || {
        let user = j.view.lock().unwrap().user.clone();
        let res = guarded(|| {
            st.hashsets.import(&src, &name, kind, &description, &user, &mut |s, d, t| j.progress(s, d, t)).and_then(|info| {
                st.users.audit.append(&user, "hashset.import", serde_json::json!({"set": info, "path": src.to_string_lossy()}))?;
                Ok(())
            })
        });
        j.finish(&res);
    });
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ISO stored on the Linux test image, extracted as evidence of its own.
    #[test]
    fn extracts_nested_image() {
        let img = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/linux-server.img");
        let iso = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/iso-rr-joliet.iso");
        if !img.exists() || !iso.exists() {
            return;
        }
        let root = std::env::temp_dir().join(format!("kokino-extract-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let st = AppState::new(root.clone(), 7311, false, vec![]).unwrap();
        let case = kokino_core::case::Case::create(&root, "Nested", "tester", "").unwrap();
        let cid = case.info.id.clone();
        let ev = Evidence::open(&img).unwrap();
        let rec = kokino_core::case::EvidenceRecord { id: "src1".into(), name: "linux-server.img".into(), path: img.display().to_string(), format: ev.format_label(), size: ev.size, added: String::new(), notes: String::new(), hashes: None, hashed_at: None, expected: None, embedded: None, acquisition: None };
        case.save_evidence(&rec).unwrap();
        let a = kokino_analysis::analyze(&ev, &mut |_, _, _| true).unwrap();
        st.put(&cid, "src1", a, ev);
        let l = st.loaded(&cid, "src1").unwrap();
        let files = &l.analysis.filesystems[0].files;
        let mut read = |e: &kokino_ntfs::FsEntry, off: u64, n: usize| l.read_file(0, e, "", off, n).unwrap_or_default();
        let found = kokino_analysis::nested::find(files, &mut read);
        assert_eq!(found.len(), 1, "{:?}", found);
        assert_eq!((found[0].path.as_str(), found[0].format.as_str()), ("/home/alice/Downloads/tools.iso", "ISO 9660"));
        let job = new_job(&st, "extract", "tester", &cid, "src1");
        let id = run_extract(&st, &job, "tester", &cid, "src1", 0, found[0].file as usize).unwrap();
        let new = case.evidence_by_id(&id).unwrap();
        assert!(new.notes.starts_with("Extracted from evidence \"linux-server.img\" (src1), file /home/alice/Downloads/tools.iso on volume"), "{}", new.notes);
        assert_eq!(std::fs::read(&new.path).unwrap(), std::fs::read(&iso).unwrap());
        assert_eq!(new.size, std::fs::metadata(&iso).unwrap().len());
        // Once only; and the audit log names the source and the copy's hashes.
        assert!(run_extract(&st, &job, "tester", &cid, "src1", 0, found[0].file as usize).is_err());
        let (h, _) = kokino_core::hashing::hash_reader(std::fs::File::open(&iso).unwrap(), |_| true).unwrap();
        let log = std::fs::read_to_string(case.dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"evidence.extract\"") && log.contains(&h.sha256));
        // The extracted image is analyzed like any evidence.
        run_ingest(&st, &job, "tester", &cid, &id, true, true).unwrap();
        assert!(st.loaded(&cid, &id).unwrap().analysis.filesystems.iter().any(|f| f.volume.fs_label.contains("ISO")));
        std::fs::remove_dir_all(&root).ok();
    }
}
