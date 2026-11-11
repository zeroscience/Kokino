//! Analysis engine: turns an evidence image into files with content facts,
//! anti-forensics indicators, a likelihood score, statistics and a timeline.
//!
//! Output is deterministic for a given image and Kokino version (apart from
//! `analyzed_at` and the "future timestamp" reference time).

#![forbid(unsafe_code)]

pub mod ioc;
pub mod plugins;
pub mod antiforensics;
pub mod binview;
pub mod signatures;
pub mod carve;
pub mod doctext;
pub mod macos;
pub mod mail;
pub mod nested;
pub mod pst;
pub mod tarfs;
pub mod zipfs;
pub mod oletext;
pub mod fs;
pub mod hashsets;
pub mod linux;
pub mod photo;
pub mod stats;
pub mod textindex;
pub mod timeline;
pub mod web;
pub mod windows;

use antiforensics::{Indicator, Score};
use kokino_image::{detect_volumes, BlockCache, Evidence, FsKind, Volume};
use fs::Fs;
use kokino_ntfs::{FsEntry, NtfsVolumeInfo, UnreadableRecord};
use serde::{Deserialize, Serialize};
use signatures::Category;
use stats::Stats;

/// 2: adds `FsAnalysis::web` (browser history).
/// 3: adds `FsAnalysis::windows` (registry, event logs, Prefetch, LNK, Jump Lists).
/// 4: FAT12/16/32 and exFAT volumes are parsed too (`volume.fs` tells which).
/// 5: ext2/3/4 volumes, `FsEntry::unix` and `FsAnalysis::linux`.
/// 6: NTFS names without an MFT record (`FsEntry::name_only`), the change
///    journal, ShellBags, BAM/DAM and SRUM.
/// 7: scheduled tasks (`WindowsArtifacts::tasks`).
/// 8: Internet Explorer index.dat history, cache and downloads (`WebActivity::cache`).
/// 9: deleted registry keys and values (`WindowsArtifacts::reg_deleted_keys`).
/// 10: email (`FsAnalysis::mail`), Internet Explorer cookies, legacy .evt logs,
///     registry transaction logs applied.
pub const SCHEMA_VERSION: u32 = 10;

/// Bytes read from the start of every file for signature and entropy.
const HEAD: usize = 8 * 1024;
/// Files at least this big also get middle and tail samples.
const MULTI_SAMPLE_MIN: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRow {
    #[serde(flatten)]
    pub e: FsEntry,
    pub ext: String,
    pub sig: Option<String>,
    pub sig_label: Option<String>,
    pub category: Option<Category>,
    pub mismatch: bool,
    pub entropy: Option<f32>,
    /// Every sampled byte had this value (possible wipe, sparse or TRIM).
    pub uniform: Option<u8>,
    /// Signature of a named stream (ADS) when it is not plain text.
    pub ads_sig: Option<String>,
    /// Ids of anti-forensics indicators that matched this file.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsAnalysis {
    pub volume: Volume,
    pub info: NtfsVolumeInfo,
    pub files: Vec<FileRow>,
    pub unreadable: Vec<UnreadableRecord>,
    pub indicators: Vec<Indicator>,
    pub score: Score,
    pub stats: Stats,
    /// Browser history found on this volume (schema 2+).
    #[serde(default)]
    pub web: kokino_artifacts::browser::WebActivity,
    /// Windows system artifacts found on this volume (schema 3+).
    #[serde(default)]
    pub windows: windows::WindowsArtifacts,
    /// Linux system artifacts found on this volume (schema 5+).
    #[serde(default)]
    pub linux: linux::LinuxArtifacts,
    /// Email in mbox mailboxes and .eml files (schema 10+).
    #[serde(default)]
    pub mail: mail::Mail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub schema: u32,
    pub tool_version: String,
    pub analyzed_at: String,
    pub image_format: String,
    pub image_size: u64,
    pub volumes: Vec<Volume>,
    pub filesystems: Vec<FsAnalysis>,
    pub errors: Vec<String>,
}

/// `progress(stage, done, total)`; return false to cancel.
pub type Progress<'a> = &'a mut dyn FnMut(&str, u64, u64) -> bool;

pub fn analyze(ev: &Evidence, progress: Progress) -> anyhow::Result<Analysis> {
    let mut r = BlockCache::new(ev.reader()?)?;
    progress("Detecting volumes", 0, 1);
    let mut volumes = detect_volumes(&mut r, ev.size);
    let unlocked = kokino_image::unlocked_volumes(ev, &volumes);
    volumes.extend(unlocked);
    let mut filesystems = vec![];
    let mut errors = vec![];
    // Remarks about the virtual disk itself (unreplayed VHDX log, a parent
    // that changed after a snapshot) come first.
    if let Some((_, notes)) = ev.vdisk_info() {
        errors.extend(notes.iter().cloned());
    }

    for v in volumes.iter().filter(|v| fs::supported(v.fs)) {
        match analyze_fs(ev, v, progress) {
            Ok(fsa) => filesystems.push(fsa),
            Err(e) => {
                if e.to_string().contains("cancelled") {
                    return Err(e);
                }
                errors.push(format!("Volume {} at offset {}: {}", v.index, v.start, e));
            }
        }
    }
    for v in volumes.iter().filter(|v| !fs::supported(v.fs) && v.fs != FsKind::Unknown) {
        if v.fs == FsKind::BitLocker {
            if !volumes.iter().any(|u| u.bitlocker.as_ref().is_some_and(|b| b.of_volume == v.index)) {
                errors.push(format!("Volume {} is encrypted with BitLocker: unlock it with its password or recovery password to read it", v.index));
            }
            continue;
        }
        errors.push(format!("Volume {} ({}) detected; parser not available yet", v.index, v.fs_label));
    }
    if let Some(info) = ev.ewf_info() {
        if !info.read_errors.is_empty() {
            let n: u64 = info.read_errors.iter().map(|r| r.1).sum();
            let ranges: Vec<String> = info.read_errors.iter().take(20).map(|(s, c)| format!("{}-{}", s, s + c.saturating_sub(1))).collect();
            errors.push(format!(
                "The imaging tool recorded {} unreadable sector(s) in {} range(s): {}{}. Their content in the image is filler, not evidence.",
                n,
                info.read_errors.len(),
                ranges.join(", "),
                if info.read_errors.len() > 20 { ", ..." } else { "" }
            ));
        }
    }

    Ok(Analysis {
        schema: SCHEMA_VERSION,
        tool_version: kokino_core::TOOL_VERSION.to_string(),
        analyzed_at: kokino_core::time::now_iso(),
        image_format: ev.format_label(),
        image_size: ev.size,
        volumes,
        filesystems,
        errors,
    })
}

pub fn volume_reader(ev: &Evidence, v: &Volume) -> anyhow::Result<BlockCache<kokino_image::VolReader>> {
    Ok(BlockCache::new(kokino_image::volume_reader(ev, v)?)?)
}

fn analyze_fs(ev: &Evidence, v: &Volume, progress: Progress) -> anyhow::Result<FsAnalysis> {
    let mut r = volume_reader(ev, v)?;
    let fs = Fs::open(&mut r, v)?;
    let stage = format!("Volume {}: {}", v.index, if fs.is_ntfs() { "reading MFT" } else { "reading directories" });
    let scan = fs.scan(&mut r, |d, t| progress(&stage, d, t))?;

    let total = scan.entries.len() as u64;
    let stage = format!("Volume {}: signatures and entropy", v.index);
    let mut files = Vec::with_capacity(scan.entries.len());
    for (i, e) in scan.entries.into_iter().enumerate() {
        if i % 512 == 0 && !progress(&stage, i as u64, total) {
            anyhow::bail!("analysis cancelled");
        }
        files.push(content_facts(&fs, &mut r, e));
    }
    progress(&stage, total, total);

    // A triage collection keeps a drive's files below a folder; the artifact
    // readers see the paths as they were on the drive (same files, same order).
    let root = drive_root(&files);
    let logical: Option<Vec<FileRow>> = root.as_ref().map(|p| files.iter().map(|f| {
        let mut g = f.clone();
        if g.e.path.len() > p.len() && g.e.path[..p.len()].eq_ignore_ascii_case(p) && g.e.path.as_bytes()[p.len()] == b'/' {
            g.e.path = g.e.path[p.len()..].to_string();
        }
        g
    }).collect());
    let view: &[FileRow] = logical.as_deref().unwrap_or(&files);
    let web = web::collect(&fs, &mut r, view, &mut *progress);
    let windows = windows::collect(&fs, &mut r, view, &mut *progress);
    let linux = linux::collect(&fs, &mut r, view, &mut *progress);
    let mail = mail::collect(&fs, &mut r, view, &mut *progress);
    drop(logical);
    // Email joins the system events on the timeline.
    let mut windows = windows;
    windows.timeline.extend(mail::timeline(&mail));
    windows.timeline.sort_by_key(|t| t.t);

    progress(&format!("Volume {}: anti-forensics indicators", v.index), 0, 1);
    let now = kokino_core::time::datetime_to_filetime(chrono::Utc::now());
    let indicators = antiforensics::evaluate(&mut files, now, &web, &windows, &linux, !fs.is_ntfs());
    let score = antiforensics::score(&indicators);
    let mut stats = match &root {
        // A collection: user profiles and the system are found at the
        // paths they had on the collected drive.
        Some(p) => {
            let mapped: Vec<FileRow> = files.iter().map(|f| {
                let mut g = f.clone();
                if g.e.path.len() > p.len() && g.e.path[..p.len()].eq_ignore_ascii_case(p) && g.e.path.as_bytes()[p.len()] == b'/' {
                    g.e.path = g.e.path[p.len()..].to_string();
                }
                g
            }).collect();
            let mut s = stats::compute(&mapped, &indicators, &score, now);
            if s.os.is_none() {
                if let Some(first) = s.impact.first_mut() {
                    *first = format!("A triage collection: files collected from a computer, not a whole volume{}.", if s.users.is_empty() { String::new() } else { format!("; user profiles: {}", s.users.join(", ")) });
                }
            }
            s
        }
        None => stats::compute(&files, &indicators, &score, now),
    };
    if !scan.unreadable.is_empty() {
        stats.impact.push(format!(
            "{} MFT record(s) could not be parsed (corrupt, partially wiped or split across clusters) and are listed separately.",
            scan.unreadable.len()
        ));
    }
    if v.fs != FsKind::ExFat && fs.is_fat() {
        stats.impact.push("FAT stores times in the local time of the device that wrote them, with no time zone; they are shown as stored.".into());
    }
    if fs.is_fat() && files.iter().any(|f| f.e.deleted && !f.e.is_dir) {
        stats.impact.push("Deleted FAT files are recovered assuming their clusters were contiguous (the chain is cleared on delete); content of fragmented deleted files can be partly wrong.".into());
    }

    stats.impact.extend(scan.notes.iter().cloned());
    if let Some(p) = &root {
        stats.impact.push(format!("Triage collection: the collected drive's files are under {}. Windows and Linux artifacts, browser history and email were read with the paths they had on the drive; checks that need a whole volume (a missing change journal or event log) are not made from them.", p));
    }
    stats.impact.extend(web::impact(&web));
    stats.impact.extend(windows::impact(&windows));
    stats.impact.extend(linux::impact(&linux));
    stats.impact.extend(mail::impact(&mail));

    Ok(FsAnalysis { volume: v.clone(), info: scan.info, files, unreadable: scan.unreadable, indicators, score, stats, web, windows, linux, mail })
}

/// The folder a collected drive sits in, when the volume is a triage
/// collection: KAPE puts drive C: under "C", Velociraptor under
/// "uploads/auto/C:" or "uploads/ntfs/\\.\C:". Found by the system files
/// below it; `None` when they are at the root, as on a disk.
pub fn drive_root(files: &[FileRow]) -> Option<String> {
    const MARKS: &[&str] = &["/windows/system32/config/system", "/windows/system32/config/software", "/private/etc/passwd", "/system/library/coreservices/systemversion.plist", "/etc/passwd", "/etc/os-release"];
    let mut best: Option<String> = None;
    for f in files.iter().filter(|f| !f.e.is_dir && !f.e.deleted) {
        let p = f.e.path.to_ascii_lowercase();
        for m in MARKS {
            if p.ends_with(m) && p.len() > m.len() {
                let prefix = f.e.path[..f.e.path.len() - m.len()].to_string();
                // Windows over Linux, and the shortest (outermost) prefix.
                if best.as_ref().is_none_or(|b| prefix.len() < b.len()) {
                    best = Some(prefix);
                }
            }
        }
    }
    // Only a real collection: not a copy of a system kept somewhere on a disk
    // that has its own system at the root.
    let at_root = files.iter().any(|f| MARKS.iter().any(|m| f.e.path.eq_ignore_ascii_case(m)));
    best.filter(|_| !at_root)
}

fn content_facts<R: std::io::Read + std::io::Seek>(fs: &Fs, r: &mut R, e: FsEntry) -> FileRow {
    let ext = signatures::extension(&e.name);
    let mut row = FileRow {
        ext,
        sig: None,
        sig_label: None,
        category: None,
        mismatch: false,
        entropy: None,
        uniform: None,
        ads_sig: None,
        flags: vec![],
        e,
    };
    let is_meta = (fs.is_ntfs() && row.e.record < 24) || row.e.path.starts_with("/$Extend");
    if is_meta || row.e.name_only.is_some() {
        return row;
    }
    // Named streams first: hiding a payload in the ADS of an empty file or a
    // directory is the common trick, so it must not depend on the main stream.
    let suspicious_ads: Vec<String> = row.e.ads().filter(|s| !antiforensics::benign_ads(&s.name)).map(|s| s.name.clone()).collect();
    for name in suspicious_ads {
        if let Ok(b) = fs.read(r, &row.e, &name, 0, 1024) {
            if let Some(s) = signatures::detect(&b) {
                row.ads_sig = Some(s.id.to_string());
                break;
            }
        }
    }
    if row.e.is_dir || row.e.size == 0 {
        return row;
    }
    let head = fs.read(r, &row.e, "", 0, HEAD).unwrap_or_default();
    if head.is_empty() {
        return row;
    }
    let mut samples = vec![head];
    if row.e.size >= MULTI_SAMPLE_MIN {
        for off in [row.e.size / 2, row.e.size.saturating_sub(HEAD as u64)] {
            if let Ok(b) = fs.read(r, &row.e, "", off, HEAD) {
                samples.push(b);
            }
        }
    }
    if let Some(s) = signatures::detect(&samples[0]) {
        row.sig = Some(s.id.to_string());
        row.sig_label = Some(s.label.to_string());
        row.category = Some(s.category);
        row.mismatch = signatures::is_mismatch(s, &row.ext);
    } else if row.e.deleted && row.e.error.is_none() && signatures::header_required(&row.ext) {
        // Typical on cameras: the clusters were reused by a later file that
        // was itself deleted, so they are free again but hold other data.
        row.e.error = Some(format!("The recovered content does not start with a .{} header: its first cluster was overwritten (possibly by a file deleted since). Try the carved files.", row.ext));
    }
    let all: Vec<u8> = samples.concat();
    row.entropy = Some((signatures::entropy(&all) * 1000.0).round() / 1000.0);
    let refs: Vec<&[u8]> = samples.iter().map(|s| s.as_slice()).collect();
    if all.len() >= 512 {
        row.uniform = signatures::uniform_byte(&refs);
    }
    row
}

pub fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/testfs1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyzes_fixture() {
        let p = fixture_path();
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        assert_eq!(a.filesystems.len(), 1);
        let fs = &a.filesystems[0];
        assert!(fs.files.len() > 500);
        assert!(fs.score.likelihood >= 0.0 && fs.score.likelihood <= 1.0);
        let tl = timeline::build(&fs.files, &fs.web, &fs.windows, &fs.linux.timeline);
        assert!(!tl.is_empty());
        assert!(tl.windows(2).all(|w| w[0].t <= w[1].t));
    }

    /// Ground truth from scripts/fixture_browsers.py, planted by
    /// make_af_fixture.py under /Users/alice.
    #[test]
    fn finds_planted_browser_history() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-af.img");
        if !p.exists() {
            return;
        }
        let a = analyze(&Evidence::open(&p).unwrap(), &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        let w = &fs.web;
        let src = |b: &str| w.sources.iter().position(|s| s.browser == b).unwrap_or_else(|| panic!("{b} profile missing")) as u32;
        let (chrome, edge, firefox) = (src("Chrome"), src("Edge"), src("Firefox"));
        for s in &w.sources {
            assert!(s.error.is_none(), "{}: {:?}", s.browser, s.error);
            assert_eq!(s.user, "alice");
        }
        let iso = |t: u64| kokino_core::time::filetime_to_iso(t);

        // Chrome: typed search, link visits, one URL-only page, a download.
        let c = &w.sources[chrome as usize];
        assert_eq!((c.profile.as_str(), c.visits, c.urls, c.downloads), ("Default", 4, 5, 1));
        let cv: Vec<_> = w.visits.iter().filter(|v| v.src == chrome).collect();
        assert_eq!(iso(cv[0].t), "2026-10-20T09:00:05.0000000Z");
        assert!(cv[0].typed && cv[0].how == "typed");
        let orphan = cv.iter().find(|v| v.url_only).expect("URL-only page");
        assert!(orphan.url.contains("files.example.test") && orphan.visit_count == 3);
        let d = w.downloads.iter().find(|d| d.src == chrome).unwrap();
        assert_eq!(d.url, "https://download.sysinternals.com/files/SDelete.zip");
        assert_eq!(d.target, r"C:\Users\alice\Downloads\SDelete.zip");
        assert_eq!((d.state.as_str(), d.received, iso(d.end).as_str()), ("complete", 851264, "2026-10-20T09:02:03.0000000Z"));
        let cs: Vec<(&str, &str)> = w.searches.iter().filter(|s| s.src == chrome).map(|s| (s.term.as_str(), s.how.as_str())).collect();
        assert!(cs.contains(&("how to permanently delete files", "keyword table")), "{cs:?}");
        assert!(cs.contains(&("secure erase ssd", "url")), "{cs:?}");
        assert_eq!(cs.len(), 2, "the Google search must not be counted twice");

        // Edge: schema present, history empty.
        assert_eq!((w.sources[edge as usize].visits, w.sources[edge as usize].urls), (0, 0));

        // Firefox: the WAL must be applied; two visits and the download live only there.
        let f = &w.sources[firefox as usize];
        assert!(f.wal);
        assert_eq!((f.profile.as_str(), f.visits, f.downloads), ("k3x9w2qe.default-release", 4, 1));
        let fd = w.downloads.iter().find(|d| d.src == firefox).unwrap();
        assert_eq!(fd.target, r"C:\Users\alice\Downloads\VeraCrypt_Setup_x64_1.26.7.exe");
        assert_eq!((fd.state.as_str(), fd.total), ("complete", 38457616));
        assert!(w.searches.iter().any(|s| s.src == firefox && s.term == "veracrypt hidden volume" && s.engine == "DuckDuckGo"));

        // Indicators point at the database files.
        let rec = |path: &str| fs.files.iter().find(|x| x.e.path == path).unwrap().e.record;
        let ind = |id: &str| fs.indicators.iter().find(|i| i.id == id).unwrap_or_else(|| panic!("{id} missing"));
        let edge_db = rec("/Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History");
        assert_eq!(ind("browser_history_cleared").records, vec![edge_db]);
        let web_ind = ind("antiforensic_web");
        assert_eq!(web_ind.count, 4, "SDelete download, two Chrome searches, one Firefox search");
        assert!(web_ind.records.contains(&rec("/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History")));

        // Web events are on the timeline.
        let tl = timeline::build(&fs.files, &fs.web, &fs.windows, &fs.linux.timeline);
        assert_eq!(tl.iter().filter(|e| e.src == "DL").count(), 2);
        assert!(tl.iter().any(|e| e.src == "SEARCH"));
    }

    /// The same disk as raw and as E01 must give identical results.
    #[test]
    fn e01_and_raw_agree() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let (raw, e01) = (dir.join("disk-af.img"), dir.join("disk-af.E01"));
        if !raw.exists() || !e01.exists() {
            return;
        }
        let a = analyze(&Evidence::open(&raw).unwrap(), &mut |_, _, _| true).unwrap();
        let b = analyze(&Evidence::open(&e01).unwrap(), &mut |_, _, _| true).unwrap();
        assert_eq!(b.image_format, "EWF (E01)");
        assert_eq!(serde_json::to_value(&a.volumes).unwrap(), serde_json::to_value(&b.volumes).unwrap());
        assert_eq!(a.filesystems.len(), b.filesystems.len());
        for (x, y) in a.filesystems.iter().zip(&b.filesystems) {
            assert_eq!(serde_json::to_value(&x.files).unwrap(), serde_json::to_value(&y.files).unwrap());
            let ids = |f: &FsAnalysis| f.indicators.iter().map(|i| (i.id.clone(), i.count)).collect::<Vec<_>>();
            assert_eq!(ids(x), ids(y));
            assert_eq!(x.score.likelihood, y.score.likelihood);
        }
    }

    /// Windows artifacts planted by scripts/make_win_fixture.py: every
    /// parser through the NTFS layer, and the facts an examiner relies on.
    #[test]
    fn finds_windows_artifacts() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-win.img");
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        let w = &fs.windows;
        assert!(w.sources.iter().all(|s| s.error.is_none()), "{:?}", w.sources);
        assert_eq!(w.computer.name, "LAB-PC");
        assert_eq!((w.computer.os.as_str(), w.computer.build.as_str()), ("Windows 10 Pro", "19045.4170"));
        assert_eq!(w.computer.active_bias_minutes, Some(-120));
        let alice = w.users.iter().find(|u| u.name == "alice").unwrap();
        assert_eq!((alice.rid, alice.logon_count, alice.profile.as_str()), (Some(1001), 214, "C:\\Users\\alice"));
        assert!(w.users.iter().any(|u| u.name == "Administrator" && u.disabled));
        let usb = w.usb.iter().find(|u| u.serial == "4C530001231109115023").unwrap();
        assert_eq!((usb.vendor.as_str(), usb.drive_letter.as_str()), ("SanDisk", "E:"));
        assert!(usb.first_connected > 0 && usb.last_removed > usb.first_connected);
        assert!(w.networks.iter().any(|n| n.name == "LabWiFi" && n.gateway_mac == "02:00:5e:10:aa:01" && n.kind == "wireless"));
        assert!(w.programs.iter().any(|p| p.name == "CCleaner" && p.wow64));
        assert!(w.autoruns.iter().any(|r| r.kind == "Service" && r.command.contains("updsvc") && r.unusual));
        assert!(!w.autoruns.iter().any(|r| r.name == "OneDrive" && r.unusual));
        let pf = w.execution.iter().find(|x| x.source == "Prefetch" && x.program.ends_with("SDELETE64.EXE")).unwrap();
        assert_eq!((pf.count, pf.times.len(), pf.tool), (Some(3), 3, true));
        assert!(w.execution.iter().any(|x| x.source == "UserAssist" && x.program == "C:\\Program Files\\VeraCrypt\\VeraCrypt.exe" && x.count == Some(2)));
        assert!(w.execution.iter().any(|x| x.source == "Amcache" && x.sha1 == "3f2a9c7d1e5b8a6f4c3d2e1f0a9b8c7d6e5f4a3b"));
        assert_eq!(w.execution.iter().filter(|x| x.source == "ShimCache").count(), 4);
        let jl = w.access.iter().find(|x| x.source == "Jump List" && x.path == "E:\\Projects\\nightjar.docx").unwrap();
        assert_eq!((jl.count, jl.pinned, jl.volume_label.as_str(), jl.drive_type.as_str()), (Some(4), true, "BACKUP", "removable"));
        assert!(w.access.iter().any(|x| x.source == "LNK" && x.path == "E:\\Projects\\nightjar.docx" && x.mac == "00:0c:29:ab:cd:ef"));
        assert!(w.access.iter().any(|x| x.source == "Explorer search" && x.path == "nightjar" && x.time > 0));
        assert!(w.access.iter().any(|x| x.source == "RunMRU" && x.path == "powershell -ep bypass"));
        let cleared: Vec<&str> = w.events.iter().filter(|e| e.category == "Log cleared").map(|e| e.summary.as_str()).collect();
        assert_eq!(cleared, vec!["Security log cleared by alice", "Windows PowerShell log cleared by alice"]);
        let rdp = w.events.iter().find(|e| e.event_id == 4624 && e.ip == "203.0.113.50" && e.summary.contains("remote desktop")).unwrap();
        assert_eq!(rdp.user, "alice");
        assert_eq!(w.events.iter().filter(|e| e.event_id == 4625).count(), 5);
        assert!(w.events.iter().any(|e| e.event_id == 4732 && e.summary.contains("svc_backup (S-1-5-21-")));
        assert!(w.events.iter().find(|e| e.event_id == 1074).map(|e| e.ip.is_empty()).unwrap());
        assert!(w.events.iter().any(|e| e.event_id == 4104 && e.summary.contains("Invoke-WebRequest")));
        for id in ["log_cleared_event", "tool_execution_record", "wipe_tool_executed"] {
            assert!(fs.indicators.iter().any(|i| i.id == id), "{} missing", id);
        }
        let tl = timeline::build(&fs.files, &fs.web, w, &[]);
        for src in ["EXEC", "OPEN", "USB", "INST", "NET", "EVT"] {
            assert!(tl.iter().any(|e| e.src == src), "{} not in timeline", src);
        }
        assert!(fs.stats.impact.iter().any(|l| l.contains("USB storage device")));

        // BAM and DAM from SYSTEM, SIDs named.
        let bam = w.execution.iter().find(|x| x.source == "BAM" && x.program == r"\Users\alice\sdelete64.exe").expect("BAM entry");
        assert_eq!((bam.user.as_str(), bam.tool, bam.detail.as_str()), ("alice", true, "last run, from HarddiskVolume3"));
        assert_eq!(kokino_core::time::filetime_to_iso(bam.times[0]), "2026-10-20T09:41:30.0000000Z");
        assert!(w.execution.iter().any(|x| x.source == "BAM" && x.program == "Microsoft.Windows.Explorer"));
        assert!(w.execution.iter().any(|x| x.source == "DAM" && x.program.ends_with("notepad.exe")));

        // SRUM written by esent.dll (scripts/make_srum_fixture.py).
        let s = w.srum.as_ref().expect("SRUM");
        assert!(s.error.is_none() && !s.dirty, "{:?}", s.error);
        assert_eq!((s.network.len(), s.usage.len(), s.connections.len(), s.dropped), (303, 3, 1, 0));
        let rc = &s.apps[0];
        assert_eq!((rc.app.as_str(), rc.user.as_str()), (r"\Users\alice\AppData\Local\Temp\rclone.exe", "alice"));
        assert_eq!((rc.sent, rc.received, rc.read, rc.written, rc.foreground, rc.records), (2_147_483_648, 4_194_304, 2_147_483_648, 12_288, 3_000_000, 5));
        assert_eq!(kokino_core::time::filetime_to_iso(rc.first), "2026-10-20T10:00:00.0000000Z");
        let n = s.network.iter().find(|n| n.app.ends_with("rclone.exe")).unwrap();
        assert_eq!((n.interface.as_str(), n.profile.as_str()), ("Wi-Fi", "LabWiFi"));
        assert!(s.apps.iter().any(|a| a.app == "wuauserv (service)" && a.user == "S-1-5-18" && a.received == 25_000_000));
        let c = &s.connections[0];
        assert_eq!((kokino_core::time::filetime_to_iso(c.start).as_str(), c.seconds, c.profile.as_str()), ("2026-10-20T08:55:00.0000000Z", 7500, "LabWiFi"));
        assert_eq!(kokino_core::time::filetime_to_iso(s.first), "2026-10-07T22:00:00.0000000Z");
        assert_eq!(w.timeline.iter().filter(|t| t.kind == "NET" && t.detail.contains("(SRUM)") && t.what.ends_with("rclone.exe")).count(), 2);
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("SRUM covers") && l.contains("rclone.exe (2048 MiB)")), "{:?}", fs.stats.impact);
        assert!(w.sources.iter().any(|x| x.kind == "Wi-Fi profile" && x.error.is_none()));

        // Scheduled tasks (fixture_windows.py TASKS).
        assert_eq!(w.tasks.len(), 4, "{:?}", w.tasks.iter().map(|k| &k.path).collect::<Vec<_>>());
        let task = |p: &str| w.tasks.iter().find(|k| k.path == p).unwrap_or_else(|| panic!("task {} missing", p));
        let up = task(r"\Updater Check");
        assert_eq!(up.command(), r"C:\Users\Public\updsvc.exe -silent");
        assert_eq!((up.user.as_str(), up.author.as_str(), up.run_level.as_str()), ("alice", r"LAB-PC\alice", "HighestAvailable"));
        assert_eq!(up.triggers, vec![r"at logon of LAB-PC\alice".to_string(), "once at 2026-10-21T04:20:00, repeated every 5 min".into()]);
        assert_eq!(kokino_core::time::filetime_to_iso(up.created), "2026-10-21T02:16:40.0000000Z");
        assert_eq!(kokino_core::time::filetime_to_iso(up.last_run), "2026-10-21T09:00:05.0000000Z");
        assert!(up.registered && up.unusual && !up.sd_removed && !up.microsoft && up.file.is_some() && up.notes.is_empty(), "{:?}", up);
        let sync = task(r"\Microsoft\Windows\WinUpdate\Sync");
        assert_eq!(w.tasks[0].path, sync.path, "hidden tasks come first");
        assert!(sync.sd_removed && sync.microsoft && sync.unusual && sync.notes[0].contains("Tarrask"), "{:?}", sync);
        assert_eq!((sync.user.as_str(), sync.command().as_str()), ("SYSTEM", r"C:\ProgramData\winupd\svch.exe"));
        assert_eq!(sync.triggers, vec!["at startup".to_string(), "daily from 2026-10-21T04:00:00".into()]);
        let gone = task(r"\OneDrive Cleanup");
        assert!(gone.file.is_none() && gone.registered && gone.notes.iter().any(|n| n.starts_with("no task file")), "{:?}", gone);
        assert_eq!(gone.command(), r"C:\Users\alice\AppData\Local\Temp\clean.cmd");
        assert_eq!(gone.user, "alice"); // the Actions blob's context, a SID
        let defrag = task(r"\Microsoft\Windows\Defrag\ScheduledDefrag");
        assert!(defrag.microsoft && !defrag.unusual && !defrag.sd_removed && defrag.notes.is_empty(), "{:?}", defrag);
        assert_eq!(defrag.triggers, vec!["weekly from 2025-01-01T01:00:00".to_string()]);
        // Windows' own task stays out of the autoruns; the other three are in.
        let tasks_in_autoruns: Vec<&str> = w.autoruns.iter().filter(|a| a.kind == "Scheduled task").map(|a| a.location.as_str()).collect();
        assert_eq!(tasks_in_autoruns.len(), 3, "{:?}", tasks_in_autoruns);
        assert!(!tasks_in_autoruns.iter().any(|l| l.contains("Defrag")));
        assert!(w.timeline.iter().any(|t| t.kind == "EXEC" && t.what == r"\Updater Check" && t.detail.starts_with("scheduled task last ran")));
        assert!(!w.timeline.iter().any(|t| t.kind == "EXEC" && t.what.contains("Defrag")));
        assert!(fs.stats.impact.iter().any(|l| l.contains("Tarrask") && l.contains("WinUpdate")), "{:?}", fs.stats.impact);

        // Internet Explorer index.dat files (fixture_windows.py, ie_files()).
        let web = &fs.web;
        let ie: Vec<_> = web.sources.iter().enumerate().filter(|(_, s)| s.engine == Some(kokino_artifacts::browser::Engine::Ie)).collect();
        let profiles: Vec<&str> = ie.iter().map(|(_, s)| s.profile.as_str()).collect();
        assert_eq!(profiles, ["History, day 2025-03-10", "History", "Cache", "Downloads"], "{:?}", ie);
        assert!(ie.iter().all(|(_, s)| s.error.is_none() && s.user == "alice"));
        let (day, daysrc) = (ie[0].0 as u32, ie[0].1);
        // The search, the bank page and the deleted upload page; the :Host: entry is not a visit.
        assert_eq!((daysrc.visits, daysrc.searches, daysrc.recovered), (3, 1, 1));
        assert!(daysrc.note.contains("UTC+01:00"), "{}", daysrc.note);
        let iso = |t: u64| kokino_core::time::filetime_to_iso(t);
        let dv: Vec<_> = web.visits.iter().filter(|v| v.src == day).collect();
        assert_eq!(iso(dv[0].t), "2025-03-10T09:15:00.0000000Z");
        assert!(dv.iter().any(|v| v.url == "http://drop.test/upload.html" && v.recovered));
        assert!(web.searches.iter().any(|s| s.src == day && s.term == "clear ie history" && s.engine == "Bing"));
        // Main history: the bank page repeats the daily file's visit and is shown once.
        let (main, mainsrc) = (ie[1].0 as u32, ie[1].1);
        assert_eq!(mainsrc.visits, 2);
        assert!(mainsrc.note.contains("1 last visit that is also in a daily"), "{}", mainsrc.note);
        assert!(web.visits.iter().any(|v| v.src == main && v.url == "file:///C:/Users/alice/Documents/plan.docx"));
        assert_eq!(web.visits.iter().filter(|v| v.url == "http://bank.test/transfer.html").count(), 1);
        // Cache: one entry, one LEAK.
        let cache = ie[2].0 as u32;
        let ce: Vec<_> = web.cache.iter().filter(|c| c.src == cache).collect();
        assert_eq!(ce.len(), 2);
        assert_eq!((ce[0].file.as_str(), ce[0].content_type.as_str(), ce[0].hits), ("QW12ER34\\logo[1].png", "image/png", 3));
        assert!(ce[1].leak && !ce[1].recovered && ce[1].url == "http://drop.test/upload.js");
        // Downloads.
        let dl = web.downloads.iter().find(|d| d.src == ie[3].0 as u32).unwrap();
        assert_eq!((dl.url.as_str(), dl.target.as_str(), dl.referrer.as_str(), dl.state.as_str(), dl.received), ("http://tools.test/sdelete.zip", "C:\\Users\\alice\\Downloads\\sdelete.zip", "http://www.bing.com/search?q=sdelete", "complete", 4096));
        let tl = timeline::build(&fs.files, web, w, &[]);
        assert!(tl.iter().any(|e| e.src == "VISIT" && web.visits[e.idx as usize].url == "http://drop.test/upload.html"));
        // Cache, downloads and daily files never count as a cleared history; the
        // search and the SDelete download count as anti-forensic research.
        let ie_recs: Vec<u64> = ie.iter().map(|(_, s)| s.record).collect();
        assert!(fs.indicators.iter().filter(|i| i.id == "browser_history_cleared").all(|i| i.records.iter().all(|r| !ie_recs.contains(r))));
        let afw = fs.indicators.iter().find(|i| i.id == "antiforensic_web").expect("antiforensic_web");
        assert!(afw.records.contains(&ie[0].1.record) && afw.records.contains(&ie[3].1.record), "{:?}", afw);
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("Internet Explorer history, day 2025-03-10 of user alice: 3 visits, 1 search") && l.contains("1 deleted entry recovered")), "{:?}", fs.stats.impact);

        // UsrClass.dat was not flushed: the sector with BagMRU is only in its
        // .LOG1, so the ShellBags checked above prove the replay.
        let usr = w.sources.iter().find(|s| s.path.ends_with("/UsrClass.dat")).unwrap();
        assert!(usr.error.is_none() && usr.note.as_deref().is_some_and(|n| n.contains("applied from LOG1 (1 log entry, 1 pages)")), "{:?}", usr);
        // Deleted registry keys and values (fixture_windows.py, hive_ntuser and hive_usrclass).
        let keys: Vec<(&str, &str, bool)> = w.reg_deleted_keys.iter().map(|k| (k.hive.as_str(), k.path.as_str(), k.complete_path)).collect();
        assert_eq!(keys, [
            ("HKU\\alice (NTUSER.DAT)", "Software\\Microsoft\\Internet Explorer", true),
            ("HKU\\alice (NTUSER.DAT)", "Software\\Microsoft\\Internet Explorer\\TypedURLs", true),
            ("HKU\\alice (NTUSER.DAT)", "Software\\Sysinternals", true),
            ("HKU\\alice (NTUSER.DAT)", "Software\\Sysinternals\\SDelete", true),
        ], "{:?}", w.reg_deleted_keys);
        let typed = &w.reg_deleted_keys[1];
        assert_eq!((typed.notable.as_str(), typed.values[0].name.as_str(), typed.values[0].text.as_str()), ("addresses typed in Internet Explorer", "url1", "http://drop.test/"));
        let eula = &w.reg_deleted_keys[3];
        assert_eq!((eula.values[0].name.as_str(), eula.values[0].kind.as_str(), eula.values[0].text.as_str()), ("EulaAccepted", "REG_DWORD", "1"));
        assert_eq!(iso(eula.last_written), "2026-10-20T10:19:00.0000000Z");
        let vals: Vec<(&str, &str, &str, &str)> = w.reg_deleted_values.iter().map(|v| (v.hive.as_str(), v.key.as_str(), v.name.as_str(), v.text.as_str())).collect();
        assert!(vals.contains(&("HKU\\alice (NTUSER.DAT)", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", "c", "sdelete64 plan.docx\\1")), "{:?}", vals);
        assert!(vals.contains(&("HKU\\alice (UsrClass.dat)", "", "LastFile", "C:\\Users\\alice\\Desktop\\keys.txt")), "{:?}", vals);
        assert_eq!(vals.len(), 2, "{:?}", vals);
        assert!(w.reg_deleted_values.iter().find(|v| v.name == "c").unwrap().notable == "Run box history");
        assert!(w.timeline.iter().any(|t| t.kind == "REG" && t.what == "HKU\\alice (NTUSER.DAT)\\Software\\Microsoft\\Internet Explorer\\TypedURLs" && t.detail.contains("addresses typed")));
        let tl = timeline::build(&fs.files, &fs.web, w, &[]);
        assert!(tl.iter().any(|e| e.src == "REG"));
        assert!(fs.indicators.iter().any(|i| i.id == "registry_traces_deleted" && i.count == 1), "{:?}", fs.indicators.iter().map(|i| (&i.id, i.count)).collect::<Vec<_>>());
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("4 deleted registry key(s) and 2 deleted value(s)") && l.contains("TypedURLs (addresses typed in Internet Explorer)")), "{:?}", fs.stats.impact);
        // Hives without deleted cells report nothing.
        assert!(!w.reg_deleted_keys.iter().any(|k| k.hive == "HKLM\\SOFTWARE" || k.hive == "HKLM\\SYSTEM"));

        // Change journal planted by make_win_fixture.py (journal()).
        let j = w.journal.as_ref().expect("change journal");
        assert!(j.error.is_none(), "{:?}", j.error);
        assert_eq!(j.records, 87);
        assert!(j.size > j.stored && j.created > 0, "{} {} {} {:?}", j.size, j.stored, j.created, j.max);
        let ch = |path: &str, what: &str| j.changes.iter().find(|c| c.path == path && c.what == what).unwrap_or_else(|| panic!("{} {} missing: {:?}", what, path, j.changes.iter().map(|c| (&c.path, &c.what)).collect::<Vec<_>>()));
        // A folder that exists only in the journal names its file's path.
        assert!(ch("/Users/alice/Exfil/dump.7z", "created, data extended").c.first > 0);
        ch("/Users/alice/Exfil/dump.7z", "deleted");
        assert!(ch("/Users/alice/Exfil", "deleted").dir);
        let first = ch("/Users/alice/AAAAAAAAAAAAAAAAAA.AAA", "renamed");
        assert_eq!(first.old_path, "/Users/alice/nightjar-notes.txt");
        ch("/Users/alice/ZZZZZZZZZZZZZZZZZZ.ZZZ", "deleted");
        ch("/Users/alice/report-v3.docx", "created");
        let gone = ch("/Users/alice/Pictures/chart.png", "deleted");
        assert_eq!(gone.file.map(|i| fs.files[i as usize].e.path.as_str()), Some("/Users/alice/Pictures/chart.png"));
        assert!(fs.indicators.iter().any(|i| i.id == "usn_wipe_rename" && i.count == 1));
        assert!(!fs.indicators.iter().any(|i| i.id == "usn_journal_recreated" || i.id == "usnjrnl_missing"));
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("The change journal covers")));
        assert!(tl.iter().any(|e| e.src == "USN"));

        // ShellBags from UsrClass.dat (fixture_windows.py, hive_usrclass()).
        let paths: Vec<&str> = w.shellbags.iter().map(|b| b.bag.path.as_str()).collect();
        assert_eq!(paths, vec!["This PC", "C:", r"C:\Users", r"C:\Users\alice", r"C:\Users\alice\Documents", "E:", r"E:\Projects 2026", r"E:\Nightjar leak", r"\\fileserver.lab.test\finance", r"\\fileserver.lab.test\finance\Q3"]);
        let leak = w.shellbags.iter().find(|b| b.bag.path == r"E:\Nightjar leak").unwrap();
        assert_eq!((leak.user.as_str(), leak.source.as_str(), leak.bag.mru, leak.bag.mft), ("alice", "UsrClass.dat", Some(0), Some((41, 1))));
        assert_eq!(kokino_core::time::filetime_to_iso(leak.bag.opened), "2026-10-20T09:47:00.0000000Z");
        assert_eq!(kokino_core::time::filetime_to_iso(leak.bag.created)[..19], *"2026-10-20T09:40:00");
        let projects = w.shellbags.iter().find(|b| b.bag.path == r"E:\Projects 2026").unwrap();
        assert_eq!((projects.bag.mru, projects.bag.opened), (Some(1), 0));
        assert!(w.sources.iter().any(|s| s.kind == "UsrClass.dat" && s.error.is_none()));
        assert!(fs.stats.impact.iter().any(|l| l.contains("ShellBags record 10 folder(s)")));
    }

    /// Ground truth from scripts/make_af_fixture.py: every planted trace must
    /// be found, on the right file, through the MBR partition.
    #[test]
    fn finds_planted_antiforensics() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/disk-af.img");
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        assert_eq!(a.volumes.len(), 3, "gap, NTFS, unallocated tail");
        let fs = &a.filesystems[0];
        assert_eq!(fs.volume.start, 1024 * 1024);
        let hit = |id: &str, path: &str| {
            let i = fs.indicators.iter().find(|i| i.id == id).unwrap_or_else(|| panic!("indicator {} missing", id));
            let f = fs.files.iter().find(|f| f.e.path == path).unwrap_or_else(|| panic!("{} missing", path));
            assert!(i.records.contains(&f.e.record), "{} not flagged by {}", path, id);
        };
        hit("si_before_fn", "/file-with-12345");
        hit("si_whole_second", "/file-with-12345");
        hit("sdelete_rename", "/ZZZZZZZZZZZZZZZ");
        hit("wiped_content", "/ZZZZZZZZZZZZZZZ");
        hit("ext_mismatch", "/photo01.jpg");
        hit("ads_payload", "/Users/alice/notes.txt");
        hit("wipe_tool", "/Users/alice/sdelete64.exe");
        hit("wipe_tool_executed", "/Windows/Prefetch/SDELETE64.EXE-1A2B3C4D.pf");
        hit("prefetch_empty", "/Windows/Prefetch");
        hit("evtx_cleared", "/Windows/System32/winevt/Logs");
        assert!(fs.indicators.iter().any(|i| i.id == "usnjrnl_missing"));
        assert!(!fs.indicators.iter().any(|i| i.id == "ads_unusual"));
        assert_eq!(fs.stats.users, vec!["alice".to_string()]);
        assert!(fs.score.likelihood > 0.9);
    }

    /// Ground truth from scripts/make_ext_fixture.py (linux-server.img).
    /// Triage collections: the Windows test artifacts as Velociraptor and
    /// KAPE pack them in a ZIP (scripts/make_collection_fixture.py).
    #[test]
    fn triage_collections() {
        for (name, prefix) in [("collection-velociraptor.zip", "/uploads/auto/C:"), ("collection-kape.zip", "/C")] {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name);
            assert!(p.exists(), "{} missing: run scripts/make_collection_fixture.py", name);
            let ev = Evidence::open(&p).unwrap();
            let a = analyze(&ev, &mut |_, _, _| true).unwrap();
            assert_eq!(a.filesystems.len(), 1, "{name}: {:?}", a.errors);
            let fs = &a.filesystems[0];
            assert_eq!(fs.volume.fs, FsKind::Zip);
            assert!(fs.files.iter().any(|f| f.e.path == format!("{prefix}/Windows/System32/config/SYSTEM")), "{name}");
            assert_eq!(drive_root(&fs.files).as_deref(), Some(prefix));
            // The same artifacts as on disk-win.img.
            let w = &fs.windows;
            assert_eq!(w.computer.name, "LAB-PC", "{name}: {:?}", w.sources);
            assert_eq!(w.tasks.len(), 4, "{name}");
            assert!(w.reg_deleted_keys.iter().any(|k| k.path.ends_with("TypedURLs")), "{name}");
            assert!(fs.web.sources.iter().any(|s| s.browser == "Internet Explorer"), "{name}");
            assert!(fs.stats.impact.iter().any(|l| l.starts_with(&format!("Triage collection: the collected drive's files are under {prefix}."))), "{name}: {:?}", fs.stats.impact);
            // Whole-volume checks are not made from a collection.
            assert!(!fs.indicators.iter().any(|i| i.id == "usnjrnl_missing" || i.id == "evtx_cleared"), "{name}: {:?}", fs.indicators.iter().map(|i| &i.id).collect::<Vec<_>>());
            // Files read back from the ZIP: the SYSTEM hive starts with regf.
            let mut r = volume_reader(&ev, &fs.volume).unwrap();
            let f = Fs::open(&mut r, &fs.volume).unwrap();
            let sys = fs.files.iter().find(|x| x.e.name == "SYSTEM").unwrap();
            assert_eq!(&f.read(&mut r, &sys.e, "", 0, 4).unwrap(), b"regf");
        }
    }

    /// A UAC collection (tar.gz): the Linux server of linux-server.img,
    /// collected under [root]/, gives the same findings as the disk.
    #[test]
    fn uac_collection() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/collection-uac.tar.gz");
        assert!(p.exists(), "run scripts/make_collection_fixture.py");
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        assert_eq!(a.filesystems.len(), 1, "{:?}", a.errors);
        let fs = &a.filesystems[0];
        assert_eq!(fs.volume.fs, FsKind::Tar);
        assert_eq!(fs.info.version, "tar.gz (UAC collection)");
        assert_eq!(drive_root(&fs.files).as_deref(), Some("/[root]"));
        let l = &fs.linux;
        assert_eq!((l.computer.hostname.as_str(), l.computer.time_zone.as_str()), ("lab-srv", "Europe/Skopje"));
        let ssh = l.events.iter().find(|e| e.category == "Logon" && e.user == "alice").unwrap();
        assert_eq!(kokino_core::time::filetime_to_iso(ssh.time), "2026-10-20T08:10:01.0000000Z");
        assert_eq!(l.events.iter().filter(|e| e.category == "Failed logon").count(), 3);
        assert!(l.users.iter().any(|u| u.name == "toor" && u.note.contains("second root")));
        assert_eq!(fs.mail.messages.len(), 3);
        // Symbolic links keep their target; permissions and owners come from the archive.
        let lt = fs.files.iter().find(|f| f.e.path == "/[root]/etc/localtime").unwrap();
        assert_eq!(lt.e.unix.as_ref().unwrap().link_target.as_deref(), Some("../usr/share/zoneinfo/Europe/Skopje"));
        let pw = fs.files.iter().find(|f| f.e.path == "/[root]/etc/passwd").unwrap();
        assert_eq!(pw.e.unix.as_ref().unwrap().mode_string(), "-rw-r--r--");
        assert!(fs.files.iter().any(|f| f.e.path == "/live_response/system/uname_-a.txt"));
    }

    /// A Mac collected by UAC (scripts/make_mac_collection.py): the system,
    /// accounts, launchd persistence, quarantine downloads, KnowledgeC and
    /// the zsh history, at the paths they had on the Mac.
    #[test]
    fn mac_collection() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/collection-uac-mac.tar.gz");
        assert!(p.exists(), "run scripts/make_mac_collection.py");
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        assert_eq!(drive_root(&fs.files).as_deref(), Some("/[root]"));
        let l = &fs.linux;
        let c = &l.computer;
        assert_eq!((c.os_id.as_str(), c.hostname.as_str(), c.os.as_str()), ("macos", "LAB-MAC", "macOS 14.4.1 (23E224)"));
        // From the /private/etc/localtime link (the zone data itself was not collected).
        assert!(c.time_zone.starts_with("Europe/Skopje"), "{}", c.time_zone);
        assert_eq!(kokino_core::time::filetime_to_iso(c.fs_created), "2026-10-01T08:05:30.0000000Z");
        let users: Vec<(&str, u32, bool)> = l.users.iter().map(|u| (u.name.as_str(), u.uid, u.admin)).collect();
        assert!(users.contains(&("alice", 501, true)) && users.contains(&("bob", 502, false)) && users.iter().any(|u| u.0 == "root" && u.2), "{:?}", users);
        assert!(!users.iter().any(|u| u.0.starts_with('_')));
        let odd: Vec<&str> = l.persistence.iter().filter(|p| p.unusual).map(|p| p.name.as_str()).collect();
        assert_eq!(odd, ["com.apple.sysmond"]);
        assert!(l.persistence.iter().any(|p| p.name == "com.lab.updater" && !p.unusual));
        let dl: Vec<(&str, &str)> = l.events.iter().filter(|e| e.category == "Download").map(|e| (e.program.as_str(), e.user.as_str())).collect();
        assert_eq!(dl, [("Safari", "alice"), ("Mail", "alice")]);
        let safari = l.events.iter().find(|e| e.category == "Download" && e.program == "Safari").unwrap();
        assert!(safari.summary.contains("https://downloads.lab.test/tools.dmg"));
        assert_eq!(kokino_core::time::filetime_to_iso(safari.time), "2026-10-20T08:15:30.0000000Z");
        let apps: Vec<&str> = l.events.iter().filter(|e| e.category == "App use").map(|e| e.summary.as_str()).collect();
        assert_eq!(apps, ["com.apple.Safari in front for 10 min 0 s", "com.apple.Terminal in front for 6 min 30 s"]);
        assert!(l.commands.iter().any(|x| x.command.contains("rm -P") && x.flag == "secure deletion" && x.user == "alice"));
        assert!(l.timeline.iter().any(|t| t.what.contains("tools.dmg")), "downloads on the timeline");
        // Safari: visits (one a search), a page without visits, a download.
        let w = &fs.web;
        let s = w.sources.iter().find(|s| s.browser == "Safari").expect("Safari history");
        assert_eq!((s.user.as_str(), s.visits, s.downloads, s.searches), ("alice", 3, 1, 1));
        assert!(w.searches.iter().any(|x| x.term == "how to wipe a mac"));
        assert!(w.visits.iter().any(|v| v.url == "https://old.lab.test/forgotten" && v.url_only && v.visit_count == 3));
        let d = &w.downloads[0];
        assert_eq!((d.url.as_str(), d.target.as_str(), d.state.as_str()), ("https://downloads.lab.test/tools.dmg", "~/Downloads/tools.dmg", "complete"));
        assert_eq!(kokino_core::time::filetime_to_iso(d.start), "2026-10-20T08:15:30.0000000Z");
        // FSEvents: the removal of plan.txt and a rename, timed by the file.
        let fe: Vec<&str> = l.events.iter().filter(|e| e.source == "FSEvents").map(|e| e.summary.as_str()).collect();
        assert_eq!(fe, ["/Users/alice/Documents/plan.txt: Created, Modified", "/Users/alice/Documents/plan.txt: Removed", "/Users/alice/Projects/old-name (folder): Renamed", "/Users/alice/Projects/new-name (folder): Renamed"]);
        assert!(!l.timeline.iter().any(|t| t.what.contains("plan.txt: Removed")), "FSEvents stay off the timeline");
    }

    /// Apple Mail: .emlx files grouped by their .mbox folder, the deleted
    /// flag read from the property list after the message.
    #[test]
    fn apple_mail() {
        let msg = |subj: &str, flags: u32| {
            let m = format!("From: Alice Lab <alice@lab.test>\r\nTo: bob@lab.test\r\nSubject: {}\r\nDate: Tue, 20 Oct 2026 10:05:30 +0200\r\nMessage-ID: <{}@lab.test>\r\n\r\nBody of {}.\r\n", subj, subj.len(), subj);
            let p = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>flags</key>\n\t<integer>{}</integer>\n</dict>\n</plist>\n", flags);
            format!("{}\n{}{}", m.len(), m, p).into_bytes()
        };
        let (a, b, c) = (msg("plan", 1), msg("wipe it", 3), msg("lunch", 1));
        let base = "Users/alice/Library/Mail/V10/0C1D2E3F-0000-4000-8000-000000000001";
        let t = crate::tarfs::tests::tar(&[
            (&format!("{}/INBOX.mbox/2A3B4C5D-0000-4000-8000-000000000002/Data/Messages/1.emlx", base), b'0', &a, ""),
            (&format!("{}/INBOX.mbox/2A3B4C5D-0000-4000-8000-000000000002/Data/Messages/2.emlx", base), b'0', &b, ""),
            (&format!("{}/Archive.mbox/2A3B4C5D-0000-4000-8000-000000000003/Data/Messages/7.emlx", base), b'0', &c, ""),
        ]);
        let dir = std::env::temp_dir().join(format!("kokino-emlx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.tar");
        std::fs::write(&p, &t).unwrap();
        let a = analyze(&Evidence::open(&p).unwrap(), &mut |_, _, _| true).unwrap();
        let m = &a.filesystems[0].mail;
        let boxes: Vec<(&str, &str, u64)> = m.mailboxes.iter().map(|b| (b.path.rsplit('/').next().unwrap(), b.kind.as_str(), b.messages)).collect();
        assert_eq!(boxes, [("INBOX.mbox", "emlx", 2), ("Archive.mbox", "emlx", 1)]);
        let got: Vec<(&str, bool)> = m.messages.iter().map(|x| (x.subject.as_str(), x.expunged)).collect();
        assert!(got.contains(&("wipe it", true)) && got.contains(&("plan", false)) && got.len() == 3, "{:?}", got);
        assert!(m.messages.iter().all(|x| x.folder.ends_with(".mbox") && x.len > 0));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// WebCache (IE 10/11, old Edge) on a volume (here in a tar collection):
    /// with the other browsers and in the summary.
    #[test]
    fn webcache_on_a_volume() {
        let wc = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/win/WebCacheV01.dat")).unwrap();
        let t = crate::tarfs::tests::tar(&[("C/Users/alice/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat", b'0', &wc, ""), ("C/Windows/System32/config/SYSTEM", b'0', b"regf", "")]);
        let dir = std::env::temp_dir().join(format!("kokino-webcache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("c.tar");
        std::fs::write(&p, &t).unwrap();
        let a = analyze(&Evidence::open(&p).unwrap(), &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        let s = fs.web.sources.iter().find(|s| s.profile == "WebCache").expect("WebCache read");
        assert_eq!((s.user.as_str(), s.visits, s.downloads, s.error.as_deref()), ("alice", 3, 1, None));
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("Internet Explorer / Edge WebCache of user alice: 3 visits, 1 cached file, 1 cookie, 1 download, 1 search")), "{:?}", fs.stats.impact);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An Outlook PST on a volume (here in a tar collection): every message
    /// with its folder, on the timeline, and in the text index.
    #[test]
    fn outlook_pst_mailbox() {
        let pst = crate::pst::tests::sample();
        let t = crate::tarfs::tests::tar(&[("Users/alice/Documents/Outlook Files/alice.pst", b'0', &pst, "")]);
        let dir = std::env::temp_dir().join(format!("kokino-pst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("collection.tar");
        std::fs::write(&p, &t).unwrap();
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        let m = &fs.mail;
        assert_eq!(m.mailboxes.iter().map(|b| (b.kind.as_str(), b.client.as_str(), b.messages)).collect::<Vec<_>>(), [("pst", "Outlook", 3)]);
        let got: Vec<(&str, &str)> = m.messages.iter().map(|x| (x.subject.as_str(), x.folder.as_str())).collect();
        assert_eq!(got, [("Q3 numbers \u{2013} confidential", "Top of Personal Folders/Inbox"), ("Lunch", "Top of Personal Folders/Inbox"), ("wipe the laptop", "Top of Personal Folders/Deleted Items")]);
        assert_eq!(m.messages[0].attachments[0].size, 20_000);
        assert!(m.messages[1].snippet.contains("Lunch at"));
        assert!(fs.windows.timeline.iter().any(|t| t.kind == "MAIL" && t.what == "wipe the laptop"));
        {
            use crate::textindex::{build, search, Mode, Scope};
            let out = dir.join("idx.sqlite");
            build(&ev, &a, None, &out, &mut |_, _, _| true).unwrap();
            let kw = |q: &str| search(&out, &a, &Mode::Keyword(q.into()), Scope::Files, None, 50, 10_000).unwrap().hits;
            let h = kw("sdelete on everything");
            assert!(h.iter().any(|x| x.part.as_deref() == Some("Top of Personal Folders/Deleted Items, message 3")), "{:?}", h);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn linux_server_artifacts() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/linux-server.img");
        if !p.exists() {
            return;
        }
        let ev = Evidence::open(&p).unwrap();
        let a = analyze(&ev, &mut |_, _, _| true).unwrap();
        let fs = &a.filesystems[0];
        let l = &fs.linux;
        let c = &l.computer;
        assert_eq!((c.hostname.as_str(), c.os.as_str(), c.time_zone.as_str()), ("lab-srv", "Debian GNU/Linux 12 (bookworm)", "Europe/Skopje"));
        let iso = kokino_core::time::filetime_to_iso;
        // Classic syslog, local time UTC+2: 10:10:01 is 08:10:01 UTC.
        let ssh = l.events.iter().find(|e| e.category == "Logon" && e.user == "alice").unwrap();
        assert_eq!(iso(ssh.time), "2026-10-20T08:10:01.0000000Z");
        assert_eq!(ssh.ip, "192.0.2.10");
        // Two failed logons in auth.log, one in the journal (its message LZ4-compressed).
        assert_eq!(l.events.iter().filter(|e| e.category == "Failed logon").count(), 3);
        assert!(l.events.iter().any(|e| e.category == "Failed logon" && e.user == "root" && e.source == "journal"));
        // The journal stores this message XZ-compressed.
        assert!(l.events.iter().any(|e| e.category == "Logon" && e.user == "bob" && e.source == "journal" && e.ip == "203.0.113.9"));
        assert!(l.logs.iter().all(|x| !x.note.contains("compressed")), "{:?}", l.logs);
        // Email: a mail spool with two messages and a saved .eml.
        let m = &fs.mail;
        let boxes: Vec<(&str, &str, u64)> = m.mailboxes.iter().map(|b| (b.path.as_str(), b.kind.as_str(), b.messages)).collect();
        assert_eq!(boxes, [("/var/mail/alice", "mbox", 2), ("/home/alice/Downloads/reset.eml", "eml", 1)], "{:?}", m.mailboxes);
        let subjects: Vec<&str> = m.messages.iter().map(|x| x.subject.as_str()).collect();
        assert_eq!(subjects, ["Q3 plan \u{2013} confidential", "Re: wipe the laptop", "Password reset"]);
        assert_eq!(m.messages[0].attachments[0].name, "ledger.pdf");
        assert!(fs.windows.timeline.iter().any(|t| t.kind == "MAIL" && t.what == "Re: wipe the laptop"));
        // Message text is decoded for search: quoted-printable with a soft
        // line break ("to=" / "night") and HTML without its tags.
        {
            use crate::textindex::{build, search, Mode, Scope};
            let dir = std::env::temp_dir().join(format!("kokino-mail-idx-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let out = dir.join("idx.sqlite");
            build(&ev, &a, None, &out, &mut |_, _, _| true).unwrap();
            let kw = |q: &str| search(&out, &a, &Mode::Keyword(q.into()), Scope::Files, None, 50, 10_000).unwrap().hits;
            assert!(kw("account tonight").iter().any(|h| h.part.as_deref() == Some("message 1")), "{:?}", kw("account tonight"));
            assert!(kw("used sdelete on everything").iter().any(|h| h.part.as_deref() == Some("message 2")));
            std::fs::remove_dir_all(&dir).ok();
        }
        assert!(fs.stats.impact.iter().any(|l| l.starts_with("3 email message(s) in 2 mailbox(es), from 2026-10-20 to 2026-10-22, with 1 attachment(s)")), "{:?}", fs.stats.impact);
        assert!(l.events.iter().any(|e| e.category == "Account" && e.user == "svc-backup"));
        assert!(l.logons.iter().any(|x| x.source == "wtmp" && x.user == "alice" && x.end > x.time));
        assert!(l.logons.iter().any(|x| x.source == "btmp" && x.user == "admin" && x.kind == "failed"));
        assert_ne!(c.last_boot, 0);
        assert_ne!(c.last_shutdown, 0);
        let user = |n: &str| l.users.iter().find(|u| u.name == n).unwrap();
        assert!(user("alice").admin && user("alice").password.starts_with("set (SHA-512)"));
        assert!(user("toor").note.contains("uid 0"));
        assert!(user("svc-backup").note.contains("without a password"));
        assert_eq!(user("bob").password, "locked");
        assert!(user("alice").logons >= 1);
        let shred = l.commands.iter().find(|x| x.shell == "bash" && x.command.starts_with("shred")).unwrap();
        assert_eq!(shred.flag, "secure deletion");
        assert_eq!(iso(shred.time), "2026-10-20T10:10:30.0000000Z");
        assert!(l.commands.iter().any(|x| x.shell == "sudo" && x.command.contains("/usr/bin/shred")));
        let nmap = l.packages.iter().find(|p| p.name == "nmap").unwrap();
        assert_eq!((nmap.by.as_str(), iso(nmap.installed).as_str()), ("alice", "2026-10-20T08:12:50.0000000Z"));
        let unusual: Vec<&str> = l.persistence.iter().filter(|p| p.unusual).map(|p| p.kind.as_str()).collect();
        for k in ["cron", "systemd", "ld.so.preload", "SSH key", "history disabled"] {
            assert!(unusual.contains(&k), "{} not flagged: {:?}", k, unusual);
        }
        assert!(l.persistence.iter().any(|p| p.kind == "SSH key" && p.command.contains("SHA256:")));
        assert_eq!(l.usb.len(), 1);
        assert_eq!((l.usb[0].name.as_str(), l.usb[0].serial.as_str()), ("SanDisk Ultra", "4C530001230920115045"));
        assert!(l.networks.iter().any(|n| n.name == "LabWiFi" && n.last_connected > 0));
        assert!(l.networks.iter().any(|n| n.kind == "SSH known host" && n.name == "192.0.2.10"));
        assert!(l.networks.iter().any(|n| n.kind == "hosts file entry" && n.description == "203.0.113.66"));
        assert!(l.interfaces.iter().any(|i| i.ip == "192.0.2.20" && i.gateway == "192.0.2.1"));
        for id in ["linux_antiforensic_command", "shell_history_cleared", "ld_preload"] {
            assert!(fs.indicators.iter().any(|i| i.id == id), "{} missing", id);
        }
        let tl = timeline::build(&fs.files, &fs.web, &fs.windows, &l.timeline);
        for src in ["EXEC", "INST", "USB", "NET", "EVT"] {
            assert!(tl.iter().any(|e| e.src == src), "{} not in timeline", src);
        }
        assert!(fs.stats.impact.iter().any(|x| x.contains("Linux computer lab-srv")));
    }
}
