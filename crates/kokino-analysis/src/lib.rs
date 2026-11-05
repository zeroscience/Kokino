//! Analysis engine: turns an evidence image into files with content facts,
//! anti-forensics indicators, a likelihood score, statistics and a timeline.
//!
//! Output is deterministic for a given image and Kokino version (apart from
//! `analyzed_at` and the "future timestamp" reference time).

#![forbid(unsafe_code)]

pub mod antiforensics;
pub mod binview;
pub mod signatures;
pub mod carve;
pub mod doctext;
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
use kokino_image::{detect_volumes, BlockCache, Evidence, FsKind, SubReader, Volume};
use fs::Fs;
use kokino_ntfs::{FsEntry, NtfsVolumeInfo, UnreadableRecord};
use serde::{Deserialize, Serialize};
use signatures::Category;
use stats::Stats;

/// 2: adds `FsAnalysis::web` (browser history).
/// 3: adds `FsAnalysis::windows` (registry, event logs, Prefetch, LNK, Jump Lists).
/// 4: FAT12/16/32 and exFAT volumes are parsed too (`volume.fs` tells which).
/// 5: ext2/3/4 volumes, `FsEntry::unix` and `FsAnalysis::linux`.
pub const SCHEMA_VERSION: u32 = 5;

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
    let volumes = detect_volumes(&mut r, ev.size);
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

pub fn volume_reader(ev: &Evidence, v: &Volume) -> anyhow::Result<BlockCache<SubReader<kokino_image::EvidenceReader>>> {
    Ok(BlockCache::new(SubReader::new(ev.reader()?, v.start, v.length))?)
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

    let web = web::collect(&fs, &mut r, &files, &mut *progress);
    let windows = windows::collect(&fs, &mut r, &files, &mut *progress);
    let linux = linux::collect(&fs, &mut r, &files, &mut *progress);

    progress(&format!("Volume {}: anti-forensics indicators", v.index), 0, 1);
    let now = kokino_core::time::datetime_to_filetime(chrono::Utc::now());
    let indicators = antiforensics::evaluate(&mut files, now, &web, &windows, &linux, !fs.is_ntfs());
    let score = antiforensics::score(&indicators);
    let mut stats = stats::compute(&files, &indicators, &score, now);
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
    stats.impact.extend(web::impact(&web));
    stats.impact.extend(windows::impact(&windows));
    stats.impact.extend(linux::impact(&linux));

    Ok(FsAnalysis { volume: v.clone(), info: scan.info, files, unreadable: scan.unreadable, indicators, score, stats, web, windows, linux })
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
        assert_eq!(l.events.iter().filter(|e| e.category == "Failed logon").count(), 2);
        assert!(l.events.iter().any(|e| e.category == "Logon" && e.user == "bob" && e.source == "journal" && e.ip == "203.0.113.9"));
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
