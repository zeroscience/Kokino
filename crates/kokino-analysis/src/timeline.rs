//! MACB timeline built from $STANDARD_INFORMATION and $FILE_NAME times.
//!
//! Identical timestamps within one attribute are merged into a single event
//! with combined MACB letters (M = modified, A = accessed, C = MFT entry
//! changed, B = born/created), the same convention as mactime/plaso.
//!
//! Browser activity joins the same timeline: page visits, download starts
//! and searches, each pointing into `FsAnalysis::web`. So do Windows
//! artifacts (program runs, files and folders opened, USB devices,
//! installs, networks, notable events and files created, deleted or renamed
//! per the change journal), each pointing into `FsAnalysis::windows.timeline` or, numbered after
//! those, `FsAnalysis::linux.timeline`.

use crate::FileRow;
use crate::windows::{WinTime, WindowsArtifacts};
use kokino_artifacts::browser::WebActivity;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    pub t: u64,
    pub macb: String,
    /// "SI" or "FN" (file times), "VISIT", "DL" or "SEARCH" (browser),
    /// "EXEC", "OPEN", "USB", "INST", "NET", "EVT", "USN" or "REG" (Windows artifacts).
    pub src: &'static str,
    /// Index into `FsAnalysis::files`, the matching `web` list, or
    /// `windows.timeline`.
    pub idx: u32,
}

pub fn is_web(src: &str) -> bool {
    matches!(src, "VISIT" | "DL" | "SEARCH")
}

pub fn is_windows(src: &str) -> bool {
    matches!(src, "EXEC" | "OPEN" | "USB" | "INST" | "NET" | "EVT" | "USN" | "REG")
}

/// Events that do not point at a file row.
pub fn is_artifact(src: &str) -> bool {
    is_web(src) || is_windows(src)
}

/// `linux`: the Linux artifacts' timeline; its events are numbered after the
/// Windows ones (see `system_event`).
/// The Windows or Linux timeline entry behind a system event's index.
pub fn system_event<'a>(windows: &'a WindowsArtifacts, linux: &'a [WinTime], idx: usize) -> Option<&'a WinTime> {
    windows.timeline.get(idx).or_else(|| linux.get(idx.checked_sub(windows.timeline.len())?))
}

pub fn build(files: &[FileRow], web: &WebActivity, windows: &WindowsArtifacts, linux: &[WinTime]) -> Vec<TimelineEvent> {
    let mut out = Vec::with_capacity(files.len() * 3);
    for (i, f) in files.iter().enumerate() {
        for (src, times) in [("SI", f.e.si), ("FN", f.e.fname)] {
            let Some(t) = times else { continue };
            let slots = [(t.modified, 0), (t.accessed, 1), (t.mft_modified, 2), (t.created, 3)];
            let mut seen: Vec<(u64, [bool; 4])> = vec![];
            for (ts, slot) in slots {
                if ts == 0 {
                    continue;
                }
                match seen.iter_mut().find(|(x, _)| *x == ts) {
                    Some((_, m)) => m[slot] = true,
                    None => {
                        let mut m = [false; 4];
                        m[slot] = true;
                        seen.push((ts, m));
                    }
                }
            }
            for (ts, m) in seen {
                let macb: String = ['M', 'A', 'C', 'B'].iter().zip(m).map(|(c, on)| if on { *c } else { '.' }).collect();
                out.push(TimelineEvent { t: ts, macb, src, idx: i as u32 });
            }
        }
        // ext2/3/4 record when an inode was deleted.
        if let Some(u) = f.e.unix.as_ref().filter(|u| u.deleted_time != 0) {
            out.push(TimelineEvent { t: u.deleted_time, macb: "D".into(), src: "DEL", idx: i as u32 });
        }
    }
    for (i, v) in web.visits.iter().enumerate().filter(|(_, v)| v.t > 0) {
        out.push(TimelineEvent { t: v.t, macb: if v.typed { "typed".into() } else { String::new() }, src: "VISIT", idx: i as u32 });
    }
    for (i, d) in web.downloads.iter().enumerate().filter(|(_, d)| d.start > 0) {
        out.push(TimelineEvent { t: d.start, macb: String::new(), src: "DL", idx: i as u32 });
    }
    for (i, s) in web.searches.iter().enumerate().filter(|(_, s)| s.t > 0) {
        out.push(TimelineEvent { t: s.t, macb: String::new(), src: "SEARCH", idx: i as u32 });
    }
    for (i, w) in windows.timeline.iter().chain(linux).enumerate() {
        let src = match w.kind.as_str() {
            "EXEC" => "EXEC",
            "OPEN" => "OPEN",
            "USB" => "USB",
            "INST" => "INST",
            "NET" => "NET",
            "FILE" => "USN",
            "REG" => "REG",
            _ => "EVT",
        };
        out.push(TimelineEvent { t: w.t, macb: String::new(), src, idx: i as u32 });
    }
    out.sort_by(|a, b| a.t.cmp(&b.t).then(a.idx.cmp(&b.idx)).then(a.src.cmp(b.src)));
    out
}
