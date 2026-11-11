//! Volume statistics and the factual "impact" summary.

use crate::antiforensics::{Indicator, Score};
use crate::FileRow;
use kokino_core::time::filetime_to_datetime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DayCount {
    pub day: String,
    pub created: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub deleted_files: u64,
    pub deleted_dirs: u64,
    pub orphans: u64,
    pub ads: u64,
    pub bytes: u64,
    pub deleted_bytes: u64,
    pub by_category: Vec<(String, u64)>,
    pub top_ext: Vec<(String, u64)>,
    pub users: Vec<String>,
    pub os: Option<String>,
    pub time_min: u64,
    pub time_max: u64,
    pub histogram: Vec<DayCount>,
    pub impact: Vec<String>,
}

pub fn compute(files: &[FileRow], indicators: &[Indicator], score: &Score, now: u64) -> Stats {
    let mut s = Stats::default();
    let mut cats: HashMap<&str, u64> = HashMap::new();
    let mut exts: HashMap<&str, u64> = HashMap::new();
    let mut days: BTreeMap<String, DayCount> = BTreeMap::new();
    const LOW: u64 = 124_604_352_000_000_000; // 1993-01-01
    let high = now + 86_400 * 10_000_000;
    let mut tmin = u64::MAX;
    let mut tmax = 0u64;

    for f in files {
        let e = &f.e;
        if e.record < 24 {
            continue;
        }
        if e.is_dir {
            s.dirs += 1;
            if e.deleted {
                s.deleted_dirs += 1;
            }
        } else {
            s.files += 1;
            s.bytes += e.size;
            if e.deleted {
                s.deleted_files += 1;
                s.deleted_bytes += e.size;
            }
            if let Some(c) = f.category {
                *cats.entry(c.label()).or_default() += 1;
            }
            if !f.ext.is_empty() {
                *exts.entry(f.ext.as_str()).or_default() += 1;
            }
        }
        if e.orphan {
            s.orphans += 1;
        }
        s.ads += e.ads().count() as u64;

        if let Some(si) = e.si {
            for (t, created) in [(si.created, true), (si.modified, false)] {
                if t < LOW || t > high {
                    continue;
                }
                tmin = tmin.min(t);
                tmax = tmax.max(t);
                if let Some(dt) = filetime_to_datetime(t) {
                    let d = days.entry(dt.format("%Y-%m-%d").to_string()).or_insert_with(|| DayCount { day: dt.format("%Y-%m-%d").to_string(), ..Default::default() });
                    if created {
                        d.created += 1;
                    } else {
                        d.modified += 1;
                    }
                }
            }
        }

        let lower = e.path.to_ascii_lowercase();
        for root in ["/users/", "/documents and settings/"] {
            if let Some(rest) = lower.strip_prefix(root) {
                if e.is_dir && !e.deleted && !rest.contains('/') {
                    let n = &e.path[root.len()..];
                    if !matches!(rest, "public" | "default" | "default user" | "all users" | "desktop.ini" | "defaultapppool") {
                        s.users.push(n.to_string());
                    }
                }
            }
        }
        if lower == "/windows/system32/ntoskrnl.exe" && !e.deleted {
            s.os = Some("Windows (system volume)".into());
        }
    }
    s.users.sort();
    s.users.dedup();
    s.time_min = if tmin == u64::MAX { 0 } else { tmin };
    s.time_max = tmax;
    s.histogram = days.into_values().collect();
    s.by_category = sorted(cats);
    s.top_ext = sorted(exts).into_iter().take(15).collect();
    s.impact = impact(&s, indicators, score);
    s
}

fn sorted(m: HashMap<&str, u64>) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = m.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

fn human(b: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{} B", b) } else { format!("{:.1} {}", v, units[i]) }
}

/// Factual statements only; every number is traceable to the file list.
fn impact(s: &Stats, indicators: &[Indicator], score: &Score) -> Vec<String> {
    let mut out = vec![];
    match &s.os {
        Some(os) => out.push(format!("{} with {} user profile(s){}.", os, s.users.len(), if s.users.is_empty() { String::new() } else { format!(": {}", s.users.join(", ")) })),
        None => out.push("Data volume (no Windows installation found).".into()),
    }
    out.push(format!("{} files ({}) in {} directories.", s.files, human(s.bytes), s.dirs));
    if s.deleted_files + s.deleted_dirs > 0 {
        out.push(format!(
            "{} deleted files ({}) and {} deleted directories still have file system entries; content may be recoverable unless clusters were reused.",
            s.deleted_files,
            human(s.deleted_bytes),
            s.deleted_dirs
        ));
    }
    if s.orphans > 0 {
        out.push(format!("{} entries are orphaned (parent directory missing or reused).", s.orphans));
    }
    if s.time_max > 0 {
        let a = kokino_core::time::filetime_to_iso(s.time_min);
        let b = kokino_core::time::filetime_to_iso(s.time_max);
        out.push(format!("File timestamps span {} to {}.", kokino_core::time::human(&a[..10.min(a.len())]), kokino_core::time::human(&b[..10.min(b.len())])));
    }
    for (cat, n) in s.by_category.iter().filter(|(c, _)| matches!(c.as_str(), "Documents" | "Email" | "Databases" | "Encrypted / keys")) {
        out.push(format!("{} {} identified by signature.", n, cat.to_lowercase()));
    }
    let hits: Vec<&Indicator> = indicators.iter().filter(|i| i.count > 0).collect();
    if hits.is_empty() {
        out.push("No anti-forensics indicators were triggered.".into());
    } else {
        out.push(format!(
            "Anti-forensics likelihood is {} ({:.0}%), driven by: {}.",
            score.band,
            score.likelihood * 100.0,
            hits.iter().take(3).map(|i| format!("{} ({})", i.title, i.count)).collect::<Vec<_>>().join("; ")
        ));
    }
    out
}
