//! Browser activity found on an NTFS volume: locates history databases by
//! name and path, reads them (with their -wal / -journal companions) through
//! the NTFS layer and hands the bytes to `kokino_artifacts::browser`.
//! Internet Explorer's index.dat files go to `kokino_artifacts::iecache`.

use crate::FileRow;
use kokino_artifacts::browser::{self, Engine, WebActivity};
use kokino_artifacts::iecache;
use std::collections::HashMap;
use std::io::{Read, Seek};

/// Databases larger than this are listed with an error instead of parsed.
const MAX_DB: u64 = 1 << 30;
const MAX_INDEX_DAT: u64 = 256 << 20;

pub fn collect<R: Read + Seek>(fs: &crate::fs::Fs, r: &mut R, files: &[FileRow], progress: crate::Progress) -> WebActivity {
    let mut out = WebActivity::default();
    // (parent record, lowercase name) -> file index; live entries win.
    let mut by_name: HashMap<(u64, String), usize> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        if f.e.is_dir {
            continue;
        }
        let key = (f.e.parent, f.e.name.to_ascii_lowercase());
        match by_name.get(&key) {
            Some(&j) if !files[j].e.deleted => {}
            _ => {
                by_name.insert(key, i);
            }
        }
    }
    let mut candidates: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.e.is_dir && (browser::classify(&f.e.path, &f.e.name).is_some() || iecache::classify(&f.e.path, &f.e.name).is_some()))
        .map(|(i, _)| i)
        .collect();
    // Daily and weekly IE history before the main file, so the main file's
    // copies of the same visits can be left out.
    candidates.sort_by_key(|&i| !files[i].e.path.to_ascii_lowercase().contains("/mshist01"));
    let total = candidates.len() as u64;
    for (n, i) in candidates.into_iter().enumerate() {
        progress("Browser history", n as u64, total);
        let f = &files[i];
        if let Some(mut src) = iecache::classify(&f.e.path, &f.e.name) {
            src.record = f.e.record;
            src.deleted = f.e.deleted;
            src.size = f.e.size;
            let res = if f.e.size > MAX_INDEX_DAT {
                Err(anyhow::anyhow!("{} bytes; larger than the {} byte limit", f.e.size, MAX_INDEX_DAT))
            } else {
                fs.read(r, &f.e, "", 0, f.e.size as usize).and_then(|d| iecache::to_web(&mut src, &d, &mut out))
            };
            if let Err(e) = res {
                src.error = Some(format!("{:#}", e));
            }
            out.sources.push(src);
            continue;
        }
        let mut src = browser::classify(&f.e.path, &f.e.name).unwrap();
        src.record = f.e.record;
        src.deleted = f.e.deleted;
        src.size = f.e.size;
        let mut read = |idx: usize| -> anyhow::Result<Vec<u8>> {
            let e = &files[idx].e;
            if e.size > MAX_DB {
                anyhow::bail!("{} is {} bytes; larger than the {} byte limit", e.path, e.size, MAX_DB);
            }
            fs.read(r, e, "", 0, e.size as usize)
        };
        let sibling = |suffix: &str| by_name.get(&(f.e.parent, format!("{}{}", f.e.name.to_ascii_lowercase(), suffix))).copied();
        let res = (|| -> anyhow::Result<()> {
            let db = read(i)?;
            let wal = sibling("-wal").map(&mut read).transpose()?;
            let journal = sibling("-journal").map(&mut read).transpose()?;
            browser::parse(&mut src, &db, wal.as_deref().filter(|w| !w.is_empty()), journal.as_deref().filter(|j| !j.is_empty()), &mut out)
        })();
        if let Err(e) = res {
            src.error = Some(format!("{:#}", e));
        }
        out.sources.push(src);
    }
    progress("Browser history", total, total);
    ie_repeats(&mut out);
    out.visits.sort_by_key(|v| v.t);
    out.cache.sort_by_key(|c| c.t);
    out.downloads.sort_by_key(|d| d.start);
    out.searches.sort_by_key(|s| s.t);
    out
}

/// IE's main history keeps the last visit of each page, which is also in
/// that day's file. Those copies are left out (and counted in the note).
fn ie_repeats(out: &mut WebActivity) {
    let ie: Vec<bool> = out.sources.iter().map(|s| s.engine == Some(Engine::Ie)).collect();
    let main: Vec<bool> = out.sources.iter().map(|s| s.engine == Some(Engine::Ie) && (s.profile == "History" || s.profile == "History (protected mode)")).collect();
    let folder = |s: &browser::WebSource| -> String {
        let p = s.path.to_ascii_lowercase();
        p.find("/history.ie5/").map(|i| p[..i].to_string()).unwrap_or(p)
    };
    let folders: Vec<String> = out.sources.iter().map(folder).collect();
    // (history folder, url) -> visit times from daily and weekly files.
    let mut daily: HashMap<(String, String), Vec<u64>> = HashMap::new();
    for v in &out.visits {
        let s = v.src as usize;
        if ie.get(s) == Some(&true) && main.get(s) == Some(&false) {
            daily.entry((folders[s].clone(), v.url.clone())).or_default().push(v.t);
        }
    }
    if daily.is_empty() {
        return;
    }
    let mut dropped = vec![0u64; out.sources.len()];
    out.visits.retain(|v| {
        let s = v.src as usize;
        if main.get(s) != Some(&true) || v.recovered {
            return true;
        }
        let same = daily.get(&(folders[s].clone(), v.url.clone())).is_some_and(|ts| ts.iter().any(|&t| t.abs_diff(v.t) <= 20_000_000));
        if same {
            dropped[s] += 1;
        }
        !same
    });
    out.searches.retain(|q| {
        let s = q.src as usize;
        main.get(s) != Some(&true) || out.visits.iter().any(|v| v.src == q.src && v.t == q.t && v.url == q.url)
    });
    for (s, n) in dropped.into_iter().enumerate() {
        if n == 0 {
            continue;
        }
        let src = &mut out.sources[s];
        src.visits -= n.min(src.visits);
        src.searches = out.searches.iter().filter(|q| q.src as usize == s).count() as u64;
        let note = if n == 1 { "1 last visit that is also in a daily or weekly file is shown once, from that file".to_string() } else { format!("{} last visits that are also in a daily or weekly file are shown once, from that file", n) };
        src.note = if src.note.is_empty() { note } else { format!("{}; {}", src.note, note) };
    }
}

/// One line per profile for the impact summary.
pub fn impact(web: &WebActivity) -> Vec<String> {
    let mut lines = vec![];
    for s in &web.sources {
        if s.engine == Some(Engine::Ie) {
            lines.extend(ie_impact(s));
            continue;
        }
        let who = if s.user.is_empty() { String::new() } else { format!(" of user {}", s.user) };
        let line = match &s.error {
            Some(e) => format!("{} history{} ({}) could not be read: {}.", s.browser, who, s.profile, e),
            None if s.visits == 0 && s.urls == 0 => format!("{} history{} ({}) is empty: cleared, or the profile was never used.", s.browser, who, s.profile),
            None => format!(
                "{} history{} ({}): {}, {}, {}, from {} to {}{}.",
                s.browser,
                who,
                s.profile,
                plural(s.visits, "visit"),
                plural(s.downloads, "download"),
                plural(s.searches, "search"),
                day(s.oldest),
                day(s.newest),
                if s.wal { "; includes changes still in the -wal file" } else { "" }
            ),
        };
        lines.push(if s.deleted { format!("{} The database file is deleted.", line) } else { line });
    }
    lines
}

fn ie_impact(s: &browser::WebSource) -> Option<String> {
    let who = if s.user.is_empty() { String::new() } else { format!(" of user {}", s.user) };
    let what = if let Some(e) = &s.error {
        format!("could not be read: {}", e)
    } else {
        let mut parts = vec![];
        if s.visits > 0 {
            parts.push(plural(s.visits, "visit"));
        }
        if s.cached > 0 {
            parts.push(format!("{} cached {}", s.cached, if s.cached == 1 { "file" } else { "files" }));
        }
        if s.downloads > 0 {
            parts.push(plural(s.downloads, "download"));
        }
        if s.searches > 0 {
            parts.push(plural(s.searches, "search"));
        }
        if parts.is_empty() {
            return None;
        }
        let mut t = format!("{}, from {} to {}", parts.join(", "), day(s.oldest), day(s.newest));
        if s.recovered > 0 {
            t.push_str(&format!("; {} deleted {} recovered from inside the file", s.recovered, if s.recovered == 1 { "entry" } else { "entries" }));
        }
        t
    };
    let line = format!("Internet Explorer {}{}: {}.", s.profile.to_lowercase(), who, what);
    Some(if s.deleted { format!("{} The index.dat file is deleted.", line) } else { line })
}

fn plural(n: u64, word: &str) -> String {
    match (n, word.ends_with('h')) {
        (1, _) => format!("1 {}", word),
        (_, true) => format!("{} {}es", n, word),
        _ => format!("{} {}s", n, word),
    }
}

fn day(ft: u64) -> String {
    if ft == 0 {
        return "?".into();
    }
    kokino_core::time::filetime_to_iso(ft).chars().take(10).collect()
}
