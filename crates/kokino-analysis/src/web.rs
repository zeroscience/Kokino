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
            if src.profile.starts_with("Cookies") {
                let mut read = |e: &kokino_ntfs::FsEntry| fs.read(r, e, "", 0, e.size as usize).ok();
                ie_cookie_files(&mut read, files, i, out.sources.len() as u32, &mut src, &mut out);
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
        // Safari keeps its downloads in Downloads.plist next to History.db.
        if src.engine == Some(browser::Engine::Safari) {
            if let Some(j) = by_name.get(&(f.e.parent, "downloads.plist".into())).copied() {
                match read(j).and_then(|d| browser::safari_downloads(&d, out.sources.len() as u32, &mut out)) {
                    Ok(n) => src.downloads += n as u64,
                    Err(e) => src.note = format!("Downloads.plist: {:#}", e),
                }
            }
        }
        out.sources.push(src);
    }
    progress("Browser history", total, total);
    ie_repeats(&mut out);
    out.visits.sort_by_key(|v| v.t);
    out.cache.sort_by_key(|c| c.t);
    out.cookies.sort_by_key(|c| c.created.max(c.last_access));
    out.downloads.sort_by_key(|d| d.start);
    out.searches.sort_by_key(|s| s.t);
    out
}

/// Internet Explorer cookies: index.dat names each site's cookie file in
/// the same folder; the cookies are in those text files. Files the index
/// no longer lists (deleted entries, deleted files) are read too.
fn ie_cookie_files(read_file: &mut dyn FnMut(&kokino_ntfs::FsEntry) -> Option<Vec<u8>>, files: &[FileRow], index: usize, src_idx: u32, src: &mut browser::WebSource, out: &mut WebActivity) {
    let parent = files[index].e.parent;
    let in_folder: Vec<usize> = files.iter().enumerate().filter(|(_, f)| f.e.parent == parent && !f.e.is_dir && f.e.name.to_ascii_lowercase().ends_with(".txt")).map(|(j, _)| j).collect();
    let mut read = |j: usize| -> Vec<browser::Cookie> {
        let e = &files[j].e;
        if e.size == 0 || e.size > 1 << 20 {
            return vec![];
        }
        read_file(e).map(|d| iecache::cookie_text(&d)).unwrap_or_default()
    };
    let entries: Vec<browser::Cookie> = {
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut out.cookies).into_iter().partition(|c| c.src == src_idx);
        out.cookies = rest;
        mine
    };
    let mut used = std::collections::HashSet::new();
    let mut rows = vec![];
    for e in entries {
        // A live file of that name first, else a deleted one.
        let j = in_folder.iter().copied().filter(|&j| files[j].e.name.eq_ignore_ascii_case(&e.file)).min_by_key(|&j| files[j].e.deleted);
        match j {
            Some(j) => {
                used.insert(j);
                let cs = read(j);
                if cs.is_empty() {
                    rows.push(browser::Cookie { note: "the cookie file is empty or unreadable".into(), ..e });
                    continue;
                }
                for c in cs {
                    rows.push(browser::Cookie { src: src_idx, last_access: e.last_access, file: e.file.clone(), recovered: e.recovered, note: if files[j].e.deleted { "cookie file deleted".into() } else { String::new() }, ..c });
                }
            }
            None => rows.push(browser::Cookie { note: "the cookie file is gone; only the index entry remains".into(), ..e }),
        }
    }
    for j in in_folder.into_iter().filter(|j| !used.contains(j)) {
        let note = if files[j].e.deleted { "cookie file deleted, and not in index.dat" } else { "not in index.dat (its entry was removed)" };
        for c in read(j) {
            rows.push(browser::Cookie { src: src_idx, file: files[j].e.name.clone(), note: note.into(), ..c });
        }
    }
    rows.truncate(200_000);
    src.cookies = rows.len() as u64;
    let times = rows.iter().flat_map(|c| [c.created, c.last_access]).filter(|&t| t > 0);
    if src.oldest == 0 {
        src.oldest = times.clone().min().unwrap_or(0);
    }
    src.newest = src.newest.max(times.max().unwrap_or(0));
    out.cookies.extend(rows);
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
        // Safari has no profiles.
        let prof = if s.profile.is_empty() { String::new() } else { format!(" ({})", s.profile) };
        let line = match &s.error {
            Some(e) => format!("{} history{}{} could not be read: {}.", s.browser, who, prof, e),
            None if s.visits == 0 && s.urls == 0 => format!("{} history{}{} is empty: cleared, or the profile was never used.", s.browser, who, prof),
            None => format!(
                "{} history{}{}: {}, {}, {}, from {} to {}{}.",
                s.browser,
                who,
                prof,
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
        if s.cookies > 0 {
            parts.push(format!("{} {}", s.cookies, if s.cookies == 1 { "cookie" } else { "cookies" }));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cookie files joined to their index entries; a file whose entry was
    /// deleted, a file with no entry, and an entry whose file is gone.
    #[test]
    fn ie_cookies_joined_to_files() {
        let row = |rec: u64, path: &str, size: u64, deleted: bool| {
            let mut r = crate::antiforensics::tests::row(rec, path, false, 0, None);
            r.e.parent = 77;
            r.e.size = size;
            r.e.deleted = deleted;
            r
        };
        let dir = "/Users/alice/AppData/Roaming/Microsoft/Windows/Cookies";
        let c = |name: &str, value: &str, site: &str| format!("{name}\n{value}\n{site}\n1024\n3643744512\n30550353\n674454847\n30182824\n*\n");
        let bank = c("session", "4471a9", "bank.test/") + &c("lang", "en", "bank.test/");
        let drop = c("uploader", "alice", "drop.test/");
        let tools = c("dl", "sdelete", "tools.test/");
        let files = vec![
            row(1, &format!("{dir}/index.dat"), 0x5000, false),
            row(2, &format!("{dir}/alice@bank[1].txt"), bank.len() as u64, false),
            row(3, &format!("{dir}/alice@drop[1].txt"), drop.len() as u64, true),
            row(4, &format!("{dir}/alice@tools[1].txt"), tools.len() as u64, false),
        ];
        let mut out = WebActivity::default();
        out.sources.push(browser::WebSource::default());
        let t = 133_000_000_000_000_000u64;
        let entry = |site: &str, file: &str, recovered: bool| browser::Cookie { src: 1, site: site.into(), file: file.into(), last_access: t, recovered, ..Default::default() };
        out.cookies = vec![entry("bank.test/", "alice@bank[1].txt", false), entry("drop.test/", "alice@drop[1].txt", true), entry("gone.test/", "alice@gone[1].txt", false)];
        let mut src = iecache::classify(&format!("{dir}/index.dat"), "index.dat").unwrap();
        let data = [bank, drop, tools];
        let mut read = |e: &kokino_ntfs::FsEntry| Some(data[(e.record - 2) as usize].clone().into_bytes());
        ie_cookie_files(&mut read, &files, 0, 1, &mut src, &mut out);
        let got: Vec<(&str, &str, &str, u64, bool, &str)> = out.cookies.iter().map(|c| (c.site.as_str(), c.name.as_str(), c.value.as_str(), c.last_access, c.recovered, c.note.as_str())).collect();
        assert_eq!(got, [
            ("bank.test/", "session", "4471a9", t, false, ""),
            ("bank.test/", "lang", "en", t, false, ""),
            ("drop.test/", "uploader", "alice", t, true, "cookie file deleted"),
            ("gone.test/", "", "", t, false, "the cookie file is gone; only the index entry remains"),
            ("tools.test/", "dl", "sdelete", 0, false, "not in index.dat (its entry was removed)"),
        ]);
        assert_eq!(src.cookies, 5);
        assert!(out.cookies[0].created > 0 && out.cookies[0].expires > out.cookies[0].created);
        assert!(ie_impact(&browser::WebSource { cookies: 5, ..src.clone() }).unwrap().contains("5 cookies"));
    }
}
