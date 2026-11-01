//! Browser activity found on an NTFS volume: locates history databases by
//! name and path, reads them (with their -wal / -journal companions) through
//! the NTFS layer and hands the bytes to `kokino_artifacts::browser`.

use crate::FileRow;
use kokino_artifacts::browser::{self, WebActivity};
use std::collections::HashMap;
use std::io::{Read, Seek};

/// Databases larger than this are listed with an error instead of parsed.
const MAX_DB: u64 = 1 << 30;

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
    let candidates: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.e.is_dir && browser::classify(&f.e.path, &f.e.name).is_some())
        .map(|(i, _)| i)
        .collect();
    let total = candidates.len() as u64;
    for (n, i) in candidates.into_iter().enumerate() {
        progress("Browser history", n as u64, total);
        let f = &files[i];
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
    out.visits.sort_by_key(|v| v.t);
    out.downloads.sort_by_key(|d| d.start);
    out.searches.sort_by_key(|s| s.t);
    out
}

/// One line per profile for the impact summary.
pub fn impact(web: &WebActivity) -> Vec<String> {
    let mut lines = vec![];
    for s in &web.sources {
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
