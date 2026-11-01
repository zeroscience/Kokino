//! Bookmarks: examiner notes and tags on items of a case (files, events,
//! carved files, search hits, byte ranges), kept in `<case>/bookmarks.json`.
//!
//! Each bookmark carries a snapshot of what it points at (title, path,
//! time, hashes for files) so a report of tagged items stays meaningful
//! even if the evidence is re-analyzed. Every change is written to the case
//! audit log by the caller.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    pub id: String,
    /// Identity of the target, so one item has at most one bookmark.
    pub key: String,
    pub evidence: String,
    /// file, event, carved, hit, offset, web
    pub kind: String,
    pub fi: Option<usize>,
    pub record: Option<u64>,
    pub idx: Option<u64>,
    pub offset: Option<u64>,
    pub len: Option<u64>,
    pub carved: Option<u32>,
    /// A rectangle (x, y, width, height in image pixels) on a picture, and
    /// the view it was marked in (original, error level, noise...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<[u32; 4]>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub view: String,
    pub title: String,
    pub detail: String,
    pub path: String,
    pub time: String,
    pub size: Option<u64>,
    pub md5: String,
    pub sha256: String,
    pub deleted: bool,
    pub tags: Vec<String>,
    pub note: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_by: String,
    pub updated_at: String,
}

/// Tags offered in the GUI; examiners can add their own.
pub const SUGGESTED_TAGS: &[&str] = &["Evidence", "Relevant", "Suspicious", "Exculpatory", "Follow up", "Privileged", "Not relevant"];

pub fn load(path: &Path) -> anyhow::Result<Vec<Bookmark>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Written to a temporary file and renamed, so a crash never leaves half a file.
pub fn save(path: &Path, list: &[Bookmark]) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(list)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Trimmed, de-duplicated (case-insensitive) tags; rejects unusable ones.
pub fn clean_tags(tags: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = vec![];
    for t in tags {
        let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.is_empty() {
            continue;
        }
        if t.chars().count() > 40 || t.chars().any(|c| c.is_control()) {
            anyhow::bail!("tags are 1 to 40 printable characters");
        }
        if !out.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    if out.len() > 20 {
        anyhow::bail!("at most 20 tags per bookmark");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_and_round_trip() {
        let t = clean_tags(&["  Evidence ".into(), "evidence".into(), "Follow   up".into(), "".into()]).unwrap();
        assert_eq!(t, vec!["Evidence", "Follow up"]);
        assert!(clean_tags(&["x".repeat(41)]).is_err());
        assert!(clean_tags(&["a\u{7}b".into()]).is_err());
        assert_eq!(clean_tags(&["a\nb".into()]).unwrap(), vec!["a b"]);
        let dir = std::env::temp_dir().join(format!("kokino-bm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bookmarks.json");
        assert!(load(&p).unwrap().is_empty());
        let b = Bookmark { id: "1".into(), key: "file:e:0:66".into(), tags: t, ..Default::default() };
        save(&p, &[b.clone()]).unwrap();
        assert_eq!(load(&p).unwrap(), vec![b]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
