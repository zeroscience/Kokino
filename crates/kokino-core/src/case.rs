//! Case store: a directory per case with metadata, evidence records, cached
//! analysis, hex patch overlays and the audit log.

use crate::audit::AuditLog;
use crate::hashing::Hashes;
use crate::time::now_iso;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub id: String,
    pub name: String,
    pub examiner: String,
    pub description: String,
    pub created: String,
    pub tool: String,
    pub tool_version: String,
    /// Assigned users and their access on this case. Admins always have access.
    #[serde(default)]
    pub members: BTreeMap<String, Access>,
}

/// Per-case access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Reviewer,
    Examiner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: String,
    pub name: String,
    pub path: String,
    pub format: String,
    pub size: u64,
    pub added: String,
    pub notes: String,
    /// Hashes computed by Kokino over the logical image stream.
    pub hashes: Option<Hashes>,
    pub hashed_at: Option<String>,
    /// Hashes stated in the acquisition notes, used for verification.
    pub expected: Option<Hashes>,
    /// Hashes the imaging tool stored inside the image (E01 hash/digest).
    #[serde(default)]
    pub embedded: Option<Hashes>,
    /// Acquisition metadata stored inside the image (E01 header, geometry,
    /// segments, unreadable sector ranges).
    #[serde(default)]
    pub acquisition: Option<serde_json::Value>,
}

/// One hex overlay edit. Applied only in memory and on export, never to evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub offset: u64,
    pub original: u8,
    pub value: u8,
    pub time: String,
    pub note: String,
}

pub struct Case {
    pub dir: PathBuf,
    pub info: CaseInfo,
    pub audit: AuditLog,
}

impl Case {
    pub fn create(root: &Path, name: &str, examiner: &str, description: &str) -> anyhow::Result<Case> {
        let id = format!("{}-{}", slug(name), &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let dir = root.join(&id);
        for sub in ["evidence", "analysis", "patches", "exports"] {
            fs::create_dir_all(dir.join(sub))?;
        }
        let info = CaseInfo {
            id,
            name: name.to_string(),
            examiner: examiner.to_string(),
            description: description.to_string(),
            created: now_iso(),
            tool: crate::TOOL_NAME.to_string(),
            tool_version: crate::TOOL_VERSION.to_string(),
            members: BTreeMap::from([(examiner.to_string(), Access::Examiner)]),
        };
        write_json(&dir.join("case.json"), &info)?;
        let audit = AuditLog::open(dir.join("audit.jsonl"))?;
        audit.append(examiner, "case.create", serde_json::to_value(&info)?)?;
        Ok(Case { dir, info, audit })
    }

    pub fn open(dir: &Path) -> anyhow::Result<Case> {
        let info: CaseInfo = read_json(&dir.join("case.json"))?;
        let audit = AuditLog::open(dir.join("audit.jsonl"))?;
        Ok(Case { dir: dir.to_path_buf(), info, audit })
    }

    pub fn list(root: &Path) -> Vec<CaseInfo> {
        let mut out: Vec<CaseInfo> = fs::read_dir(root)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| read_json(&e.path().join("case.json")).ok())
            .collect();
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    /// Moves a cases folder made before the rename (`old`, e.g.
    /// ~/BaboonCases) to `new` (~/KokinoCases) when `new` does not exist yet.
    /// Evidence paths that pointed inside the old folder are rewritten, each
    /// with an audit entry in its case. Returns the folder to use and what
    /// happened, for the caller to report; when the move fails (a file in
    /// it is open), the old folder keeps being used.
    pub fn migrate_root(old: &Path, new: &Path) -> (PathBuf, Option<String>) {
        if new.exists() || !old.is_dir() {
            return (new.to_path_buf(), None);
        }
        if let Err(e) = fs::rename(old, new) {
            return (old.to_path_buf(), Some(format!("could not rename {} to {} ({}); still using the old folder", old.display(), new.display(), e)));
        }
        let old_s = old.to_string_lossy().to_string();
        let mut moved = 0;
        for info in Case::list(new) {
            let Ok(case) = Case::open(&new.join(&info.id)) else { continue };
            for mut rec in case.evidence() {
                let p = rec.path.clone();
                if p.len() >= old_s.len() && p[..old_s.len()].eq_ignore_ascii_case(&old_s) {
                    let np = new.join(p[old_s.len()..].trim_start_matches(['\\', '/']));
                    let _ = case.audit.append("kokino", "evidence.path_moved", serde_json::json!({"evidence": rec.id, "from": p, "to": np.to_string_lossy()}));
                    rec.path = np.to_string_lossy().into_owned();
                    if case.save_evidence(&rec).is_ok() {
                        moved += 1;
                    }
                }
            }
        }
        (new.to_path_buf(), Some(format!("renamed cases folder {} to {}{}", old.display(), new.display(), if moved > 0 { format!(" ({} evidence path(s) inside it updated)", moved) } else { String::new() })))
    }

    pub fn save_info(&self) -> anyhow::Result<()> {
        write_json(&self.dir.join("case.json"), &self.info)
    }

    pub fn evidence(&self) -> Vec<EvidenceRecord> {
        let mut out: Vec<EvidenceRecord> = fs::read_dir(self.dir.join("evidence"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| read_json(&e.path()).ok())
            .collect();
        out.sort_by(|a, b| a.added.cmp(&b.added));
        out
    }

    pub fn evidence_by_id(&self, eid: &str) -> anyhow::Result<EvidenceRecord> {
        read_json(&self.dir.join("evidence").join(format!("{}.json", safe_id(eid)?)))
    }

    pub fn save_evidence(&self, rec: &EvidenceRecord) -> anyhow::Result<()> {
        write_json(&self.dir.join("evidence").join(format!("{}.json", safe_id(&rec.id)?)), rec)
    }

    pub fn analysis_path(&self, eid: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join("analysis").join(format!("{}.json", safe_id(eid)?)))
    }

    pub fn bookmarks_path(&self) -> PathBuf {
        self.dir.join("bookmarks.json")
    }

    /// Files carved from unallocated space (offsets and hashes, no copies).
    pub fn carved_path(&self, eid: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join("carved").join(format!("{}.json", safe_id(eid)?)))
    }

    /// Picture analysis of one evidence item (findings per image, no copies).
    pub fn photos_path(&self, eid: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join("photos").join(format!("{}.json", safe_id(eid)?)))
    }

    /// Hash analysis of one evidence item (every file's hashes, set matches).
    pub fn hashes_path(&self, eid: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join("hashes").join(format!("{}.json", safe_id(eid)?)))
    }

    /// Full-text index (SQLite FTS5) of one evidence item.
    pub fn index_path(&self, eid: &str) -> anyhow::Result<PathBuf> {
        Ok(self.dir.join("index").join(format!("{}.sqlite", safe_id(eid)?)))
    }

    pub fn patches(&self, eid: &str) -> anyhow::Result<Vec<Patch>> {
        let p = self.dir.join("patches").join(format!("{}.json", safe_id(eid)?));
        if !p.exists() {
            return Ok(vec![]);
        }
        read_json(&p)
    }

    pub fn save_patches(&self, eid: &str, patches: &[Patch]) -> anyhow::Result<()> {
        write_json(&self.dir.join("patches").join(format!("{}.json", safe_id(eid)?)), &patches)
    }
}

/// Ids are generated by us; reject anything that could escape the case dir.
pub fn safe_id(id: &str) -> anyhow::Result<&str> {
    if id.is_empty() || id.len() > 96 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("invalid id");
    }
    Ok(id)
}

fn slug(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let s = s.split('-').filter(|p| !p.is_empty()).collect::<Vec<_>>().join("-");
    let s: String = s.chars().take(40).collect();
    if s.is_empty() { "case".into() } else { s }
}

pub fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}

/// Writes via a temp file and rename so a crash never leaves half a file.
pub fn write_json<T: Serialize>(p: &Path, v: &T) -> anyhow::Result<()> {
    let tmp = p.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    fs::rename(&tmp, p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, path: &str) -> EvidenceRecord {
        EvidenceRecord {
            id: id.into(),
            name: id.into(),
            path: path.into(),
            format: "Raw".into(),
            size: 1,
            added: String::new(),
            notes: String::new(),
            hashes: None,
            hashed_at: None,
            expected: None,
            embedded: None,
            acquisition: None,
        }
    }

    #[test]
    fn migrate_root_moves_folder_and_inner_evidence_paths() {
        let base = std::env::temp_dir().join(format!("kokino-migrate-{}", std::process::id()));
        let (old, new) = (base.join("BaboonCases"), base.join("KokinoCases"));
        std::fs::create_dir_all(&old).unwrap();
        let c = Case::create(&old, "Test case", "alice", "").unwrap();
        let inside = old.join("images").join("disk.img").to_string_lossy().into_owned();
        c.save_evidence(&rec("e1", &inside)).unwrap();
        c.save_evidence(&rec("e2", r"D:\evidence\other.E01")).unwrap();
        let id = c.info.id.clone();
        drop(c);

        let (root, note) = Case::migrate_root(&old, &new);
        assert_eq!(root, new);
        assert!(note.unwrap().contains("1 evidence path(s)"));
        assert!(!old.exists());
        let c = Case::open(&new.join(&id)).unwrap();
        let paths: Vec<String> = c.evidence().into_iter().map(|e| e.path).collect();
        assert!(paths.contains(&new.join("images").join("disk.img").to_string_lossy().into_owned()));
        assert!(paths.contains(&r"D:\evidence\other.E01".to_string()));
        assert!(crate::audit::verify(&new.join(&id).join("audit.jsonl")).unwrap().ok);

        // Second run: nothing to do, the new folder is used.
        assert_eq!(Case::migrate_root(&old, &new), (new.clone(), None));
        std::fs::remove_dir_all(&base).ok();
    }
}
