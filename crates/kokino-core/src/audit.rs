//! Hash-chained, append-only audit log (JSON Lines).
//!
//! Each entry stores the SHA-256 of the previous entry's line. Any edit,
//! deletion or reordering of earlier lines breaks the chain and is reported
//! by `verify`.
//!
//! Appends hold an exclusive OS file lock and take the chain head from the
//! file's actual last line, so any number of `AuditLog` instances, threads
//! or processes (the server and `kokino user` on the console) extend one
//! chain instead of forking it.

use crate::hashing::sha256_hex;
use crate::time::now_iso;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub time: String,
    pub examiner: String,
    pub action: String,
    pub detail: serde_json::Value,
    pub tool_version: String,
    pub prev: String,
}

pub struct AuditLog {
    path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub entries: u64,
    pub ok: bool,
    pub broken_at: Option<u64>,
    pub head: String,
}

impl AuditLog {
    /// Opening never fails on a broken chain: the case must stay accessible
    /// so the break can be seen. Call `verify` to check it.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self { path: path.as_ref().to_path_buf() })
    }

    pub fn append(&self, examiner: &str, action: &str, detail: serde_json::Value) -> anyhow::Result<AuditEntry> {
        let mut f = OpenOptions::new().create(true).read(true).append(true).open(&self.path)?;
        f.lock()?;
        let res = (|| {
            let (seq, prev) = tail_state(&mut f)?;
            let entry = AuditEntry {
                seq,
                time: now_iso(),
                examiner: examiner.to_string(),
                action: action.to_string(),
                detail,
                tool_version: crate::TOOL_VERSION.to_string(),
                prev,
            };
            let mut line = serde_json::to_string(&entry)?;
            line.push('\n');
            f.write_all(line.as_bytes())?;
            f.sync_data()?;
            Ok(entry)
        })();
        let _ = f.unlock();
        res
    }

    pub fn entries(&self) -> anyhow::Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for line in BufReader::new(File::open(&self.path)?).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                out.push(serde_json::from_str(&line)?);
            }
        }
        Ok(out)
    }
}

/// Next sequence number and chain head, from the last line of the file.
fn tail_state(f: &mut File) -> anyhow::Result<(u64, String)> {
    let len = f.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok((0, GENESIS.to_string()));
    }
    let mut want = 4096u64;
    loop {
        let start = len.saturating_sub(want);
        f.seek(SeekFrom::Start(start))?;
        let mut buf = vec![0u8; (len - start) as usize];
        f.read_exact(&mut buf)?;
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        match body.iter().rposition(|&b| b == b'\n') {
            Some(i) => return state_from(&body[i + 1..], f),
            None if start == 0 => return state_from(body, f),
            None => want *= 4,
        }
    }
}

fn state_from(last: &[u8], f: &mut File) -> anyhow::Result<(u64, String)> {
    let head = sha256_hex(last);
    match serde_json::from_slice::<AuditEntry>(last) {
        Ok(e) => Ok((e.seq + 1, head)),
        // Unparseable last line (tampering or a torn write): continue after
        // it; verify() reports the break.
        Err(_) => {
            f.seek(SeekFrom::Start(0))?;
            let n = BufReader::new(&mut *f).lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()).count();
            Ok((n as u64, head))
        }
    }
}

/// Walks the chain and reports the first entry whose `prev` does not match.
pub fn verify(path: &Path) -> anyhow::Result<VerifyReport> {
    let mut head = GENESIS.to_string();
    let mut n = 0u64;
    if path.exists() {
        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let e: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => return Ok(VerifyReport { entries: n, ok: false, broken_at: Some(n), head }),
            };
            if e.prev != head || e.seq != n {
                return Ok(VerifyReport { entries: n, ok: false, broken_at: Some(n), head });
            }
            head = sha256_hex(line.as_bytes());
            n += 1;
        }
    }
    Ok(VerifyReport { entries: n, ok: true, broken_at: None, head })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("kokino-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        log.append("tester", "a", serde_json::json!({"x": 1})).unwrap();
        log.append("tester", "b", serde_json::json!({"x": 2})).unwrap();
        log.append("tester", "c", serde_json::json!({"x": 3})).unwrap();
        assert!(verify(&p).unwrap().ok);

        let text = std::fs::read_to_string(&p).unwrap().replace("\"x\":2", "\"x\":9");
        std::fs::write(&p, text).unwrap();
        let r = verify(&p).unwrap();
        assert!(!r.ok);
        assert_eq!(r.broken_at, Some(2));
        // A tampered log still opens and keeps recording.
        AuditLog::open(&p).unwrap().append("tester", "d", serde_json::json!({})).unwrap();
        assert_eq!(verify(&p).unwrap().broken_at, Some(2));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Separate instances on separate threads (as server requests and
    /// background jobs have) must extend one chain.
    #[test]
    fn concurrent_writers_keep_one_chain() {
        let dir = std::env::temp_dir().join(format!("kokino-audit-mt-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("audit.jsonl");
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let log = AuditLog::open(&p).unwrap();
                    for i in 0..40 {
                        log.append(&format!("w{t}"), "x", serde_json::json!({"i": i})).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let r = verify(&p).unwrap();
        assert!(r.ok, "{:?}", r);
        assert_eq!(r.entries, 320);
        std::fs::remove_dir_all(&dir).ok();
    }
}
