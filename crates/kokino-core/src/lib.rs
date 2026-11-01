//! Kokino core: case store, hash-chained audit log, hashing and time helpers.

#![forbid(unsafe_code)]

pub mod audit;
pub mod bookmarks;
pub mod case;
pub mod hashing;
pub mod time;
pub mod users;

pub const TOOL_NAME: &str = "Kokino Forensic Toolkit";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VENDOR: &str = "Zero Science Lab";

/// Hidden folder under the cases root for accounts, the system audit log and
/// TLS material. A `.baboon` folder from before the rename is moved here once.
pub fn state_dir(cases_root: &std::path::Path) -> std::path::PathBuf {
    let dir = cases_root.join(".kokino");
    let legacy = cases_root.join(".baboon");
    if !dir.exists() && legacy.is_dir() {
        let _ = std::fs::rename(&legacy, &dir);
    }
    dir
}
