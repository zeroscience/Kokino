//! Checking for a newer Kokino release, only when someone asks.
//!
//! Nothing here runs on its own: the About page's "Check for updates"
//! button and `kokino version --check` call `check`, which makes one HTTPS
//! request to GitHub's releases API. Nothing is downloaded or installed;
//! the result names the version, its notes and checksums, and where to get
//! it. The server records every check in the system audit log.

use serde::Serialize;
use std::time::Duration;

pub const RELEASES_API: &str = "https://api.github.com/repos/zeroscience/Kokino/releases/latest";
pub const RELEASES_PAGE: &str = "https://github.com/zeroscience/Kokino/releases";

#[derive(Debug, Serialize)]
pub struct Update {
    pub current: String,
    pub latest: String,
    pub newer: bool,
    pub published: String,
    pub url: String,
    pub notes: String,
    /// Package file names and sizes.
    pub assets: Vec<(String, u64)>,
    /// SHA256SUMS.txt of the release, when it has one.
    pub checksums: Option<String>,
}

/// "v1.2.10" -> [1, 2, 10]; anything after a '-' is ignored.
fn parse(v: &str) -> Vec<u64> {
    v.trim_start_matches(['v', 'V']).split('-').next().unwrap_or("").split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    parse(latest) > parse(current)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).user_agent(&format!("Kokino/{}", kokino_core::TOOL_VERSION)).build()
}

/// Asks GitHub for the latest release.
pub fn check() -> anyhow::Result<Update> {
    let a = agent();
    let rel: serde_json::Value = a.get(RELEASES_API).set("Accept", "application/vnd.github+json").call()?.into_json()?;
    let tag = rel["tag_name"].as_str().unwrap_or("").to_string();
    if tag.is_empty() {
        anyhow::bail!("GitHub returned no release");
    }
    let assets: Vec<(String, u64)> = rel["assets"].as_array().map(|a| a.iter().map(|x| (x["name"].as_str().unwrap_or("").to_string(), x["size"].as_u64().unwrap_or(0))).collect()).unwrap_or_default();
    // The checksum file is small text; fetch it so the examiner can verify
    // a download against what the release itself states.
    let checksums = rel["assets"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"] == "SHA256SUMS.txt"))
        .and_then(|x| x["browser_download_url"].as_str())
        .and_then(|u| agent().get(u).call().ok())
        .and_then(|r| r.into_string().ok())
        .map(|s| s.chars().take(8192).collect());
    let current = kokino_core::TOOL_VERSION.to_string();
    Ok(Update {
        newer: is_newer(&tag, &current),
        latest: tag.trim_start_matches('v').to_string(),
        current,
        published: rel["published_at"].as_str().unwrap_or("").to_string(),
        url: rel["html_url"].as_str().unwrap_or(RELEASES_PAGE).to_string(),
        notes: rel["body"].as_str().unwrap_or("").chars().take(20_000).collect(),
        assets,
        checksums,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_newer("v1.2.7", "1.2.6"));
        assert!(is_newer("v1.10.0", "1.9.9"));
        assert!(!is_newer("v1.2.6", "1.2.6"));
        assert!(!is_newer("v1.2.5", "1.2.6"));
        assert!(!is_newer("garbage", "1.2.6"));
    }
}
