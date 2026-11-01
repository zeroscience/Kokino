//! TLS for LAN mode: a provided certificate or a self-signed one kept in
//! `<cases root>/.kokino/tls/` and reused while its names still match.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct SelfSigned {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// SHA-256 of the DER certificate, colon-separated, for out-of-band checks.
    pub fingerprint: String,
}

pub fn self_signed(cases_root: &Path, names: &[String]) -> anyhow::Result<SelfSigned> {
    let dir = kokino_core::state_dir(cases_root).join("tls");
    std::fs::create_dir_all(&dir)?;
    let (cert, key, meta) = (dir.join("cert.pem"), dir.join("key.pem"), dir.join("cert.txt"));
    let wanted = names.join(",");
    if cert.exists() && key.exists() {
        if let Ok(m) = std::fs::read_to_string(&meta) {
            let mut lines = m.lines();
            if lines.next() == Some(wanted.as_str()) {
                if let Some(fp) = lines.next() {
                    return Ok(SelfSigned { cert, key, fingerprint: fp.to_string() });
                }
            }
        }
    }
    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Kokino Forensic Toolkit (self-signed)");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Zero Science Lab");
    // Valid from yesterday for two years (browsers reject longer leaf validity).
    use chrono::Datelike;
    let y = chrono::Utc::now().date_naive() - chrono::Days::new(1);
    params.not_before = rcgen::date_time_ymd(y.year(), y.month() as u8, y.day() as u8);
    params.not_after = rcgen::date_time_ymd(y.year() + 2, y.month() as u8, y.day().min(28) as u8);
    let kp = rcgen::KeyPair::generate()?;
    let c = params.self_signed(&kp)?;
    let fp = Sha256::digest(c.der()).iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":");
    std::fs::write(&cert, c.pem())?;
    std::fs::write(&key, kp.serialize_pem())?;
    std::fs::write(&meta, format!("{}\n{}\n", wanted, fp))?;
    Ok(SelfSigned { cert, key, fingerprint: fp })
}
