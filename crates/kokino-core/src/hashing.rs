//! Streaming multi-hash (MD5, SHA-1, SHA-256) in a single pass.

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Default)]
pub struct MultiHasher {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
}

impl MultiHasher {
    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
        self.sha256.update(data);
    }

    pub fn finish(self) -> Hashes {
        Hashes {
            md5: hex::encode(self.md5.finalize()),
            sha1: hex::encode(self.sha1.finalize()),
            sha256: hex::encode(self.sha256.finalize()),
        }
    }
}

/// Hashes a reader to EOF. `progress` receives the running byte count and may
/// return false to cancel.
pub fn hash_reader<R: Read>(mut r: R, mut progress: impl FnMut(u64) -> bool) -> anyhow::Result<(Hashes, u64)> {
    let mut h = MultiHasher::default();
    let mut buf = vec![0u8; 4 << 20];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
        if !progress(total) {
            anyhow::bail!("hashing cancelled");
        }
    }
    Ok((h.finish(), total))
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        let (h, n) = hash_reader(&b"abc"[..], |_| true).unwrap();
        assert_eq!(n, 3);
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
