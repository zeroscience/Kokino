//! Golden results: every test image analyzed and reduced to the numbers an
//! examiner relies on, compared with what was recorded in tests/golden/.
//!
//! For each volume: its place and file system, the file statistics, the
//! anti-forensics score, the number of entries in every list the analysis
//! produces (web visits, event records, logons, messages, ...) and a digest
//! of the file listing (path, size, deleted, directory, signature). Any
//! change to what Kokino finds in these images fails the test with the
//! differences listed.
//!
//! After a deliberate change, review the differences, then record the new
//! results with
//!     KOKINO_BLESS=1 cargo test -p kokino-analysis --test golden
//! and commit tests/golden/ with the change that explains them.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// (golden name, image, BitLocker startup key)
const IMAGES: &[(&str, &str, Option<&str>)] = &[
    ("apfs", "apfs.img", None),
    ("bitlocker-xts-locked", "bitlocker-xts.img", None),
    ("bitlocker-xts-unlocked", "bitlocker-xts.img", Some("bitlocker-xts.BEK")),
    ("collection-kape", "collection-kape.zip", None),
    ("collection-uac-mac", "collection-uac-mac.tar.gz", None),
    ("collection-uac", "collection-uac.tar.gz", None),
    ("collection-velociraptor", "collection-velociraptor.zip", None),
    ("disk-af-odd-e01", "disk-af-odd.E01", None),
    ("disk-af-split-e01", "disk-af-split.E01", None),
    ("disk-af-e01", "disk-af.E01", None),
    ("disk-af", "disk-af.img", None),
    ("disk-fat", "disk-fat.img", None),
    ("disk-win", "disk-win.img", None),
    ("exfat", "exfat.img", None),
    ("ext2", "ext2.img", None),
    ("ext3", "ext3.img", None),
    ("ext4", "ext4.img", None),
    ("fat12", "fat12.img", None),
    ("fat16", "fat16.img", None),
    ("fat32", "fat32.img", None),
    ("hfsplus", "hfsplus.img", None),
    ("iso-multisession", "iso-multisession.iso", None),
    ("iso-rr-joliet", "iso-rr-joliet.iso", None),
    ("iso-udf", "iso-udf.iso", None),
    ("linux-server", "linux-server.img", None),
    ("testfs1", "testfs1", None),
    ("testfs1-af", "testfs1-af", None),
    ("testfs1-win", "testfs1-win", None),
    ("vd-diff-vhd", "vd-diff.vhd", None),
    ("vd-diff-vhdx", "vd-diff.vhdx", None),
    ("vd-dynamic-vhd", "vd-dynamic.vhd", None),
    ("vd-dynamic-vhdx", "vd-dynamic.vhdx", None),
    ("vd-flat-vmdk", "vd-flat.vmdk", None),
    ("vd-snap-vmdk", "vd-snap.vmdk", None),
    ("vd-sparse-vmdk", "vd-sparse.vmdk", None),
    ("vd-split-vmdk", "vd-split.vmdk", None),
    ("vd-stream-vmdk", "vd-stream.vmdk", None),
    ("vd-vmware-stream-vmdk", "vd-vmware-stream.vmdk", None),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// 64-bit FNV-1a: a stable digest with no extra dependency.
fn fnv(data: &[u8], mut h: u64) -> u64 {
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// The length of every list in `v`, by its path ("web.visits": 12).
fn lists(v: &Value, path: &str, out: &mut BTreeMap<String, usize>) {
    match v {
        Value::Array(a) => {
            out.insert(path.to_string(), a.len());
        }
        Value::Object(m) => {
            for (k, x) in m {
                let p = if path.is_empty() { k.clone() } else { format!("{}.{}", path, k) };
                lists(x, &p, out);
            }
        }
        _ => {}
    }
}

/// Fractions to 4 places: the scores are f32 and their last digits do not
/// survive a trip through JSON text.
fn round(v: &mut Value) {
    match v {
        Value::Number(n) if n.is_f64() => *v = json!((n.as_f64().unwrap() * 10_000.0).round() / 10_000.0),
        Value::Array(a) => a.iter_mut().for_each(round),
        Value::Object(m) => m.values_mut().for_each(round),
        _ => {}
    }
}

fn summarize(a: &kokino_analysis::Analysis) -> Value {
    let mut vols = vec![];
    for f in &a.filesystems {
        let v = serde_json::to_value(f).unwrap();
        let mut counts = BTreeMap::new();
        for k in ["web", "windows", "linux", "mail", "indicators", "unreadable"] {
            if let Some(x) = v.get(k) {
                lists(x, k, &mut counts);
            }
        }
        // Empty lists say nothing and would make every new artifact a diff.
        counts.retain(|_, n| *n > 0);
        let mut rows: Vec<String> = f
            .files
            .iter()
            .map(|r| format!("{}|{}|{}|{}|{}", r.e.path, r.e.size, r.e.deleted, r.e.is_dir, r.sig.as_deref().unwrap_or("")))
            .collect();
        rows.sort();
        let digest = rows.iter().fold(0xcbf2_9ce4_8422_2325, |h, r| fnv(r.as_bytes(), fnv(b"\n", h)));
        vols.push(json!({
            "volume": {"index": f.volume.index, "start": f.volume.start, "length": f.volume.length, "fs": f.volume.fs_label},
            "stats": v["stats"],
            "score": v["score"],
            "files": f.files.len(),
            "listing": format!("{:016x}", digest),
            "lists": counts,
        }));
    }
    json!({
        "image_format": a.image_format,
        "image_size": a.image_size,
        "volumes": a.volumes.len(),
        "errors": a.errors.len(),
        "filesystems": vols,
    })
}

fn analyze(image: &str, bek: Option<&str>) -> kokino_analysis::Analysis {
    let fx = root().join("tests/fixtures");
    let mut ev = kokino_image::Evidence::open(&fx.join(image)).unwrap_or_else(|e| panic!("{}: {}", image, e));
    if let Some(k) = bek {
        let key = std::fs::read(fx.join(k)).unwrap();
        let (e, res) = kokino_image::unlock_bitlocker(ev, &kokino_image::bde::Secret::StartupKey(&key));
        assert!(res.iter().any(|x| x.2.is_ok()), "{} did not unlock", image);
        ev = e;
    }
    kokino_analysis::analyze(&ev, &mut |_, _, _| true).unwrap_or_else(|e| panic!("{}: {}", image, e))
}

/// Differences between two JSON values, one line each.
fn diff(path: &str, want: &Value, got: &Value, out: &mut Vec<String>) {
    match (want, got) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            let null = Value::Null;
            for k in keys {
                diff(&format!("{}.{}", path, k), a.get(k).unwrap_or(&null), b.get(k).unwrap_or(&null), out);
            }
        }
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                diff(&format!("{}[{}]", path, i), x, y, out);
            }
        }
        _ if want != got => out.push(format!("{}: was {}, now {}", path, want, got)),
        _ => {}
    }
}

#[test]
fn golden_results() {
    let dir = root().join("tests/golden");
    let bless = std::env::var("KOKINO_BLESS").is_ok_and(|v| v == "1");
    let mut problems = vec![];
    for (name, image, bek) in IMAGES {
        let mut got = summarize(&analyze(image, *bek));
        round(&mut got);
        let file = dir.join(format!("{}.json", name));
        if bless {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&file, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            problems.push(format!("{}: no recorded results ({}); run with KOKINO_BLESS=1", name, file.display()));
            continue;
        };
        let want: Value = serde_json::from_str(&text).unwrap();
        let mut d = vec![];
        diff(name, &want, &got, &mut d);
        problems.extend(d);
    }
    // A recorded result whose image is gone from the list is stale.
    if !bless {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().trim_end_matches(".json").to_string();
            if !IMAGES.iter().any(|x| x.0 == n) {
                problems.push(format!("{}: recorded but no longer tested", n));
            }
        }
    }
    assert!(problems.is_empty(), "results differ from tests/golden ({} differences):\n{}", problems.len(), problems.join("\n"));
}
