//! Fuzz targets: every parser that reads evidence bytes, each wrapped as
//! `fn(&[u8])`, with the seed files it starts from. A target must never
//! panic, hang or allocate without bound, whatever the input; errors are
//! fine. The driver is in `main.rs`; `tests/regress.rs` replays the inputs
//! saved in `regress/`.

use std::io::Cursor;
use std::path::{Path, PathBuf};

pub struct Target {
    pub name: &'static str,
    pub run: fn(&[u8]),
    /// Seed files or folders, relative to the workspace root.
    pub seeds: &'static [&'static str],
}

pub const TARGETS: &[Target] = &[
    Target { name: "volume", run: volume, seeds: &["tests/fixtures/disk-fat.img", "tests/fixtures/disk-win.img"] },
    Target { name: "ntfs", run: ntfs, seeds: &["tests/fixtures/testfs1", "tests/fixtures/testfs1-af", "tests/fixtures/testfs1-win"] },
    Target { name: "fat", run: fat, seeds: &["tests/fixtures/fat12.img", "tests/fixtures/fat16.img", "tests/fixtures/fat32.img", "tests/fixtures/exfat.img"] },
    Target { name: "ext", run: ext, seeds: &["tests/fixtures/ext2.img", "tests/fixtures/ext3.img", "tests/fixtures/ext4.img"] },
    Target { name: "linuxlogs", run: linuxlogs, seeds: &["crates/kokino-fuzz/seeds/linux"] },
    Target { name: "vdisk", run: vdisk, seeds: &["tests/fixtures/vd-dynamic.vhd", "tests/fixtures/vd-dynamic.vhdx", "tests/fixtures/vd-sparse.vmdk", "tests/fixtures/vd-stream.vmdk"] },
    Target { name: "optical", run: optical, seeds: &["tests/fixtures/iso-rr-joliet.iso", "tests/fixtures/iso-udf.iso", "tests/fixtures/iso-multisession.iso"] },
    Target { name: "mac", run: mac, seeds: &["tests/fixtures/hfsplus.img", "tests/fixtures/apfs.img"] },
    Target { name: "ewf", run: ewf, seeds: &["tests/fixtures/disk-af-odd.E01", "tests/fixtures/disk-af.E01"] },
    Target { name: "indx", run: indx, seeds: &["crates/kokino-fuzz/seeds/indx"] },
    Target { name: "usn", run: usn, seeds: &["crates/kokino-fuzz/seeds/usn"] },
    Target { name: "shellbags", run: shellbags, seeds: &["crates/kokino-fuzz/seeds/shellbags"] },
    Target { name: "ese", run: ese, seeds: &["tests/fixtures/win/SRUDB-4k.dat", "tests/fixtures/win/SRUDB.dat"] },
    Target { name: "registry", run: registry, seeds: &["tests/fixtures/win/Users_alice_NTUSER.DAT", "tests/fixtures/win/Windows_System32_config_SAM", "tests/fixtures/win/Windows_System32_config_SOFTWARE", "tests/fixtures/win/Windows_System32_config_SYSTEM", "tests/fixtures/win/Windows_AppCompat_Programs_Amcache.hve"] },
    Target { name: "evtx", run: evtx, seeds: &["tests/fixtures/win/Windows_System32_winevt_Logs_Security.evtx", "tests/fixtures/win/Windows_System32_winevt_Logs_System.evtx", "tests/fixtures/win/Windows_System32_winevt_Logs_Microsoft-Windows-PowerShell_4Operational.evtx"] },
    Target { name: "lnk", run: lnk, seeds: &["tests/fixtures/win/Users_alice_AppData_Roaming_Microsoft_Windows_Recent_keys.txt.lnk", "tests/fixtures/win/Users_alice_AppData_Roaming_Microsoft_Windows_Recent_nightjar.docx.lnk"] },
    Target { name: "prefetch", run: prefetch, seeds: &["tests/fixtures/win/CMD.EXE-4A81B364.pf", "tests/fixtures/win/SDELETE64.EXE-1A2B3C4D.pf", "tests/fixtures/win/Windows_Prefetch_POWERSHELL.EXE-022A3C66.pf", "tests/fixtures/win/Windows_Prefetch_VERACRYPT.EXE-7E3A5C21.pf"] },
    Target { name: "jumplist", run: jumplist, seeds: &["tests/fixtures/win/Users_alice_AppData_Roaming_Microsoft_Windows_Recent_AutomaticDestinations_9b9cdc69c1c24e2b.automaticDestinations-ms", "tests/fixtures/win/Users_alice_AppData_Roaming_Microsoft_Windows_Recent_CustomDestinations_5d696d521de238c3.customDestinations-ms"] },
    Target { name: "xpress", run: xpress, seeds: &["crates/kokino-fuzz/seeds/xpress"] },
    Target { name: "lznt1", run: lznt1, seeds: &["tests/fixtures/win/lznt1-text.lznt", "tests/fixtures/win/lznt1-long.lznt", "tests/fixtures/win/lznt1-mixed.lznt"] },
    Target { name: "doc", run: doc, seeds: &["crates/kokino-fuzz/seeds/doc"] },
    Target { name: "photo", run: photo, seeds: &["crates/kokino-fuzz/seeds/photo"] },
    Target { name: "carve", run: carve, seeds: &["crates/kokino-fuzz/seeds/photo", "crates/kokino-fuzz/seeds/doc", "tests/fixtures/win/Users_alice_AppData_Roaming_Microsoft_Windows_Recent_keys.txt.lnk", "tests/fixtures/win/CMD.EXE-4A81B364.pf"] },
    Target { name: "browser", run: browser, seeds: &["crates/kokino-fuzz/seeds/browser"] },
    Target { name: "strings", run: strings, seeds: &["crates/kokino-fuzz/seeds/doc", "tests/fixtures/win/Users_alice_NTUSER.DAT"] },
];

pub fn target(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.name == name)
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The seed files of a target, in a stable order.
pub fn load_seeds(t: &Target) -> Vec<Vec<u8>> {
    let root = workspace_root();
    let mut files = vec![];
    for s in t.seeds {
        let p = root.join(s);
        if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
            v.sort();
            files.extend(v);
        } else {
            files.push(p);
        }
    }
    files.iter().filter_map(|p| std::fs::read(p).ok()).collect()
}

const READ_CAP: usize = 64 << 10;

fn volume(d: &[u8]) {
    let mut c = Cursor::new(d);
    for v in kokino_image::volume::detect_volumes(&mut c, d.len() as u64) {
        kokino_image::volume::detect_fs(&mut c, v.start);
    }
}

/// With KOKINO_FUZZ_TRACE set, targets say which stage they are in (to
/// locate a hang).
fn trace(stage: &str) {
    if std::env::var_os("KOKINO_FUZZ_TRACE").is_some() {
        static T0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        eprintln!("trace: {:>8.3}s {}", T0.get_or_init(std::time::Instant::now).elapsed().as_secs_f64(), stage);
    }
}

fn ntfs(d: &[u8]) {
    let mut c = Cursor::new(d);
    trace("open");
    let Ok(ntfs) = kokino_ntfs::open_ntfs(&mut c) else { return };
    trace("scan");
    if let Ok(scan) = kokino_ntfs::scan_with(&ntfs, &mut c, |n, t| {
        trace(&format!("record {} of {}", n, t));
        true
    }) {
        for e in scan.entries.iter().take(64) {
            for s in &e.streams {
                trace(&format!("read record {} stream {:?}", e.record, s.name));
                let _ = kokino_ntfs::read_stream_with(&ntfs, &mut c, e.record, &s.name, 0, READ_CAP);
                trace("extents");
                let _ = kokino_ntfs::stream_extents(&ntfs, &mut c, e.record, &s.name);
            }
        }
    }
    trace("free runs");
    let _ = kokino_ntfs::free_runs(&ntfs, &mut c);
    trace("done");
}

fn fat(d: &[u8]) {
    let mut c = Cursor::new(d);
    let Ok(v) = kokino_fat::open(&mut c, d.len() as u64) else { return };
    if let Ok(scan) = kokino_fat::scan(&v, &mut c, |_, _| true) {
        for e in scan.entries.iter().take(64) {
            let _ = v.read(&mut c, e, 0, READ_CAP);
            v.extents(e);
        }
    }
}

fn ext(d: &[u8]) {
    let mut c = Cursor::new(d);
    let Ok(v) = kokino_ext::open(&mut c, d.len() as u64) else { return };
    if let Ok(scan) = kokino_ext::scan(&v, &mut c, |_, _| true) {
        for e in scan.entries.iter().take(64) {
            let _ = v.read(&mut c, e, 0, READ_CAP);
            let _ = v.extents(&mut c, e);
        }
    }
    v.free_runs(&mut c);
}

fn linuxlogs(d: &[u8]) {
    kokino_analysis::linux::fuzz_parsers(d);
}

fn ewf(d: &[u8]) {
    use std::io::Read;
    let dir = std::env::temp_dir().join(format!("kokino-fuzz-ewf-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("image.E01");
    if std::fs::write(&p, d).is_err() {
        return;
    }
    if let Ok(img) = kokino_image::ewf::EwfImage::open(&p) {
        let img = std::sync::Arc::new(img);
        let mut r = img.reader();
        let mut buf = vec![0u8; READ_CAP];
        let mut total = 0;
        while total < (8 << 20) {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    }
}

fn vdisk(d: &[u8]) {
    use std::io::{Read, Seek, SeekFrom};
    let dir = std::env::temp_dir().join(format!("kokino-fuzz-vdisk-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("disk.bin");
    if std::fs::write(&p, d).is_err() {
        return;
    }
    if let Ok(Some(v)) = kokino_image::vdisk::open(&p) {
        let v = std::sync::Arc::new(v);
        let mut r = v.reader();
        let mut buf = vec![0u8; READ_CAP];
        let mut total = 0;
        while total < (8 << 20) {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        // A few reads far into the disk (sparse disks claim large sizes).
        for f in [3u64, 7, 11] {
            let _ = r.seek(SeekFrom::Start(v.size / f));
            let _ = r.read(&mut buf[..4096]);
        }
    }
}

fn optical(d: &[u8]) {
    let mut c = Cursor::new(d);
    if let Ok(v) = kokino_iso::open(&mut c, d.len() as u64) {
        if let Ok(s) = kokino_iso::scan(&v, &mut c, |_, _| true) {
            for e in s.entries.iter().take(64) {
                let _ = v.read(&mut c, e, 0, READ_CAP);
            }
        }
    }
    if let Ok(v) = kokino_iso::udf::open(&mut c, d.len() as u64) {
        if let Ok(s) = kokino_iso::udf::scan(&v, &mut c, |_, _| true) {
            for e in s.entries.iter().take(64) {
                let _ = v.read(&mut c, e, 0, READ_CAP);
            }
        }
    }
}

fn mac(d: &[u8]) {
    // A GPT disk (the APFS seed): start at its first partition.
    let d = if d.get(512..520) == Some(b"EFI PART") {
        let lba = d.get(1024 + 32..1024 + 40).map(|x| u64::from_le_bytes(x.try_into().unwrap())).unwrap_or(0) as usize;
        d.get(lba.saturating_mul(512)..).unwrap_or(&[])
    } else {
        d
    };
    let mut c = Cursor::new(d);
    if let Ok(v) = kokino_mac::hfs::open(&mut c, d.len() as u64) {
        if let Ok(s) = kokino_mac::hfs::scan(&v, &mut c, |_, _| true) {
            for e in s.entries.iter().take(64) {
                let _ = v.read(&mut c, e, 0, READ_CAP);
            }
        }
        let _ = v.free_runs(&mut c);
    }
    if let Ok(v) = kokino_mac::apfs::open(&mut c, d.len() as u64) {
        if let Ok(s) = kokino_mac::apfs::scan(&v, &mut c, |_, _| true) {
            for e in s.entries.iter().take(64) {
                let _ = v.read(&mut c, e, 0, READ_CAP);
            }
        }
    }
    // The decompressors on the raw input too.
    let _ = kokino_mac::decmpfs::lzvn(d.get(..4096).unwrap_or(d), 1 << 16);
    let _ = kokino_mac::decmpfs::decompress(d.get(..4096).unwrap_or(d), d.get(4096..65536));
}

/// Folder index records and $LogFile pages: the name carver with a fixed
/// folder, and with every parent accepted (the most permissive case).
fn indx(d: &[u8]) {
    let _ = kokino_ntfs::indx::scan_allocation(&mut d.to_vec(), (40, 3), true);
    let _ = kokino_ntfs::indx::scan_root(d, (5, 5));
    let _ = kokino_ntfs::indx::scan_logfile(&mut d.to_vec(), &|_| true);
}

fn usn(d: &[u8]) {
    let mut g = kokino_artifacts::usn::Grouper::default();
    // In two pieces, as the reader hands over chunks.
    let half = d.len() / 2;
    let used = kokino_artifacts::usn::parse(&d[..half], &mut |r| g.push(r));
    kokino_artifacts::usn::parse(&d[used..], &mut |r| g.push(r));
    let (changes, _) = g.finish();
    for c in changes.iter().take(64) {
        let _ = kokino_artifacts::usn::describe(c.reasons);
    }
    let _ = kokino_artifacts::usn::parse_max(d);
}

fn shellbags(d: &[u8]) {
    if let Ok(h) = kokino_artifacts::registry::Hive::parse(d.to_vec()) {
        for p in ["Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "Software\\Microsoft\\Windows\\Shell\\BagMRU"] {
            if let Some(k) = h.open(p) {
                let _ = kokino_artifacts::shellbags::walk(&k);
            }
        }
    }
    let _ = kokino_artifacts::shellbags::shell_item(d);
    let _ = kokino_artifacts::shellbags::shell_item(d.get(..512).unwrap_or(d));
}

/// ESE databases: catalog, every table's rows, and SRUM on top.
fn ese(d: &[u8]) {
    if let Ok(db) = kokino_artifacts::ese::Db::open(d) {
        for t in &db.tables {
            let _ = db.rows(t, 5000);
        }
    }
    kokino_analysis::windows::fuzz_srum(d);
    let _ = kokino_artifacts::ese::uncompress(d.get(..4096).unwrap_or(d));
}

fn registry(d: &[u8]) {
    let Ok(h) = kokino_artifacts::registry::Hive::parse(d.to_vec()) else { return };
    let mut n = 0;
    h.root().walk(&mut |k, _| {
        n += 1;
        if n < 5000 {
            let _ = k.name();
            let _ = k.values();
        }
    });
    for p in ["ControlSet001\\Enum\\USBSTOR", "Microsoft\\Windows\\CurrentVersion\\Run", "SAM\\Domains\\Account\\Users", "Root\\InventoryApplicationFile"] {
        if let Some(k) = h.open(p) {
            for s in k.subkeys() {
                let _ = s.values();
            }
        }
    }
}

fn evtx(d: &[u8]) {
    let _ = kokino_artifacts::evtx::parse(d, &mut |_| {});
}

fn lnk(d: &[u8]) {
    let _ = kokino_artifacts::lnk::parse(d);
    let _ = kokino_artifacts::lnk::shell_items_path(d);
}

fn prefetch(d: &[u8]) {
    let _ = kokino_artifacts::prefetch::parse(d);
}

fn jumplist(d: &[u8]) {
    let _ = kokino_artifacts::jumplist::parse("9b9cdc69c1c24e2b.automaticDestinations-ms", d);
    let _ = kokino_artifacts::cfb::streams(d, 1 << 20);
}

/// First 4 bytes: the declared decompressed size; the rest: compressed data.
fn xpress(d: &[u8]) {
    if d.len() < 4 {
        return;
    }
    let n = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize;
    let _ = kokino_artifacts::xpress::decompress(&d[4..], n);
}

/// NTFS compression units are 64 KiB.
fn lznt1(d: &[u8]) {
    let _ = kokino_ntfs::lznt1::decompress(d, 64 << 10);
    let _ = kokino_ntfs::lznt1::decompress(d, usize::MAX);
}

fn doc(d: &[u8]) {
    let _ = kokino_analysis::doctext::extract(d);
}

fn photo(d: &[u8]) {
    trace("analyze");
    let _ = kokino_analysis::photo::analyze(d, "DCIM/IMG_0001.JPG");
    trace("decode_rgb");
    let _ = kokino_analysis::photo::decode_rgb(d);
    trace("png");
    let _ = kokino_analysis::photo::raster::png(d);
    trace("bmp");
    let _ = kokino_analysis::photo::raster::bmp(d);
    trace("done");
}

fn carve(d: &[u8]) {
    let mut s: &[u8] = d;
    let _ = kokino_analysis::carve::identify(&mut s, 0);
}

fn browser(d: &[u8]) {
    let (path, name) = if d.windows(10).any(|w| w == b"moz_places") {
        ("Users/alice/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite", "places.sqlite")
    } else {
        ("Users/alice/AppData/Local/Google/Chrome/User Data/Default/History", "History")
    };
    let Some(mut src) = kokino_artifacts::browser::classify(path, name) else { return };
    let mut out = kokino_artifacts::browser::WebActivity::default();
    let _ = kokino_artifacts::browser::parse(&mut src, d, None, None, &mut out);
}

fn strings(d: &[u8]) {
    let _ = kokino_analysis::binview::strings(d, 0, 4);
    let _ = kokino_analysis::binview::cell(d);
}

// ---------------------------------------------------------------- inputs

/// splitmix64: small, fast, and the whole state is the seed.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// Offsets worth mutating: mostly near non-zero bytes, where the
/// structures are (images are largely zero-filled).
pub struct Seed {
    data: Vec<u8>,
    hot: Vec<usize>,
}

pub fn prepare(seeds: Vec<Vec<u8>>) -> Vec<Seed> {
    seeds
        .into_iter()
        .map(|data| {
            let step = (data.len() / 200_000).max(1);
            let hot = (0..data.len()).step_by(step).filter(|&i| data[i] != 0).collect();
            Seed { data, hot }
        })
        .collect()
}

const INTERESTING: &[u64] = &[0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x1_0000, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff, 0x1_0000_0000, u64::MAX / 2, u64::MAX - 1, u64::MAX];

/// Input number `n` for this run: a seed with 1 to 8 stacked mutations.
pub fn generate(seeds: &[Seed], run_seed: u64, n: u64) -> Vec<u8> {
    let mut r = Rng(run_seed ^ n.wrapping_mul(0xA24B_AED4_963E_E407));
    let s = &seeds[r.below(seeds.len())];
    let mut d = s.data.clone();
    if n == 0 {
        return d; // the seed itself, unmutated
    }
    for _ in 0..1 + r.below(8) {
        if d.is_empty() {
            d.push(0);
        }
        let at = if !s.hot.is_empty() && r.below(10) < 7 {
            (s.hot[r.below(s.hot.len())] + r.below(64)).saturating_sub(32).min(d.len() - 1)
        } else {
            r.below(d.len())
        };
        match r.below(10) {
            0 => d[at] ^= 1 << r.below(8),
            1 => d[at] = r.next() as u8,
            2 | 3 => {
                let w = [1usize, 2, 4, 8][r.below(4)];
                let v = INTERESTING[r.below(INTERESTING.len())].wrapping_add([0u64, 1, u64::MAX][r.below(3)]);
                let bytes = if r.below(4) == 0 { v.to_be_bytes() } else { v.to_le_bytes() };
                let src = if r.below(4) == 0 { &bytes[8 - w..] } else { &bytes[..w] };
                for (i, b) in src.iter().enumerate() {
                    if at + i < d.len() {
                        d[at + i] = *b;
                    }
                }
            }
            4 => {
                let len = 1 + r.below(256);
                let fill = [0u8, 0xff, 0x41][r.below(3)];
                for b in d.iter_mut().skip(at).take(len) {
                    *b = fill;
                }
            }
            5 => {
                // Copy a block from elsewhere in the input over this place.
                let len = 1 + r.below(512);
                let from = r.below(d.len());
                let chunk: Vec<u8> = d[from..(from + len).min(d.len())].to_vec();
                for (i, b) in chunk.iter().enumerate() {
                    if at + i < d.len() {
                        d[at + i] = *b;
                    }
                }
            }
            6 => d.truncate(at.max(1)),
            7 => {
                let len = 1 + r.below(64);
                d.drain(at..(at + len).min(d.len()));
            }
            8 => {
                let len = 1 + r.below(64);
                let ins: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
                d.splice(at..at, ins);
            }
            _ => {
                for i in 0..1 + r.below(16) {
                    if at + i < d.len() {
                        d[at + i] = r.next() as u8;
                    }
                }
            }
        }
    }
    d
}
