//! File signature (magic number) detection and extension mismatch checks.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Executable,
    Document,
    Image,
    Audio,
    Video,
    Archive,
    Database,
    Email,
    Crypto,
    DiskImage,
    Forensic,
    System,
    Script,
    Other,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::Executable => "Executables",
            Category::Document => "Documents",
            Category::Image => "Images",
            Category::Audio => "Audio",
            Category::Video => "Video",
            Category::Archive => "Archives",
            Category::Database => "Databases",
            Category::Email => "Email",
            Category::Crypto => "Encrypted / keys",
            Category::DiskImage => "Disk images",
            Category::Forensic => "Windows artifacts",
            Category::System => "System",
            Category::Script => "Scripts",
            Category::Other => "Other",
        }
    }
}

pub struct Signature {
    pub id: &'static str,
    pub label: &'static str,
    pub category: Category,
    pub offset: usize,
    pub magic: &'static [u8],
    /// Extensions that legitimately carry this signature (lowercase, no dot).
    pub exts: &'static [&'static str],
}

macro_rules! sig {
    ($id:expr, $label:expr, $cat:ident, $off:expr, $magic:expr, [$($e:expr),*]) => {
        Signature { id: $id, label: $label, category: Category::$cat, offset: $off, magic: $magic, exts: &[$($e),*] }
    };
}

/// Ordered most specific first.
pub static SIGNATURES: &[Signature] = &[
    sig!("pe", "Windows PE executable", Executable, 0, b"MZ", ["exe", "dll", "sys", "scr", "ocx", "cpl", "drv", "efi", "mui", "com", "ax", "acm", "tlb", "winmd", "node", "pyd", "msstyles", "tsp", "fon", "mun", "ime", "flt", "api", "ex_", "dl_", "sy_", "nls", "pif", "icl", "rll", "bpl", "xll", "wll", "olb"]),
    sig!("elf", "ELF executable", Executable, 0, b"\x7fELF", ["", "so", "o", "elf", "bin", "ko", "axf", "prx", "puff", "mod"]),
    sig!("macho64", "Mach-O executable", Executable, 0, b"\xcf\xfa\xed\xfe", ["", "dylib", "bundle", "so"]),
    sig!("lnk", "Windows shortcut (LNK)", Forensic, 0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", ["lnk"]),
    sig!("evtx", "Windows event log (EVTX)", Forensic, 0, b"ElfFile\x00", ["evtx"]),
    sig!("regf", "Registry hive", Forensic, 0, b"regf", ["", "dat", "hve", "sav", "log", "log1", "log2", "hiv", "bak", "old", "tmp"]),
    sig!("pf_mam", "Prefetch (compressed)", Forensic, 0, b"MAM\x04", ["pf"]),
    sig!("pf", "Prefetch", Forensic, 4, b"SCCA", ["pf"]),
    sig!("esedb", "ESE database", Database, 4, b"\xef\xcd\xab\x89", ["edb", "dat", "db", "sdb", "jfm", "chk", "vol"]),
    sig!("sqlite", "SQLite database", Database, 0, b"SQLite format 3\x00", ["db", "sqlite", "sqlite3", "", "dat", "localstorage", "storage", "ldb", "db3", "sqlitedb", "cookies", "tmp", "edb"]),
    sig!("pdf", "PDF document", Document, 0, b"%PDF", ["pdf", "ai"]),
    sig!("ole", "OLE2 compound (Office 97-2003, MSI)", Document, 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ["doc", "xls", "ppt", "msi", "msp", "msg", "dot", "xlt", "pps", "pot", "vsd", "pub", "db", "mpp", "ost", "suo", "wps", "xla", "ppa", "mst", "adp", "cab", "", "dat", "sldprt", "max", "ica", "thumbcache", "automaticdestinations-ms", "jtx", "hwp", "doc_", "ole", "edrwx", "pcb", "sch", "sldasm"]),
    sig!("zip", "ZIP container (also DOCX/XLSX/JAR/APK)", Archive, 0, b"PK\x03\x04", ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "xltx", "potx", "jar", "apk", "aar", "xpi", "crx", "odt", "ods", "odp", "odg", "epub", "kmz", "vsix", "nupkg", "appx", "msix", "appxbundle", "ipa", "whl", "egg", "war", "ear", "xps", "oxps", "3mf", "sketch", "pbix", "idml", "cbz", "zipx", "mmap", "xmind", "vsdx", "ora", "usdz", "kra", "pkpass", "aab", "sb3", "mcworld", "pk3", "pk4", "gadget", "wmz", "thmx", "ear", "sxw", "otf_", "lpkg", "jmod", "", "dat", "tmp", "pack", "bin", "zip_", "crx3", "ova_"]),
    sig!("rar", "RAR archive", Archive, 0, b"Rar!\x1a\x07", ["rar", "cbr", "r00", "r01"]),
    sig!("7z", "7-Zip archive", Archive, 0, b"7z\xbc\xaf\x27\x1c", ["7z"]),
    sig!("gzip", "GZIP", Archive, 0, b"\x1f\x8b\x08", ["gz", "tgz", "svgz", "emz", "wmz", "", "dat", "tar_"]),
    sig!("bzip2", "BZIP2", Archive, 0, b"BZh", ["bz2", "tbz2", "tbz"]),
    sig!("xz", "XZ", Archive, 0, b"\xfd7zXZ\x00", ["xz", "txz"]),
    sig!("zstd", "Zstandard", Archive, 0, b"\x28\xb5\x2f\xfd", ["zst", ""]),
    sig!("cab", "Microsoft Cabinet", Archive, 0, b"MSCF", ["cab", "msu", "onepkg", "", "ex_", "dl_", "sy_", "in_", "xpi"]),
    sig!("tar", "TAR archive", Archive, 257, b"ustar", ["tar"]),
    sig!("png", "PNG image", Image, 0, b"\x89PNG\r\n\x1a\n", ["png", "apng"]),
    sig!("jpeg", "JPEG image", Image, 0, b"\xff\xd8\xff", ["jpg", "jpeg", "jpe", "jfif", "thm", ""]),
    sig!("gif", "GIF image", Image, 0, b"GIF8", ["gif"]),
    sig!("bmp", "BMP image", Image, 0, b"BM", ["bmp", "dib", "cur_"]),
    sig!("tiff_le", "TIFF image", Image, 0, b"II*\x00", ["tif", "tiff", "dng", "nef", "cr2", "arw", "orf", "rw2", "pef", "sr2", "srw"]),
    sig!("tiff_be", "TIFF image", Image, 0, b"MM\x00*", ["tif", "tiff", "dng", "nef", "pef", "srf", "3fr", "erf"]),
    sig!("ico", "Icon", Image, 0, b"\x00\x00\x01\x00", ["ico", "cur", "spl"]),
    sig!("psd", "Photoshop", Image, 0, b"8BPS", ["psd", "psb"]),
    sig!("webp", "WebP image", Image, 8, b"WEBP", ["webp"]),
    sig!("wav", "WAV audio", Audio, 8, b"WAVE", ["wav"]),
    sig!("avi", "AVI video", Video, 8, b"AVI ", ["avi"]),
    sig!("mp3", "MP3 audio", Audio, 0, b"ID3", ["mp3"]),
    sig!("flac", "FLAC audio", Audio, 0, b"fLaC", ["flac"]),
    sig!("ogg", "OGG media", Audio, 0, b"OggS", ["ogg", "oga", "ogv", "opus"]),
    sig!("mp4", "MP4/MOV video", Video, 4, b"ftyp", ["mp4", "m4a", "m4v", "mov", "3gp", "3g2", "heic", "heif", "avif", "f4v", "m4b", "qt", "crx_", "cr3"]),
    sig!("mkv", "Matroska/WebM", Video, 0, b"\x1a\x45\xdf\xa3", ["mkv", "webm", "mka", "mk3d"]),
    sig!("asf", "ASF (WMV/WMA)", Video, 0, b"\x30\x26\xb2\x75\x8e\x66\xcf\x11", ["wmv", "wma", "asf", "dvr-ms"]),
    sig!("pst", "Outlook PST/OST", Email, 0, b"!BDN", ["pst", "ost"]),
    sig!("rtf", "RTF document", Document, 0, b"{\\rtf", ["rtf", "doc", "wri"]),
    sig!("vhdx", "VHDX disk image", DiskImage, 0, b"vhdxfile", ["vhdx", "avhdx"]),
    sig!("vmdk", "VMDK disk image", DiskImage, 0, b"KDMV", ["vmdk"]),
    sig!("ewf", "EnCase evidence (E01)", DiskImage, 0, b"EVF\x09\x0d\x0a\xff\x00", ["e01", "ex01", "l01", "s01"]),
    sig!("iso", "ISO 9660", DiskImage, 0x8001, b"CD001", ["iso", "img", "udf"]),
    sig!("qcow", "QCOW disk image", DiskImage, 0, b"QFI\xfb", ["qcow", "qcow2", "img"]),
    sig!("kdbx", "KeePass database", Crypto, 0, b"\x03\xd9\xa2\x9a", ["kdbx", "kdb"]),
    sig!("pgp_armor", "PGP armored data", Crypto, 0, b"-----BEGIN PGP", ["asc", "pgp", "gpg", "txt", "key", "sig"]),
    sig!("pem_key", "PEM private key", Crypto, 0, b"-----BEGIN ", ["pem", "key", "crt", "cer", "csr", "pub", "txt", "der", ""]),
    sig!("luks", "LUKS encrypted volume", Crypto, 0, b"LUKS\xba\xbe", ["luks", "img", ""]),
    sig!("bitlocker", "BitLocker volume", Crypto, 3, b"-FVE-FS-", ["vhd", "img", "bek", ""]),
    sig!("ps1_sig", "Script (shebang)", Script, 0, b"#!", ["sh", "py", "pl", "rb", "bash", "", "zsh", "ksh", "cgi", "php", "js", "awk", "tcl", "lua", "r", "in", "command", "fish"]),
    sig!("dex", "Android DEX", Executable, 0, b"dex\n", ["dex", "odex"]),
    sig!("class", "Java class", Executable, 0, b"\xca\xfe\xba\xbe", ["class", "", "dylib", "bundle"]),
    sig!("wasm", "WebAssembly", Executable, 0, b"\x00asm", ["wasm"]),
    sig!("swf", "Flash SWF", Executable, 0, b"FWS", ["swf"]),
    sig!("hiberfil", "Hibernation file", System, 0, b"HIBR", ["sys"]),
    sig!("hiberfil_w", "Hibernation file (wake)", System, 0, b"WAKE", ["sys"]),
    sig!("mdmp", "Minidump", System, 0, b"MDMP", ["dmp", "mdmp", "hdmp"]),
    sig!("pagedmp", "Kernel crash dump", System, 0, b"PAGEDU64", ["dmp"]),
    sig!("thumbcache", "Thumbcache", Forensic, 0, b"CMMM", ["db"]),
    sig!("recyclebin_i", "Recycle Bin $I record", Forensic, 0, b"\x02\x00\x00\x00\x00\x00\x00\x00", [""]),
];

pub fn detect(head: &[u8]) -> Option<&'static Signature> {
    SIGNATURES.iter().find(|s| head.len() >= s.offset + s.magic.len() && &head[s.offset..s.offset + s.magic.len()] == s.magic && sanity(s, head))
}

/// Extra checks for very short magics that otherwise false-positive.
fn sanity(s: &Signature, head: &[u8]) -> bool {
    match s.id {
        "pe" => {
            // e_lfanew must point at "PE\0\0" when we have enough bytes.
            if head.len() < 64 {
                return false;
            }
            let lfanew = u32::from_le_bytes(head[60..64].try_into().unwrap()) as usize;
            lfanew + 4 <= head.len() && &head[lfanew..lfanew + 4] == b"PE\x00\x00"
        }
        "bmp" => head.len() >= 18 && head[14] >= 12 && head[15] == 0 && head[6..10] == [0, 0, 0, 0],
        "ico" => head.len() >= 6 && head[4] > 0 && head[5] == 0,
        "recyclebin_i" | "ps1_sig" | "bzip2" => head.len() >= 8,
        "mp4" => head[..4].iter().take(2).all(|b| *b == 0),
        _ => true,
    }
}

pub fn extension(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 16 => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Extensions whose files are expected to be passive content. Content that
/// does not match one of these is the classic "renamed to hide" pattern.
const CONTENT_EXTS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic", "ico", "svg",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "rtf", "txt", "csv", "log", "md", "xml", "json", "html", "htm",
    "mp3", "wav", "flac", "ogg", "m4a", "wma", "mp4", "mov", "avi", "mkv", "wmv", "webm",
    "zip", "rar", "7z", "gz", "tar", "iso",
    "ini", "cfg", "conf", "yml", "yaml",
];

/// True when the content signature contradicts a passive-content extension
/// (for example a PE executable named `.jpg`, or a RAR named `.mp3`).
/// Unknown signatures and unknown extensions never mismatch: applications
/// legitimately reuse ZIP, OLE, SQLite and friends under countless names.
/// Extensions whose files always start with their format's magic, so a
/// missing header means the bytes are not (or no longer) that file.
pub fn header_required(ext: &str) -> bool {
    matches!(
        ext,
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tif" | "tiff" | "cr2" | "nef" | "pdf" | "zip" | "docx" | "xlsx" | "pptx" | "7z" | "rar" | "mp4" | "mov" | "avi" | "wav" | "exe" | "dll" | "sqlite" | "evtx" | "lnk" | "pst"
    )
}

pub fn is_mismatch(sig: &Signature, ext: &str) -> bool {
    if ext.is_empty() || sig.exts.contains(&ext) || !CONTENT_EXTS.contains(&ext) {
        return false;
    }
    // ZIP-based and OLE-based documents share magic with their containers.
    if matches!(sig.id, "zip" | "ole") && matches!(ext, "docx" | "xlsx" | "pptx" | "odt" | "ods" | "doc" | "xls" | "ppt") {
        return false;
    }
    // Text-ish files can begin with almost anything.
    if matches!(ext, "txt" | "log" | "csv" | "xml" | "json" | "html" | "htm" | "md" | "ini" | "cfg" | "conf" | "yml" | "yaml")
        && matches!(sig.category, Category::Script | Category::Crypto)
    {
        return false;
    }
    true
}

/// Shannon entropy in bits per byte (0.0 - 8.0).
pub fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for c in counts.iter().filter(|c| **c > 0) {
        let p = *c as f64 / n;
        h -= p * p.log2();
    }
    h as f32
}

/// Returns the repeated byte when every byte in all samples is identical.
pub fn uniform_byte(samples: &[&[u8]]) -> Option<u8> {
    let first = samples.iter().find(|s| !s.is_empty())?[0];
    if samples.iter().all(|s| s.iter().all(|b| *b == first)) {
        Some(first)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_mismatches() {
        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[60] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        let s = detect(&pe).unwrap();
        assert_eq!(s.id, "pe");
        assert!(is_mismatch(s, "jpg"));
        assert!(!is_mismatch(s, "dll"));
        assert!(detect(b"MZ just text without a PE header, padded out to sixty-four bytes...").is_none());
        assert_eq!(detect(b"%PDF-1.7\n").unwrap().id, "pdf");
        assert_eq!(extension("report.final.PDF"), "pdf");
        assert_eq!(extension(".bashrc"), "");
        assert!(entropy(&[0u8; 100]) < 0.01);
        assert_eq!(uniform_byte(&[&[0, 0, 0], &[0, 0]]), Some(0));
    }
}
