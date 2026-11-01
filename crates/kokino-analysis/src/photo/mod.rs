//! Photo forensics: JPEG structure and compression history, EXIF and its
//! thumbnail, editing-software traces, data hidden after the image and LSB
//! embedding in lossless images. `analyze` reports on one image; `scan`
//! runs it over every picture of an evidence item (live, deleted, carved)
//! and adds checks across photos of the same camera.
//!
//! The pixel views (magnifier, error level, noise, clones...) run in the
//! browser on the same bytes; this module is what can be computed and
//! stated as a finding.

pub mod compare;
pub mod exif;
pub mod jpeg;
pub mod raster;
pub mod tables;

use crate::fs::Fs;
use crate::{volume_reader, Analysis, Progress};
use kokino_image::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 1: first version.
pub const PHOTO_SCHEMA: u32 = 1;
/// Pictures larger than this are listed but not analyzed.
pub const MAX_BYTES: u64 = 64 << 20;

/// A finding's fixed text. `flag` findings count in the Flagged filter;
/// `info` ones describe the picture.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub flag: bool,
    pub explanation: &'static str,
    pub caveat: &'static str,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "editor_software",
        title: "Saved by editing software",
        flag: true,
        explanation: "The file names a photo editor (EXIF Software, XMP CreatorTool, an Adobe or Photoshop segment, or a comment). The picture went through that program after it was taken.",
        caveat: "Editors are also used for routine work (resizing, exporting, rotating, color correction). This says the file was processed, not that its content was changed.",
    },
    Rule {
        id: "thumbnail_mismatch",
        title: "EXIF thumbnail shows a different picture",
        flag: true,
        explanation: "The small preview stored in the EXIF block no longer matches the image: a region differs or the shape is different. Programs that keep the original EXIF block when saving an edited image leave the old preview behind, so it shows the picture before the edit.",
        caveat: "Global changes (brightness, color) are not detected. Some cameras store a preview with a different crop; check the side-by-side view.",
    },
    Rule {
        id: "double_jpeg",
        title: "Compressed twice (re-saved JPEG)",
        flag: true,
        explanation: "The histograms of quantized DCT coefficients show the periodic peaks and gaps that a second JPEG compression with different settings leaves. A camera original is compressed once.",
        caveat: "Saving again at the same quality, or after a crop that shifts the 8x8 grid, leaves no such trace, and first saves at very high quality are hard to see. Any re-save (sharing apps, rotation in some viewers) also causes it.",
    },
    Rule {
        id: "standard_tables_camera",
        title: "Camera named, but software compression tables",
        flag: true,
        explanation: "The EXIF names a dedicated camera brand, but the image uses the standard IJG (libjpeg) quantization tables that software such as GIMP, Pillow, ImageMagick and browsers write. Those cameras use their own tables, so the file was most likely re-encoded by software that kept the EXIF block.",
        caveat: "A few cameras and firmware versions do use the standard tables. Compare with other photos from the same camera.",
    },
    Rule {
        id: "tables_differ_model",
        title: "Compression differs from the same camera's other photos",
        flag: true,
        explanation: "Other photos in this evidence with the same EXIF make and model share their quantization tables; this one uses tables none of them has.",
        caveat: "Cameras switch tables with the quality setting (fine, normal) and firmware. It is a pointer to compare, not proof.",
    },
    Rule {
        id: "trailing_data",
        title: "Data hidden after the end of the image",
        flag: true,
        explanation: "Bytes follow the image's end marker. Viewers ignore them, which is how a ZIP, document or message is hidden inside a picture (a polyglot or appended file).",
        caveat: "Some phones append their own data (Samsung trailers, Google motion photos, extra MPF images); those are listed as information, not flagged.",
    },
    Rule {
        id: "lsb_embedding",
        title: "Least significant bits look like hidden data",
        flag: true,
        explanation: "The chi-square test (Westfeld and Pfitzmann) finds the value pairs (2k, 2k+1) evened out over the share of the image shown, as replacing the lowest bit with message bits does. Natural images keep those pairs uneven.",
        caveat: "Only lossless images (PNG, BMP) are tested. Embedding spread at a low rate over the whole image, and JPEG-domain tools (steghide, F5, OutGuess), are not detected by this test. Images with heavy noise or dithering can score high.",
    },
    Rule {
        id: "modified_after_capture",
        title: "EXIF modify date differs from capture date",
        flag: false,
        explanation: "The EXIF DateTime (last change, set by software that saves the file) differs from DateTimeOriginal (when the picture was taken).",
        caveat: "Rotating or tagging in a photo manager also updates it. EXIF dates are the camera clock's local time.",
    },
    Rule {
        id: "exif_missing",
        title: "No EXIF in a camera folder",
        flag: false,
        explanation: "A JPEG stored under a DCIM folder carries no EXIF block, although cameras always write one. The metadata was removed or the file was put there by other software.",
        caveat: "Messaging and social apps strip EXIF when they save; so do some privacy tools.",
    },
    Rule {
        id: "gps",
        title: "GPS location",
        flag: false,
        explanation: "The EXIF block holds a GPS position.",
        caveat: "The position is what the device recorded or what software wrote; it can be edited like any other EXIF field.",
    },
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Trailing {
    pub offset: usize,
    pub len: usize,
    /// Signature of what follows (zip, pdf...) or a known trailer kind.
    pub kind: String,
    pub benign: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JpegFacts {
    pub mode: String,
    pub subsampling: String,
    pub restart: u32,
    pub tables: Option<tables::TableInfo>,
    pub luma: Option<Vec<u16>>,
    pub chroma: Option<Vec<u16>>,
    pub segments: Vec<String>,
    pub comments: Vec<String>,
    pub jfif: bool,
    pub icc: bool,
    pub mpf: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub format: String,
    pub width: u32,
    pub height: u32,
    pub size: usize,
    pub exif: Option<exif::Exif>,
    pub jpeg: Option<JpegFacts>,
    pub raster: Option<raster::Raster>,
    /// Software named anywhere in the file.
    pub software: Vec<String>,
    pub double: Option<compare::DoubleJpeg>,
    pub thumbnail: Option<compare::ThumbCompare>,
    /// EXIF thumbnail as a data URL, for the side-by-side view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_data: Option<String>,
    pub trailing: Option<Trailing>,
    pub lsb: Option<raster::LsbTest>,
    pub findings: Vec<Finding>,
    /// Checks that could not run, and why.
    pub notes: Vec<String>,
}

/// Programs that edit pictures. Matched case-insensitively in software traces.
const EDITORS: &[&str] = &[
    "photoshop", "gimp", "paint.net", "lightroom", "affinity", "pixelmator", "snapseed", "paintshop", "corel", "facetune", "faceapp", "canva", "luminar", "darktable",
    "rawtherapee", "photopea", "fotor", "picsart", "acdsee", "photoscape", "capture one", "photodirector", "krita", "inkscape", "imagemagick", "graphicsmagick",
];

/// Brands that make dedicated cameras with their own quantization tables.
const CAMERA_BRANDS: &[&str] = &["canon", "nikon", "fujifilm", "olympus", "om digital", "panasonic", "pentax", "ricoh", "leica", "kodak", "casio", "hasselblad", "sigma", "minolta", "konica"];

fn xmp_value(xmp: &str, key: &str) -> Option<String> {
    let a = xmp.find(key)? + key.len();
    let rest = &xmp[a..];
    let v = if let Some(r) = rest.strip_prefix("=\"") {
        r.split('"').next()?
    } else if let Some(r) = rest.strip_prefix('>') {
        r.split('<').next()?
    } else {
        return None;
    };
    let v = v.trim();
    (!v.is_empty()).then(|| v.chars().take(120).collect())
}

pub fn b64(d: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(d.len().div_ceil(3) * 4);
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            s.push(if k <= c.len() { A[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

fn trailing(d: &[u8], end: usize, mpf: bool, xmp: Option<&str>) -> Option<Trailing> {
    if end >= d.len() {
        return None;
    }
    let t = &d[end..];
    // Padding: all one value (zeros or 0xFF), as cards and some cameras leave.
    if t.iter().all(|&b| b == t[0]) {
        return None;
    }
    let sig = crate::signatures::detect(t).map(|s| s.id.to_string());
    let has = |n: &[u8]| t.windows(n.len()).take(64 << 20).any(|w| w == n);
    let (kind, benign) = if mpf && t.starts_with(b"\xFF\xD8") {
        ("more MPF images".to_string(), true)
    } else if has(b"SEFH") || has(b"SEFT") {
        ("Samsung trailer".to_string(), true)
    } else if xmp.map(|x| x.contains("MotionPhoto") || x.contains("MicroVideo")).unwrap_or(false) && sig.as_deref() == Some("mp4") {
        ("motion photo video".to_string(), true)
    } else if let Some(s) = sig {
        (s, false)
    } else if has(b"PK\x03\x04") {
        ("zip (inside)".to_string(), false)
    } else {
        ("unknown data".to_string(), false)
    };
    Some(Trailing { offset: end, len: t.len(), kind, benign })
}

/// Everything Kokino can say about one picture. `path` is used for the
/// camera-folder check only.
pub fn analyze(d: &[u8], path: &str) -> Report {
    let mut r = Report {
        format: String::new(),
        width: 0,
        height: 0,
        size: d.len(),
        exif: None,
        jpeg: None,
        raster: None,
        software: vec![],
        double: None,
        thumbnail: None,
        thumbnail_data: None,
        trailing: None,
        lsb: None,
        findings: vec![],
        notes: vec![],
    };
    let mut found: Vec<Finding> = vec![];
    let push = |f: &mut Vec<Finding>, id: &str, detail: String| f.push(Finding { id: id.into(), detail });
    if d.starts_with(b"\xFF\xD8\xFF") {
        r.format = "JPEG".into();
        let j = match jpeg::parse(d) {
            Ok(j) => j,
            Err(e) => {
                r.notes.push(format!("{:#}", e));
                return r;
            }
        };
        r.width = j.width;
        r.height = j.height;
        if let Some((a, b)) = j.exif {
            r.exif = exif::parse(&d[a..b]);
            if let Some(x) = &r.exif {
                if let Some((o, l)) = x.thumb {
                    let t = &d[a + o..a + o + l];
                    if t.starts_with(b"\xFF\xD8") {
                        r.thumbnail_data = Some(format!("data:image/jpeg;base64,{}", b64(t)));
                        if j.is_baseline() {
                            match compare::thumbnail(d, &j, t) {
                                Ok(c) => r.thumbnail = Some(c),
                                Err(e) => r.notes.push(format!("thumbnail comparison: {:#}", e)),
                            }
                        }
                    }
                }
            }
        }
        // Software traces.
        let mut sw: Vec<String> = vec![];
        if let Some(x) = &r.exif {
            if !x.software.is_empty() {
                sw.push(x.software.clone());
            }
        }
        if let Some(x) = &j.xmp {
            for k in ["xmp:CreatorTool", "photoshop:History", "stEvt:softwareAgent"] {
                if let Some(v) = xmp_value(x, k) {
                    sw.push(v);
                }
            }
            if x.contains("xmlns:photoshop") && !sw.iter().any(|s| s.to_lowercase().contains("photoshop")) {
                sw.push("Adobe Photoshop (XMP namespace)".into());
            }
        }
        if j.photoshop {
            sw.push("Photoshop image resources (APP13)".into());
        }
        if j.adobe {
            sw.push("Adobe segment (APP14)".into());
        }
        for c in &j.comments {
            if c.len() > 3 {
                sw.push(format!("comment: {}", c.chars().take(80).collect::<String>()));
            }
        }
        sw.dedup();
        r.software = sw;
        let editors: Vec<&String> = r.software.iter().filter(|s| {
            let l = s.to_lowercase();
            EDITORS.iter().any(|e| l.contains(e)) || l.contains("adobe segment") || l.contains("app13")
        }).collect();
        if !editors.is_empty() {
            let detail = editors.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("; ");
            push(&mut found, "editor_software", detail);
        }
        let ti = j.luma_table().map(|l| tables::identify(&l, j.chroma_table().as_ref()));
        let sub = j.components.first().map(|c| match (c.h, c.v, j.components.len()) {
            (_, _, 1) => "gray".to_string(),
            (2, 2, _) => "4:2:0".into(),
            (2, 1, _) => "4:2:2".into(),
            (1, 1, _) => "4:4:4".into(),
            (h, v, _) => format!("{}x{}", h, v),
        });
        r.jpeg = Some(JpegFacts {
            mode: match j.sof {
                0xC0 => "baseline",
                0xC1 => "extended sequential",
                0xC2 => "progressive",
                0xC3 => "lossless",
                _ => "other",
            }
            .into(),
            subsampling: sub.unwrap_or_default(),
            restart: j.restart,
            tables: ti.clone(),
            luma: j.luma_table().map(|t| t.to_vec()),
            chroma: j.chroma_table().map(|t| t.to_vec()),
            segments: j.segments.iter().map(|(m, o, l)| format!("{:02X} at {} ({} bytes)", m, o, l)).take(64).collect(),
            comments: j.comments.clone(),
            jfif: j.jfif,
            icc: j.icc,
            mpf: j.mpf,
        });
        if let (Some(x), Some(t)) = (&r.exif, &ti) {
            let make = x.make.to_lowercase();
            if t.exact && CAMERA_BRANDS.iter().any(|b| make.contains(b)) {
                push(&mut found, "standard_tables_camera", format!("EXIF says {} {}; tables are standard IJG at quality {}", x.make, x.model, t.quality));
            }
        }
        if j.is_baseline() {
            match compare::double_jpeg(d, &j) {
                Ok(dj) => {
                    if dj.detected {
                        push(&mut found, "double_jpeg", format!("score {:.3} (threshold {})", dj.score.unwrap_or(0.0), compare::DOUBLE_THRESHOLD));
                    }
                    r.double = Some(dj);
                }
                Err(e) => r.notes.push(format!("compression history: {:#}", e)),
            }
        } else {
            r.notes.push(format!("compression history and thumbnail check need a baseline JPEG; this one is {}", r.jpeg.as_ref().map(|x| x.mode.as_str()).unwrap_or("?")));
        }
        if let Some(t) = &r.thumbnail {
            if t.differs {
                let detail = if t.aspect_differs {
                    format!("thumbnail shape {:.3} versus image {:.3}", t.thumb_aspect, t.image_aspect)
                } else {
                    format!("largest difference {:.2} in cell {},{} of 6x6 (threshold {})", t.max_cell, t.cell.0 + 1, t.cell.1 + 1, compare::THUMB_CELL_THRESHOLD)
                };
                push(&mut found, "thumbnail_mismatch", detail);
            }
        }
        if !j.eoi {
            r.notes.push("no end-of-image marker: the file is cut off or damaged".into());
        }
        r.trailing = trailing(d, j.end, j.mpf, j.xmp.as_deref());
        if let Some(x) = &r.exif {
            if !x.datetime.is_empty() && !x.original.is_empty() && x.datetime != x.original {
                push(&mut found, "modified_after_capture", format!("taken {}, changed {}", x.original, x.datetime));
            }
            if let Some(g) = &x.gps {
                push(&mut found, "gps", format!("{:.6}, {:.6}{}", g.lat, g.lon, g.alt.map(|a| format!(", {:.0} m", a)).unwrap_or_default()));
            }
        } else if path.to_ascii_lowercase().contains("/dcim/") {
            push(&mut found, "exif_missing", path.to_string());
        }
    } else if d.starts_with(b"\x89PNG") || d.starts_with(b"BM") {
        let res = if d.starts_with(b"BM") { raster::bmp(d) } else { raster::png(d) };
        match res {
            Ok(mut ras) => {
                r.format = ras.format.into();
                r.width = ras.width;
                r.height = ras.height;
                for (k, v) in &ras.text {
                    if k.eq_ignore_ascii_case("software") || k.eq_ignore_ascii_case("creator") {
                        r.software.push(v.clone());
                    }
                }
                let editors: Vec<String> = r.software.iter().filter(|s| EDITORS.iter().any(|e| s.to_lowercase().contains(e))).cloned().collect();
                if !editors.is_empty() {
                    push(&mut found, "editor_software", editors.join("; "));
                }
                r.trailing = trailing(d, ras.end, false, None);
                r.lsb = raster::lsb(&ras.samples);
                if ras.samples.is_empty() && !ras.note.is_empty() {
                    r.notes.push(ras.note.clone());
                }
                if let Some(t) = &r.lsb {
                    if t.detected {
                        push(&mut found, "lsb_embedding", format!("{} {:.0}% of the pixel data (p >= {})", if t.from_end { "last" } else { "first" }, t.embedded_share * 100.0, raster::LSB_THRESHOLD));
                    }
                }
                ras.samples = vec![];
                r.raster = Some(ras);
            }
            Err(e) => r.notes.push(format!("{:#}", e)),
        }
    } else {
        r.format = "other".into();
        r.notes.push("only JPEG, PNG and BMP are analyzed".into());
    }
    if let Some(t) = &r.trailing {
        if !t.benign {
            push(&mut found, "trailing_data", format!("{} bytes of {} at offset {}", t.len, t.kind, t.offset));
        }
    }
    r.findings = found;
    r
}

/// 8-bit RGB pixels, row by row.
#[derive(Debug, Clone)]
pub struct Rgb {
    pub w: usize,
    pub h: usize,
    pub px: Vec<u8>,
}

/// Pixels of a picture for report exhibits: baseline JPEG, 8-bit
/// non-interlaced gray or RGB(A) PNG, and 24/32-bit BMP.
pub fn decode_rgb(d: &[u8]) -> anyhow::Result<Rgb> {
    const MAX: usize = 50_000_000;
    if d.starts_with(&[0xFF, 0xD8]) {
        let j = jpeg::parse(d)?;
        if !j.is_baseline() {
            anyhow::bail!("{} JPEGs are not rendered", if j.progressive() { "progressive" } else { "non-baseline" });
        }
        let (w, h, px) = jpeg::rgb(d, &j, MAX)?;
        return Ok(Rgb { w, h, px });
    }
    let (r, bmp) = if d.starts_with(b"\x89PNG") {
        (raster::png(d)?, false)
    } else if d.starts_with(b"BM") {
        (raster::bmp(d)?, true)
    } else {
        anyhow::bail!("not a JPEG, PNG or BMP picture");
    };
    let (w, h) = (r.width as usize, r.height as usize);
    if r.samples.len() != w * h * r.channels || !(r.channels == 1 || r.channels == 3) {
        anyhow::bail!("{}", if r.note.is_empty() { "pixel data not decoded" } else { &r.note });
    }
    let mut px = Vec::with_capacity(w * h * 3);
    for y in 0..h {
        // BMP rows are stored bottom-up (positive height) in BGR order.
        let sy = if bmp && d.len() > 25 && i32::from_le_bytes([d[22], d[23], d[24], d[25]]) > 0 { h - 1 - y } else { y };
        let row = &r.samples[sy * w * r.channels..(sy + 1) * w * r.channels];
        for p in row.chunks_exact(r.channels) {
            match (r.channels, bmp) {
                (1, _) => px.extend_from_slice(&[p[0]; 3]),
                (_, true) => px.extend_from_slice(&[p[2], p[1], p[0]]),
                _ => px.extend_from_slice(p),
            }
        }
    }
    Ok(Rgb { w, h, px })
}

/// One picture in the evidence-wide list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRow {
    /// "file" or "carved"
    pub source: String,
    pub fi: Option<usize>,
    pub idx: Option<usize>,
    pub record: Option<u64>,
    pub carved: Option<u32>,
    pub name: String,
    pub path: String,
    pub deleted: bool,
    pub size: u64,
    pub format: String,
    pub width: u32,
    pub height: u32,
    pub make: String,
    pub model: String,
    pub software: String,
    pub taken: String,
    pub gps: Option<(f64, f64)>,
    pub quality: Option<u32>,
    pub tables: String,
    pub fingerprint: String,
    pub double_score: Option<f64>,
    pub thumb_diff: Option<f64>,
    pub trailing: Option<u64>,
    pub lsb_share: Option<f64>,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

impl ImageRow {
    pub fn flagged(&self) -> bool {
        self.findings.iter().any(|f| rule(&f.id).map(|r| r.flag).unwrap_or(false))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhotoScan {
    pub schema: u32,
    pub tool_version: String,
    pub scanned_at: String,
    pub images: Vec<ImageRow>,
    /// Pictures over MAX_BYTES or unreadable, listed with a reason.
    pub skipped: u64,
}

pub fn row(r: &Report, base: ImageRow) -> ImageRow {
    let x = r.exif.as_ref();
    let t = r.jpeg.as_ref().and_then(|j| j.tables.as_ref());
    ImageRow {
        format: r.format.clone(),
        width: r.width,
        height: r.height,
        make: x.map(|x| x.make.clone()).unwrap_or_default(),
        model: x.map(|x| x.model.clone()).unwrap_or_default(),
        software: r.software.join("; ").chars().take(200).collect(),
        taken: x.map(|x| if x.original.is_empty() { x.datetime.clone() } else { x.original.clone() }).unwrap_or_default(),
        gps: x.and_then(|x| x.gps.as_ref()).map(|g| (g.lat, g.lon)),
        quality: t.map(|t| t.quality),
        tables: t.map(|t| t.kind.clone()).unwrap_or_default(),
        fingerprint: t.map(|t| t.fingerprint.clone()).unwrap_or_default(),
        double_score: r.double.as_ref().and_then(|d| d.score),
        thumb_diff: r.thumbnail.as_ref().map(|t| if t.aspect_differs { 9.0 } else { t.max_cell }),
        trailing: r.trailing.as_ref().map(|t| t.len as u64),
        lsb_share: r.lsb.as_ref().map(|l| l.embedded_share),
        findings: r.findings.clone(),
        error: (r.format.is_empty() || (r.width == 0 && !r.notes.is_empty())).then(|| r.notes.join("; ")),
        ..base
    }
}

/// Photos of one camera model normally share a few table sets; a table set
/// no other photo of that model uses is flagged when at least 3 others agree.
pub fn cross_check(images: &mut [ImageRow]) {
    let mut by_model: HashMap<(String, String), HashMap<String, usize>> = HashMap::new();
    for i in images.iter().filter(|i| !i.make.is_empty() && !i.fingerprint.is_empty()) {
        *by_model.entry((i.make.clone(), i.model.clone())).or_default().entry(i.fingerprint.clone()).or_default() += 1;
    }
    for i in images.iter_mut() {
        let Some(m) = by_model.get(&(i.make.clone(), i.model.clone())) else { continue };
        let own = m.get(&i.fingerprint).copied().unwrap_or(0);
        let others: usize = m.values().sum::<usize>() - own;
        if own == 1 && others >= 3 {
            i.findings.push(Finding { id: "tables_differ_model".into(), detail: format!("{} other photo(s) from {} {} use {} other table set(s)", others, i.make, i.model, m.len() - 1) });
        }
    }
}

/// Analyzes every JPEG, PNG and BMP of an evidence item: files (live and
/// deleted) found by signature, and carved pictures.
pub fn scan(ev: &Evidence, analysis: &Analysis, carved: Option<&crate::carve::CarveResult>, progress: Progress) -> anyhow::Result<PhotoScan> {
    let mut out = PhotoScan { schema: PHOTO_SCHEMA, tool_version: kokino_core::TOOL_VERSION.into(), scanned_at: kokino_core::time::now_iso(), ..Default::default() };
    let wanted = |s: &str| matches!(s, "jpeg" | "png" | "bmp");
    let total = analysis.filesystems.iter().map(|f| f.files.iter().filter(|r| !r.e.is_dir && r.sig.as_deref().map(wanted).unwrap_or(false)).count()).sum::<usize>()
        + carved.map(|c| c.files.iter().filter(|f| wanted(&f.kind)).count()).unwrap_or(0);
    let stage = "Analyzing pictures";
    let mut done = 0u64;
    for (fi, fsa) in analysis.filesystems.iter().enumerate() {
        let mut r = volume_reader(ev, &fsa.volume)?;
        let fs = Fs::open(&mut r, &fsa.volume)?;
        for (idx, f) in fsa.files.iter().enumerate() {
            if f.e.is_dir || !f.sig.as_deref().map(wanted).unwrap_or(false) {
                continue;
            }
            if done % 16 == 0 && !progress(stage, done, total as u64) {
                anyhow::bail!("picture analysis cancelled");
            }
            done += 1;
            let base = ImageRow {
                source: "file".into(),
                fi: Some(fi),
                idx: Some(idx),
                record: Some(f.e.record),
                carved: None,
                name: f.e.name.clone(),
                path: f.e.path.clone(),
                deleted: f.e.deleted,
                size: f.e.size,
                format: String::new(),
                width: 0,
                height: 0,
                make: String::new(),
                model: String::new(),
                software: String::new(),
                taken: String::new(),
                gps: None,
                quality: None,
                tables: String::new(),
                fingerprint: String::new(),
                double_score: None,
                thumb_diff: None,
                trailing: None,
                lsb_share: None,
                findings: vec![],
                error: None,
            };
            if f.e.size > MAX_BYTES {
                out.skipped += 1;
                out.images.push(ImageRow { error: Some(format!("larger than {} MiB; open it to analyze", MAX_BYTES >> 20)), ..base });
                continue;
            }
            match fs.read(&mut r, &f.e, "", 0, f.e.size as usize) {
                Ok(d) => out.images.push(row(&analyze(&d, &f.e.path), base)),
                Err(e) => {
                    out.skipped += 1;
                    out.images.push(ImageRow { error: Some(format!("not readable: {:#}", e)), ..base });
                }
            }
        }
    }
    if let Some(c) = carved {
        let mut img = ev.reader()?;
        for f in c.files.iter().filter(|f| wanted(&f.kind)) {
            if done % 16 == 0 && !progress(stage, done, total as u64) {
                anyhow::bail!("picture analysis cancelled");
            }
            done += 1;
            let base = ImageRow {
                source: "carved".into(),
                fi: f.fi,
                idx: None,
                record: None,
                carved: Some(f.id),
                name: format!("carved-{}.{}", f.id, f.ext),
                path: f.region.clone(),
                deleted: true,
                size: f.len,
                format: String::new(),
                width: 0,
                height: 0,
                make: String::new(),
                model: String::new(),
                software: String::new(),
                taken: String::new(),
                gps: None,
                quality: None,
                tables: String::new(),
                fingerprint: String::new(),
                double_score: None,
                thumb_diff: None,
                trailing: None,
                lsb_share: None,
                findings: vec![],
                error: None,
            };
            if f.len > MAX_BYTES {
                out.skipped += 1;
                continue;
            }
            let mut buf = vec![0u8; f.len as usize];
            let n = kokino_image::read_at(&mut img, f.offset, &mut buf)?;
            buf.truncate(n);
            out.images.push(row(&analyze(&buf, ""), base));
        }
    }
    progress(stage, total as u64, total as u64);
    cross_check(&mut out.images);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground truth from scripts/make_photo_fixture.py.
    #[test]
    fn decode_rgb_matches_luma_and_raster() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/photo");
        if !dir.exists() {
            return;
        }
        for name in ["camera.jpg", "single.jpg"] {
            let d = std::fs::read(dir.join(name)).unwrap();
            let j = jpeg::parse(&d).unwrap();
            let img = decode_rgb(&d).unwrap();
            assert_eq!((img.w, img.h), (j.width as usize, j.height as usize));
            // Luminance from the color decode agrees with the luma decoder.
            let l = jpeg::luma(&d, &j).unwrap();
            let mut err = 0f64;
            for y in 0..img.h {
                for x in 0..img.w {
                    let o = (y * img.w + x) * 3;
                    let yy = 0.299 * img.px[o] as f64 + 0.587 * img.px[o + 1] as f64 + 0.114 * img.px[o + 2] as f64;
                    err += (yy - l.px[y * l.w + x] as f64).abs();
                }
            }
            assert!(err / (img.w * img.h) as f64 <= 2.0, "{}: {}", name, err / (img.w * img.h) as f64);
        }
        for name in ["clean.png", "stego.bmp"] {
            let img = decode_rgb(&std::fs::read(dir.join(name)).unwrap()).unwrap();
            assert_eq!(img.px.len(), img.w * img.h * 3);
        }
    }

    #[test]
    fn photo_fixtures() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/photo");
        if !dir.exists() {
            return;
        }
        let ids = |name: &str| {
            let r = analyze(&std::fs::read(dir.join(name)).unwrap(), "/Pictures/x.jpg");
            let mut v: Vec<String> = r.findings.iter().map(|f| f.id.clone()).filter(|i| i != "gps").collect();
            v.sort();
            (v, r)
        };
        let (v, r) = ids("camera.jpg");
        assert!(v.is_empty(), "{:?}", v);
        let x = r.exif.as_ref().unwrap();
        assert_eq!((x.make.as_str(), x.model.as_str(), x.original.as_str()), ("Canon", "Kokino Lab Camera", "2026:10:20 09:45:30"));
        let g = x.gps.as_ref().unwrap();
        assert!((g.lat - 41.99).abs() < 0.001 && (g.lon - 21.43).abs() < 0.001, "{:?}", g);
        assert!(!r.thumbnail.as_ref().unwrap().differs && r.thumbnail_data.is_some());
        assert_eq!(r.jpeg.as_ref().unwrap().tables.as_ref().unwrap().kind, "custom");
        assert_eq!(ids("edited.jpg").0, ["editor_software", "modified_after_capture", "thumbnail_mismatch"]);
        assert_eq!(ids("resaved.jpg").0, ["standard_tables_camera"]);
        let (v, r) = ids("cropped.jpg");
        assert_eq!(v, ["thumbnail_mismatch"]);
        assert!(r.thumbnail.unwrap().aspect_differs);
        assert_eq!(ids("double.jpg").0, ["double_jpeg"]);
        let r = analyze(&std::fs::read(dir.join("single.jpg")).unwrap(), "/DCIM/100LAB/IMG_0001.JPG");
        assert_eq!(r.findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), ["exif_missing"]);
        let (v, r) = ids("single.jpg");
        assert!(v.is_empty() && r.double.unwrap().score.unwrap() < compare::DOUBLE_THRESHOLD);
        let (v, r) = ids("appended.jpg");
        assert_eq!(v, ["trailing_data"]);
        let t = r.trailing.unwrap();
        assert_eq!((t.kind.as_str(), t.offset), ("zip", std::fs::metadata(dir.join("camera.jpg")).unwrap().len() as usize));
        assert!(ids("clean.png").0.is_empty());
        assert!(ids("cloned.jpg").0.is_empty());
        for f in ["stego.png", "stego.bmp"] {
            let (v, r) = ids(f);
            assert_eq!(v, ["lsb_embedding"], "{}", f);
            let l = r.lsb.unwrap();
            // BMP rows are stored bottom-up: the top 30% is the end of the data.
            assert_eq!((l.embedded_share, l.from_end), (0.3, f.ends_with(".bmp")), "{}", f);
        }
    }

    #[test]
    fn same_model_table_outlier() {
        let mk = |fp: &str| ImageRow {
            source: "file".into(),
            fi: None,
            idx: None,
            record: None,
            carved: None,
            name: String::new(),
            path: String::new(),
            deleted: false,
            size: 0,
            format: "JPEG".into(),
            width: 0,
            height: 0,
            make: "Canon".into(),
            model: "X".into(),
            software: String::new(),
            taken: String::new(),
            gps: None,
            quality: None,
            tables: "custom".into(),
            fingerprint: fp.into(),
            double_score: None,
            thumb_diff: None,
            trailing: None,
            lsb_share: None,
            findings: vec![],
            error: None,
        };
        let mut v = vec![mk("a"), mk("a"), mk("a"), mk("b"), mk("c"), mk("c")];
        cross_check(&mut v);
        let flagged: Vec<&str> = v.iter().filter(|i| !i.findings.is_empty()).map(|i| i.fingerprint.as_str()).collect();
        assert_eq!(flagged, ["b"]);
    }
}
