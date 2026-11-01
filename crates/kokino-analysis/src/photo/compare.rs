//! Compression history (double JPEG quantization) and the EXIF thumbnail
//! against the image it claims to show.

use super::jpeg::{self, Jpeg, Plane, ZIGZAG};
use serde::Serialize;

/// Low-frequency AC positions (zigzag 1..=19) examined for double quantization.
const POSITIONS: usize = 19;
/// Bins need this many coefficients (with a neighbor) to count.
const MIN_COUNT: u32 = 50;
/// Score at or above which double compression is reported. Calibrated on
/// 594 images: single-compressed ones (camera originals, libjpeg saves at
/// quality 60 to 90, resampled saves, a synthetic noisy scene) scored at
/// most 0.138; 62% of the re-saved ones (first save at quality 60 to 85,
/// second at 65 to 95) reach 0.20, the rest scored lower or had too few
/// coefficients to judge. Missing a re-save is preferred to a false one.
pub const DOUBLE_THRESHOLD: f64 = 0.20;

#[derive(Debug, Clone, Serialize)]
pub struct DoubleJpeg {
    /// Median peak residual over the usable positions; None: not enough data.
    pub score: Option<f64>,
    pub positions: usize,
    pub detected: bool,
    /// Histogram (|value| 1..=30) of the most telling position, for display.
    pub example: Vec<u32>,
    pub example_position: usize,
    pub example_step: u16,
}

/// Double quantization leaves periodic peaks and empty bins in the
/// histograms of quantized DCT coefficients, where a single compression
/// leaves a smooth, roughly log-linear decay. For each position the score
/// is the mean positive deviation of ln(count+1) from the mean of its
/// neighbors.
pub fn double_jpeg(d: &[u8], j: &Jpeg) -> anyhow::Result<DoubleJpeg> {
    let mut hist = vec![[0u32; 50]; POSITIONS + 1];
    jpeg::for_each_block(d, j, 4_000_000, |ci, _, _, c| {
        if ci != 0 {
            return;
        }
        for (zi, h) in hist.iter_mut().enumerate().skip(1) {
            let v = c[ZIGZAG[zi]].unsigned_abs() as usize;
            if (1..=49).contains(&v) {
                h[v - 1] += 1;
            }
        }
    })?;
    let q = j.luma_table().unwrap_or([1; 64]);
    let mut scores: Vec<(f64, usize)> = vec![];
    for (zi, hk) in hist.iter().enumerate().skip(1) {
        let mut k: usize = 0;
        while k < 48 && hk[k.saturating_sub(1)].max(hk[k]).max(hk[k + 1]) >= MIN_COUNT {
            k += 1;
        }
        if k < 5 {
            continue;
        }
        let l: Vec<f64> = hk[..k].iter().map(|&c| (c as f64 + 1.0).ln()).collect();
        let s = (1..k - 1).map(|i| (l[i] - (l[i - 1] + l[i + 1]) / 2.0).max(0.0)).sum::<f64>() / (k - 2) as f64;
        scores.push((s, zi));
    }
    let positions = scores.len();
    let score = (positions >= 3).then(|| {
        let mut v: Vec<f64> = scores.iter().map(|s| s.0).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        let m = v.len() / 2;
        if v.len() % 2 == 1 { v[m] } else { (v[m - 1] + v[m]) / 2.0 }
    });
    let best = scores.iter().max_by(|a, b| a.0.total_cmp(&b.0)).map(|s| s.1).unwrap_or(1);
    Ok(DoubleJpeg {
        score: score.map(|s| (s * 1000.0).round() / 1000.0),
        positions,
        detected: score.map(|s| s >= DOUBLE_THRESHOLD).unwrap_or(false),
        example: hist[best][..30].to_vec(),
        example_position: best,
        example_step: q[ZIGZAG[best]],
    })
}

/// Block means (1/8 scale) of a baseline JPEG's luminance, from the DC terms.
pub fn dc_plane(d: &[u8], j: &Jpeg) -> anyhow::Result<Plane> {
    if j.components.is_empty() {
        anyhow::bail!("no frame header");
    }
    let q0 = j.luma_table().ok_or_else(|| anyhow::anyhow!("no luminance table"))?[0] as f32;
    let (bw, bh) = j.blocks(0);
    let mut p = Plane { w: bw, h: bh, px: vec![0.0; bw * bh] };
    jpeg::for_each_block(d, j, 4_000_000, |ci, bx, by, c| {
        if ci == 0 && bx < bw && by < bh {
            p.px[by * bw + bx] = (c[0] as f32 * q0 / 8.0 + 128.0).clamp(0.0, 255.0);
        }
    })?;
    // Only blocks inside the image count (the last ones are padding).
    let c = &j.components[0];
    let lw = (j.width as usize * c.h as usize).div_ceil(j.hmax() as usize);
    let lh = (j.height as usize * c.v as usize).div_ceil(j.vmax() as usize);
    Ok(jpeg::crop(&p, (lw / 8).max(1).min(bw), (lh / 8).max(1).min(bh)))
}

/// Area-average resize.
pub fn resize(p: &Plane, w: usize, h: usize) -> Plane {
    let mut out = Plane { w, h, px: vec![0.0; w * h] };
    let (sx, sy) = (p.w as f32 / w as f32, p.h as f32 / h as f32);
    for y in 0..h {
        let (y0, y1) = ((y as f32 * sy) as usize, (((y + 1) as f32 * sy).ceil() as usize).min(p.h).max((y as f32 * sy) as usize + 1));
        for x in 0..w {
            let (x0, x1) = ((x as f32 * sx) as usize, (((x + 1) as f32 * sx).ceil() as usize).min(p.w).max((x as f32 * sx) as usize + 1));
            let mut s = 0.0;
            for yy in y0..y1 {
                for xx in x0..x1 {
                    s += p.px[yy * p.w + xx];
                }
            }
            out.px[y * w + x] = s / ((y1 - y0) * (x1 - x0)) as f32;
        }
    }
    out
}

/// Rows and columns of black letterbox bars around a thumbnail's content.
fn content_box(p: &Plane) -> (usize, usize, usize, usize) {
    let dark_row = |y: usize| {
        let r = &p.px[y * p.w..(y + 1) * p.w];
        r.iter().sum::<f32>() / p.w as f32 <= 12.0 && r.iter().all(|&v| v < 40.0)
    };
    let dark_col = |x: usize| {
        let s: f32 = (0..p.h).map(|y| p.px[y * p.w + x]).sum();
        s / p.h as f32 <= 12.0 && (0..p.h).all(|y| p.px[y * p.w + x] < 40.0)
    };
    let (mut t, mut b, mut l, mut r) = (0, p.h, 0, p.w);
    while t < b && dark_row(t) {
        t += 1;
    }
    while b > t && dark_row(b - 1) {
        b -= 1;
    }
    while l < r && dark_col(l) {
        l += 1;
    }
    while r > l && dark_col(r - 1) {
        r -= 1;
    }
    (l, t, r, b)
}

fn normalize(p: &mut Plane) {
    let n = p.px.len().max(1) as f32;
    let m = p.px.iter().sum::<f32>() / n;
    let sd = (p.px.iter().map(|v| (v - m) * (v - m)).sum::<f32>() / n).sqrt().max(1.0);
    p.px.iter_mut().for_each(|v| *v = (*v - m) / sd);
}

#[derive(Debug, Clone, Serialize)]
pub struct ThumbCompare {
    pub thumb_width: usize,
    pub thumb_height: usize,
    /// Width / height of the thumbnail's picture (bars removed) and of the image.
    pub thumb_aspect: f64,
    pub image_aspect: f64,
    pub aspect_differs: bool,
    /// Mean absolute difference after normalizing brightness and contrast.
    pub mean_diff: f64,
    /// Largest difference of one cell in a 6 x 6 grid.
    pub max_cell: f64,
    /// The cell (column, row) where the difference is largest.
    pub cell: (usize, usize),
    pub differs: bool,
}

/// Largest cell difference at or above which the thumbnail is reported as
/// showing a different picture. Calibrated on 33 camera originals and 33
/// unedited re-saves (all at most 0.171) against edits that kept the EXIF
/// block: 79% of cloned regions, all painted-over areas and all crops
/// (through the aspect check) were caught; global tone changes are not.
pub const THUMB_CELL_THRESHOLD: f64 = 0.30;
pub const ASPECT_TOLERANCE: f64 = 0.05;

pub fn thumbnail(d: &[u8], j: &Jpeg, thumb: &[u8]) -> anyhow::Result<ThumbCompare> {
    let tj = jpeg::parse(thumb)?;
    let t = jpeg::luma(thumb, &tj)?;
    let m = dc_plane(d, j)?;
    let image_aspect = j.width as f64 / j.height.max(1) as f64;
    // Trim letterbox bars only when that brings the thumbnail closer to the
    // image's shape: a dark photo has dark rows that are not bars.
    let off = |a: f64| ((a - image_aspect) / image_aspect).abs().min(((a - 1.0 / image_aspect) * image_aspect).abs());
    let trimmed = content_box(&t);
    let (l, top, r, b) = if trimmed.2 - trimmed.0 >= 8 && trimmed.3 - trimmed.1 >= 8 && off((trimmed.2 - trimmed.0) as f64 / (trimmed.3 - trimmed.1) as f64) < off(t.w as f64 / t.h as f64) {
        trimmed
    } else {
        (0, 0, t.w, t.h)
    };
    let mut tc = Plane { w: r - l, h: b - top, px: vec![] };
    for y in top..b {
        tc.px.extend_from_slice(&t.px[y * t.w + l..y * t.w + r]);
    }
    let thumb_aspect = tc.w as f64 / tc.h as f64;
    let aspect_differs = off(thumb_aspect) > ASPECT_TOLERANCE;
    let (w, h) = (tc.w.min(m.w).max(8), tc.h.min(m.h).max(8));
    let (mut a, mut bp) = (resize(&tc, w, h), resize(&m, w, h));
    normalize(&mut a);
    normalize(&mut bp);
    let diff: Vec<f32> = a.px.iter().zip(&bp.px).map(|(x, y)| (x - y).abs()).collect();
    let mean_diff = diff.iter().sum::<f32>() as f64 / diff.len() as f64;
    let (mut max_cell, mut cell) = (0f64, (0, 0));
    const G: usize = 6;
    for gy in 0..G {
        for gx in 0..G {
            let (x0, x1, y0, y1) = (gx * w / G, (gx + 1) * w / G, gy * h / G, (gy + 1) * h / G);
            let mut s = 0.0;
            let mut n = 0;
            for y in y0..y1 {
                for x in x0..x1 {
                    s += diff[y * w + x];
                    n += 1;
                }
            }
            let v = if n > 0 { s as f64 / n as f64 } else { 0.0 };
            if v > max_cell {
                max_cell = v;
                cell = (gx, gy);
            }
        }
    }
    let round = |v: f64| (v * 1000.0).round() / 1000.0;
    Ok(ThumbCompare {
        thumb_width: t.w,
        thumb_height: t.h,
        thumb_aspect: round(thumb_aspect),
        image_aspect: round(image_aspect),
        aspect_differs,
        mean_diff: round(mean_diff),
        max_cell: round(max_cell),
        cell,
        differs: aspect_differs || max_cell >= THUMB_CELL_THRESHOLD,
    })
}
