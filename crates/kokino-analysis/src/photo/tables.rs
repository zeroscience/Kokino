//! Quantization tables: the standard IJG (libjpeg) tables scaled by a
//! quality setting, used by GIMP, Pillow, ImageMagick, browsers and many
//! phones, versus custom tables (cameras, Photoshop and others).

use serde::Serialize;

/// ITU-T T.81 Annex K example tables, natural order.
pub const STD_LUMA: [u16; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35,
    55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
pub const STD_CHROMA: [u16; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// libjpeg's `jpeg_quality_scaling` + `jpeg_add_quant_table` with baseline forcing.
pub fn scaled(base: &[u16; 64], q: u32) -> [u16; 64] {
    let s = if q < 50 { 5000 / q.max(1) } else { 200 - 2 * q.min(100) };
    let mut t = [0u16; 64];
    for (o, &b) in t.iter_mut().zip(base) {
        *o = ((b as u32 * s + 50) / 100).clamp(1, 255) as u16;
    }
    t
}

#[derive(Debug, Clone, Serialize)]
pub struct TableInfo {
    /// "standard" (IJG tables at a quality setting) or "custom".
    pub kind: String,
    /// Exact IJG quality for standard tables, estimate for custom ones.
    pub quality: u32,
    pub exact: bool,
    /// Short fingerprint of the tables, to group photos made the same way.
    pub fingerprint: String,
}

pub fn identify(luma: &[u16; 64], chroma: Option<&[u16; 64]>) -> TableInfo {
    let exact = (1..=100).rev().find(|&q| scaled(&STD_LUMA, q) == *luma && chroma.map(|c| scaled(&STD_CHROMA, q) == *c).unwrap_or(true));
    let quality = exact.unwrap_or_else(|| {
        // Closest IJG quality by mean log ratio over the luminance table.
        (1..=100)
            .min_by(|&a, &b| {
                let err = |q| scaled(&STD_LUMA, q).iter().zip(luma).map(|(&s, &t)| ((s as f64) / (t.max(1) as f64)).ln().abs()).sum::<f64>();
                err(a).total_cmp(&err(b))
            })
            .unwrap_or(0)
    });
    let mut h: u64 = 0xcbf29ce484222325;
    for v in luma.iter().chain(chroma.into_iter().flatten()) {
        h = (h ^ *v as u64).wrapping_mul(0x100000001b3);
    }
    TableInfo { kind: if exact.is_some() { "standard" } else { "custom" }.into(), quality, exact: exact.is_some(), fingerprint: format!("{:08x}", h as u32) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_quality_75_and_50() {
        let t = identify(&scaled(&STD_LUMA, 75), Some(&scaled(&STD_CHROMA, 75)));
        assert_eq!((t.kind.as_str(), t.quality, t.exact), ("standard", 75, true));
        assert_eq!(scaled(&STD_LUMA, 50), STD_LUMA);
        let mut odd = scaled(&STD_LUMA, 90);
        odd[63] += 1;
        let c = identify(&odd, None);
        assert_eq!((c.kind.as_str(), c.quality), ("custom", 90));
    }
}
