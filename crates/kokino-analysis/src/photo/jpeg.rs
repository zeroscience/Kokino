//! JPEG structure: markers, quantization tables, EXIF / XMP / Photoshop
//! segments and where the image really ends, plus a baseline entropy
//! decoder that yields the quantized DCT coefficients (double-compression
//! analysis) and the luminance plane (thumbnail comparison).
//!
//! Progressive and lossless JPEGs are parsed for structure only.

/// `ZIGZAG[k]` is the natural (row-major) index of the k-th coefficient in
/// zigzag order, the order JPEG stores tables and coefficients in.
pub const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29,
    22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

#[derive(Debug, Clone)]
pub struct Component {
    pub id: u8,
    pub h: u8,
    pub v: u8,
    pub tq: u8,
}

#[derive(Debug, Clone)]
pub struct Scan {
    /// (component index, DC table, AC table)
    pub comps: Vec<(usize, u8, u8)>,
    pub data: (usize, usize),
    pub ss: u8,
    pub se: u8,
}

#[derive(Debug, Clone)]
struct HuffSpec {
    class: u8,
    id: u8,
    counts: [u8; 16],
    vals: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Jpeg {
    pub width: u32,
    pub height: u32,
    /// SOF marker (0xC0 baseline, 0xC1 extended, 0xC2 progressive...).
    pub sof: u8,
    pub precision: u8,
    pub components: Vec<Component>,
    /// Quantization tables in natural order, by table id.
    pub qt: [Option<[u16; 64]>; 4],
    pub restart: u32,
    /// TIFF data inside the APP1 Exif segment (file offsets).
    pub exif: Option<(usize, usize)>,
    pub xmp: Option<String>,
    pub comments: Vec<String>,
    pub jfif: bool,
    /// APP14 "Adobe" (written by Adobe software and some others).
    pub adobe: bool,
    /// APP13 "Photoshop 3.0" (IPTC / image resources).
    pub photoshop: bool,
    /// APP2 "MPF": the file holds more images after the first one.
    pub mpf: bool,
    /// APP2 ICC profile present.
    pub icc: bool,
    pub scans: Vec<Scan>,
    huff: Vec<HuffSpec>,
    /// Offset just after the EOI marker, or where parsing stopped.
    pub end: usize,
    pub eoi: bool,
    /// Marker segments in order: (marker, offset of the 0xFF, total length).
    pub segments: Vec<(u8, usize, usize)>,
}

fn be16(d: &[u8], i: usize) -> usize {
    ((d[i] as usize) << 8) | d[i + 1] as usize
}

impl Jpeg {
    pub fn is_baseline(&self) -> bool {
        matches!(self.sof, 0xC0 | 0xC1) && self.precision == 8
    }

    pub fn progressive(&self) -> bool {
        matches!(self.sof, 0xC2 | 0xC6 | 0xCA | 0xCE)
    }

    pub fn hmax(&self) -> u8 {
        self.components.iter().map(|c| c.h).max().unwrap_or(1).max(1)
    }

    pub fn vmax(&self) -> u8 {
        self.components.iter().map(|c| c.v).max().unwrap_or(1).max(1)
    }

    /// Size of a component's block grid (blocks across, blocks down).
    pub fn blocks(&self, ci: usize) -> (usize, usize) {
        let c = &self.components[ci];
        let (hm, vm) = (self.hmax() as usize, self.vmax() as usize);
        let cw = (self.width as usize * c.h as usize).div_ceil(hm);
        let ch = (self.height as usize * c.v as usize).div_ceil(vm);
        (cw.div_ceil(8), ch.div_ceil(8))
    }

    /// Luminance quantization table (component 0), natural order.
    pub fn luma_table(&self) -> Option<[u16; 64]> {
        self.components.first().and_then(|c| self.qt[c.tq as usize & 3])
    }

    pub fn chroma_table(&self) -> Option<[u16; 64]> {
        self.components.get(1).and_then(|c| self.qt[c.tq as usize & 3])
    }
}

/// Walks the marker segments of a JPEG. Fails only when the data does not
/// start like a JPEG; damage later stops the walk and is reflected in
/// `eoi` and `end`.
pub fn parse(d: &[u8]) -> anyhow::Result<Jpeg> {
    if d.len() < 4 || d[0] != 0xFF || d[1] != 0xD8 {
        anyhow::bail!("not a JPEG (no SOI marker)");
    }
    let mut j = Jpeg { end: d.len(), ..Default::default() };
    let mut i = 2;
    loop {
        if i + 1 >= d.len() || d[i] != 0xFF {
            j.end = i.min(d.len());
            break;
        }
        let start = i;
        while i < d.len() && d[i] == 0xFF {
            i += 1;
        }
        if i >= d.len() {
            j.end = d.len();
            break;
        }
        let m = d[i];
        i += 1;
        match m {
            0xD9 => {
                j.end = i;
                j.eoi = true;
                j.segments.push((m, start, i - start));
                break;
            }
            0xD8 | 0x01 | 0xD0..=0xD7 => continue,
            _ => {}
        }
        if i + 2 > d.len() {
            j.end = start;
            break;
        }
        let len = be16(d, i);
        if len < 2 || i + len > d.len() {
            j.end = start;
            break;
        }
        let seg = &d[i + 2..i + len];
        j.segments.push((m, start, i + len - start));
        match m {
            0xC0..=0xCF if m != 0xC4 && m != 0xC8 && m != 0xCC => {
                if seg.len() >= 6 {
                    j.sof = m;
                    j.precision = seg[0];
                    j.height = be16(seg, 1) as u32;
                    j.width = be16(seg, 3) as u32;
                    let n = seg[5] as usize;
                    j.components = (0..n)
                        .filter(|k| 6 + 3 * k + 2 < seg.len())
                        .map(|k| Component { id: seg[6 + 3 * k], h: (seg[7 + 3 * k] >> 4).max(1), v: (seg[7 + 3 * k] & 15).max(1), tq: seg[8 + 3 * k] & 3 })
                        .collect();
                }
            }
            0xDB => {
                let mut p = 0;
                while p < seg.len() {
                    let (pq, tq) = (seg[p] >> 4, seg[p] & 3);
                    p += 1;
                    let w = if pq == 0 { 1 } else { 2 };
                    if p + 64 * w > seg.len() {
                        break;
                    }
                    let mut t = [0u16; 64];
                    for (k, &nat) in ZIGZAG.iter().enumerate() {
                        t[nat] = if w == 1 { seg[p + k] as u16 } else { be16(seg, p + 2 * k) as u16 };
                    }
                    j.qt[tq as usize] = Some(t);
                    p += 64 * w;
                }
            }
            0xC4 => {
                let mut p = 0;
                while p + 17 <= seg.len() {
                    let (class, id) = (seg[p] >> 4, seg[p] & 3);
                    let mut counts = [0u8; 16];
                    counts.copy_from_slice(&seg[p + 1..p + 17]);
                    let n: usize = counts.iter().map(|&c| c as usize).sum();
                    if p + 17 + n > seg.len() {
                        break;
                    }
                    let vals = seg[p + 17..p + 17 + n].to_vec();
                    j.huff.retain(|h| !(h.class == class && h.id == id));
                    j.huff.push(HuffSpec { class, id, counts, vals });
                    p += 17 + n;
                }
            }
            0xDD if seg.len() >= 2 => j.restart = be16(seg, 0) as u32,
            0xE0 if seg.starts_with(b"JFIF\0") => j.jfif = true,
            0xE1 if seg.starts_with(b"Exif\0\0") => j.exif = Some((i + 2 + 6, i + len)),
            0xE1 if seg.starts_with(b"http://ns.adobe.com/xap/1.0/\0") => {
                j.xmp = Some(String::from_utf8_lossy(&seg[29..]).chars().take(64 * 1024).collect());
            }
            0xE2 if seg.starts_with(b"MPF\0") => j.mpf = true,
            0xE2 if seg.starts_with(b"ICC_PROFILE\0") => j.icc = true,
            0xED if seg.starts_with(b"Photoshop 3.0\0") => j.photoshop = true,
            0xEE if seg.starts_with(b"Adobe") => j.adobe = true,
            0xFE => j.comments.push(String::from_utf8_lossy(seg).chars().filter(|c| !c.is_control() || *c == '\n').take(300).collect()),
            0xDA => {
                let n = seg.first().copied().unwrap_or(0) as usize;
                let comps = (0..n)
                    .filter(|k| 2 + 2 * k < seg.len())
                    .filter_map(|k| {
                        let cid = seg[1 + 2 * k];
                        let ci = j.components.iter().position(|c| c.id == cid)?;
                        Some((ci, seg[2 + 2 * k] >> 4, seg[2 + 2 * k] & 15))
                    })
                    .collect();
                let (ss, se) = (seg.get(1 + 2 * n).copied().unwrap_or(0), seg.get(2 + 2 * n).copied().unwrap_or(63));
                // Entropy-coded data runs to the next marker that is not a
                // stuffed byte or a restart marker.
                let s = i + len;
                let mut k = s;
                while k + 1 < d.len() {
                    if d[k] == 0xFF && d[k + 1] != 0 && !(0xD0..=0xD7).contains(&d[k + 1]) && d[k + 1] != 0xFF {
                        break;
                    }
                    k += 1;
                }
                if k + 1 >= d.len() {
                    k = d.len();
                }
                j.scans.push(Scan { comps, data: (s, k), ss, se });
                i = k;
                if k >= d.len() {
                    j.end = d.len();
                    break;
                }
                continue;
            }
            _ => {}
        }
        i += len;
    }
    Ok(j)
}

struct Huff {
    maxcode: [i32; 18],
    valptr: [i32; 17],
    mincode: [i32; 17],
    vals: Vec<u8>,
}

impl Huff {
    fn new(s: &HuffSpec) -> Huff {
        let mut h = Huff { maxcode: [-1; 18], valptr: [0; 17], mincode: [0; 17], vals: s.vals.clone() };
        let (mut code, mut k) = (0i32, 0i32);
        for l in 1..=16 {
            let n = s.counts[l - 1] as i32;
            if n > 0 {
                h.valptr[l] = k;
                h.mincode[l] = code;
                code += n;
                k += n;
                h.maxcode[l] = code - 1;
            }
            code <<= 1;
        }
        h.maxcode[17] = i32::MAX;
        h
    }
}

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
    end: usize,
    buf: u32,
    n: u32,
    /// Zero bytes fed since real data ran out (end of scan or a marker).
    starved: u32,
}

/// Padding allowed past the end of the scan data before decoding stops: a
/// truncated file still shows what it has, and a frame header claiming far
/// more blocks than the data holds cannot keep the decoder busy.
const MAX_STARVED: u32 = 1024;

impl<'a> Bits<'a> {
    fn bit(&mut self) -> u32 {
        if self.n == 0 {
            let mut b = 0u32;
            let pos0 = self.pos;
            if self.pos < self.end {
                let x = self.d[self.pos];
                if x == 0xFF {
                    let nx = self.d.get(self.pos + 1).copied().unwrap_or(0);
                    if nx == 0 {
                        self.pos += 2;
                        b = 0xFF;
                    }
                    // A marker: feed zeros until the caller handles it.
                } else {
                    self.pos += 1;
                    b = x as u32;
                }
            }
            self.starved = if self.pos == pos0 { self.starved.saturating_add(1) } else { 0 };
            self.buf = b;
            self.n = 8;
        }
        self.n -= 1;
        (self.buf >> self.n) & 1
    }

    fn bits(&mut self, s: u32) -> i32 {
        let mut v = 0i32;
        for _ in 0..s {
            v = (v << 1) | self.bit() as i32;
        }
        v
    }

    fn decode(&mut self, h: &Huff) -> anyhow::Result<u8> {
        let mut code = self.bit() as i32;
        let mut l = 1;
        while code > h.maxcode[l] {
            code = (code << 1) | self.bit() as i32;
            l += 1;
            if l > 16 {
                anyhow::bail!("bad Huffman code");
            }
        }
        h.vals.get((h.valptr[l] + code - h.mincode[l]) as usize).copied().ok_or_else(|| anyhow::anyhow!("bad Huffman value"))
    }

    /// Skips to just after the next RSTn marker and drops buffered bits.
    fn restart(&mut self) {
        self.n = 0;
        while self.pos + 1 < self.end {
            if self.d[self.pos] == 0xFF && (0xD0..=0xD7).contains(&self.d[self.pos + 1]) {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
    }
}

fn extend(v: i32, s: u32) -> i32 {
    if s == 0 {
        0
    } else if v < (1 << (s - 1)) {
        v - (1 << s) + 1
    } else {
        v
    }
}

/// Decodes every block of a baseline JPEG and calls `f(component, bx, by,
/// coefficients)` with the quantized coefficients in natural order.
/// `max_blocks` bounds the work on huge images.
pub fn for_each_block(d: &[u8], j: &Jpeg, max_blocks: usize, mut f: impl FnMut(usize, usize, usize, &[i32; 64])) -> anyhow::Result<()> {
    if !j.is_baseline() {
        anyhow::bail!("only baseline JPEGs are decoded");
    }
    if j.components.is_empty() || j.width == 0 || j.height == 0 {
        anyhow::bail!("no frame header");
    }
    let table = |class: u8, id: u8| j.huff.iter().find(|h| h.class == class && h.id == id).map(Huff::new);
    let mut done = 0usize;
    for scan in &j.scans {
        // A later frame header can leave fewer components than a scan names.
        if scan.comps.iter().any(|&(ci, _, _)| ci >= j.components.len()) {
            anyhow::bail!("scan names a component the frame does not have");
        }
        let mut dcs = vec![];
        let mut acs = vec![];
        for &(_, td, ta) in &scan.comps {
            dcs.push(table(0, td).ok_or_else(|| anyhow::anyhow!("missing DC table"))?);
            acs.push(table(1, ta).ok_or_else(|| anyhow::anyhow!("missing AC table"))?);
        }
        let mut bits = Bits { d, pos: scan.data.0, end: scan.data.1, buf: 0, n: 0, starved: 0 };
        let mut pred = vec![0i32; scan.comps.len()];
        // Each unit: (scan component, bx, by).
        let units: Box<dyn Iterator<Item = (usize, usize, usize)>> = if scan.comps.len() == 1 {
            let ci = scan.comps[0].0;
            let c = &j.components[ci];
            let (hm, vm) = (j.hmax() as usize, j.vmax() as usize);
            let bw = (j.width as usize * c.h as usize).div_ceil(hm).div_ceil(8);
            let bh = (j.height as usize * c.v as usize).div_ceil(vm).div_ceil(8);
            Box::new((0..bh).flat_map(move |by| (0..bw).map(move |bx| (0usize, bx, by))))
        } else {
            let (hm, vm) = (j.hmax() as usize, j.vmax() as usize);
            let mx = (j.width as usize).div_ceil(8 * hm);
            let my = (j.height as usize).div_ceil(8 * vm);
            let layout: Vec<(usize, usize, usize)> = scan
                .comps
                .iter()
                .enumerate()
                .flat_map(|(si, &(ci, _, _))| {
                    let c = &j.components[ci];
                    (0..c.v as usize).flat_map(move |v| (0..c.h as usize).map(move |h| (si, h, v)))
                })
                .collect();
            let comps: Vec<(usize, usize)> = scan.comps.iter().map(|&(ci, _, _)| (j.components[ci].h as usize, j.components[ci].v as usize)).collect();
            Box::new((0..my).flat_map(move |my_| (0..mx).map(move |mx_| (mx_, my_))).flat_map(move |(mx_, my_)| {
                let comps = comps.clone();
                layout.clone().into_iter().map(move |(si, h, v)| (si, mx_ * comps[si].0 + h, my_ * comps[si].1 + v))
            }))
        };
        let per_mcu: usize = if scan.comps.len() == 1 { 1 } else { scan.comps.iter().map(|&(ci, _, _)| j.components[ci].h as usize * j.components[ci].v as usize).sum() };
        let mut unit_no = 0usize;
        for (si, bx, by) in units {
            if j.restart > 0 && unit_no > 0 && unit_no % (per_mcu * j.restart as usize) == 0 {
                bits.restart();
                pred.iter_mut().for_each(|p| *p = 0);
            }
            unit_no += 1;
            if bits.starved > MAX_STARVED {
                break;
            }
            let mut coef = [0i32; 64];
            let t = bits.decode(&dcs[si])? as u32;
            if t > 16 {
                anyhow::bail!("bad DC difference size {}", t);
            }
            pred[si] = pred[si].wrapping_add(extend(bits.bits(t), t));
            coef[0] = pred[si];
            let mut k = 1;
            while k < 64 {
                let rs = bits.decode(&acs[si])?;
                let (r, s) = ((rs >> 4) as usize, (rs & 15) as u32);
                if s == 0 {
                    if r == 15 {
                        k += 16;
                        continue;
                    }
                    break;
                }
                k += r;
                if k > 63 {
                    anyhow::bail!("coefficient index out of range");
                }
                coef[ZIGZAG[k]] = extend(bits.bits(s), s);
                k += 1;
            }
            f(scan.comps[si].0, bx, by, &coef);
            done += 1;
            if done >= max_blocks {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// 8x8 inverse DCT of dequantized coefficients (natural order), level-shifted.
pub fn idct(c: &[f32; 64]) -> [f32; 64] {
    static COS: std::sync::OnceLock<[[f32; 8]; 8]> = std::sync::OnceLock::new();
    let cos = COS.get_or_init(|| {
        let mut cos = [[0f32; 8]; 8];
        for (x, row) in cos.iter_mut().enumerate() {
            for (u, v) in row.iter_mut().enumerate() {
                let cu = if u == 0 { std::f32::consts::FRAC_1_SQRT_2 } else { 1.0 };
                *v = cu * (((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI) / 16.0).cos() / 2.0;
            }
        }
        cos
    });
    let mut tmp = [0f32; 64];
    for y in 0..8 {
        for x in 0..8 {
            tmp[y * 8 + x] = (0..8).map(|u| cos[x][u] * c[y * 8 + u]).sum();
        }
    }
    let mut out = [0f32; 64];
    for x in 0..8 {
        for y in 0..8 {
            out[y * 8 + x] = (0..8).map(|v| cos[y][v] * tmp[v * 8 + x]).sum::<f32>() + 128.0;
        }
    }
    out
}

/// A grayscale plane.
#[derive(Debug, Clone)]
pub struct Plane {
    pub w: usize,
    pub h: usize,
    pub px: Vec<f32>,
}

/// Full-resolution luminance of a small baseline JPEG (an EXIF thumbnail).
pub fn luma(d: &[u8], j: &Jpeg) -> anyhow::Result<Plane> {
    let q = j.luma_table().ok_or_else(|| anyhow::anyhow!("no luminance table"))?;
    let (bw, bh) = j.blocks(0);
    if bw * bh > 40_000 {
        anyhow::bail!("image too large for a full decode");
    }
    let mut p = Plane { w: bw * 8, h: bh * 8, px: vec![0.0; bw * bh * 64] };
    for_each_block(d, j, usize::MAX, |ci, bx, by, c| {
        if ci != 0 || bx >= bw || by >= bh {
            return;
        }
        let mut dq = [0f32; 64];
        for k in 0..64 {
            dq[k] = c[k].saturating_mul(q[k] as i32) as f32;
        }
        let b = idct(&dq);
        for y in 0..8 {
            for x in 0..8 {
                p.px[(by * 8 + y) * p.w + bx * 8 + x] = b[y * 8 + x].clamp(0.0, 255.0);
            }
        }
    })?;
    // Crop the padding blocks to the real luminance size.
    let (cw, ch) = {
        let c = &j.components[0];
        ((j.width as usize * c.h as usize).div_ceil(j.hmax() as usize), (j.height as usize * c.v as usize).div_ceil(j.vmax() as usize))
    };
    Ok(crop(&p, cw.min(p.w), ch.min(p.h)))
}

/// Color decode of a baseline JPEG (gray or YCbCr) to 8-bit RGB, row by
/// row, for report exhibits. Chroma is upsampled by nearest neighbour.
pub fn rgb(d: &[u8], j: &Jpeg, max_pixels: usize) -> anyhow::Result<(usize, usize, Vec<u8>)> {
    let nc = j.components.len();
    if nc != 1 && nc != 3 {
        anyhow::bail!("{} color components (only gray and YCbCr are rendered)", nc);
    }
    let (w, h) = (j.width as usize, j.height as usize);
    if w * h > max_pixels {
        anyhow::bail!("{}x{} pixels is too large to render", w, h);
    }
    let (hm, vm) = (j.hmax() as usize, j.vmax() as usize);
    let (mx, my) = (w.div_ceil(8 * hm), h.div_ceil(8 * vm));
    // Planes sized to whole MCUs, so interleaved padding blocks fit.
    let mut planes: Vec<(usize, Vec<u8>)> = j.components.iter().map(|c| (mx * c.h as usize * 8, vec![0u8; mx * c.h as usize * 8 * my * c.v as usize * 8])).collect();
    let mut qs = vec![];
    for c in &j.components {
        qs.push(j.qt[c.tq as usize & 3].ok_or_else(|| anyhow::anyhow!("missing quantization table"))?);
    }
    for_each_block(d, j, usize::MAX, |ci, bx, by, c| {
        let (pw, px) = &mut planes[ci];
        let pw = *pw;
        if (bx + 1) * 8 > pw || (by + 1) * 8 * pw > px.len() {
            return;
        }
        let mut dq = [0f32; 64];
        for k in 0..64 {
            dq[k] = c[k].saturating_mul(qs[ci][k] as i32) as f32;
        }
        let b = idct(&dq);
        for y in 0..8 {
            for x in 0..8 {
                px[(by * 8 + y) * pw + bx * 8 + x] = b[y * 8 + x].round().clamp(0.0, 255.0) as u8;
            }
        }
    })?;
    let mut out = Vec::with_capacity(w * h * 3);
    let sample = |ci: usize, x: usize, y: usize| {
        let c = &j.components[ci];
        let (pw, px) = &planes[ci];
        px[(y * c.v as usize / vm) * pw + x * c.h as usize / hm] as f32
    };
    for y in 0..h {
        for x in 0..w {
            let l = sample(0, x, y);
            if nc == 1 {
                out.extend_from_slice(&[l as u8; 3]);
                continue;
            }
            let (cb, cr) = (sample(1, x, y) - 128.0, sample(2, x, y) - 128.0);
            for v in [l + 1.402 * cr, l - 0.344_136 * cb - 0.714_136 * cr, l + 1.772 * cb] {
                out.push(v.round().clamp(0.0, 255.0) as u8);
            }
        }
    }
    Ok((w, h, out))
}

pub fn crop(p: &Plane, w: usize, h: usize) -> Plane {
    let mut out = Plane { w, h, px: Vec::with_capacity(w * h) };
    for y in 0..h {
        out.px.extend_from_slice(&p.px[y * p.w..y * p.w + w]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zigzag_is_a_permutation() {
        let mut s = ZIGZAG.to_vec();
        s.sort();
        assert_eq!(s, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn idct_of_dc_is_flat() {
        let mut c = [0f32; 64];
        c[0] = 80.0; // DC of 80 -> mean 10 above 128
        let b = idct(&c);
        assert!(b.iter().all(|v| (v - 138.0).abs() < 0.01), "{:?}", &b[..8]);
    }
}
