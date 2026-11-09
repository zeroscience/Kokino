//! BitLocker (Windows 7 and later, BitLocker To Go): the FVE metadata, its key
//! protectors, unlocking with a password, a recovery password or a clear key
//! (protection suspended), and the decrypted volume.
//!
//! Format: Joachim Metz, "BitLocker Drive Encryption (BDE) format" (libbde);
//! the Elephant diffuser: Niels Ferguson, "AES-CBC + Elephant diffuser" (2006).
//! Windows Vista volumes (metadata version 1) are recognised but not read.

use crate::read_at;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom};

/// 4967d63b-2e29-4ad8-8399-f6a339e3d001 as stored.
pub const GUID: [u8; 16] = [0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01];
/// 92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8: "used disk space only" encryption.
pub const GUID_USED_SPACE: [u8; 16] = [0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8];

/// The space each FVE metadata block takes on the volume (read back as zeros).
const META_SPAN: u64 = 64 * 1024;
const STRETCH_ROUNDS: u64 = 0x10_0000;

/// True for a BitLocker volume header (any version).
pub fn is_bitlocker(boot: &[u8]) -> bool {
    boot.len() >= 512 && (&boot[3..11] == b"-FVE-FS-" || boot[424..440] == GUID)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Protector {
    /// "Password", "Recovery password", "TPM", "Startup key", "TPM and PIN", "Clear key"...
    pub kind: String,
    pub id: String,
    /// FILETIME of the last change.
    pub modified: u64,
}

/// What the unencrypted metadata says about a BitLocker volume.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Info {
    pub to_go: bool,
    pub method: u32,
    pub method_label: String,
    pub volume_id: String,
    /// FILETIME the volume was encrypted.
    pub created: u64,
    /// The drive label BitLocker stored: computer name, drive and date.
    pub description: String,
    pub protectors: Vec<Protector>,
    /// Bytes still encrypted (from the start of the volume); the rest is plain
    /// while BitLocker is turned off part way.
    pub encrypted_size: u64,
    pub sector_size: u64,
    pub header_offset: u64,
    pub header_size: u64,
    pub metadata: Vec<u64>,
    #[serde(skip)]
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    etype: u16,
    vtype: u16,
    data: Vec<u8>,
}

pub fn method_label(m: u32) -> &'static str {
    match m & 0xFFFF {
        0x8000 => "AES-128-CBC with Elephant diffuser",
        0x8001 => "AES-256-CBC with Elephant diffuser",
        0x8002 => "AES-128-CBC",
        0x8003 => "AES-256-CBC",
        0x8004 => "AES-128-XTS",
        0x8005 => "AES-256-XTS",
        _ => "unknown",
    }
}

fn protector_label(t: u16) -> &'static str {
    match t {
        0x0000 => "Clear key",
        0x0100 => "TPM",
        0x0200 => "Startup key",
        0x0500 => "TPM and PIN",
        0x0800 => "Recovery password",
        0x2000 => "Password",
        _ => "Other",
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}
fn u32le(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
fn u64le(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}

fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32le(b, 0),
        u16le(b, 4),
        u16le(b, 6),
        b[8],
        b[9],
        b[10..16].iter().map(|x| format!("{:02x}", x)).collect::<String>()
    )
}

fn entries(b: &[u8]) -> Vec<Entry> {
    let mut out = vec![];
    let mut p = 0;
    while p + 8 <= b.len() && out.len() < 1024 {
        let size = u16le(b, p) as usize;
        if size < 8 || p + size > b.len() {
            break;
        }
        out.push(Entry { etype: u16le(b, p + 2), vtype: u16le(b, p + 4), data: b[p + 8..p + size].to_vec() });
        p += size;
    }
    out
}

fn utf16(b: &[u8]) -> String {
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&w)
}

/// Reads the volume header and the first FVE metadata block that parses.
pub fn info<R: Read + Seek>(r: &mut R, len: u64) -> io::Result<Info> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let mut h = [0u8; 512];
    if read_at(r, 0, &mut h)? < 512 {
        return Err(bad("not a BitLocker volume"));
    }
    let (at, to_go) = if h[160..176] == GUID || h[160..176] == GUID_USED_SPACE {
        (176, false)
    } else if h[424..440] == GUID {
        (440, true)
    } else if &h[3..11] == b"-FVE-FS-" {
        return Err(bad("BitLocker from Windows Vista is not supported yet"));
    } else {
        return Err(bad("not a BitLocker volume"));
    };
    let ss = match u16le(&h, 11) {
        s @ (512 | 1024 | 2048 | 4096) => s as u64,
        _ => 512,
    };
    let offsets: Vec<u64> = (0..3).map(|i| u64le(&h, at + i * 8)).collect();
    for &o in &offsets {
        if o == 0 || o >= len {
            continue;
        }
        let mut b = [0u8; 112];
        if read_at(r, o, &mut b)? < 112 || &b[0..8] != b"-FVE-FS-" {
            continue;
        }
        if u16le(&b, 10) != 2 {
            return Err(bad("BitLocker from Windows Vista is not supported yet"));
        }
        let msize = (u32le(&b, 64) as usize).clamp(48, 1 << 20);
        let mut m = vec![0u8; msize];
        let got = read_at(r, o + 64, &mut m)?;
        m.truncate(got);
        if m.len() < 48 || u32le(&m, 8) != 48 {
            continue;
        }
        let es = entries(&m[48..]);
        let mut header_offset = u64le(&b, 56);
        let mut header_size = u32le(&b, 28) as u64 * ss;
        if header_size == 0 {
            if let Some(d) = es.iter().find(|e| e.etype == 0x000F && e.vtype == 0x000F && e.data.len() >= 16) {
                header_offset = u64le(&d.data, 0);
                header_size = u64le(&d.data, 8);
            }
        }
        let protectors = es
            .iter()
            .filter(|e| e.etype == 0x0002 && e.vtype == 0x0008 && e.data.len() >= 28)
            .map(|e| Protector { kind: protector_label(u16le(&e.data, 26)).into(), id: guid(&e.data[0..16]), modified: u64le(&e.data, 16) })
            .collect();
        let description = es.iter().find(|e| e.etype == 0x0007 && e.vtype == 0x0002).map(|e| utf16(&e.data)).unwrap_or_default();
        let enc = u64le(&b, 16);
        let method = u32le(&m, 36);
        return Ok(Info {
            to_go,
            method,
            method_label: method_label(method).into(),
            volume_id: guid(&m[16..32]),
            created: u64le(&m, 40),
            description,
            protectors,
            encrypted_size: if enc == 0 || enc > len { len } else { enc },
            sector_size: ss,
            header_offset,
            header_size: header_size.min(len),
            metadata: offsets,
            entries: es,
        });
    }
    Err(bad("no readable BitLocker metadata block"))
}

/// The key that decrypts the volume, as kept with the evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Key {
    pub method: u32,
    /// Full volume encryption key (both XTS keys for XTS), hex.
    pub fvek: String,
    /// The diffuser's tweak key, hex (empty without the diffuser).
    #[serde(default)]
    pub tweak: String,
    /// How it was unlocked: "Password", "Recovery password", "Clear key".
    pub protector: String,
}

pub enum Secret<'a> {
    Password(&'a str),
    /// 48 digits in 8 groups, as Windows shows it.
    RecoveryPassword(&'a str),
    /// Protection suspended: the volume master key is stored unprotected.
    ClearKey,
    /// The contents of a startup key file ({GUID}.BEK).
    StartupKey(&'a [u8]),
}

/// The key identifier and the 256-bit key in a startup key (.BEK) file.
pub fn bek_key(bek: &[u8]) -> Option<(String, Vec<u8>)> {
    if bek.len() < 56 || u32le(bek, 8) != 48 {
        return None;
    }
    let size = (u32le(bek, 0) as usize).clamp(48, bek.len());
    let ext = entries(&bek[48..size]).into_iter().find(|e| e.vtype == 0x0009 && e.data.len() >= 24)?;
    let key = entries(&ext.data[24..]).into_iter().find(|p| p.vtype == 0x0001 && p.data.len() >= 36)?;
    Some((guid(&ext.data[0..16]), key.data[4..36].to_vec()))
}

fn sha256(d: &[u8]) -> [u8; 32] {
    Sha256::digest(d).into()
}

/// BitLocker's key stretching: 2^20 rounds of SHA-256 over
/// (last hash, initial hash, salt, round).
fn stretch(initial: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut s = [0u8; 88];
    s[32..64].copy_from_slice(initial);
    s[64..80].copy_from_slice(&salt[..16]);
    for i in 0..STRETCH_ROUNDS {
        s[80..88].copy_from_slice(&i.to_le_bytes());
        let h = sha256(&s);
        s[0..32].copy_from_slice(&h);
    }
    s[0..32].try_into().unwrap()
}

/// The 16-byte key behind a recovery password: each group of 6 digits is a
/// multiple of 11, and the quotient a 16-bit word.
pub fn recovery_key(pw: &str) -> Option<[u8; 16]> {
    let groups: Vec<&str> = pw.trim().split(['-', ' ']).filter(|g| !g.is_empty()).collect();
    let digits: String = groups.concat();
    if digits.len() != 48 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut k = [0u8; 16];
    for i in 0..8 {
        let n: u32 = digits[i * 6..i * 6 + 6].parse().ok()?;
        if n % 11 != 0 || n / 11 > 0xFFFF {
            return None;
        }
        k[i * 2..i * 2 + 2].copy_from_slice(&((n / 11) as u16).to_le_bytes());
    }
    Some(k)
}

enum Cipher {
    A128(Box<Aes128>),
    A256(Box<Aes256>),
}

impl Cipher {
    fn new(k: &[u8]) -> Option<Cipher> {
        match k.len() {
            16 => Some(Cipher::A128(Box::new(Aes128::new(GenericArray::from_slice(k))))),
            32 => Some(Cipher::A256(Box::new(Aes256::new(GenericArray::from_slice(k))))),
            _ => None,
        }
    }
    fn enc(&self, b: &mut [u8]) {
        let b = GenericArray::from_mut_slice(b);
        match self {
            Cipher::A128(c) => c.encrypt_block(b),
            Cipher::A256(c) => c.encrypt_block(b),
        }
    }
    fn dec(&self, b: &mut [u8]) {
        let b = GenericArray::from_mut_slice(b);
        match self {
            Cipher::A128(c) => c.decrypt_block(b),
            Cipher::A256(c) => c.decrypt_block(b),
        }
    }
}

/// AES-CCM as BitLocker uses it for keys: 12-byte nonce, 16-byte tag stored
/// before the data, no associated data. `None` when the tag does not match
/// (the wrong key).
fn ccm_decrypt(key: &[u8], d: &[u8]) -> Option<Vec<u8>> {
    if d.len() < 28 || d.len() - 28 >= 1 << 24 {
        return None;
    }
    let c = Cipher::new(key)?;
    let (nonce, tag, ct) = (&d[0..12], &d[12..28], &d[28..]);
    let block = |i: u32| {
        let mut a = [0u8; 16];
        a[0] = 2;
        a[1..13].copy_from_slice(nonce);
        a[13..16].copy_from_slice(&i.to_be_bytes()[1..]);
        c.enc(&mut a);
        a
    };
    let mut pt = ct.to_vec();
    for (i, ch) in pt.chunks_mut(16).enumerate() {
        let s = block(i as u32 + 1);
        ch.iter_mut().zip(s).for_each(|(b, k)| *b ^= k);
    }
    let mut x = [0u8; 16];
    x[0] = 0x3A; // tag of 16 bytes, 3-byte length
    x[1..13].copy_from_slice(nonce);
    x[13..16].copy_from_slice(&(pt.len() as u32).to_be_bytes()[1..]);
    c.enc(&mut x);
    for ch in pt.chunks(16) {
        x.iter_mut().zip(ch).for_each(|(a, b)| *a ^= b);
        c.enc(&mut x);
    }
    let s0 = block(0);
    let ok = x.iter().zip(s0).zip(tag).fold(0u8, |acc, ((a, s), t)| acc | (a ^ s ^ t));
    (ok == 0).then_some(pt)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()).collect()
}

/// Unlocks the volume: finds the protector the secret is for, opens the
/// volume master key with it, then the full volume encryption key.
pub fn unlock(info: &Info, secret: &Secret) -> Result<Key, String> {
    let (want, label) = match secret {
        Secret::Password(_) => (0x2000u16, "Password"),
        Secret::RecoveryPassword(_) => (0x0800, "Recovery password"),
        Secret::ClearKey => (0x0000, "Clear key"),
        Secret::StartupKey(_) => (0x0200, "Startup key"),
    };
    let bek = match secret {
        Secret::StartupKey(b) => Some(bek_key(b).ok_or("not a BitLocker startup key file (.BEK)")?),
        _ => None,
    };
    let mut vmks: Vec<&Entry> = info.entries.iter().filter(|e| e.etype == 0x0002 && e.vtype == 0x0008 && e.data.len() >= 28 && u16le(&e.data, 26) == want).collect();
    if let Some((id, _)) = &bek {
        // A startup key opens the protector with its own identifier.
        let n = vmks.len();
        vmks.retain(|e| guid(&e.data[0..16]) == *id);
        if vmks.is_empty() && n > 0 {
            return Err(format!("this startup key ({}) is for another volume", id));
        }
    }
    if vmks.is_empty() {
        return Err(format!("this volume has no {} protector (it has: {})", label.to_lowercase(), info.protectors.iter().map(|p| p.kind.clone()).collect::<Vec<_>>().join(", ")));
    }
    let initial = match secret {
        Secret::Password(p) => {
            let w: Vec<u8> = p.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            Some(sha256(&sha256(&w)))
        }
        Secret::RecoveryPassword(p) => Some(sha256(&recovery_key(p).ok_or("a recovery password is 48 digits in 8 groups of 6, each a multiple of 11")?)),
        Secret::ClearKey | Secret::StartupKey(_) => None,
    };
    let mut vmk = None;
    for e in vmks {
        let props = entries(&e.data[28..]);
        let Some(ccm) = props.iter().find(|p| p.vtype == 0x0005) else { continue };
        let key = match &initial {
            Some(init) => match props.iter().find(|p| p.vtype == 0x0003 && p.data.len() >= 20) {
                Some(s) => stretch(init, &s.data[4..20]).to_vec(),
                None => continue,
            },
            None => match &bek {
                Some((_, k)) => k.clone(),
                None => match props.iter().find(|p| p.vtype == 0x0001 && p.data.len() >= 36) {
                    Some(k) => k.data[4..36].to_vec(),
                    None => continue,
                },
            },
        };
        if let Some(pt) = ccm_decrypt(&key, &ccm.data) {
            if pt.len() >= 44 {
                vmk = Some(pt[12..44].to_vec());
                break;
            }
        }
    }
    let vmk = vmk.ok_or_else(|| match secret {
        Secret::Password(_) => "wrong password".to_string(),
        Secret::RecoveryPassword(_) => "wrong recovery password".to_string(),
        Secret::ClearKey => "the clear key does not open the volume master key".to_string(),
        Secret::StartupKey(_) => "this startup key does not open the volume master key".to_string(),
    })?;
    let fvek = info.entries.iter().filter(|e| e.etype == 0x0003 && e.vtype == 0x0005).find_map(|e| ccm_decrypt(&vmk, &e.data)).ok_or("the volume master key does not open the volume encryption key")?;
    if fvek.len() < 12 {
        return Err("volume encryption key too short".into());
    }
    let method = u32le(&fvek, 8) & 0xFFFF;
    let k = &fvek[12..];
    let need = |n: usize| if k.len() >= n { Ok(()) } else { Err(format!("volume encryption key too short for {}", method_label(method))) };
    let (f, t) = match method {
        0x8000 => {
            need(48)?;
            (&k[0..16], &k[32..48])
        }
        0x8001 => {
            need(64)?;
            (&k[0..32], &k[32..64])
        }
        0x8002 | 0x8004 => {
            need(if method == 0x8004 { 32 } else { 16 })?;
            (&k[0..if method == 0x8004 { 32 } else { 16 }], &k[0..0])
        }
        0x8003 | 0x8005 => {
            need(if method == 0x8005 { 64 } else { 32 })?;
            (&k[0..if method == 0x8005 { 64 } else { 32 }], &k[0..0])
        }
        m => return Err(format!("encryption method 0x{:04x} not supported", m)),
    };
    Ok(Key { method, fvek: hex(f), tweak: hex(t), protector: label.into() })
}

/// The sector cipher for one key.
struct Crypt {
    method: u32,
    fvek: Cipher,
    /// The tweak key (diffuser) or the second XTS key.
    tweak: Option<Cipher>,
}

impl Crypt {
    fn new(k: &Key) -> io::Result<Crypt> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "BitLocker key does not fit its method");
        let f = unhex(&k.fvek);
        let t = unhex(&k.tweak);
        let (fvek, tweak) = match k.method {
            0x8000 | 0x8001 => (Cipher::new(&f), Some(Cipher::new(&t).ok_or_else(bad)?)),
            0x8002 | 0x8003 => (Cipher::new(&f), None),
            0x8004 | 0x8005 => {
                let h = f.len() / 2;
                (Cipher::new(&f[..h]), Some(Cipher::new(&f[h..]).ok_or_else(bad)?))
            }
            _ => (None, None),
        };
        Ok(Crypt { method: k.method, fvek: fvek.ok_or_else(bad)?, tweak })
    }

    /// Decrypts one sector stored at byte `off` of the volume.
    fn sector(&self, off: u64, ss: u64, b: &mut [u8]) {
        let mut iv = [0u8; 16];
        match self.method {
            0x8004 | 0x8005 => {
                let Some(t2) = &self.tweak else { return };
                iv[..8].copy_from_slice(&(off / ss).to_le_bytes());
                t2.enc(&mut iv);
                for blk in b.chunks_exact_mut(16) {
                    blk.iter_mut().zip(iv).for_each(|(x, t)| *x ^= t);
                    self.fvek.dec(blk);
                    blk.iter_mut().zip(iv).for_each(|(x, t)| *x ^= t);
                    // Next tweak: multiply by x in GF(2^128).
                    let carry = iv[15] >> 7;
                    for i in (1..16).rev() {
                        iv[i] = (iv[i] << 1) | (iv[i - 1] >> 7);
                    }
                    iv[0] = (iv[0] << 1) ^ (0x87 * carry);
                }
            }
            _ => {
                iv[..8].copy_from_slice(&off.to_le_bytes());
                self.fvek.enc(&mut iv);
                let mut prev = iv;
                for blk in b.chunks_exact_mut(16) {
                    let c: [u8; 16] = (&*blk).try_into().unwrap();
                    self.fvek.dec(blk);
                    blk.iter_mut().zip(prev).for_each(|(x, p)| *x ^= p);
                    prev = c;
                }
                if let (0x8000 | 0x8001, Some(t)) = (self.method, &self.tweak) {
                    diffuser_b_decrypt(b);
                    diffuser_a_decrypt(b);
                    let mut sk = [0u8; 32];
                    sk[..8].copy_from_slice(&off.to_le_bytes());
                    sk[16..24].copy_from_slice(&off.to_le_bytes());
                    sk[31] = 0x80;
                    t.enc(&mut sk[..16]);
                    t.enc(&mut sk[16..]);
                    b.iter_mut().enumerate().for_each(|(i, x)| *x ^= sk[i % 32]);
                }
            }
        }
    }
}

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}
fn unwords(w: &[u32], b: &mut [u8]) {
    for (c, x) in b.chunks_exact_mut(4).zip(w) {
        c.copy_from_slice(&x.to_le_bytes());
    }
}

fn diffuser_a_decrypt(b: &mut [u8]) {
    const R: [u32; 4] = [9, 0, 13, 0];
    let mut d = words(b);
    let n = d.len();
    if n < 8 {
        return;
    }
    for _ in 0..5 {
        for i in 0..n {
            d[i] = d[i].wrapping_add(d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(R[i % 4]));
        }
    }
    unwords(&d, b);
}

fn diffuser_b_decrypt(b: &mut [u8]) {
    const R: [u32; 4] = [0, 10, 0, 25];
    let mut d = words(b);
    let n = d.len();
    if n < 8 {
        return;
    }
    for _ in 0..3 {
        for i in 0..n {
            d[i] = d[i].wrapping_add(d[(i + 2) % n] ^ d[(i + 5) % n].rotate_left(R[i % 4]));
        }
    }
    unwords(&d, b);
}

/// The decrypted volume. The first sectors (the original boot record) are
/// read from where BitLocker moved them; the metadata blocks and that copy
/// read as zeros; bytes past the encrypted size are passed through.
pub struct BdeReader<R> {
    inner: R,
    len: u64,
    pos: u64,
    ss: u64,
    header_offset: u64,
    header_size: u64,
    metadata: Vec<u64>,
    encrypted_size: u64,
    crypt: Crypt,
}

impl<R: Read + Seek> BdeReader<R> {
    pub fn new(mut inner: R, len: u64, key: &Key) -> io::Result<BdeReader<R>> {
        let i = info(&mut inner, len)?;
        Ok(BdeReader {
            inner,
            len,
            pos: 0,
            ss: i.sector_size,
            header_offset: i.header_offset,
            header_size: i.header_size,
            metadata: i.metadata.into_iter().filter(|&m| m > 0).collect(),
            encrypted_size: i.encrypted_size,
            crypt: Crypt::new(key)?,
        })
    }

    fn hidden(&self, x: u64) -> bool {
        (self.header_size > 0 && x >= self.header_offset && x < self.header_offset.saturating_add(self.header_size)) || self.metadata.iter().any(|&m| x >= m && x < m.saturating_add(META_SPAN))
    }

    /// Fills `out` with the decrypted bytes from sector-aligned `off`.
    fn fill(&mut self, off: u64, out: &mut [u8]) -> io::Result<()> {
        let n = read_at(&mut self.inner, off, out)?;
        out[n..].fill(0);
        let ss = self.ss as usize;
        for (k, s) in out.chunks_mut(ss).enumerate() {
            let x = off + (k * ss) as u64;
            if x < self.header_size {
                // The original first sectors, kept encrypted elsewhere.
                let src = self.header_offset.saturating_add(x);
                let got = read_at(&mut self.inner, src, s)?;
                s[got..].fill(0);
                if s.len() == ss {
                    self.crypt.sector(src, self.ss, s);
                }
            } else if self.hidden(x) {
                s.fill(0);
            } else if x < self.encrypted_size && s.len() == ss {
                self.crypt.sector(x, self.ss, s);
            }
        }
        Ok(())
    }
}

impl<R: Read + Seek> Read for BdeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - self.pos).min(1 << 20);
        let first = self.pos / self.ss * self.ss;
        let end = (self.pos + want).div_ceil(self.ss) * self.ss;
        let mut tmp = vec![0u8; (end - first) as usize];
        self.fill(first, &mut tmp)?;
        let skip = (self.pos - first) as usize;
        let n = want as usize;
        buf[..n].copy_from_slice(&tmp[skip..skip + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for BdeReader<R> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let np = match p {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::End(o) => self.len as i128 + o as i128,
            SeekFrom::Current(o) => self.pos as i128 + o as i128,
        };
        if np < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn recovery_passwords() {
        // Each group is 11 times a 16-bit word.
        let k = recovery_key("000011-000022-000033-000044-000055-000066-000077-720885").unwrap();
        assert_eq!(&k[..4], &[1, 0, 2, 0]);
        assert_eq!(&k[14..], &[0xFF, 0xFF]);
        assert!(recovery_key("000012-000022-000033-000044-000055-000066-000077-000088").is_none());
        assert!(recovery_key("123").is_none());
    }

    #[test]
    fn xts_matches_ieee_1619() {
        // IEEE 1619-2007 vector 1: both keys zero, data unit 0, 32 zero bytes.
        let k = Key { method: 0x8004, fvek: "00".repeat(32), tweak: String::new(), protector: String::new() };
        let c = Crypt::new(&k).unwrap();
        let mut b = unhex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e");
        c.sector(0, 512, &mut b);
        assert_eq!(b, vec![0u8; 32]);
    }

    fn diffuser_a_encrypt(b: &mut [u8]) {
        const R: [u32; 4] = [9, 0, 13, 0];
        let mut d = words(b);
        let n = d.len();
        for _ in 0..5 {
            for i in (0..n).rev() {
                d[i] = d[i].wrapping_sub(d[(i + n - 2) % n] ^ d[(i + n - 5) % n].rotate_left(R[i % 4]));
            }
        }
        unwords(&d, b);
    }

    #[test]
    fn diffuser_round_trips() {
        let orig: Vec<u8> = (0..512u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut b = orig.clone();
        diffuser_a_encrypt(&mut b);
        assert_ne!(b, orig);
        diffuser_a_decrypt(&mut b);
        assert_eq!(b, orig);
    }

    /// AES-CCM as BitLocker stores keys: nonce, tag, data.
    fn seal(key: &[u8], nonce: [u8; 12], pt: &[u8]) -> Vec<u8> {
        let c = Cipher::new(key).unwrap();
        let block = |i: u32| {
            let mut a = [0u8; 16];
            a[0] = 2;
            a[1..13].copy_from_slice(&nonce);
            a[13..16].copy_from_slice(&i.to_be_bytes()[1..]);
            c.enc(&mut a);
            a
        };
        let mut x = [0u8; 16];
        x[0] = 0x3A;
        x[1..13].copy_from_slice(&nonce);
        x[13..16].copy_from_slice(&(pt.len() as u32).to_be_bytes()[1..]);
        c.enc(&mut x);
        for ch in pt.chunks(16) {
            x.iter_mut().zip(ch).for_each(|(a, b)| *a ^= b);
            c.enc(&mut x);
        }
        let tag: Vec<u8> = x.iter().zip(block(0)).map(|(a, s)| a ^ s).collect();
        let mut ct = pt.to_vec();
        for (i, ch) in ct.chunks_mut(16).enumerate() {
            ch.iter_mut().zip(block(i as u32 + 1)).for_each(|(b, k)| *b ^= k);
        }
        let mut d = nonce.to_vec();
        d.extend(&tag);
        d.extend(&ct);
        d
    }

    #[test]
    fn ccm_rejects_a_wrong_key() {
        let pt = b"0123456789abcdef0123456789abcdef0123456789ab".to_vec();
        let d = seal(&[7u8; 32], [1u8; 12], &pt);
        assert_eq!(ccm_decrypt(&[7u8; 32], &d).unwrap(), pt);
        assert!(ccm_decrypt(&[8u8; 32], &d).is_none());
    }

    fn xts_encrypt(k1: &Cipher, k2: &Cipher, unit: u64, b: &mut [u8]) {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&unit.to_le_bytes());
        k2.enc(&mut t);
        for blk in b.chunks_exact_mut(16) {
            blk.iter_mut().zip(t).for_each(|(x, y)| *x ^= y);
            k1.enc(blk);
            blk.iter_mut().zip(t).for_each(|(x, y)| *x ^= y);
            let carry = t[15] >> 7;
            for i in (1..16).rev() {
                t[i] = (t[i] << 1) | (t[i - 1] >> 7);
            }
            t[0] = (t[0] << 1) ^ (0x87 * carry);
        }
    }

    fn entry(etype: u16, vtype: u16, data: &[u8]) -> Vec<u8> {
        let mut e = ((data.len() + 8) as u16).to_le_bytes().to_vec();
        e.extend(etype.to_le_bytes());
        e.extend(vtype.to_le_bytes());
        e.extend(1u16.to_le_bytes());
        e.extend(data);
        e
    }

    pub(crate) enum Prot<'a> {
        Password(&'a str),
        Recovery(&'a str),
        /// Key identifier and the 256-bit external key.
        Startup([u8; 16], [u8; 32]),
    }

    /// A Windows 10 style BitLocker volume (AES-128-XTS) holding `plain`
    /// decrypted. The metadata blocks and the boot sector copy go at the
    /// given offsets, which must hold zeros in `plain` (as BitLocker's
    /// reserved files do).
    pub(crate) fn build(plain: &[u8], metas: [usize; 3], header_at: usize, prots: &[Prot]) -> Vec<u8> {
        let len = plain.len();
        let header_len = 16 * 512;
        let (fvek, vmk) = ([0x11u8; 32], [0x33u8; 32]);
        let mut vmk_pt = vec![44, 0, 0, 0, 1, 0, 0, 0, 0, 0x20, 0, 0];
        vmk_pt.extend(vmk);
        let mut fvek_pt = vec![44, 0, 0, 0, 1, 0, 0, 0, 4, 0x80, 0, 0];
        fvek_pt.extend(fvek);
        let mut es = entry(7, 2, &"LAB-PC E: 2026-11-09\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>());
        for (n, pr) in prots.iter().enumerate() {
            let salt = [0x20 + n as u8; 16];
            let mut stretch_d = 0x1000u32.to_le_bytes().to_vec();
            stretch_d.extend(salt);
            let (id, kind, key, stretched) = match pr {
                Prot::Password(pw) => {
                    let w: Vec<u8> = pw.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
                    ([0xA0 + n as u8; 16], 0x2000u16, stretch(&sha256(&sha256(&w)), &salt), true)
                }
                Prot::Recovery(rp) => ([0xA0 + n as u8; 16], 0x0800, stretch(&sha256(&recovery_key(rp).unwrap()), &salt), true),
                Prot::Startup(id, k) => (*id, 0x0200, *k, false),
            };
            let mut props = if stretched { entry(0, 3, &stretch_d) } else { vec![] };
            props.extend(entry(0, 5, &seal(&key, [5 + n as u8; 12], &vmk_pt)));
            let mut d = id.to_vec();
            d.extend(0x01DB_0000_0000_0000u64.to_le_bytes());
            d.extend(0u16.to_le_bytes());
            d.extend(kind.to_le_bytes());
            d.extend(props);
            es.extend(entry(2, 8, &d));
        }
        es.extend(entry(3, 5, &seal(&vmk, [0x40; 12], &fvek_pt)));
        let mut meta = vec![0u8; 48];
        meta[0..4].copy_from_slice(&((48 + es.len()) as u32).to_le_bytes());
        meta[4] = 1;
        meta[8] = 48;
        meta[16..32].copy_from_slice(&[0x77; 16]);
        meta[36..40].copy_from_slice(&0x8004u32.to_le_bytes());
        meta[40..48].copy_from_slice(&0x01DB_0000_0000_0000u64.to_le_bytes());
        meta.extend(es);

        let k1 = Cipher::new(&fvek[..16]).unwrap();
        let k2 = Cipher::new(&fvek[16..]).unwrap();
        let mut disk = vec![0u8; len];
        for x in (0..len).step_by(512) {
            if x < header_len {
                let mut s = plain[x..x + 512].to_vec();
                xts_encrypt(&k1, &k2, ((header_at + x) / 512) as u64, &mut s);
                disk[header_at + x..header_at + x + 512].copy_from_slice(&s);
            } else if !(header_at..header_at + header_len).contains(&x) {
                let mut s = plain[x..x + 512].to_vec();
                xts_encrypt(&k1, &k2, (x / 512) as u64, &mut s);
                disk[x..x + 512].copy_from_slice(&s);
            }
        }
        disk[0..512].fill(0);
        disk[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        disk[3..11].copy_from_slice(b"-FVE-FS-");
        disk[11..13].copy_from_slice(&512u16.to_le_bytes());
        disk[13] = 8;
        disk[160..176].copy_from_slice(&GUID);
        for (i, m) in metas.into_iter().enumerate() {
            disk[176 + i * 8..184 + i * 8].copy_from_slice(&(m as u64).to_le_bytes());
            let mut b = vec![0u8; 64];
            b[0..8].copy_from_slice(b"-FVE-FS-");
            b[10] = 2;
            b[12] = 4;
            b[14] = 4;
            b[16..24].copy_from_slice(&(len as u64).to_le_bytes());
            b[28..32].copy_from_slice(&16u32.to_le_bytes());
            for (j, o) in metas.into_iter().enumerate() {
                b[32 + j * 8..40 + j * 8].copy_from_slice(&(o as u64).to_le_bytes());
            }
            b[56..64].copy_from_slice(&(header_at as u64).to_le_bytes());
            b.extend(&meta);
            disk[m..m + b.len()].copy_from_slice(&b);
        }
        disk[510] = 0x55;
        disk[511] = 0xAA;
        disk
    }

    /// The startup key file for `Prot::Startup(id, key)`.
    pub(crate) fn bek(id: [u8; 16], key: [u8; 32]) -> Vec<u8> {
        let mut kd = 0x2002u32.to_le_bytes().to_vec();
        kd.extend(key);
        let mut props = entry(0, 2, &"ExternalKey\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>());
        props.extend(entry(0, 1, &kd));
        let mut d = id.to_vec();
        d.extend(0x01DB_0000_0000_0000u64.to_le_bytes());
        d.extend(props);
        let e = entry(6, 9, &d);
        let mut h = vec![0u8; 48];
        h[0..4].copy_from_slice(&((48 + e.len()) as u32).to_le_bytes());
        h[4] = 1;
        h[8] = 48;
        h[12..16].copy_from_slice(&((48 + e.len()) as u32).to_le_bytes());
        h[16..32].copy_from_slice(&[0x77; 16]);
        h[36..40].copy_from_slice(&0x2002u32.to_le_bytes());
        h.extend(e);
        h
    }

    /// A volume made here, read back through the metadata, the unlock and
    /// the reader.
    #[test]
    fn synthetic_volume_round_trips() {
        const LEN: usize = 4 << 20;
        const MB: usize = 1 << 20;
        let header_at = MB + 64 * 1024;
        let mut plain: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8 ^ (i / 512) as u8).collect();
        plain[3..11].copy_from_slice(b"NTFS    ");
        plain[510] = 0x55;
        plain[511] = 0xAA;
        for m in [MB, 2 * MB, 3 * MB] {
            plain[m..m + 64 * 1024].fill(0);
        }
        plain[header_at..header_at + 8192].fill(0);
        let disk = build(&plain, [MB, 2 * MB, 3 * MB], header_at, &[Prot::Password("Lab-Pa55")]);

        let mut c = std::io::Cursor::new(&disk);
        assert!(is_bitlocker(&disk[..512]));
        let i = info(&mut c, LEN as u64).unwrap();
        assert_eq!((i.method_label.as_str(), i.header_offset, i.header_size), ("AES-128-XTS", header_at as u64, 8192));
        assert_eq!(i.protectors.len(), 1);
        assert_eq!(i.protectors[0].kind, "Password");
        assert_eq!(i.description, "LAB-PC E: 2026-11-09");
        assert!(unlock(&i, &Secret::RecoveryPassword("1")).unwrap_err().contains("no recovery password protector"));
        assert!(unlock(&i, &Secret::ClearKey).is_err());
        let k = unlock(&i, &Secret::Password("Lab-Pa55")).unwrap();
        assert_eq!(k.fvek, hex(&[0x11u8; 32]));
        let mut r = BdeReader::new(std::io::Cursor::new(&disk), LEN as u64, &k).unwrap();
        let mut got = vec![];
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), LEN);
        assert!(got == plain, "first difference at {:?}", got.iter().zip(&plain).position(|(a, b)| a != b));
        // Reads that start and end inside sectors.
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut b = [0u8; 3000];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b[..], &plain[1000..4000]);
    }

    pub(crate) const FIXTURE_PASSWORD: &str = "Lab-Pa55";
    pub(crate) const FIXTURE_RECOVERY: &str = "111111-222222-333333-444444-555555-666666-000077-123453";
    pub(crate) const FIXTURE_KEY_ID: [u8; 16] = [0xB0, 0x0B, 0x1E, 0x55, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
    pub(crate) const FIXTURE_KEY: [u8; 32] = [0x5C; 32];

    fn fixtures() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
    }

    /// Writes tests/fixtures/bitlocker-xts.img and its .BEK: testfs1-win
    /// (NTFS with carving ground truth) in a BitLocker volume with a
    /// password, a recovery password and a startup key protector; the
    /// metadata sits in a 256 KiB tail after the NTFS volume.
    /// Run: cargo test -p kokino-image make_bitlocker_fixture -- --ignored
    #[test]
    #[ignore]
    fn make_bitlocker_fixture() {
        let mut plain = std::fs::read(fixtures().join("testfs1-win")).unwrap();
        let ntfs = plain.len();
        plain.resize(ntfs + 256 * 1024, 0);
        let disk = build(&plain, [ntfs, ntfs + 64 * 1024, ntfs + 128 * 1024], ntfs + 192 * 1024,
            &[Prot::Password(FIXTURE_PASSWORD), Prot::Recovery(FIXTURE_RECOVERY), Prot::Startup(FIXTURE_KEY_ID, FIXTURE_KEY)]);
        std::fs::write(fixtures().join("bitlocker-xts.img"), disk).unwrap();
        std::fs::write(fixtures().join("bitlocker-xts.BEK"), bek(FIXTURE_KEY_ID, FIXTURE_KEY)).unwrap();
    }

    /// The committed fixture opens with each of its three protectors, to
    /// the same key, and decrypts to testfs1-win.
    #[test]
    fn fixture_unlocks_every_way() {
        let Ok(disk) = std::fs::read(fixtures().join("bitlocker-xts.img")) else { return };
        let i = info(&mut std::io::Cursor::new(&disk), disk.len() as u64).unwrap();
        assert_eq!(i.protectors.iter().map(|p| p.kind.as_str()).collect::<Vec<_>>(), ["Password", "Recovery password", "Startup key"]);
        let b = std::fs::read(fixtures().join("bitlocker-xts.BEK")).unwrap();
        assert_eq!(b.len(), 156, "the size Windows writes");
        let k = unlock(&i, &Secret::StartupKey(&b)).unwrap();
        assert_eq!(k.protector, "Startup key");
        let mut other = b.clone();
        other[56] ^= 1; // another key identifier
        assert!(unlock(&i, &Secret::StartupKey(&other)).unwrap_err().contains("another volume"));
        assert!(unlock(&i, &Secret::StartupKey(b"not a key")).is_err());
        assert_eq!(unlock(&i, &Secret::RecoveryPassword(FIXTURE_RECOVERY)).unwrap().fvek, k.fvek);
        let plain = std::fs::read(fixtures().join("testfs1-win")).unwrap();
        let mut r = BdeReader::new(std::io::Cursor::new(&disk), disk.len() as u64, &k).unwrap();
        let mut got = vec![0u8; plain.len()];
        r.read_exact(&mut got).unwrap();
        assert!(got == plain);
    }
}

/// Local validation (dfvfs test data, not in the repository): runs only when
/// `target/validation/dfvfs/bdetogo.raw` is there.
#[cfg(test)]
mod validation {
    use super::*;

    #[test]
    fn bitlocker_to_go_image() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/validation/dfvfs/bdetogo.raw");
        let Ok(mut f) = std::fs::File::open(&p) else { return };
        let len = f.metadata().unwrap().len();
        let i = info(&mut f, len).unwrap();
        eprintln!("{:#?}", Info { entries: vec![], ..i.clone() });
        for e in &i.entries {
            eprintln!("entry type {:#x} value {:#x} len {}", e.etype, e.vtype, e.data.len());
        }
        assert!(unlock(&i, &Secret::Password("wrong")).is_err());
        let k = unlock(&i, &Secret::Password("bde-TEST")).unwrap();
        eprintln!("{:?}", k.method);
        let mut r = BdeReader::new(f, len, &k).unwrap();
        let mut b = [0u8; 512];
        r.read_exact(&mut b).unwrap();
        eprintln!("{:02x?}", &b[..96]);
        assert_eq!(&b[510..], &[0x55, 0xAA]);
    }
}
