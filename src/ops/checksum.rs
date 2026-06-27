//! Checksums, CRCs and cryptographic digests over a document range.

use crate::data::ByteReader;
use md5::Digest as _;

use super::Progress;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Algo {
    Checksum8,
    Checksum16,
    Checksum32,
    Adler32,
    Crc16,
    Crc32,
    Crc64,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    pub const ALL: &'static [Algo] = &[
        Algo::Checksum8,
        Algo::Checksum16,
        Algo::Checksum32,
        Algo::Adler32,
        Algo::Crc16,
        Algo::Crc32,
        Algo::Crc64,
        Algo::Md5,
        Algo::Sha1,
        Algo::Sha256,
        Algo::Sha512,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algo::Checksum8 => "Checksum-8",
            Algo::Checksum16 => "Checksum-16",
            Algo::Checksum32 => "Checksum-32",
            Algo::Adler32 => "Adler-32",
            Algo::Crc16 => "CRC-16/ARC",
            Algo::Crc32 => "CRC-32",
            Algo::Crc64 => "CRC-64/XZ",
            Algo::Md5 => "MD5",
            Algo::Sha1 => "SHA-1",
            Algo::Sha256 => "SHA-256",
            Algo::Sha512 => "SHA-512",
        }
    }
}

/// Streaming digest engine that can be fed chunks.
enum Engine {
    Sum8(u8),
    Sum16(u16),
    Sum32(u32),
    Adler(adler::Adler32),
    Crc16(crc::Digest<'static, u16>),
    Crc32(crc32fast::Hasher),
    Crc64(crc::Digest<'static, u64>),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

static CRC16_ARC: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_ARC);
static CRC64_XZ: crc::Crc<u64> = crc::Crc::<u64>::new(&crc::CRC_64_XZ);

impl Engine {
    fn new(algo: Algo) -> Self {
        match algo {
            Algo::Checksum8 => Engine::Sum8(0),
            Algo::Checksum16 => Engine::Sum16(0),
            Algo::Checksum32 => Engine::Sum32(0),
            Algo::Adler32 => Engine::Adler(adler::Adler32::new()),
            Algo::Crc16 => Engine::Crc16(CRC16_ARC.digest()),
            Algo::Crc32 => Engine::Crc32(crc32fast::Hasher::new()),
            Algo::Crc64 => Engine::Crc64(CRC64_XZ.digest()),
            Algo::Md5 => Engine::Md5(md5::Md5::new()),
            Algo::Sha1 => Engine::Sha1(sha1::Sha1::new()),
            Algo::Sha256 => Engine::Sha256(sha2::Sha256::new()),
            Algo::Sha512 => Engine::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Engine::Sum8(s) => {
                for &b in data {
                    *s = s.wrapping_add(b);
                }
            }
            Engine::Sum16(s) => {
                for &b in data {
                    *s = s.wrapping_add(b as u16);
                }
            }
            Engine::Sum32(s) => {
                for &b in data {
                    *s = s.wrapping_add(b as u32);
                }
            }
            Engine::Adler(a) => a.write_slice(data),
            Engine::Crc16(d) => d.update(data),
            Engine::Crc32(h) => h.update(data),
            Engine::Crc64(d) => d.update(data),
            Engine::Md5(h) => h.update(data),
            Engine::Sha1(h) => h.update(data),
            Engine::Sha256(h) => h.update(data),
            Engine::Sha512(h) => h.update(data),
        }
    }

    fn finish(self) -> String {
        fn hexstr(b: &[u8]) -> String {
            let mut s = String::with_capacity(b.len() * 2);
            for &x in b {
                s.push_str(&format!("{:02x}", x));
            }
            s
        }
        match self {
            Engine::Sum8(s) => format!("{:02X}", s),
            Engine::Sum16(s) => format!("{:04X}", s),
            Engine::Sum32(s) => format!("{:08X}", s),
            Engine::Adler(a) => format!("{:08X}", a.checksum()),
            Engine::Crc16(d) => format!("{:04X}", d.finalize()),
            Engine::Crc32(h) => format!("{:08X}", h.finalize()),
            Engine::Crc64(d) => format!("{:016X}", d.finalize()),
            Engine::Md5(h) => hexstr(&h.finalize()),
            Engine::Sha1(h) => hexstr(&h.finalize()),
            Engine::Sha256(h) => hexstr(&h.finalize()),
            Engine::Sha512(h) => hexstr(&h.finalize()),
        }
    }
}

/// Compute several algorithms over `[offset, offset+len)` in a single streaming
/// pass. Honors progress/cancel. Returns (algo, hex-string) pairs.
pub fn compute(
    doc: &dyn ByteReader,
    offset: u64,
    len: u64,
    algos: &[Algo],
    progress: &Progress,
) -> Vec<(Algo, String)> {
    let end = (offset + len).min(doc.len());
    progress.set_total(end.saturating_sub(offset));
    let mut engines: Vec<Engine> = algos.iter().map(|a| Engine::new(*a)).collect();
    let mut pos = offset;
    let mut buf = vec![0u8; 1 << 20];
    while pos < end {
        if progress.is_cancelled() {
            break;
        }
        let want = ((end - pos) as usize).min(buf.len());
        let n = doc.read_at(pos, &mut buf[..want]);
        if n == 0 {
            break;
        }
        for e in &mut engines {
            e.update(&buf[..n]);
        }
        pos += n as u64;
        progress.set_done(pos - offset);
    }
    progress.finish();
    algos
        .iter()
        .copied()
        .zip(engines.into_iter().map(|e| e.finish()))
        .collect()
}

/// Parameters of a CRC per the Rocksoft^tm model — lets you compute any CRC
/// (including nonstandard / proprietary ones) by supplying the constants.
#[derive(Clone, Copy, Debug)]
pub struct CrcParams {
    pub width: u32,    // 1..=64
    pub poly: u64,     // generator polynomial (normal form)
    pub init: u64,     // initial register value
    pub refin: bool,   // reflect input bytes
    pub refout: bool,  // reflect the output
    pub xorout: u64,   // final XOR value
}

fn reflect(mut v: u64, bits: u32) -> u64 {
    let mut r = 0u64;
    for _ in 0..bits {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    r
}

/// Compute a custom CRC over `data`. Bit-at-a-time (clear and correct; the inputs
/// here are interactive selections, not gigabytes). Requires `width >= 8`.
pub fn custom_crc(data: &[u8], p: &CrcParams) -> u64 {
    let width = p.width.clamp(8, 64);
    let topbit = 1u64 << (width - 1);
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let mut crc = p.init & mask;
    for &byte in data {
        let b = if p.refin { reflect(byte as u64, 8) } else { byte as u64 };
        // bring the byte into the top 8 bits of the register
        crc ^= (b << (width - 8)) & mask;
        for _ in 0..8 {
            crc = if crc & topbit != 0 {
                ((crc << 1) ^ p.poly) & mask
            } else {
                (crc << 1) & mask
            };
        }
    }
    if p.refout {
        crc = reflect(crc, width);
    }
    (crc ^ p.xorout) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    #[test]
    fn custom_crc_known_vectors() {
        // The standard "123456789" check values for several CRCs.
        let check = b"123456789";
        // CRC-32 (ISO-HDLC): poly 0x04C11DB7, init/xorout 0xFFFFFFFF, reflected
        let crc32 = custom_crc(check, &CrcParams {
            width: 32, poly: 0x04C11DB7, init: 0xFFFFFFFF, refin: true, refout: true, xorout: 0xFFFFFFFF,
        });
        assert_eq!(crc32, 0xCBF43926);
        // CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection
        let crc16 = custom_crc(check, &CrcParams {
            width: 16, poly: 0x1021, init: 0xFFFF, refin: false, refout: false, xorout: 0,
        });
        assert_eq!(crc16, 0x29B1);
        // CRC-8 (SMBus): poly 0x07, init 0, no reflection
        let crc8 = custom_crc(check, &CrcParams {
            width: 8, poly: 0x07, init: 0, refin: false, refout: false, xorout: 0,
        });
        assert_eq!(crc8, 0xF4);
        // CRC-16/ARC: poly 0x8005, reflected — matches our built-in CRC-16
        let arc = custom_crc(check, &CrcParams {
            width: 16, poly: 0x8005, init: 0, refin: true, refout: true, xorout: 0,
        });
        assert_eq!(arc, 0xBB3D);
    }

    #[test]
    fn known_vectors() {
        let doc = Document::from_source(Arc::new(MemSource::new(b"abc".to_vec(), "t")));
        let p = Progress::default();
        let r = compute(
            &doc,
            0,
            doc.len(),
            &[Algo::Md5, Algo::Sha1, Algo::Crc32, Algo::Sha256],
            &p,
        );
        let map: std::collections::HashMap<_, _> = r.into_iter().collect();
        assert_eq!(map[&Algo::Md5], "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(map[&Algo::Sha1], "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            map[&Algo::Sha256],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(map[&Algo::Crc32], "352441C2");
    }

    fn hashes(data: &[u8], algos: &[Algo]) -> std::collections::HashMap<Algo, String> {
        let doc = Document::from_source(Arc::new(MemSource::new(data.to_vec(), "t")));
        compute(&doc, 0, doc.len(), algos, &Progress::default())
            .into_iter()
            .collect()
    }

    #[test]
    fn empty_input_vectors() {
        let m = hashes(b"", &[Algo::Md5, Algo::Sha1, Algo::Crc32, Algo::Sha256]);
        assert_eq!(m[&Algo::Md5], "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(m[&Algo::Sha1], "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(m[&Algo::Crc32], "00000000");
        assert_eq!(
            m[&Algo::Sha256],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha512_and_crc_variants() {
        let m = hashes(b"abc", &[Algo::Sha512, Algo::Crc16, Algo::Crc64, Algo::Adler32]);
        assert_eq!(
            m[&Algo::Sha512],
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // CRC-16/ARC of "abc" = 0x9738
        assert_eq!(m[&Algo::Crc16], "9738");
        // Adler-32 of "abc" = 0x024D0127
        assert_eq!(m[&Algo::Adler32], "024D0127");
    }

    #[test]
    fn simple_checksums_wrap() {
        let m = hashes(&[0xFF, 0x02], &[Algo::Checksum8, Algo::Checksum16]);
        assert_eq!(m[&Algo::Checksum8], "01"); // 0xFF + 0x02 = 0x101 -> 0x01
        assert_eq!(m[&Algo::Checksum16], "0101");
    }

    #[test]
    fn cancel_stops_early() {
        let doc = Document::from_source(Arc::new(MemSource::new(vec![0u8; 1 << 20], "t")));
        let p = Progress::default();
        p.cancel();
        let r = compute(&doc, 0, doc.len(), &[Algo::Sha256], &p);
        // cancelled before processing: result is the digest of zero bytes
        assert_eq!(
            r[0].1,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
