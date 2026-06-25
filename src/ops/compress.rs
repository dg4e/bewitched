//! Compression / decompression of a byte range (gzip, zlib, raw deflate).
//!
//! Pure Rust via `flate2`'s `miniz_oxide` backend — no C dependency. Handy for
//! decompressing embedded blobs found while analyzing firmware/containers.

use std::io::{Read, Write};

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::Compression;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Codec {
    Gzip,
    Zlib,
    Deflate,
}

impl Codec {
    pub fn name(self) -> &'static str {
        match self {
            Codec::Gzip => "gzip",
            Codec::Zlib => "zlib",
            Codec::Deflate => "deflate",
        }
    }

    pub fn parse(s: &str) -> Option<Codec> {
        match s.to_lowercase().as_str() {
            "gzip" | "gz" => Some(Codec::Gzip),
            "zlib" => Some(Codec::Zlib),
            "deflate" | "raw" => Some(Codec::Deflate),
            _ => None,
        }
    }
}

/// Sniff a header to guess the codec (gzip and zlib only — raw deflate is
/// headerless). Returns `None` if nothing recognizable is at the front.
pub fn detect(data: &[u8]) -> Option<Codec> {
    if data.len() < 2 {
        return None;
    }
    if data[0] == 0x1f && data[1] == 0x8b {
        return Some(Codec::Gzip);
    }
    // zlib: CM=8 in low nibble of byte 0, and (CMF<<8 | FLG) % 31 == 0
    if (data[0] & 0x0f) == 8
        && (data[0] & 0xf0) <= 0x70
        && ((data[0] as u16) << 8 | data[1] as u16) % 31 == 0
    {
        return Some(Codec::Zlib);
    }
    None
}

pub fn decompress(data: &[u8], codec: Codec) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let res = match codec {
        Codec::Gzip => GzDecoder::new(data).read_to_end(&mut out),
        Codec::Zlib => ZlibDecoder::new(data).read_to_end(&mut out),
        Codec::Deflate => DeflateDecoder::new(data).read_to_end(&mut out),
    };
    res.map_err(|e| format!("decompress ({}) failed: {e}", codec.name()))?;
    Ok(out)
}

pub fn compress(data: &[u8], codec: Codec, level: u32) -> Vec<u8> {
    let c = Compression::new(level.min(9));
    match codec {
        Codec::Gzip => {
            let mut e = GzEncoder::new(Vec::new(), c);
            let _ = e.write_all(data);
            e.finish().unwrap_or_default()
        }
        Codec::Zlib => {
            let mut e = ZlibEncoder::new(Vec::new(), c);
            let _ = e.write_all(data);
            e.finish().unwrap_or_default()
        }
        Codec::Deflate => {
            let mut e = DeflateEncoder::new(Vec::new(), c);
            let _ = e.write_all(data);
            e.finish().unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"the quick brown fox jumps over the lazy dog, again and again and again";

    #[test]
    fn roundtrip_all_codecs() {
        for codec in [Codec::Gzip, Codec::Zlib, Codec::Deflate] {
            let comp = compress(SAMPLE, codec, 6);
            let back = decompress(&comp, codec).unwrap();
            assert_eq!(back, SAMPLE, "{codec:?} roundtrip mismatch");
        }
        // a large, repetitive payload definitely shrinks
        let big = SAMPLE.repeat(100);
        let comp = compress(&big, Codec::Zlib, 9);
        assert!(comp.len() < big.len() / 10);
        assert_eq!(decompress(&comp, Codec::Zlib).unwrap(), big);
    }

    #[test]
    fn detect_headers() {
        assert_eq!(detect(&compress(SAMPLE, Codec::Gzip, 6)), Some(Codec::Gzip));
        assert_eq!(detect(&compress(SAMPLE, Codec::Zlib, 6)), Some(Codec::Zlib));
        // raw deflate has no header -> not detected
        assert_eq!(detect(&compress(SAMPLE, Codec::Deflate, 6)), None);
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"not compressed"), None);
    }

    #[test]
    fn decompress_garbage_errors() {
        assert!(decompress(b"\x1f\x8b not really gzip", Codec::Gzip).is_err());
    }

    #[test]
    fn parse_codec_names() {
        assert_eq!(Codec::parse("gz"), Some(Codec::Gzip));
        assert_eq!(Codec::parse("ZLIB"), Some(Codec::Zlib));
        assert_eq!(Codec::parse("raw"), Some(Codec::Deflate));
        assert_eq!(Codec::parse("lz4"), None);
    }
}
