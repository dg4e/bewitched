//! Signature scanner — a small "binwalk": locate embedded file formats and
//! well-known cryptographic constants by their magic byte sequences.

use crate::data::ByteReader;

use super::Progress;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    FileFormat,
    Compression,
    Crypto,
    Executable,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::FileFormat => "format",
            Category::Compression => "compressed",
            Category::Crypto => "crypto",
            Category::Executable => "executable",
        }
    }
}

struct SigDef {
    magic: &'static [u8],
    name: &'static str,
    category: Category,
}

#[derive(Clone, Debug)]
pub struct Hit {
    pub offset: u64,
    pub name: &'static str,
    pub category: Category,
}

// AES S-box (first 32 of 256 bytes) — a strong fingerprint for AES code/tables.
const AES_SBOX_PREFIX: &[u8] = &[
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
];

// SHA-256 round constants K[0..4], big-endian.
const SHA256_K_PREFIX: &[u8] = &[
    0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
];

const SIGS: &[SigDef] = &[
    // File formats
    SigDef { magic: b"\x89PNG\r\n\x1a\n", name: "PNG image", category: Category::FileFormat },
    SigDef { magic: b"GIF87a", name: "GIF image", category: Category::FileFormat },
    SigDef { magic: b"GIF89a", name: "GIF image", category: Category::FileFormat },
    SigDef { magic: b"\xff\xd8\xff", name: "JPEG image", category: Category::FileFormat },
    SigDef { magic: b"BM", name: "BMP image", category: Category::FileFormat },
    SigDef { magic: b"%PDF-", name: "PDF document", category: Category::FileFormat },
    SigDef { magic: b"RIFF", name: "RIFF (WAV/AVI)", category: Category::FileFormat },
    SigDef { magic: b"OggS", name: "Ogg stream", category: Category::FileFormat },
    SigDef { magic: b"fLaC", name: "FLAC audio", category: Category::FileFormat },
    SigDef { magic: b"SQLite format 3\x00", name: "SQLite database", category: Category::FileFormat },
    SigDef { magic: b"\x1aE\xdf\xa3", name: "Matroska/WebM", category: Category::FileFormat },
    // Compression / archives
    SigDef { magic: b"PK\x03\x04", name: "ZIP archive", category: Category::Compression },
    SigDef { magic: b"\x1f\x8b", name: "gzip", category: Category::Compression },
    SigDef { magic: b"BZh", name: "bzip2", category: Category::Compression },
    SigDef { magic: b"\xfd7zXZ\x00", name: "xz", category: Category::Compression },
    SigDef { magic: b"\x28\xb5\x2f\xfd", name: "zstd", category: Category::Compression },
    SigDef { magic: b"Rar!\x1a\x07", name: "RAR archive", category: Category::Compression },
    SigDef { magic: b"7z\xbc\xaf\x27\x1c", name: "7-Zip archive", category: Category::Compression },
    // Executables
    SigDef { magic: b"\x7fELF", name: "ELF executable", category: Category::Executable },
    SigDef { magic: b"MZ", name: "DOS/PE executable", category: Category::Executable },
    SigDef { magic: b"\xca\xfe\xba\xbe", name: "Java class / Mach-O FAT", category: Category::Executable },
    SigDef { magic: b"\xfe\xed\xfa\xce", name: "Mach-O (32-bit)", category: Category::Executable },
    SigDef { magic: b"\xfe\xed\xfa\xcf", name: "Mach-O (64-bit)", category: Category::Executable },
    SigDef { magic: b"\xcf\xfa\xed\xfe", name: "Mach-O (64-bit LE)", category: Category::Executable },
    // Crypto constants
    SigDef { magic: AES_SBOX_PREFIX, name: "AES S-box", category: Category::Crypto },
    SigDef { magic: SHA256_K_PREFIX, name: "SHA-256 constants", category: Category::Crypto },
];

const WIN: usize = 1 << 20;

/// Scan `[offset, offset+len)` for known signatures. Single streaming pass,
/// bucketed by first magic byte. Results capped at `max`.
pub fn scan(
    reader: &dyn ByteReader,
    offset: u64,
    len: u64,
    max: usize,
    progress: &Progress,
) -> Vec<Hit> {
    // Bucket signatures by their first byte for a cheap inner check.
    let mut by_first: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    let mut max_sig = 0usize;
    for (i, s) in SIGS.iter().enumerate() {
        by_first[s.magic[0] as usize].push(i);
        max_sig = max_sig.max(s.magic.len());
    }

    let end = (offset + len).min(reader.len());
    progress.set_total(end.saturating_sub(offset));
    let overlap = max_sig.saturating_sub(1) as u64;
    let mut buf = vec![0u8; WIN + overlap as usize];
    let mut out = Vec::new();
    let mut pos = offset;

    while pos < end {
        if progress.is_cancelled() || out.len() >= max {
            break;
        }
        let want = ((end - pos) as usize).min(buf.len());
        let n = reader.read_at(pos, &mut buf[..want]);
        if n == 0 {
            break;
        }
        let hay = &buf[..n];
        for i in 0..n {
            if out.len() >= max {
                break;
            }
            for &si in &by_first[hay[i] as usize] {
                let m = SIGS[si].magic;
                if i + m.len() <= hay.len() && &hay[i..i + m.len()] == m {
                    out.push(Hit {
                        offset: pos + i as u64,
                        name: SIGS[si].name,
                        category: SIGS[si].category,
                    });
                    if out.len() >= max {
                        break;
                    }
                }
            }
        }
        // advance, preserving overlap so a signature on the boundary is caught
        pos += (n as u64).saturating_sub(overlap).max(1);
        progress.set_done(pos.saturating_sub(offset));
    }
    out.sort_by_key(|h| h.offset);
    out.dedup_by_key(|h| (h.offset, h.name));
    progress.finish();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn doc(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    #[test]
    fn finds_png_and_zip() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(b"PK\x03\x04");
        let d = doc(&data);
        let hits = scan(&d, 0, d.len(), 100, &Progress::default());
        assert!(hits.iter().any(|h| h.name == "PNG image" && h.offset == 8));
        assert!(hits.iter().any(|h| h.name == "ZIP archive"));
    }

    #[test]
    fn detects_aes_sbox() {
        let mut data = vec![0xAA; 32];
        data.extend_from_slice(AES_SBOX_PREFIX);
        let d = doc(&data);
        let hits = scan(&d, 0, d.len(), 100, &Progress::default());
        let h = hits.iter().find(|h| h.name == "AES S-box").unwrap();
        assert_eq!(h.offset, 32);
        assert_eq!(h.category, Category::Crypto);
    }

    #[test]
    fn empty_input_no_hits() {
        let d = doc(b"");
        assert!(scan(&d, 0, 0, 100, &Progress::default()).is_empty());
    }

    #[test]
    fn boundary_signature_caught() {
        // place a PNG header straddling the 1 MiB window boundary
        let win = 1usize << 20;
        let mut data = vec![0u8; win + 32];
        let pos = win - 3;
        data[pos..pos + 8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        let d = doc(&data);
        let hits = scan(&d, 0, d.len(), 100, &Progress::default());
        assert!(hits.iter().any(|h| h.offset == pos as u64 && h.name == "PNG image"));
    }

    #[test]
    fn results_capped() {
        let mut data = Vec::new();
        for _ in 0..50 {
            data.extend_from_slice(b"MZ\x00\x00");
        }
        let d = doc(&data);
        let hits = scan(&d, 0, d.len(), 5, &Progress::default());
        assert_eq!(hits.len(), 5);
    }
}
