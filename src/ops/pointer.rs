//! Pointer scanning: find pointer values that reference an address.
//!
//! Given a memory image (a file dump, or live process memory via `ProcessSource`)
//! where the byte at document offset `o` lives at address `image_base + o`, find
//! every aligned 64-bit little-endian value that points into
//! `[target - max_offset, target]`. Each hit is `(pointer_address, offset)` where
//! `offset = target - value` — i.e. "this address holds a pointer that lands
//! `offset` bytes before `target`." Chaining these is the basis of pointer maps.

use crate::data::ByteReader;

use super::Progress;

const WIN: usize = 1 << 20;

/// Find 64-bit LE pointers to `[target - max_offset, target]`. `align` steps the
/// scan over addresses (8 for natural 64-bit alignment, 1 for unaligned).
/// Results are capped at `max`.
pub fn find_pointers_to(
    reader: &dyn ByteReader,
    image_base: u64,
    target: u64,
    max_offset: u64,
    align: u64,
    max: usize,
    progress: &Progress,
) -> Vec<(u64, u64)> {
    let total = reader.len();
    progress.set_total(total);
    let align = align.max(1);
    let lo = target.saturating_sub(max_offset);
    let mut out = Vec::new();
    let mut buf = vec![0u8; WIN + 8];
    let mut pos = 0u64;
    while pos + 8 <= total {
        if progress.is_cancelled() || out.len() >= max {
            break;
        }
        let want = ((total - pos) as usize).min(buf.len());
        let n = reader.read_at(pos, &mut buf[..want]);
        if n < 8 {
            break;
        }
        let mut i = 0;
        while i + 8 <= n {
            if (pos + i as u64) % align == 0 {
                let v = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                if v >= lo && v <= target {
                    out.push((image_base + pos + i as u64, target - v));
                    if out.len() >= max {
                        break;
                    }
                }
            }
            i += 1;
        }
        // keep a 7-byte overlap so a pointer on the window edge isn't missed
        pos += (n as u64).saturating_sub(7).max(1);
        progress.set_done(pos);
    }
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
    fn finds_aligned_pointers_within_offset() {
        // offset 0:  value 0x1000        -> points exactly at target (offset 0)
        // offset 8:  value 0x0FF8        -> 8 bytes before target (offset 8)
        // offset 16: value 0xDEAD        -> out of range, ignored
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x0FF8u64.to_le_bytes());
        data.extend_from_slice(&0xDEADu64.to_le_bytes());
        let d = doc(&data);

        let hits = find_pointers_to(&d, 0, 0x1000, 16, 8, 100, &Progress::default());
        assert_eq!(hits, vec![(0, 0), (8, 8)]);
    }

    #[test]
    fn image_base_offsets_addresses() {
        let data = 0x4020u64.to_le_bytes();
        let d = doc(&data);
        // image_base shifts the reported pointer address
        let hits = find_pointers_to(&d, 0x140000000, 0x4020, 0, 8, 10, &Progress::default());
        assert_eq!(hits, vec![(0x140000000, 0)]);
    }

    #[test]
    fn alignment_skips_unaligned() {
        // a pointer placed at offset 1 (unaligned) is skipped when align = 8
        let mut data = vec![0u8; 16];
        data[1..9].copy_from_slice(&0x2000u64.to_le_bytes());
        let d = doc(&data);
        assert!(find_pointers_to(&d, 0, 0x2000, 0, 8, 10, &Progress::default()).is_empty());
        // ...but found with align = 1
        let un = find_pointers_to(&d, 0, 0x2000, 0, 1, 10, &Progress::default());
        assert_eq!(un, vec![(1, 0)]);
    }

    #[test]
    fn respects_cap() {
        // many identical pointers; cap the results
        let mut data = Vec::new();
        for _ in 0..50 {
            data.extend_from_slice(&0x3000u64.to_le_bytes());
        }
        let d = doc(&data);
        let hits = find_pointers_to(&d, 0, 0x3000, 0, 8, 5, &Progress::default());
        assert_eq!(hits.len(), 5);
    }
}
