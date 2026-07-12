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

/// A discovered pointer chain: a static base address plus a list of offsets to
/// add-and-dereference at each level to reach the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub base: u64,
    pub offsets: Vec<u64>,
}

/// Read an aligned 64-bit LE pointer at `addr` from an image based at `base`.
fn read_ptr(reader: &dyn ByteReader, base: u64, addr: u64) -> Option<u64> {
    if addr < base {
        return None;
    }
    let off = addr - base;
    let mut buf = [0u8; 8];
    if reader.read_at(off, &mut buf) == 8 {
        Some(u64::from_le_bytes(buf))
    } else {
        None
    }
}

/// Find pointer chains `base_addr → … → target` up to `max_depth` levels deep.
///
/// At each level, every address whose 64-bit value lands in
/// `[node - max_offset, node]` is a candidate parent (offset = value distance);
/// chains that bottom out at a `static_base` (within `static_window` of it) are
/// returned. This is a breadth-first reverse walk — the standard pointer-scan
/// approach — bounded by `max_results` to stay tractable.
#[allow(clippy::too_many_arguments)]
pub fn find_chains(
    reader: &dyn ByteReader,
    image_base: u64,
    target: u64,
    static_base: u64,
    static_window: u64,
    max_offset: u64,
    max_depth: usize,
    max_results: usize,
    progress: &Progress,
) -> Vec<Chain> {
    // Each frontier node: (address, offsets-from-here-to-target reversed).
    let mut frontier: Vec<(u64, Vec<u64>)> = vec![(target, Vec::new())];
    let mut chains = Vec::new();
    progress.set_total(max_depth as u64);

    for depth in 0..max_depth {
        if progress.is_cancelled() || chains.len() >= max_results {
            break;
        }
        // Pointers (whole image) that reference any current frontier node.
        let mut next: Vec<(u64, Vec<u64>)> = Vec::new();
        for (node, tail) in &frontier {
            let hits = find_pointers_to(
                reader,
                image_base,
                *node,
                max_offset,
                8,
                max_results,
                progress,
            );
            for (ptr_addr, off) in hits {
                let mut offsets = vec![off];
                offsets.extend_from_slice(tail);
                // Is this pointer in the static region? -> a complete chain.
                if ptr_addr >= static_base && ptr_addr <= static_base + static_window {
                    chains.push(Chain {
                        base: ptr_addr,
                        offsets: offsets.clone(),
                    });
                    if chains.len() >= max_results {
                        break;
                    }
                }
                if depth + 1 < max_depth {
                    next.push((ptr_addr, offsets));
                }
            }
        }
        progress.set_done(depth as u64 + 1);
        if next.is_empty() {
            break;
        }
        next.truncate(max_results * 4); // keep the frontier bounded
        frontier = next;
    }
    progress.finish();
    chains
}

/// Resolve a chain forward to the address it currently points at, for verifying
/// a chain still works (e.g. after a process restart). At each level we read the
/// 8-byte pointer at the running address and add the next offset; the final
/// result is the target address.
pub fn resolve_chain(reader: &dyn ByteReader, image_base: u64, chain: &Chain) -> Option<u64> {
    let mut addr = chain.base;
    for off in &chain.offsets {
        let v = read_ptr(reader, image_base, addr)?;
        addr = v.wrapping_add(*off);
    }
    Some(addr)
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
    fn one_level_chain() {
        // address 0 (static base) holds the pointer 0x1000; target = 0x1010.
        let d = doc(&0x1000u64.to_le_bytes());
        let chains = find_chains(&d, 0, 0x1010, 0, 0, 0x20, 1, 10, &Progress::default());
        assert_eq!(chains.len(), 1);
        assert_eq!(
            chains[0],
            Chain {
                base: 0,
                offsets: vec![0x10]
            }
        );
        // forward-resolve lands on the target
        assert_eq!(resolve_chain(&d, 0, &chains[0]), Some(0x1010));
    }

    #[test]
    fn two_level_chain() {
        // [0]=0x100 (static base) -> [0x100]=0x2000 -> target 0x2000
        let mut data = vec![0u8; 0x108];
        data[0..8].copy_from_slice(&0x100u64.to_le_bytes());
        data[0x100..0x108].copy_from_slice(&0x2000u64.to_le_bytes());
        let d = doc(&data);
        let chains = find_chains(&d, 0, 0x2000, 0, 0x10, 0, 2, 10, &Progress::default());
        let c = chains
            .iter()
            .find(|c| c.offsets.len() == 2)
            .expect("a 2-level chain");
        assert_eq!(c.base, 0);
        assert_eq!(resolve_chain(&d, 0, c), Some(0x2000));
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
