//! Value scanner — the "Cheat Engine" workflow.
//!
//! Find every offset whose bytes equal a typed value (first scan), then
//! repeatedly *refine* that candidate set as the underlying data changes:
//! keep only the offsets that are now equal to a new value, or that
//! changed / stayed the same / increased / decreased. Works on any
//! [`ByteReader`] — a file, a save game, or (in future) live process memory.

use crate::data::ByteReader;

use super::search::{DataType, Endian};
use super::Progress;

/// A surviving candidate: its offset and the value bytes observed last scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// Refinement predicate applied to each candidate on a re-scan.
#[derive(Clone, Debug)]
pub enum Refine {
    /// Keep candidates now equal to these bytes.
    Eq(Vec<u8>),
    /// Keep candidates whose bytes differ from the previous scan.
    Changed,
    /// Keep candidates whose bytes match the previous scan.
    Unchanged,
    /// Keep candidates whose numeric value rose since the previous scan.
    Increased,
    /// Keep candidates whose numeric value fell since the previous scan.
    Decreased,
    /// Keep candidates now numerically greater than this value.
    GreaterThan(Vec<u8>),
    /// Keep candidates now numerically less than this value.
    LessThan(Vec<u8>),
}

const SCAN_WIN: usize = 1 << 20;

/// First scan: every offset whose bytes equal `needle`. `align` steps the scan
/// (1 = byte-aligned, or the type width for aligned-only matches). Results are
/// capped at `max` to bound memory.
pub fn first_scan(
    reader: &dyn ByteReader,
    needle: &[u8],
    align: u64,
    max: usize,
    progress: &Progress,
) -> Vec<Match> {
    let mut out = Vec::new();
    if needle.is_empty() {
        return out;
    }
    let total = reader.len();
    progress.set_total(total);
    let nlen = needle.len();
    let align = align.max(1);
    let overlap = nlen as u64 - 1;
    let mut buf = vec![0u8; SCAN_WIN + overlap as usize];
    let mut pos = 0u64;
    while pos < total {
        if progress.is_cancelled() || out.len() >= max {
            break;
        }
        let want = ((total - pos) as usize).min(buf.len());
        let n = reader.read_at(pos, &mut buf[..want]);
        if (n as u64) < nlen as u64 {
            break;
        }
        let hay = &buf[..n];
        let mut i = 0usize;
        while i + nlen <= hay.len() {
            let abs = pos + i as u64;
            if abs % align == 0 && &hay[i..i + nlen] == needle {
                out.push(Match {
                    offset: abs,
                    bytes: needle.to_vec(),
                });
                if out.len() >= max {
                    break;
                }
            }
            i += 1;
        }
        pos += (n as u64).saturating_sub(overlap).max(1);
        progress.set_done(pos);
    }
    progress.finish();
    out
}

/// Re-scan: apply `refine` to each previous candidate, reading the data again.
/// `ty`/`endian` interpret bytes numerically for the comparative predicates.
pub fn refine(
    reader: &dyn ByteReader,
    prev: &[Match],
    refine: &Refine,
    ty: DataType,
    endian: Endian,
) -> Vec<Match> {
    let mut out = Vec::with_capacity(prev.len());
    for m in prev {
        let width = m.bytes.len();
        let mut cur = vec![0u8; width];
        if reader.read_at(m.offset, &mut cur) != width {
            continue;
        }
        let keep = match refine {
            Refine::Eq(n) => &cur == n,
            Refine::Changed => cur != m.bytes,
            Refine::Unchanged => cur == m.bytes,
            Refine::Increased => num(&cur, ty, endian) > num(&m.bytes, ty, endian),
            Refine::Decreased => num(&cur, ty, endian) < num(&m.bytes, ty, endian),
            Refine::GreaterThan(n) => num(&cur, ty, endian) > num(n, ty, endian),
            Refine::LessThan(n) => num(&cur, ty, endian) < num(n, ty, endian),
        };
        if keep {
            out.push(Match {
                offset: m.offset,
                bytes: cur,
            });
        }
    }
    out
}

/// Interpret bytes as a number for comparisons. Returns NaN-safe ordering via
/// `f64`; unknown/short inputs sort as the smallest value.
fn num(bytes: &[u8], ty: DataType, endian: Endian) -> f64 {
    let le = endian == Endian::Little;
    let rd = |n: usize| -> Option<u64> {
        if bytes.len() < n {
            return None;
        }
        let mut v = 0u64;
        if le {
            for i in (0..n).rev() {
                v = (v << 8) | bytes[i] as u64;
            }
        } else {
            for &b in bytes.iter().take(n) {
                v = (v << 8) | b as u64;
            }
        }
        Some(v)
    };
    let sx = |v: u64, n: usize| -> i64 {
        let shift = 64 - n * 8;
        ((v << shift) as i64) >> shift
    };
    let val = match ty {
        DataType::I8 => rd(1).map(|v| sx(v, 1) as f64),
        DataType::I16 => rd(2).map(|v| sx(v, 2) as f64),
        DataType::I32 => rd(4).map(|v| sx(v, 4) as f64),
        DataType::I64 => rd(8).map(|v| sx(v, 8) as f64),
        DataType::F32 => rd(4).map(|v| f32::from_bits(v as u32) as f64),
        DataType::F64 => rd(8).map(f64::from_bits),
        // Text/hex/utf16 are not numerically ordered; fall back to first byte.
        _ => bytes.first().map(|&b| b as f64),
    };
    val.unwrap_or(f64::NEG_INFINITY)
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
    fn first_scan_finds_all() {
        // three little-endian u32 100s among noise
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(&100u32.to_le_bytes());
            data.extend_from_slice(&[0xAA, 0xBB]);
        }
        let d = doc(&data);
        let m = first_scan(&d, &100u32.to_le_bytes(), 1, 1000, &Progress::default());
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].offset, 0);
        assert_eq!(m[1].offset, 6);
    }

    #[test]
    fn refine_equal_narrows() {
        let data = [10u8, 20, 10, 30, 10];
        let d = doc(&data);
        let m = first_scan(&d, &[10], 1, 1000, &Progress::default());
        assert_eq!(m.len(), 3);
        // narrow to those equal to 10 still (all), then to 20 (none of the prev)
        let n = refine(&d, &m, &Refine::Eq(vec![10]), DataType::I8, Endian::Little);
        assert_eq!(n.len(), 3);
    }

    #[test]
    fn refine_increased_after_edit() {
        let mut d = doc(&[5u8, 5, 5, 5]);
        let m = first_scan(&d, &[5], 1, 1000, &Progress::default());
        assert_eq!(m.len(), 4);
        // bump bytes at offset 1 and 3
        d.overwrite(1, &[9]);
        d.overwrite(3, &[9]);
        let up = refine(&d, &m, &Refine::Increased, DataType::I8, Endian::Little);
        assert_eq!(up.iter().map(|x| x.offset).collect::<Vec<_>>(), vec![1, 3]);
        // and the surviving candidates record the NEW value
        assert_eq!(up[0].bytes, vec![9]);
    }

    #[test]
    fn refine_changed_and_unchanged() {
        let mut d = doc(&[1u8, 2, 3, 4]);
        let m = first_scan(&d, &[1], 1, 1000, &Progress::default()); // offset 0
        // also include other offsets manually
        let cands = vec![
            Match { offset: 0, bytes: vec![1] },
            Match { offset: 1, bytes: vec![2] },
        ];
        let _ = m;
        d.overwrite(0, &[9]); // changed
        let changed = refine(&d, &cands, &Refine::Changed, DataType::I8, Endian::Little);
        assert_eq!(changed.iter().map(|x| x.offset).collect::<Vec<_>>(), vec![0]);
        let unchanged = refine(&d, &cands, &Refine::Unchanged, DataType::I8, Endian::Little);
        assert_eq!(unchanged.iter().map(|x| x.offset).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn aligned_scan_skips_unaligned() {
        // value at offset 1 (unaligned for width 2) should be skipped when align=2
        let data = [0u8, 0x2A, 0x00];
        let d = doc(&data);
        let needle = 0x002Au16.to_le_bytes(); // [0x2A, 0x00]
        let unaligned = first_scan(&d, &needle, 1, 1000, &Progress::default());
        assert_eq!(unaligned.len(), 1);
        assert_eq!(unaligned[0].offset, 1);
        let aligned = first_scan(&d, &needle, 2, 1000, &Progress::default());
        assert!(aligned.is_empty());
    }

    #[test]
    fn results_are_capped() {
        let d = doc(&vec![7u8; 1000]);
        let m = first_scan(&d, &[7], 1, 10, &Progress::default());
        assert_eq!(m.len(), 10);
    }
}
