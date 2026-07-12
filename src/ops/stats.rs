//! Byte/character distribution and basic data analysis.

use crate::data::ByteReader;

use super::Progress;

pub struct Stats {
    pub counts: [u64; 256],
    pub total: u64,
    pub entropy: f64,
}

impl Stats {
    pub fn most_common(&self) -> Option<(u8, u64)> {
        self.counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .filter(|(_, &c)| c > 0)
            .map(|(b, &c)| (b as u8, c))
    }

    /// A rough classification hint based on entropy & printable ratio.
    pub fn classify(&self) -> &'static str {
        if self.total == 0 {
            return "empty";
        }
        let printable: u64 = (0x20u8..=0x7e)
            .map(|b| self.counts[b as usize])
            .sum::<u64>()
            + self.counts[b'\t' as usize]
            + self.counts[b'\n' as usize]
            + self.counts[b'\r' as usize];
        let pr = printable as f64 / self.total as f64;
        if self.entropy > 7.5 {
            "compressed / encrypted (high entropy)"
        } else if pr > 0.85 {
            "text"
        } else if self.entropy < 1.0 {
            "uniform / sparse (mostly one value)"
        } else {
            "binary"
        }
    }
}

pub fn analyze(doc: &dyn ByteReader, offset: u64, len: u64, progress: &Progress) -> Stats {
    let end = offset.saturating_add(len).min(doc.len());
    progress.set_total(end.saturating_sub(offset));
    let mut counts = [0u64; 256];
    let mut total = 0u64;
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
        for &b in &buf[..n] {
            counts[b as usize] += 1;
        }
        total += n as u64;
        pos += n as u64;
        progress.set_done(pos - offset);
    }
    progress.finish();

    let mut entropy = 0.0f64;
    if total > 0 {
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / total as f64;
                entropy -= p * p.log2();
            }
        }
    }
    Stats {
        counts,
        total,
        entropy,
    }
}

/// Compute a per-bucket entropy strip across `[offset, offset+len)`, for an
/// overview/"binwalk" style visualization. Each of `buckets` segments is sampled
/// (up to `SAMPLE` bytes from its start) so the strip is cheap even on huge
/// inputs. Values are in bits/byte (0..8).
pub fn entropy_map(
    doc: &dyn ByteReader,
    offset: u64,
    len: u64,
    buckets: usize,
    progress: &Progress,
) -> Vec<f32> {
    const SAMPLE: u64 = 1 << 16;
    let buckets = buckets.max(1);
    let total = offset
        .saturating_add(len)
        .min(doc.len())
        .saturating_sub(offset);
    progress.set_total(buckets as u64);
    let mut out = Vec::with_capacity(buckets);
    if total == 0 {
        return vec![0.0; buckets];
    }
    let step = total / buckets as u64;
    let mut buf = vec![0u8; SAMPLE as usize];
    for b in 0..buckets {
        if progress.is_cancelled() {
            break;
        }
        let bstart = offset + b as u64 * step;
        let bend = if b + 1 == buckets {
            offset + total
        } else {
            bstart + step
        };
        let want = (bend - bstart).min(SAMPLE) as usize;
        let n = doc.read_at(bstart, &mut buf[..want]);
        let mut counts = [0u64; 256];
        for &x in &buf[..n] {
            counts[x as usize] += 1;
        }
        let mut e = 0.0f64;
        if n > 0 {
            for &c in &counts {
                if c > 0 {
                    let p = c as f64 / n as f64;
                    e -= p * p.log2();
                }
            }
        }
        out.push(e as f32);
        progress.set_done(b as u64 + 1);
    }
    progress.finish();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    #[test]
    fn analyze_offset_len_overflow_is_safe() {
        // `offset + len` overflowing u64 must not panic (it did in debug builds);
        // an out-of-range window simply yields nothing.
        let doc = Document::from_source(Arc::new(MemSource::new(vec![0u8; 16], "t")));
        let s = analyze(&doc, u64::MAX - 1, u64::MAX, &Progress::default());
        assert_eq!(s.total, 0);
    }

    #[test]
    fn uniform_zero_entropy() {
        let doc = Document::from_source(Arc::new(MemSource::new(vec![7u8; 100], "t")));
        let s = analyze(&doc, 0, doc.len(), &Progress::default());
        assert_eq!(s.total, 100);
        assert_eq!(s.counts[7], 100);
        assert!(s.entropy.abs() < 1e-9);
        assert_eq!(s.most_common(), Some((7, 100)));
    }

    #[test]
    fn full_byte_range_max_entropy() {
        let data: Vec<u8> = (0..=255u8).collect();
        let doc = Document::from_source(Arc::new(MemSource::new(data, "t")));
        let s = analyze(&doc, 0, doc.len(), &Progress::default());
        assert!((s.entropy - 8.0).abs() < 1e-9);
    }

    fn classify(data: &[u8]) -> &'static str {
        let doc = Document::from_source(Arc::new(MemSource::new(data.to_vec(), "t")));
        analyze(&doc, 0, doc.len(), &Progress::default()).classify()
    }

    #[test]
    fn classification_hints() {
        assert_eq!(classify(b""), "empty");
        assert_eq!(
            classify(b"The quick brown fox jumps over the lazy dog.\n"),
            "text"
        );
        assert_eq!(
            classify(&[0xAAu8; 200]),
            "uniform / sparse (mostly one value)"
        );
        // pseudo-random high-entropy bytes
        let mut data = Vec::new();
        let mut x: u32 = 0x12345678;
        for _ in 0..4096 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((x >> 24) as u8);
        }
        assert_eq!(classify(&data), "compressed / encrypted (high entropy)");
    }

    #[test]
    fn entropy_map_low_then_high() {
        // first half all zeros (entropy 0), second half full byte range (entropy 8)
        let mut data = vec![0u8; 4096];
        let high: Vec<u8> = (0..4096u32).map(|x| x as u8).collect();
        data.extend_from_slice(&high);
        let d = Document::from_source(Arc::new(MemSource::new(data, "t")));
        let map = entropy_map(&d, 0, d.len(), 2, &Progress::default());
        assert_eq!(map.len(), 2);
        assert!(map[0] < 0.5, "low half entropy {}", map[0]);
        assert!(map[1] > 7.5, "high half entropy {}", map[1]);
    }

    #[test]
    fn entropy_map_empty() {
        let d = Document::empty();
        let map = entropy_map(&d, 0, 0, 4, &Progress::default());
        assert_eq!(map, vec![0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn analyze_offset_subrange() {
        let doc = Document::from_source(Arc::new(MemSource::new(b"AAAABBBB".to_vec(), "t")));
        let s = analyze(&doc, 4, 4, &Progress::default());
        assert_eq!(s.total, 4);
        assert_eq!(s.counts[b'B' as usize], 4);
        assert_eq!(s.counts[b'A' as usize], 0);
    }
}
