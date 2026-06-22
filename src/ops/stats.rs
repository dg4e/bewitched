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
        let printable: u64 = (0x20u8..=0x7e).map(|b| self.counts[b as usize]).sum::<u64>()
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
    let end = (offset + len).min(doc.len());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

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
        assert_eq!(classify(&[0xAAu8; 200]), "uniform / sparse (mostly one value)");
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
    fn analyze_offset_subrange() {
        let doc = Document::from_source(Arc::new(MemSource::new(
            b"AAAABBBB".to_vec(),
            "t",
        )));
        let s = analyze(&doc, 4, 4, &Progress::default());
        assert_eq!(s.total, 4);
        assert_eq!(s.counts[b'B' as usize], 4);
        assert_eq!(s.counts[b'A' as usize], 0);
    }
}
