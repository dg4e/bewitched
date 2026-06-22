//! Detailed binary diff: every differing range between two byte sources.

use crate::data::ByteReader;

use super::Progress;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiffRange {
    pub offset: u64,
    pub len: u64,
}

pub struct DiffResult {
    pub ranges: Vec<DiffRange>,
    pub len_a: u64,
    pub len_b: u64,
    /// True if more differences existed than `max` (results truncated).
    pub truncated: bool,
}

const WIN: usize = 1 << 20;

/// Compute the differing ranges between `a` and `b`. Bytes past the shorter
/// input's end (where the lengths differ) are reported as one trailing range.
/// Capped at `max` ranges.
pub fn diff(
    a: &dyn ByteReader,
    b: &dyn ByteReader,
    max: usize,
    progress: &Progress,
) -> DiffResult {
    let len_a = a.len();
    let len_b = b.len();
    let common = len_a.min(len_b);
    progress.set_total(common.max(1));

    let mut ranges: Vec<DiffRange> = Vec::new();
    let mut truncated = false;
    let mut run_start: Option<u64> = None;

    let mut ba = vec![0u8; WIN];
    let mut bb = vec![0u8; WIN];
    let mut pos = 0u64;

    'outer: while pos < common {
        if progress.is_cancelled() {
            break;
        }
        let want = ((common - pos) as usize).min(WIN);
        let na = a.read_at(pos, &mut ba[..want]);
        let nb = b.read_at(pos, &mut bb[..want]);
        let n = na.min(nb);
        if n == 0 {
            break;
        }
        for i in 0..n {
            let differs = ba[i] != bb[i];
            let abs = pos + i as u64;
            match (differs, run_start) {
                (true, None) => run_start = Some(abs),
                (false, Some(start)) => {
                    ranges.push(DiffRange { offset: start, len: abs - start });
                    run_start = None;
                    if ranges.len() >= max {
                        truncated = true;
                        break 'outer;
                    }
                }
                _ => {}
            }
        }
        pos += n as u64;
        progress.set_done(pos);
    }

    // close an open run at the end of the common region
    if let Some(start) = run_start {
        if ranges.len() < max {
            ranges.push(DiffRange { offset: start, len: common - start });
        } else {
            truncated = true;
        }
    }

    // length mismatch tail
    if len_a != len_b && ranges.len() < max {
        ranges.push(DiffRange {
            offset: common,
            len: len_a.max(len_b) - common,
        });
    } else if len_a != len_b {
        truncated = true;
    }

    progress.finish();
    DiffResult {
        ranges,
        len_a,
        len_b,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn d(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    #[test]
    fn identical_no_ranges() {
        let a = d(b"hello world");
        let b = d(b"hello world");
        let r = diff(&a, &b, 100, &Progress::default());
        assert!(r.ranges.is_empty());
        assert_eq!(r.len_a, r.len_b);
    }

    #[test]
    fn scattered_diffs_grouped() {
        let a = d(b"AAAAAAAAAA");
        let b = d(b"AABBAAAACA");
        let r = diff(&a, &b, 100, &Progress::default());
        // differ at [2,4) and [8,9)
        assert_eq!(r.ranges, vec![
            DiffRange { offset: 2, len: 2 },
            DiffRange { offset: 8, len: 1 },
        ]);
    }

    #[test]
    fn length_mismatch_tail() {
        let a = d(b"abc");
        let b = d(b"abcdef");
        let r = diff(&a, &b, 100, &Progress::default());
        assert_eq!(r.ranges, vec![DiffRange { offset: 3, len: 3 }]);
        assert_eq!((r.len_a, r.len_b), (3, 6));
    }

    #[test]
    fn run_to_end() {
        let a = d(b"abcde");
        let b = d(b"abcXY");
        let r = diff(&a, &b, 100, &Progress::default());
        assert_eq!(r.ranges, vec![DiffRange { offset: 3, len: 2 }]);
    }

    #[test]
    fn cap_truncates() {
        // alternating diffs produce many ranges
        let a = d(&[0u8; 100]);
        let mut bb = vec![0u8; 100];
        for i in (0..100).step_by(2) {
            bb[i] = 1;
        }
        let b = d(&bb);
        let r = diff(&a, &b, 5, &Progress::default());
        assert_eq!(r.ranges.len(), 5);
        assert!(r.truncated);
    }
}
