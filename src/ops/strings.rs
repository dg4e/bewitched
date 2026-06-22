//! Extract printable strings (ASCII and UTF-16LE) from a document, streaming.

use crate::data::ByteReader;

use super::Progress;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Ascii,
    Utf16,
}

#[derive(Clone, Debug)]
pub struct Found {
    pub offset: u64,
    pub kind: Kind,
    pub text: String,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Find ASCII and UTF-16LE strings of at least `min_len` printable characters in
/// `[offset, offset+len)`. Results are capped at `max_results` (reported via the
/// status when truncated by the caller). Streams in windows; never loads all data.
pub fn extract(
    doc: &dyn ByteReader,
    offset: u64,
    len: u64,
    min_len: usize,
    max_results: usize,
    progress: &Progress,
) -> Vec<Found> {
    let end = (offset + len).min(doc.len());
    progress.set_total(end.saturating_sub(offset));
    let mut out = Vec::new();

    // We read in overlapping-free windows but carry partial runs across the
    // boundary using `run_*` accumulators so a string split by a window edge is
    // still captured whole.
    const WIN: usize = 1 << 20;
    let mut buf = vec![0u8; WIN];
    let mut pos = offset;

    // ASCII run state
    let mut a_start = 0u64;
    let mut a_buf: Vec<u8> = Vec::new();
    // UTF-16LE run state: we detect [printable, 0x00] pairs
    let mut u_start = 0u64;
    let mut u_buf: Vec<u8> = Vec::new();

    let flush_ascii = |out: &mut Vec<Found>, start: u64, b: &mut Vec<u8>| {
        if b.len() >= min_len {
            out.push(Found {
                offset: start,
                kind: Kind::Ascii,
                text: String::from_utf8_lossy(b).into_owned(),
            });
        }
        b.clear();
    };
    let flush_utf16 = |out: &mut Vec<Found>, start: u64, b: &mut Vec<u8>| {
        if b.len() >= min_len {
            out.push(Found {
                offset: start,
                kind: Kind::Utf16,
                text: String::from_utf8_lossy(b).into_owned(),
            });
        }
        b.clear();
    };

    while pos < end {
        if progress.is_cancelled() || out.len() >= max_results {
            break;
        }
        let want = ((end - pos) as usize).min(WIN);
        let n = doc.read_at(pos, &mut buf[..want]);
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];

        // ASCII scan
        for (i, &b) in chunk.iter().enumerate() {
            let abs = pos + i as u64;
            if printable(b) {
                if a_buf.is_empty() {
                    a_start = abs;
                }
                a_buf.push(b);
            } else {
                flush_ascii(&mut out, a_start, &mut a_buf);
            }
        }

        // UTF-16LE scan (pairs of printable + 0x00). Process pairs aligned to the
        // window; a pair split across a window boundary is rare and simply ends a
        // run — acceptable for a discovery tool.
        let mut i = 0;
        while i + 1 < chunk.len() {
            let lo = chunk[i];
            let hi = chunk[i + 1];
            let abs = pos + i as u64;
            if hi == 0 && printable(lo) {
                if u_buf.is_empty() {
                    u_start = abs;
                }
                u_buf.push(lo);
                i += 2;
            } else {
                flush_utf16(&mut out, u_start, &mut u_buf);
                i += 1;
            }
        }

        pos += n as u64;
        progress.set_done(pos - offset);
    }
    flush_ascii(&mut out, a_start, &mut a_buf);
    flush_utf16(&mut out, u_start, &mut u_buf);
    out.truncate(max_results);
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
    fn finds_ascii_runs() {
        let d = doc(b"\x00\x01hello\x00world\xff\xfe!!");
        let found = extract(&d, 0, d.len(), 4, 1000, &Progress::default());
        let texts: Vec<&str> = found
            .iter()
            .filter(|f| f.kind == Kind::Ascii)
            .map(|f| f.text.as_str())
            .collect();
        assert!(texts.contains(&"hello"));
        assert!(texts.contains(&"world"));
    }

    #[test]
    fn respects_min_length() {
        let d = doc(b"ab\x00abcd\x00x");
        let found = extract(&d, 0, d.len(), 4, 1000, &Progress::default());
        let texts: Vec<&str> = found.iter().map(|f| f.text.as_str()).collect();
        assert!(texts.contains(&"abcd"));
        assert!(!texts.contains(&"ab")); // too short
    }

    #[test]
    fn finds_utf16le() {
        // "Hi" in UTF-16LE: 48 00 69 00
        let d = doc(b"\xff\x48\x00\x69\x00\x00");
        let found = extract(&d, 0, d.len(), 2, 1000, &Progress::default());
        assert!(found.iter().any(|f| f.kind == Kind::Utf16 && f.text == "Hi"));
    }

    #[test]
    fn records_offset() {
        let d = doc(b"\x00\x00KEY=value\x00");
        let found = extract(&d, 0, d.len(), 3, 1000, &Progress::default());
        let f = found.iter().find(|f| f.text.contains("KEY")).unwrap();
        assert_eq!(f.offset, 2);
        assert_eq!(f.text, "KEY=value");
    }

    #[test]
    fn cap_results() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(b"abcd\x00");
        }
        let d = doc(&data);
        let found = extract(&d, 0, d.len(), 4, 10, &Progress::default());
        assert_eq!(found.len(), 10);
    }
}
