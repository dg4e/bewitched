//! Flexible, streaming search & replace over a document.
//!
//! Supports several needle data types and three directions. Searching streams
//! the document in overlapping windows so it never loads the whole file.

use crate::data::{ByteReader, Document};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Forward,
    Backward,
    /// Restart from the beginning and find the first match.
    All,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DataType {
    Text,
    Utf16,
    Hex,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

/// Parse a user-entered needle of the given type into raw bytes to scan for.
pub fn needle_bytes(
    input: &str,
    ty: DataType,
    endian: Endian,
    case_insensitive: bool,
) -> Result<Vec<u8>, String> {
    let swap = |mut v: Vec<u8>| {
        if endian == Endian::Big {
            v.reverse();
        }
        v
    };
    match ty {
        DataType::Text => {
            let s = if case_insensitive {
                input.to_lowercase()
            } else {
                input.to_string()
            };
            Ok(s.into_bytes())
        }
        DataType::Utf16 => {
            let mut v = Vec::new();
            for u in input.encode_utf16() {
                let b = u.to_le_bytes();
                if endian == Endian::Big {
                    v.extend_from_slice(&[b[1], b[0]]);
                } else {
                    v.extend_from_slice(&b);
                }
            }
            Ok(v)
        }
        DataType::Hex => {
            let cleaned: String = input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != ',' && *c != '-')
                .collect();
            if cleaned.len() % 2 != 0 {
                return Err("hex needs an even number of digits".into());
            }
            let mut v = Vec::with_capacity(cleaned.len() / 2);
            let bytes = cleaned.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let hi = hexval(bytes[i]).ok_or("invalid hex digit")?;
                let lo = hexval(bytes[i + 1]).ok_or("invalid hex digit")?;
                v.push(hi << 4 | lo);
                i += 2;
            }
            Ok(v)
        }
        DataType::I8 => {
            let n: i64 = input.trim().parse().map_err(|_| "invalid integer")?;
            Ok(vec![n as u8])
        }
        DataType::I16 => {
            let n: i64 = input.trim().parse().map_err(|_| "invalid integer")?;
            Ok(swap((n as i16).to_le_bytes().to_vec()))
        }
        DataType::I32 => {
            let n: i64 = input.trim().parse().map_err(|_| "invalid integer")?;
            Ok(swap((n as i32).to_le_bytes().to_vec()))
        }
        DataType::I64 => {
            let n: i64 = input.trim().parse().map_err(|_| "invalid integer")?;
            Ok(swap(n.to_le_bytes().to_vec()))
        }
        DataType::F32 => {
            let n: f32 = input.trim().parse().map_err(|_| "invalid float")?;
            Ok(swap(n.to_le_bytes().to_vec()))
        }
        DataType::F64 => {
            let n: f64 = input.trim().parse().map_err(|_| "invalid float")?;
            Ok(swap(n.to_le_bytes().to_vec()))
        }
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const WIN: usize = 1 << 20; // 1 MiB scan window

/// Find the next match at or after `from` (forward) or strictly before `from`
/// (backward). `All` behaves like forward starting at 0. Returns match offset.
pub fn find(
    doc: &dyn ByteReader,
    needle: &[u8],
    from: u64,
    dir: Direction,
    case_insensitive: bool,
) -> Option<u64> {
    if needle.is_empty() || doc.is_empty() {
        return None;
    }
    let total = doc.len();
    match dir {
        Direction::All => scan_forward(doc, needle, 0, total, case_insensitive),
        Direction::Forward => scan_forward(doc, needle, from.min(total), total, case_insensitive),
        Direction::Backward => scan_backward(doc, needle, from.min(total), case_insensitive),
    }
}

fn scan_forward(doc: &dyn ByteReader, needle: &[u8], start: u64, end: u64, ci: bool) -> Option<u64> {
    let nlen = needle.len() as u64;
    if start + nlen > end {
        return None;
    }
    let overlap = nlen - 1;
    let mut pos = start;
    let mut buf = vec![0u8; WIN + overlap as usize];
    while pos < end {
        let want = ((end - pos) as usize).min(WIN + overlap as usize);
        let n = doc.read_at(pos, &mut buf[..want]);
        if (n as u64) < nlen {
            break;
        }
        let hay = &buf[..n];
        if let Some(rel) = find_in(hay, needle, ci) {
            return Some(pos + rel as u64);
        }
        // advance by window minus overlap so cross-boundary matches are caught
        pos += (n as u64).saturating_sub(overlap).max(1);
    }
    None
}

fn scan_backward(doc: &dyn ByteReader, needle: &[u8], before: u64, ci: bool) -> Option<u64> {
    let nlen = needle.len() as u64;
    if before < nlen {
        return None;
    }
    let overlap = nlen - 1;
    let mut end = before; // exclusive upper bound for a match start+len
    loop {
        let win = (WIN as u64 + overlap).min(end);
        let start = end - win;
        let mut buf = vec![0u8; win as usize];
        let n = doc.read_at(start, &mut buf);
        let hay = &buf[..n];
        if let Some(rel) = rfind_in(hay, needle, ci) {
            let abs = start + rel as u64;
            if abs + nlen <= before {
                return Some(abs);
            }
        }
        if start == 0 {
            return None;
        }
        end = start + overlap;
    }
}

fn find_in(hay: &[u8], needle: &[u8], ci: bool) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let c = if ci {
            hay[i].eq_ignore_ascii_case(&first)
        } else {
            hay[i] == first
        };
        if c {
            let win = &hay[i..i + needle.len()];
            let m = if ci {
                win.eq_ignore_ascii_case(needle)
            } else {
                win == needle
            };
            if m {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn rfind_in(hay: &[u8], needle: &[u8], ci: bool) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    let mut i = hay.len() - needle.len();
    loop {
        let win = &hay[i..i + needle.len()];
        let m = if ci {
            win.eq_ignore_ascii_case(needle)
        } else {
            win == needle
        };
        if m {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Replace all occurrences of `needle` with `repl`. Returns count.
/// Done back-to-front so offsets stay valid across length changes.
pub fn replace_all(
    doc: &mut Document,
    needle: &[u8],
    repl: &[u8],
    ci: bool,
    progress: &super::Progress,
) -> usize {
    if needle.is_empty() {
        return 0;
    }
    // Collect match positions forward first.
    let mut positions = Vec::new();
    let mut from = 0u64;
    let total = ByteReader::len(doc);
    progress.set_total(total);
    while let Some(p) = scan_forward(&*doc as &dyn ByteReader, needle, from, total, ci) {
        positions.push(p);
        from = p + needle.len() as u64;
        progress.set_done(from);
        if progress.is_cancelled() {
            break;
        }
    }
    // Apply in reverse.
    for &p in positions.iter().rev() {
        doc.replace(p, needle.len() as u64, repl);
    }
    progress.finish();
    positions.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::MemSource;
    use std::sync::Arc;

    fn d(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    #[test]
    fn forward_and_back() {
        let doc = d(b"abcXYabcXY");
        assert_eq!(find(&doc, b"abc", 0, Direction::Forward, false), Some(0));
        assert_eq!(find(&doc, b"abc", 1, Direction::Forward, false), Some(5));
        assert_eq!(find(&doc, b"abc", 10, Direction::Backward, false), Some(5));
        assert_eq!(find(&doc, b"abc", 5, Direction::Backward, false), Some(0));
    }

    #[test]
    fn case_insensitive() {
        let doc = d(b"Hello WORLD");
        assert_eq!(find(&doc, b"world", 0, Direction::Forward, true), Some(6));
        assert_eq!(find(&doc, b"world", 0, Direction::Forward, false), None);
    }

    #[test]
    fn hex_needle() {
        let v = needle_bytes("DE AD be ef", DataType::Hex, Endian::Little, false).unwrap();
        assert_eq!(v, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn int_needle_endian() {
        let le = needle_bytes("258", DataType::I16, Endian::Little, false).unwrap();
        assert_eq!(le, vec![0x02, 0x01]);
        let be = needle_bytes("258", DataType::I16, Endian::Big, false).unwrap();
        assert_eq!(be, vec![0x01, 0x02]);
    }

    #[test]
    fn replace_changes_len() {
        let mut doc = d(b"aXaXa");
        let p = super::super::Progress::default();
        let n = replace_all(&mut doc, b"X", b"YY", false, &p);
        assert_eq!(n, 2);
        assert_eq!(doc.to_vec(), b"aYYaYYa");
    }
}
