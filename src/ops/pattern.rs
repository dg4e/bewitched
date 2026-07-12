//! Byte-pattern generation for insertion / fill.

/// Parse a hex pattern string ("DE AD BE EF" / "DEADBEEF") into bytes.
pub fn parse_hex_pattern(input: &str) -> Result<Vec<u8>, String> {
    crate::ops::search::needle_bytes(
        input,
        crate::ops::search::DataType::Hex,
        crate::ops::search::Endian::Little,
        false,
    )
}

/// Build `count` bytes by repeating `pattern`. An empty pattern yields zeros.
pub fn build(pattern: &[u8], count: u64) -> Vec<u8> {
    let count = count as usize;
    if pattern.is_empty() {
        return vec![0u8; count];
    }
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let take = (count - out.len()).min(pattern.len());
        out.extend_from_slice(&pattern[..take]);
    }
    out
}

/// An incrementing-byte ("counter") pattern, useful for test data.
pub fn counter(start: u8, step: u8, count: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(count as usize);
    let mut cur = start;
    for _ in 0..count {
        v.push(cur);
        cur = cur.wrapping_add(step);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_pattern() {
        assert_eq!(build(&[0xAB, 0xCD], 5), vec![0xAB, 0xCD, 0xAB, 0xCD, 0xAB]);
        assert_eq!(build(&[], 3), vec![0, 0, 0]);
    }

    #[test]
    fn counts() {
        assert_eq!(counter(0, 1, 4), vec![0, 1, 2, 3]);
        assert_eq!(counter(254, 1, 4), vec![254, 255, 0, 1]);
    }

    #[test]
    fn parse_hex_pattern_forms() {
        assert_eq!(
            parse_hex_pattern("DEADBEEF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            parse_hex_pattern("de ad be ef").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(parse_hex_pattern("XYZ").is_err());
        assert!(parse_hex_pattern("A").is_err());
    }

    #[test]
    fn build_zero_count() {
        assert!(build(&[0xAB], 0).is_empty());
    }
}
