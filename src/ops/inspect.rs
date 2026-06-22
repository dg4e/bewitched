//! Data inspector: interpret the bytes at the cursor as many data types at once.
//!
//! Given a small window of bytes (read at the cursor) and an endianness, produce
//! a list of (label, rendered-value) pairs. Insufficient bytes for a type render
//! as "—". Date conversions are done arithmetically (no time-zone library) and
//! always reported in UTC.

/// One interpreted value.
pub struct Interp {
    pub label: &'static str,
    pub value: String,
}

fn rd_uint(bytes: &[u8], n: usize, le: bool) -> Option<u64> {
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
}

fn sign_extend(v: u64, n: usize) -> i64 {
    let bits = n * 8;
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn dash() -> String {
    "—".to_string()
}

/// Produce the full set of interpretations for `bytes` (cursor window).
pub fn inspect(bytes: &[u8], le: bool) -> Vec<Interp> {
    let mut out = Vec::new();
    let mut push = |label, value| out.push(Interp { label, value });

    // Binary / octal of the first byte.
    if let Some(&b) = bytes.first() {
        push("binary", format!("{:08b}", b));
        push("octal", format!("0o{:o}", b));
    } else {
        push("binary", dash());
        push("octal", dash());
    }

    // Signed / unsigned integers.
    for (label_s, label_u, n) in [
        ("int8", "uint8", 1usize),
        ("int16", "uint16", 2),
        ("int32", "uint32", 4),
        ("int64", "uint64", 8),
    ] {
        match rd_uint(bytes, n, le) {
            Some(v) => {
                push(label_u, v.to_string());
                push(label_s, sign_extend(v, n).to_string());
            }
            None => {
                push(label_u, dash());
                push(label_s, dash());
            }
        }
    }

    // Floats.
    push(
        "float32",
        rd_uint(bytes, 4, le)
            .map(|v| format!("{}", f32::from_bits(v as u32)))
            .unwrap_or_else(dash),
    );
    push(
        "float64",
        rd_uint(bytes, 8, le)
            .map(|v| format!("{}", f64::from_bits(v)))
            .unwrap_or_else(dash),
    );

    // Characters.
    push(
        "ASCII",
        bytes
            .first()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    format!("'{}'", b as char)
                } else {
                    format!("\\x{:02X}", b)
                }
            })
            .unwrap_or_else(dash),
    );
    push("UTF-8", utf8_at(bytes));

    // Unsigned LEB128 varint.
    push("uLEB128", leb128(bytes).map(|(v, n)| format!("{v} ({n} bytes)")).unwrap_or_else(dash));

    // Colors.
    push(
        "RGB",
        if bytes.len() >= 3 {
            format!("#{:02X}{:02X}{:02X}", bytes[0], bytes[1], bytes[2])
        } else {
            dash()
        },
    );
    push(
        "RGBA",
        if bytes.len() >= 4 {
            format!("#{:02X}{:02X}{:02X}{:02X}", bytes[0], bytes[1], bytes[2], bytes[3])
        } else {
            dash()
        },
    );

    // Timestamps.
    push(
        "time_t (32)",
        rd_uint(bytes, 4, le)
            .map(|v| unix_to_iso(sign_extend(v, 4)))
            .unwrap_or_else(dash),
    );
    push(
        "time_t (64)",
        rd_uint(bytes, 8, le)
            .map(|v| unix_to_iso(v as i64))
            .unwrap_or_else(dash),
    );
    push(
        "FILETIME",
        rd_uint(bytes, 8, le)
            .map(|ft| unix_to_iso((ft / 10_000_000) as i64 - 11_644_473_600))
            .unwrap_or_else(dash),
    );
    push("DOS date/time", dos_datetime(bytes));

    // GUID (16 bytes, Microsoft mixed-endian when little-endian).
    push("GUID", guid(bytes, le));

    out
}

fn utf8_at(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return dash();
    }
    // Try the longest valid prefix up to 4 bytes.
    for n in (1..=4.min(bytes.len())).rev() {
        if let Ok(s) = std::str::from_utf8(&bytes[..n]) {
            if let Some(c) = s.chars().next() {
                return format!("U+{:04X} '{}'", c as u32, c);
            }
        }
    }
    format!("invalid (\\x{:02X})", bytes[0])
}

fn leb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None // ran out of bytes before a terminating byte
}

fn dos_datetime(bytes: &[u8]) -> String {
    // FAT/DOS: u16 date then u16 time (little-endian).
    let (Some(date), Some(time)) = (rd_uint(bytes, 2, true), rd_uint(bytes.get(2..).unwrap_or(&[]), 2, true))
    else {
        return dash();
    };
    let year = ((date >> 9) & 0x7f) + 1980;
    let month = (date >> 5) & 0x0f;
    let day = date & 0x1f;
    let hour = (time >> 11) & 0x1f;
    let min = (time >> 5) & 0x3f;
    let sec = (time & 0x1f) * 2;
    if month == 0 || day == 0 {
        return dash();
    }
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

fn guid(bytes: &[u8], le: bool) -> String {
    if bytes.len() < 16 {
        return dash();
    }
    let d1 = rd_uint(&bytes[0..4], 4, le).unwrap();
    let d2 = rd_uint(&bytes[4..6], 2, le).unwrap();
    let d3 = rd_uint(&bytes[6..8], 2, le).unwrap();
    let mut tail = String::new();
    for &b in &bytes[8..16] {
        tail.push_str(&format!("{:02X}", b));
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{}-{}",
        d1,
        d2,
        d3,
        &tail[..4],
        &tail[4..]
    )
}

/// Convert a Unix timestamp (seconds, may be negative) to an ISO-8601 UTC string.
/// Uses Howard Hinnant's `civil_from_days` algorithm; no external time library.
pub fn unix_to_iso(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(v: &'a [Interp], label: &str) -> &'a str {
        &v.iter().find(|i| i.label == label).unwrap().value
    }

    #[test]
    fn integer_endianness() {
        let b = [0x01, 0x02, 0x03, 0x04];
        let le = inspect(&b, true);
        assert_eq!(find(&le, "uint32"), "67305985"); // 0x04030201
        let be = inspect(&b, false);
        assert_eq!(find(&be, "uint32"), "16909060"); // 0x01020304
    }

    #[test]
    fn signed_negative() {
        let b = [0xFF];
        let v = inspect(&b, true);
        assert_eq!(find(&v, "int8"), "-1");
        assert_eq!(find(&v, "uint8"), "255");
        assert_eq!(find(&v, "binary"), "11111111");
    }

    #[test]
    fn float_roundtrip() {
        let b = 1.5f32.to_le_bytes();
        let v = inspect(&b, true);
        assert_eq!(find(&v, "float32"), "1.5");
    }

    #[test]
    fn short_window_dashes() {
        let b = [0x41];
        let v = inspect(&b, true);
        assert_eq!(find(&v, "uint32"), "—");
        assert_eq!(find(&v, "ASCII"), "'A'");
    }

    #[test]
    fn unix_epoch_dates() {
        assert_eq!(unix_to_iso(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(unix_to_iso(1_000_000_000), "2001-09-09 01:46:40 UTC");
        assert_eq!(unix_to_iso(-86_400), "1969-12-31 00:00:00 UTC");
        assert_eq!(unix_to_iso(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn leb128_decode() {
        assert_eq!(leb128(&[0xE5, 0x8E, 0x26]), Some((624485, 3)));
        assert_eq!(leb128(&[0x00]), Some((0, 1)));
        assert_eq!(leb128(&[0x80]), None); // unterminated
    }

    #[test]
    fn guid_format() {
        let b: Vec<u8> = (0..16u8).collect();
        let v = inspect(&b, true);
        // little-endian mixed: Data1=03020100, Data2=0504, Data3=0706
        assert_eq!(find(&v, "GUID"), "03020100-0504-0706-0809-0A0B0C0D0E0F");
    }

    #[test]
    fn utf8_multibyte() {
        let b = "é".as_bytes();
        let v = inspect(b, true);
        assert!(find(&v, "UTF-8").starts_with("U+00E9"));
    }
}
