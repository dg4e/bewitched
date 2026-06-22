//! IPS binary patches — create a patch from a diff, and parse one for applying.
//!
//! IPS is the classic ROM/save patch format: the literal bytes `PATCH`, a series
//! of records `[offset:3][size:2][data:size]` (a `size` of 0 introduces an RLE
//! record `[rle_len:2][value:1]`), terminated by `EOF`. Offsets are 24-bit, so
//! the format addresses at most 16 MiB — we surface that as an error rather than
//! silently producing a broken patch.

/// One write described by a patch: place `data` at `offset`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpsWrite {
    pub offset: u64,
    pub data: Vec<u8>,
}

const MAX_OFF: u64 = 0xFF_FFFF;
const MAX_REC: usize = 0xFFFF;

/// Build an IPS patch describing how to turn `original` into `modified`.
/// Differing runs become records; trailing data in `modified` beyond
/// `original`'s length is included.
pub fn make_ips(original: &[u8], modified: &[u8]) -> Result<Vec<u8>, String> {
    if modified.len() as u64 > MAX_OFF + 1 {
        return Err("IPS cannot address beyond 16 MiB".into());
    }
    let mut out = Vec::from(*b"PATCH");
    let mut i = 0usize;
    while i < modified.len() {
        let orig = original.get(i).copied();
        let differs = orig != Some(modified[i]);
        if !differs {
            i += 1;
            continue;
        }
        // start of a differing run
        let start = i;
        while i < modified.len()
            && i - start < MAX_REC
            && original.get(i).copied() != Some(modified[i])
        {
            i += 1;
        }
        let chunk = &modified[start..i];
        // IPS forbids an offset equal to the bytes "EOF" (0x454F46).
        if start as u64 == 0x454F46 {
            return Err("diff begins at the reserved IPS offset 0x454F46".into());
        }
        let off = start as u64;
        out.push((off >> 16) as u8);
        out.push((off >> 8) as u8);
        out.push(off as u8);
        out.push((chunk.len() >> 8) as u8);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(b"EOF");
    Ok(out)
}

/// Parse an IPS patch into a list of writes (offset, data), expanding RLE.
pub fn parse_ips(patch: &[u8]) -> Result<Vec<IpsWrite>, String> {
    if patch.len() < 8 || &patch[..5] != b"PATCH" {
        return Err("not an IPS patch (missing PATCH header)".into());
    }
    let mut writes = Vec::new();
    let mut p = 5usize;
    loop {
        if p + 3 > patch.len() {
            return Err("truncated patch".into());
        }
        if &patch[p..p + 3] == b"EOF" {
            break;
        }
        let offset = ((patch[p] as u64) << 16) | ((patch[p + 1] as u64) << 8) | patch[p + 2] as u64;
        p += 3;
        if p + 2 > patch.len() {
            return Err("truncated record header".into());
        }
        let size = ((patch[p] as usize) << 8) | patch[p + 1] as usize;
        p += 2;
        if size == 0 {
            // RLE record
            if p + 3 > patch.len() {
                return Err("truncated RLE record".into());
            }
            let rle_len = ((patch[p] as usize) << 8) | patch[p + 1] as usize;
            let value = patch[p + 2];
            p += 3;
            writes.push(IpsWrite {
                offset,
                data: vec![value; rle_len],
            });
        } else {
            if p + size > patch.len() {
                return Err("truncated data record".into());
            }
            writes.push(IpsWrite {
                offset,
                data: patch[p..p + size].to_vec(),
            });
            p += size;
        }
    }
    Ok(writes)
}

/// Apply patch writes to a byte buffer, growing it if a write extends past the end.
pub fn apply_to_vec(target: &mut Vec<u8>, writes: &[IpsWrite]) {
    for w in writes {
        let end = w.offset as usize + w.data.len();
        if end > target.len() {
            target.resize(end, 0);
        }
        target[w.offset as usize..end].copy_from_slice(&w.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_parse_apply_roundtrip() {
        let original = b"the quick brown fox".to_vec();
        let mut modified = original.clone();
        modified[4] = b'Q';
        modified[10] = b'B';
        let patch = make_ips(&original, &modified).unwrap();
        assert_eq!(&patch[..5], b"PATCH");
        assert_eq!(&patch[patch.len() - 3..], b"EOF");

        let writes = parse_ips(&patch).unwrap();
        let mut rebuilt = original.clone();
        apply_to_vec(&mut rebuilt, &writes);
        assert_eq!(rebuilt, modified);
    }

    #[test]
    fn patch_extends_file() {
        let original = b"abc".to_vec();
        let modified = b"abcdef".to_vec();
        let patch = make_ips(&original, &modified).unwrap();
        let mut rebuilt = original.clone();
        apply_to_vec(&mut rebuilt, &parse_ips(&patch).unwrap());
        assert_eq!(rebuilt, modified);
    }

    #[test]
    fn identical_inputs_make_empty_patch() {
        let data = b"unchanged".to_vec();
        let patch = make_ips(&data, &data).unwrap();
        assert_eq!(patch, b"PATCHEOF");
        assert!(parse_ips(&patch).unwrap().is_empty());
    }

    #[test]
    fn rle_record_parses() {
        // PATCH, offset 0x000010, size 0 (RLE), rle_len 0x0004, value 0xAB, EOF
        let patch = b"PATCH\x00\x00\x10\x00\x00\x00\x04\xABEOF";
        let writes = parse_ips(patch).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].offset, 0x10);
        assert_eq!(writes[0].data, vec![0xAB; 4]);
    }

    #[test]
    fn rejects_non_ips() {
        assert!(parse_ips(b"NOPE....").is_err());
        assert!(parse_ips(b"PATCH").is_err());
    }

    #[test]
    fn rejects_oversize() {
        let big = vec![0u8; (MAX_OFF + 2) as usize];
        assert!(make_ips(&[], &big).is_err());
    }

    #[test]
    fn long_run_splits_into_records() {
        let original = vec![0u8; 0x20000];
        let modified = vec![0xFFu8; 0x20000];
        let patch = make_ips(&original, &modified).unwrap();
        let writes = parse_ips(&patch).unwrap();
        // 0x20000 bytes / 0xFFFF max per record => at least 3 records
        assert!(writes.len() >= 3);
        let mut rebuilt = original.clone();
        apply_to_vec(&mut rebuilt, &writes);
        assert_eq!(rebuilt, modified);
    }
}
