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

// ============================== BPS ========================================
//
// BPS is the modern successor to IPS: it handles files of any size, and embeds
// CRC-32 checksums of the source, target and the patch itself for validation.
// The format: "BPS1", source-size, target-size, metadata-size (+ metadata),
// then a stream of actions, then source-CRC, target-CRC, patch-CRC (LE u32).
//
// Each action is a varint `(length-1) << 2 | command`:
//   0 SourceRead  copy `length` bytes from source at the output position
//   1 TargetRead  copy `length` literal bytes that follow
//   2 SourceCopy  signed-varint relative move of a source cursor, then copy
//   3 TargetCopy  signed-varint relative move of a target cursor, then copy
//
// We always *create* patches using only TargetRead (a literal of the whole
// target) — simple and correct, though not maximally compact — but we *apply*
// all four actions, so patches produced by other tools (Flips, beat) work.

fn bps_encode_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let x = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(0x80 | x);
            break;
        }
        out.push(x);
        n -= 1;
    }
}

fn bps_decode_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0u64;
    loop {
        let b = *data.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        result += ((b & 0x7f) as u64) << shift;
        if b & 0x80 != 0 {
            return Ok(result);
        }
        shift += 7;
        result += 1u64 << shift;
    }
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Build a BPS patch turning `source` into `target` (literal TargetRead body).
pub fn make_bps(source: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::from(*b"BPS1");
    bps_encode_varint(&mut out, source.len() as u64);
    bps_encode_varint(&mut out, target.len() as u64);
    bps_encode_varint(&mut out, 0); // no metadata
    if !target.is_empty() {
        // one TargetRead action covering the entire target
        bps_encode_varint(&mut out, ((target.len() as u64 - 1) << 2) | 1);
        out.extend_from_slice(target);
    }
    for v in [crc32(source), crc32(target)] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let patch_crc = crc32(&out);
    out.extend_from_slice(&patch_crc.to_le_bytes());
    out
}

/// Apply a BPS patch to `source`, producing the target. Validates the source and
/// target CRC-32s embedded in the patch.
pub fn apply_bps(patch: &[u8], source: &[u8]) -> Result<Vec<u8>, String> {
    if patch.len() < 4 + 12 || &patch[..4] != b"BPS1" {
        return Err("not a BPS patch".into());
    }
    let body_end = patch.len() - 12;
    let src_crc = u32::from_le_bytes(patch[body_end..body_end + 4].try_into().unwrap());
    let tgt_crc = u32::from_le_bytes(patch[body_end + 4..body_end + 8].try_into().unwrap());
    if crc32(source) != src_crc {
        return Err("source CRC mismatch (wrong base file)".into());
    }

    let mut pos = 4;
    let _source_size = bps_decode_varint(patch, &mut pos)?;
    let target_size = bps_decode_varint(patch, &mut pos)? as usize;
    let meta_size = bps_decode_varint(patch, &mut pos)? as usize;
    pos += meta_size;

    let mut out = Vec::with_capacity(target_size);
    let mut source_rel: i64 = 0;
    let mut target_rel: i64 = 0;

    while pos < body_end {
        let action = bps_decode_varint(patch, &mut pos)?;
        let len = (action >> 2) as usize + 1;
        match action & 3 {
            0 => {
                // SourceRead at the current output offset
                let start = out.len();
                for i in 0..len {
                    let b = *source.get(start + i).ok_or("SourceRead out of range")?;
                    out.push(b);
                }
            }
            1 => {
                // TargetRead: literal bytes from the patch
                for _ in 0..len {
                    let b = *patch.get(pos).ok_or("TargetRead out of range")?;
                    pos += 1;
                    out.push(b);
                }
            }
            2 => {
                let raw = bps_decode_varint(patch, &mut pos)?;
                let delta = if raw & 1 != 0 { -((raw >> 1) as i64) } else { (raw >> 1) as i64 };
                source_rel += delta;
                for _ in 0..len {
                    let idx = usize::try_from(source_rel).map_err(|_| "negative source offset")?;
                    let b = *source.get(idx).ok_or("SourceCopy out of range")?;
                    out.push(b);
                    source_rel += 1;
                }
            }
            3 => {
                let raw = bps_decode_varint(patch, &mut pos)?;
                let delta = if raw & 1 != 0 { -((raw >> 1) as i64) } else { (raw >> 1) as i64 };
                target_rel += delta;
                for _ in 0..len {
                    let idx = usize::try_from(target_rel).map_err(|_| "negative target offset")?;
                    let b = *out.get(idx).ok_or("TargetCopy out of range")?;
                    out.push(b);
                    target_rel += 1;
                }
            }
            _ => unreachable!(),
        }
    }

    if out.len() != target_size {
        return Err(format!("target size mismatch ({} vs {target_size})", out.len()));
    }
    if crc32(&out) != tgt_crc {
        return Err("target CRC mismatch (corrupt patch)".into());
    }
    Ok(out)
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
    fn bps_roundtrip() {
        let source = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut target = source.clone();
        target.extend_from_slice(b" -- and then some extra trailing bytes");
        target[4] = b'Q';
        let patch = make_bps(&source, &target);
        assert_eq!(&patch[..4], b"BPS1");
        let back = apply_bps(&patch, &source).unwrap();
        assert_eq!(back, target);
    }

    #[test]
    fn bps_rejects_wrong_source() {
        let patch = make_bps(b"original", b"modified");
        assert!(apply_bps(&patch, b"WRONG BASE").unwrap_err().contains("source CRC"));
    }

    #[test]
    fn bps_varint_roundtrip() {
        for n in [0u64, 1, 127, 128, 255, 16384, 1_000_000, u32::MAX as u64] {
            let mut buf = Vec::new();
            bps_encode_varint(&mut buf, n);
            let mut pos = 0;
            assert_eq!(bps_decode_varint(&buf, &mut pos).unwrap(), n, "varint {n}");
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn bps_detects_corruption() {
        let mut patch = make_bps(b"aaaa", b"bbbb");
        // corrupt a literal byte in the body
        patch[12] ^= 0xFF;
        assert!(apply_bps(&patch, b"aaaa").is_err());
    }

    #[test]
    fn bps_empty_target() {
        let patch = make_bps(b"abc", b"");
        assert_eq!(apply_bps(&patch, b"abc").unwrap(), b"");
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
