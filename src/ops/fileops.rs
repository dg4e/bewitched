//! File tools: secure shredder, splitting and concatenation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::Progress;

/// Overwrite a file's contents with several passes, then remove it.
///
/// This is best-effort: on modern SSDs/CoW filesystems overwriting in place is
/// not guaranteed to hit the original blocks. We surface that honestly in the UI
/// rather than promising forensic-grade erasure.
pub fn shred(path: impl AsRef<Path>, passes: u32, progress: &Progress) -> std::io::Result<()> {
    let path = path.as_ref();
    let len = std::fs::metadata(path)?.len();
    let mut f = OpenOptions::new().write(true).open(path)?;
    let patterns: [u8; 3] = [0x00, 0xFF, 0xAA];
    progress.set_total(len.saturating_mul(passes as u64).max(1));
    let mut buf = vec![0u8; 1 << 20];
    let mut done = 0u64;
    for pass in 0..passes {
        let fill = patterns[(pass as usize) % patterns.len()];
        for b in buf.iter_mut() {
            *b = fill;
        }
        f.seek(SeekFrom::Start(0))?;
        let mut written = 0u64;
        while written < len {
            if progress.is_cancelled() {
                return Ok(());
            }
            let want = ((len - written) as usize).min(buf.len());
            f.write_all(&buf[..want])?;
            written += want as u64;
            done += want as u64;
            progress.set_done(done);
        }
        f.flush()?;
        f.sync_all()?;
    }
    drop(f);
    std::fs::remove_file(path)?;
    progress.finish();
    Ok(())
}

/// Split `path` into chunks of `chunk_size` bytes, written as `name.000`, `.001`...
/// Returns the list of created parts.
pub fn split(
    path: impl AsRef<Path>,
    chunk_size: u64,
    progress: &Progress,
) -> std::io::Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let total = std::fs::metadata(path)?.len();
    progress.set_total(total);
    let mut src = File::open(path)?;
    let mut parts = Vec::new();
    let mut idx = 0u32;
    let mut remaining = total;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        if progress.is_cancelled() {
            break;
        }
        let part_path = path.with_extension(format!("{:03}", idx));
        let mut out = File::create(&part_path)?;
        let mut to_write = chunk_size.min(remaining);
        while to_write > 0 {
            let want = (to_write as usize).min(buf.len());
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            to_write -= n as u64;
            remaining -= n as u64;
            progress.add(n as u64);
        }
        out.flush()?;
        parts.push(part_path);
        idx += 1;
    }
    progress.finish();
    Ok(parts)
}

/// Concatenate `inputs` in order into `output`.
pub fn concat(
    inputs: &[PathBuf],
    output: impl AsRef<Path>,
    progress: &Progress,
) -> std::io::Result<()> {
    let total: u64 = inputs
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    progress.set_total(total);
    let mut out = File::create(output.as_ref())?;
    let mut buf = vec![0u8; 1 << 20];
    for inp in inputs {
        if progress.is_cancelled() {
            break;
        }
        let mut f = File::open(inp)?;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            progress.add(n as u64);
        }
    }
    out.flush()?;
    progress.finish();
    Ok(())
}

/// Result of comparing two files byte-for-byte.
pub struct CompareResult {
    pub equal: bool,
    pub first_diff: Option<u64>,
    pub len_a: u64,
    pub len_b: u64,
}

/// Simple byte-for-byte file comparison; reports the first differing offset.
pub fn compare(
    a: impl AsRef<Path>,
    b: impl AsRef<Path>,
    progress: &Progress,
) -> std::io::Result<CompareResult> {
    let mut fa = File::open(a.as_ref())?;
    let mut fb = File::open(b.as_ref())?;
    let len_a = fa.metadata()?.len();
    let len_b = fb.metadata()?.len();
    progress.set_total(len_a.min(len_b).max(1));
    let mut ba = vec![0u8; 1 << 20];
    let mut bb = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    let mut first_diff = None;
    loop {
        if progress.is_cancelled() {
            break;
        }
        let na = fa.read(&mut ba)?;
        let nb = fb.read(&mut bb)?;
        let n = na.min(nb);
        if n == 0 {
            break;
        }
        if ba[..n] != bb[..n] {
            for i in 0..n {
                if ba[i] != bb[i] {
                    first_diff = Some(pos + i as u64);
                    break;
                }
            }
            break;
        }
        pos += n as u64;
        progress.set_done(pos);
        if na != nb {
            break;
        }
    }
    progress.finish();
    let equal = first_diff.is_none() && len_a == len_b;
    if first_diff.is_none() && len_a != len_b {
        first_diff = Some(len_a.min(len_b));
    }
    Ok(CompareResult {
        equal,
        first_diff,
        len_a,
        len_b,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let mut d = std::env::temp_dir();
        // unique-ish without Date/rand: use the test thread id via address
        let stamp = &d as *const _ as usize;
        d.push(format!("ganghex_test_{:x}", stamp));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn split_then_concat_roundtrips() {
        let dir = tmpdir();
        let src = dir.join("data.bin");
        let payload: Vec<u8> = (0..1000u32).map(|x| x as u8).collect();
        std::fs::write(&src, &payload).unwrap();

        let p = Progress::default();
        let parts = split(&src, 256, &p).unwrap();
        assert_eq!(parts.len(), 4); // 256*3 + 232

        let out = dir.join("rejoined.bin");
        concat(&parts, &out, &Progress::default()).unwrap();
        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, payload);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shred_removes_file() {
        let dir = tmpdir();
        let f = dir.join("secret.bin");
        std::fs::write(&f, vec![1u8; 4096]).unwrap();
        shred(&f, 3, &Progress::default()).unwrap();
        assert!(!f.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
