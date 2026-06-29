//! Byte sources.
//!
//! Everything bewitched edits — a regular file, a raw disk, a region of RAM, or a
//! scratch buffer — is exposed through the [`DataSource`] trait: a flat,
//! addressable, read-only stream of bytes with a known length. The editing layer
//! ([`crate::data::document::Document`]) layers a piece-table on top so the
//! underlying source is never mutated in place. This is what lets us "open"
//! an 8 EB disk instantly: we just record its length and read on demand.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use memmap2::Mmap;

/// A flat, random-access, read-only sequence of bytes.
pub trait DataSource: Send + Sync {
    /// Total number of bytes addressable in this source.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fill `buf` starting at byte `offset`. Returns the number of bytes
    /// actually read (short reads only at end-of-source). Bytes past the end
    /// are left untouched.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize;

    /// Human-readable label for the source (file name, device, ...).
    fn label(&self) -> &str {
        "source"
    }
}

/// An empty source — used for brand-new documents.
pub struct EmptySource;

impl DataSource for EmptySource {
    fn len(&self) -> u64 {
        0
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> usize {
        0
    }
    fn label(&self) -> &str {
        "untitled"
    }
}

/// An in-memory source backed by an owned buffer. Used for the piece-table's
/// "add buffer" and for small/synthetic documents.
pub struct MemSource {
    data: Vec<u8>,
    label: String,
}

impl MemSource {
    pub fn new(data: Vec<u8>, label: impl Into<String>) -> Self {
        Self {
            data,
            label: label.into(),
        }
    }
}

impl DataSource for MemSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        let off = offset as usize;
        if off >= self.data.len() {
            return 0;
        }
        let n = buf.len().min(self.data.len() - off);
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        n
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// A file-backed source.
///
/// Regular files are memory-mapped for instant open and zero-copy random access
/// regardless of size. Sources that cannot be mapped (raw devices, growable
/// files, zero-length files) fall back to positioned reads behind a mutex.
pub struct FileSource {
    backing: Backing,
    len: u64,
    label: String,
}

enum Backing {
    Mapped(Mmap),
    Seek(Mutex<File>),
}

impl FileSource {
    /// Open a path read-only, preferring a memory map.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let label = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        // Empty files cannot be mapped; everything else we try to map and only
        // fall back to seek-based reads if the OS refuses (e.g. some devices).
        let backing = if len == 0 {
            Backing::Seek(Mutex::new(file))
        } else {
            match unsafe { Mmap::map(&file) } {
                Ok(m) => Backing::Mapped(m),
                Err(_) => Backing::Seek(Mutex::new(file)),
            }
        };

        Ok(Self {
            backing,
            len,
            label,
        })
    }
}

impl DataSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let avail = (self.len - offset) as usize;
        let n = buf.len().min(avail);
        match &self.backing {
            Backing::Mapped(m) => {
                let off = offset as usize;
                buf[..n].copy_from_slice(&m[off..off + n]);
                n
            }
            Backing::Seek(file) => {
                let mut f = file.lock().unwrap();
                if f.seek(SeekFrom::Start(offset)).is_err() {
                    return 0;
                }
                f.read(&mut buf[..n]).unwrap_or(0)
            }
        }
    }

    fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_source_mmap_reads() {
        let mut path = std::env::temp_dir();
        let stamp = &path as *const _ as usize;
        path.push(format!("bewitched_src_{:x}.bin", stamp));
        let payload: Vec<u8> = (0..5000u32).map(|x| x as u8).collect();
        std::fs::write(&path, &payload).unwrap();

        let src = FileSource::open(&path).unwrap();
        assert_eq!(src.len(), 5000);
        let mut buf = [0u8; 256];
        let n = src.read_at(1000, &mut buf);
        assert_eq!(n, 256);
        assert_eq!(buf[0], 1000u32 as u8);
        // short read at EOF
        let n = src.read_at(4990, &mut buf);
        assert_eq!(n, 10);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_is_seek_backed() {
        let mut path = std::env::temp_dir();
        let stamp = (&path as *const _ as usize).wrapping_add(1);
        path.push(format!("bewitched_empty_{:x}.bin", stamp));
        std::fs::write(&path, b"").unwrap();
        let src = FileSource::open(&path).unwrap();
        assert_eq!(src.len(), 0);
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(0, &mut buf), 0);
        let _ = std::fs::remove_file(&path);
    }
}
