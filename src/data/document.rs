//! The editable document model: a piece-table over a [`DataSource`].
//!
//! Edits never touch the original source. Instead the document is described as a
//! sequence of *pieces*, each pointing either into the original source or into a
//! growable "add buffer" of inserted/overwritten bytes. Splicing the piece list
//! is O(pieces), independent of file size, so editing an 8 EB disk costs the same
//! as editing a 1 KB file. Undo/redo snapshot the (small) piece list.

use std::sync::Arc;

use super::source::{DataSource, EmptySource};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Src {
    Original,
    Add,
}

#[derive(Clone, Copy, Debug)]
struct Piece {
    src: Src,
    start: u64,
    len: u64,
    /// True if this piece represents bytes the user changed (always Add-sourced).
    modified: bool,
}

#[derive(Clone)]
struct Snapshot {
    pieces: Vec<Piece>,
    total: u64,
    cursor: u64,
}

pub struct Document {
    original: Arc<dyn DataSource>,
    add: Vec<u8>,
    pieces: Vec<Piece>,
    /// Cumulative start offset of each piece, `cum[i]` = sum of lens before i.
    cum: Vec<u64>,
    total: u64,

    undo: Vec<Snapshot>,
    redo: Vec<Snapshot>,
    saved_marker: Option<usize>, // undo-stack depth at last save
    pub path: Option<std::path::PathBuf>,

    /// Cursor position used purely so undo can restore a sensible caret.
    pub cursor: u64,
}

impl Document {
    pub fn from_source(src: Arc<dyn DataSource>) -> Self {
        let total = src.len();
        let pieces = if total == 0 {
            Vec::new()
        } else {
            vec![Piece {
                src: Src::Original,
                start: 0,
                len: total,
                modified: false,
            }]
        };
        let mut doc = Self {
            original: src,
            add: Vec::new(),
            pieces,
            cum: Vec::new(),
            total,
            undo: Vec::new(),
            redo: Vec::new(),
            saved_marker: Some(0),
            path: None,
            cursor: 0,
        };
        doc.reindex();
        doc
    }

    pub fn empty() -> Self {
        Self::from_source(Arc::new(EmptySource))
    }

    pub fn open_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let src = super::source::FileSource::open(&p)?;
        let mut doc = Self::from_source(Arc::new(src));
        doc.path = Some(p);
        Ok(doc)
    }

    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn label(&self) -> String {
        self.path
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.original.label().to_string())
    }

    pub fn is_modified(&self) -> bool {
        self.saved_marker != Some(self.undo.len())
    }

    pub fn mark_saved(&mut self) {
        self.saved_marker = Some(self.undo.len());
    }

    fn reindex(&mut self) {
        self.cum.clear();
        self.cum.reserve(self.pieces.len());
        let mut acc = 0u64;
        for p in &self.pieces {
            self.cum.push(acc);
            acc += p.len;
        }
        self.total = acc;
    }

    fn locate(&self, offset: u64) -> (usize, u64) {
        locate_in(&self.cum, &self.pieces, self.total, offset)
    }

    /// Read up to `buf.len()` bytes starting at `offset`. Returns bytes read.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        read_impl(
            self.original.as_ref(),
            &self.add,
            &self.pieces,
            &self.cum,
            self.total,
            offset,
            buf,
        )
    }

    /// A cheap, `Send + Sync`, read-only snapshot of the current document state.
    /// Long read-only operations run against this on a worker thread without
    /// blocking (or being invalidated by) further editing.
    pub fn reader(&self) -> DocReader {
        DocReader {
            original: self.original.clone(),
            add: self.add.clone().into(),
            pieces: self.pieces.clone().into(),
            cum: self.cum.clone().into(),
            total: self.total,
        }
    }

    /// Convenience: allocate and read a range. The allocation is capped to the
    /// bytes actually available from `offset` — reading past the end returns
    /// nothing, so a huge `len` (from a crafted length field, or an untrusted
    /// MCP/template/CLI argument) cannot drive a multi-gigabyte allocation.
    pub fn read_range(&self, offset: u64, len: usize) -> Vec<u8> {
        let avail = self.total.saturating_sub(offset).min(len as u64) as usize;
        let mut v = vec![0u8; avail];
        let n = self.read_at(offset, &mut v);
        v.truncate(n);
        v
    }

    /// Return true if the byte at `offset` belongs to a modified piece.
    pub fn is_byte_modified(&self, offset: u64) -> bool {
        if offset >= self.total {
            return false;
        }
        let (pi, _) = self.locate(offset);
        self.pieces.get(pi).map(|p| p.modified).unwrap_or(false)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            pieces: self.pieces.clone(),
            total: self.total,
            cursor: self.cursor,
        }
    }

    fn push_undo(&mut self) {
        self.undo.push(self.snapshot());
        self.redo.clear();
    }

    /// Core splice primitive: replace `del_len` bytes at `offset` with `bytes`.
    /// Handles insert (del_len == 0), delete (bytes empty) and overwrite.
    pub fn replace(&mut self, offset: u64, del_len: u64, bytes: &[u8]) {
        let offset = offset.min(self.total);
        let del_len = del_len.min(self.total - offset);
        if del_len == 0 && bytes.is_empty() {
            return;
        }
        self.push_undo();

        // Stage the inserted bytes into the add buffer.
        let new_piece = if bytes.is_empty() {
            None
        } else {
            let start = self.add.len() as u64;
            self.add.extend_from_slice(bytes);
            Some(Piece {
                src: Src::Add,
                start,
                len: bytes.len() as u64,
                modified: true,
            })
        };

        let mut out: Vec<Piece> = Vec::with_capacity(self.pieces.len() + 2);

        // Left part: pieces fully before `offset`, splitting the boundary piece.
        let (li, loff) = self.locate(offset);
        for p in &self.pieces[..li.min(self.pieces.len())] {
            out.push(*p);
        }
        if loff > 0 {
            if let Some(p) = self.pieces.get(li) {
                out.push(Piece {
                    src: p.src,
                    start: p.start,
                    len: loff,
                    modified: p.modified,
                });
            }
        }

        if let Some(np) = new_piece {
            out.push(np);
        }

        // Right part: everything at/after `offset + del_len`.
        let end = offset + del_len;
        let (ri, roff) = self.locate(end);
        if let Some(p) = self.pieces.get(ri) {
            if roff < p.len {
                out.push(Piece {
                    src: p.src,
                    start: p.start + roff,
                    len: p.len - roff,
                    modified: p.modified,
                });
            }
        }
        for p in &self.pieces[(ri + 1).min(self.pieces.len())..] {
            out.push(*p);
        }

        // Drop empty pieces.
        out.retain(|p| p.len > 0);
        self.pieces = out;
        self.reindex();
    }

    pub fn insert(&mut self, offset: u64, bytes: &[u8]) {
        self.replace(offset, 0, bytes);
    }

    pub fn delete(&mut self, offset: u64, len: u64) {
        self.replace(offset, len, &[]);
    }

    /// Overwrite bytes in place. Extends the document if writing past the end.
    pub fn overwrite(&mut self, offset: u64, bytes: &[u8]) {
        let avail = self.total.saturating_sub(offset);
        let del = (bytes.len() as u64).min(avail);
        self.replace(offset, del, bytes);
    }

    pub fn can_undo(&self) -> bool {
        !self.undo.is_empty()
    }
    pub fn can_redo(&self) -> bool {
        !self.redo.is_empty()
    }

    pub fn undo(&mut self) {
        if let Some(snap) = self.undo.pop() {
            self.redo.push(self.snapshot());
            self.apply(snap);
        }
    }

    pub fn redo(&mut self) {
        if let Some(snap) = self.redo.pop() {
            self.undo.push(self.snapshot());
            self.apply(snap);
        }
    }

    fn apply(&mut self, snap: Snapshot) {
        // The add buffer is append-only; pieces hold absolute offsets into it, so
        // we only swap the piece list back. Stale trailing add bytes are inert.
        self.pieces = snap.pieces;
        self.total = snap.total;
        self.cursor = snap.cursor;
        self.reindex();
    }

    /// Materialize the whole document into a buffer (used for save / small docs).
    /// Streams in chunks so it works for large—but—memory-fitting documents.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total as usize);
        let mut off = 0u64;
        let mut buf = [0u8; 1 << 16];
        while off < self.total {
            let n = self.read_at(off, &mut buf);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
        out
    }

    /// Save by streaming the document to a path.
    ///
    /// Uses temp-file + atomic rename, which is only sound when the target is (or
    /// will be) an ordinary regular file. If the target already exists as a raw
    /// device (`/dev/rdiskN`), fifo, socket, etc., the rename would fail and leave
    /// a stray `.bewitched.tmp` behind, so this refuses up front with a clear
    /// error. Positioned device / live-process writes are handled elsewhere
    /// (write-in-place), never here.
    pub fn save_to(&mut self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use std::io::Write;
        let path = path.as_ref();

        // Refuse to temp+rename over a non-regular target (raw device, fifo, ...).
        match std::fs::metadata(path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "save_to requires a regular-file-backed document; use \
                     write-in-place for devices/process memory",
                ));
            }
            _ => {}
        }

        // Write to a temp file then rename, so a crash can't truncate the target.
        let tmp = path.with_extension("bewitched.tmp");
        {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            let mut off = 0u64;
            let mut buf = vec![0u8; 1 << 20];
            while off < self.total {
                let n = self.read_at(off, &mut buf);
                if n == 0 {
                    break;
                }
                f.write_all(&buf[..n])?;
                off += n as u64;
            }
            f.flush()?;
        }
        std::fs::rename(&tmp, path)?;
        // After save, the on-disk bytes ARE the document. Re-open the saved file
        // as a fresh memory-mapped source and collapse edit history onto it; this
        // releases the old mmap and the add buffer WITHOUT loading the whole file
        // into RAM, so saving an 8 EB document does not require 8 EB of memory.
        let src = super::source::FileSource::open(path)?;
        *self = Self::from_source(Arc::new(src));
        self.path = Some(path.to_path_buf());
        self.mark_saved();
        Ok(())
    }
}

// ---- shared read internals (used by Document and DocReader) ----

fn locate_in(cum: &[u64], pieces: &[Piece], total: u64, offset: u64) -> (usize, u64) {
    if offset >= total {
        return (pieces.len(), 0);
    }
    let idx = match cum.binary_search(&offset) {
        Ok(i) => i,
        Err(i) => i - 1,
    };
    (idx, offset - cum[idx])
}

fn read_add_impl(add: &[u8], start: u64, max: u64, buf: &mut [u8]) -> usize {
    let s = start as usize;
    if s >= add.len() {
        return 0;
    }
    let n = buf.len().min(max as usize).min(add.len() - s);
    buf[..n].copy_from_slice(&add[s..s + n]);
    n
}

fn read_piece_impl(
    original: &dyn DataSource,
    add: &[u8],
    p: &Piece,
    inner: u64,
    buf: &mut [u8],
) -> usize {
    // Never read past this piece's own extent — the source underneath may
    // contain bytes belonging to a different piece (e.g. after a delete).
    let cap = (p.len - inner) as usize;
    let n = buf.len().min(cap);
    if n == 0 {
        return 0;
    }
    match p.src {
        Src::Original => original.read_at(p.start + inner, &mut buf[..n]),
        Src::Add => read_add_impl(add, p.start + inner, p.len - inner, &mut buf[..n]),
    }
}

fn read_impl(
    original: &dyn DataSource,
    add: &[u8],
    pieces: &[Piece],
    cum: &[u64],
    total: u64,
    offset: u64,
    buf: &mut [u8],
) -> usize {
    if offset >= total || buf.is_empty() {
        return 0;
    }
    let (mut pi, mut inner) = locate_in(cum, pieces, total, offset);
    let mut written = 0usize;
    while written < buf.len() && pi < pieces.len() {
        let p = pieces[pi];
        let got = read_piece_impl(original, add, &p, inner, &mut buf[written..]);
        if got == 0 {
            break;
        }
        written += got;
        if inner + got as u64 >= p.len {
            pi += 1;
            inner = 0;
        } else {
            inner += got as u64;
        }
    }
    written
}

/// A read-only byte source abstraction shared by the live document and its
/// snapshots, so feature operations can be written once and run on either.
pub trait ByteReader: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_range(&self, offset: u64, len: usize) -> Vec<u8> {
        // Cap the allocation to the bytes actually available (see the inherent
        // `Document::read_range` for rationale): an untrusted `len` must not be
        // able to force an arbitrarily large allocation.
        let avail = self.len().saturating_sub(offset).min(len as u64) as usize;
        let mut v = vec![0u8; avail];
        let n = self.read_at(offset, &mut v);
        v.truncate(n);
        v
    }
}

impl ByteReader for Document {
    fn len(&self) -> u64 {
        self.total
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        Document::read_at(self, offset, buf)
    }
}

/// An immutable, cheaply-cloned, thread-safe snapshot of a document.
#[derive(Clone)]
pub struct DocReader {
    original: Arc<dyn DataSource>,
    add: Arc<[u8]>,
    pieces: Arc<[Piece]>,
    cum: Arc<[u64]>,
    total: u64,
}

impl ByteReader for DocReader {
    fn len(&self) -> u64 {
        self.total
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize {
        read_impl(
            self.original.as_ref(),
            &self.add,
            &self.pieces,
            &self.cum,
            self.total,
            offset,
            buf,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::MemSource;

    fn doc_with(data: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(data.to_vec(), "t")))
    }

    fn all(d: &Document) -> Vec<u8> {
        d.to_vec()
    }

    #[test]
    fn read_basic() {
        let d = doc_with(b"hello world");
        assert_eq!(d.len(), 11);
        assert_eq!(d.read_range(0, 5), b"hello");
        assert_eq!(d.read_range(6, 5), b"world");
        assert_eq!(d.read_range(9, 99), b"ld");
    }

    #[test]
    fn insert_middle() {
        let mut d = doc_with(b"helloworld");
        d.insert(5, b", ");
        assert_eq!(all(&d), b"hello, world");
        assert_eq!(d.len(), 12);
    }

    #[test]
    fn insert_ends() {
        let mut d = doc_with(b"bcd");
        d.insert(0, b"a");
        d.insert(d.len(), b"e");
        assert_eq!(all(&d), b"abcde");
    }

    #[test]
    fn delete_range() {
        let mut d = doc_with(b"hello, world");
        d.delete(5, 2);
        assert_eq!(all(&d), b"helloworld");
    }

    #[test]
    fn overwrite_inplace() {
        let mut d = doc_with(b"hello world");
        d.overwrite(6, b"WORLD");
        assert_eq!(all(&d), b"hello WORLD");
        assert_eq!(d.len(), 11);
    }

    #[test]
    fn overwrite_past_end_extends() {
        let mut d = doc_with(b"ab");
        d.overwrite(1, b"XYZ");
        assert_eq!(all(&d), b"aXYZ");
    }

    #[test]
    fn modified_tracking() {
        let mut d = doc_with(b"aaaa");
        assert!(!d.is_byte_modified(1));
        d.overwrite(1, b"b");
        assert!(d.is_byte_modified(1));
        assert!(!d.is_byte_modified(0));
        assert!(!d.is_byte_modified(2));
    }

    #[test]
    fn undo_redo_chain() {
        let mut d = doc_with(b"abc");
        d.insert(1, b"X"); // aXbc
        d.overwrite(0, b"Z"); // ZXbc
        d.delete(2, 1); // ZXc
        assert_eq!(all(&d), b"ZXc");
        d.undo();
        assert_eq!(all(&d), b"ZXbc");
        d.undo();
        assert_eq!(all(&d), b"aXbc");
        d.undo();
        assert_eq!(all(&d), b"abc");
        assert!(!d.can_undo());
        d.redo();
        assert_eq!(all(&d), b"aXbc");
        d.redo();
        assert_eq!(all(&d), b"ZXbc");
    }

    #[test]
    fn many_edits_consistency() {
        let mut d = doc_with(b"0123456789");
        d.insert(10, b"abc");
        d.insert(0, b"xyz");
        d.delete(3, 4); // remove "0123"
        d.overwrite(0, b"___");
        let v = all(&d);
        // xyz0123456789abc -> overwrite/delete sequence
        // after insert10: 0123456789abc
        // after insert0:  xyz0123456789abc
        // after delete(3,4): xyz456789abc
        // after overwrite(0,___): ___456789abc
        assert_eq!(v, b"___456789abc");
    }

    #[test]
    fn read_across_piece_boundaries() {
        let mut d = doc_with(b"AAAABBBB");
        d.insert(4, b"....."); // AAAA.....BBBB
                               // a single read spanning original/add/original pieces
        assert_eq!(d.read_range(2, 9), b"AA.....BB");
        assert_eq!(d.len(), 13);
    }

    #[test]
    fn overwrite_spanning_pieces() {
        let mut d = doc_with(b"AAAABBBB");
        d.insert(4, b"xx"); // AAAAxxBBBB
        d.overwrite(2, b"123456"); // span AA|xx|BB
        assert_eq!(all(&d), b"AA123456BB");
    }

    #[test]
    fn delete_whole_then_type() {
        let mut d = doc_with(b"hello");
        d.delete(0, d.len());
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
        d.insert(0, b"new");
        assert_eq!(all(&d), b"new");
    }

    #[test]
    fn modified_flag_and_saved_marker() {
        let mut d = doc_with(b"abcd");
        assert!(!d.is_modified());
        d.overwrite(0, b"X");
        assert!(d.is_modified());
        d.mark_saved();
        assert!(!d.is_modified());
        d.undo();
        assert!(d.is_modified()); // undo moves away from saved marker
    }

    #[test]
    fn reader_snapshot_is_independent() {
        let mut d = doc_with(b"snapshot");
        let snap = d.reader();
        d.overwrite(0, b"X"); // mutate after snapshotting
                              // snapshot still reflects the state at capture time
        let mut buf = [0u8; 8];
        let n = ByteReader::read_at(&snap, 0, &mut buf);
        assert_eq!(&buf[..n], b"snapshot");
        assert_eq!(all(&d), b"Xnapshot");
    }

    #[test]
    fn save_reopen_roundtrip() {
        let mut path = std::env::temp_dir();
        let stamp = &path as *const _ as usize;
        path.push(format!("bewitched_save_{:x}.bin", stamp));

        let mut d = doc_with(b"original content here");
        d.overwrite(0, b"EDITED");
        d.insert(d.len(), b"!!!");
        let expect = d.to_vec();
        d.save_to(&path).unwrap();

        assert!(!d.is_modified());
        assert!(!d.can_undo()); // history collapsed onto the saved file
        assert_eq!(d.to_vec(), expect);

        // reopen independently to confirm bytes are on disk
        let d2 = Document::open_file(&path).unwrap();
        assert_eq!(d2.to_vec(), expect);
        let _ = std::fs::remove_file(&path);
    }

    // save_to must refuse a non-regular-file target (fifo stands in for a raw
    // device: temp+rename over it is unsound and would leave a stray .tmp).
    #[cfg(unix)]
    #[test]
    fn save_to_refuses_non_regular_target() {
        use std::ffi::CString;
        let mut path = std::env::temp_dir();
        let stamp = &path as *const _ as usize;
        path.push(format!("bewitched_fifo_{:x}", stamp));
        let _ = std::fs::remove_file(&path);
        let c = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        extern "C" {
            fn mkfifo(path: *const std::os::raw::c_char, mode: u32) -> std::os::raw::c_int;
        }
        let rc = unsafe { mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed");

        let mut d = doc_with(b"payload");
        let err = d.save_to(&path).expect_err("save_to over a fifo must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("regular-file-backed"));

        // no stray temp file left behind
        assert!(!path.with_extension("bewitched.tmp").exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn insert_at_end_repeatedly() {
        let mut d = Document::empty();
        for i in 0..100u8 {
            let len = d.len();
            d.insert(len, &[i]);
        }
        assert_eq!(d.len(), 100);
        assert_eq!(d.read_range(0, 100), (0..100u8).collect::<Vec<_>>());
    }

    #[test]
    fn replace_clamps_out_of_range() {
        let mut d = doc_with(b"abc");
        // offset and del_len past end are clamped, not panicking
        d.replace(100, 50, b"XY");
        assert_eq!(all(&d), b"abcXY");
    }

    #[test]
    fn read_range_caps_oversized_len() {
        let d = doc_with(b"abcd");
        // A `usize::MAX` len must neither allocate astronomically nor panic; only
        // the bytes actually present are returned. (Regression: the old code did
        // `vec![0u8; len]` despite a comment claiming it capped — a DoS vector
        // reachable from MCP/template length fields.)
        assert_eq!(d.read_range(0, usize::MAX), b"abcd");
        assert_eq!(d.read_range(2, usize::MAX), b"cd");
        assert!(d.read_range(100, usize::MAX).is_empty());
        // The thread-safe snapshot reader caps identically.
        let r = d.reader();
        assert_eq!(ByteReader::read_range(&r, 0, usize::MAX), b"abcd");
        assert!(ByteReader::read_range(&r, 4, usize::MAX).is_empty());
    }
}
