//! The editable document model: a piece-table over a [`DataSource`].
//!
//! Edits never touch the original source. Instead the document is described as a
//! sequence of *pieces*, each pointing either into the original source or into a
//! growable "add buffer" of inserted/overwritten bytes. Splicing the piece list
//! is O(pieces), independent of file size, so editing an 8 EB disk costs the same
//! as editing a 1 KB file. Undo/redo snapshot the (small) piece list.

use std::sync::Arc;

use super::source::{DataSource, EmptySource, MemSource};

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

    /// Convenience: allocate and read a range. Caps absurd requests.
    pub fn read_range(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
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
    pub fn save_to(&mut self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use std::io::Write;
        let path = path.as_ref();
        // Write to a temp file then rename, so a crash can't truncate the target.
        let tmp = path.with_extension("ganghex.tmp");
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
        self.path = Some(path.to_path_buf());
        // After save, the on-disk bytes ARE the document; collapse history onto a
        // fresh in-memory source so the old mmap can be released.
        let data = self.to_vec();
        let src = Arc::new(MemSource::new(data, self.label()));
        *self = Self::from_source(src);
        self.path = Some(path.to_path_buf());
        self.mark_saved();
        Ok(())
    }

    pub fn piece_count(&self) -> usize {
        self.pieces.len()
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

fn read_piece_impl(original: &dyn DataSource, add: &[u8], p: &Piece, inner: u64, buf: &mut [u8]) -> usize {
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
        let mut v = vec![0u8; len];
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
}
