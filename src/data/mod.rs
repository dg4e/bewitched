pub mod document;
pub mod source;

pub use document::{ByteReader, DocReader, Document};
pub use source::{DataSource, EmptySource, FileSource, MemSource};
