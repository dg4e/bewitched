//! ganghex — a fast, cross-platform, hacker-esque hex editor.
//!
//! Library crate holding the engine (`data`), feature operations (`ops`) and
//! the GUI (`ui`). The binary in `main.rs` is a thin shell around [`ui::run`].

pub mod data;
pub mod ops;
pub mod ui;
