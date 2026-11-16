//! Feature operations that run over a [`crate::data::Document`].
//!
//! These are deliberately decoupled from the GUI: each takes a document (or a
//! byte range) and returns data or progress, so they can be unit-tested and, in
//! future, driven from a CLI.

pub mod byteplot;
pub mod checksum;
pub mod compress;
pub mod diff;
pub mod disasm;
pub mod export;
pub mod fileops;
pub mod inspect;
pub mod kstruct;
pub mod patch;
pub mod pattern;
pub mod pointer;
pub mod scan;
pub mod script;
pub mod script_store;
pub mod search;
pub mod sidecar;
pub mod signatures;
pub mod stats;
pub mod strings;
pub mod template;
pub mod transform;

/// The per-user config directory (`%APPDATA%\bewitched` on Windows,
/// `$XDG_CONFIG_HOME/bewitched` or `~/.config/bewitched` elsewhere).
pub fn config_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    let base = std::env::var("APPDATA").ok();
    #[cfg(not(windows))]
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.config")));
    let mut p = std::path::PathBuf::from(base.unwrap_or_else(|| ".".into()));
    p.push("bewitched");
    p
}

/// Parse a `0x`-prefixed hex or plain decimal unsigned integer — an offset,
/// length or address as typed by the user. Whitespace is trimmed.
pub fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse a `0x`-prefixed hex or plain decimal *signed* integer literal (as used
/// in template/struct DSL field values and enum entries). Whitespace is trimmed.
/// Widened to `i128` so it covers the full `u64`/`i64` literal range; callers
/// narrow as needed.
pub fn parse_int_lit(s: &str) -> Option<i128> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i128::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Cooperative progress/cancel handle shared with long-running operations.
#[derive(Clone)]
pub struct Progress {
    inner: std::sync::Arc<ProgressInner>,
}

pub struct ProgressInner {
    pub done: std::sync::atomic::AtomicU64,
    pub total: std::sync::atomic::AtomicU64,
    pub cancel: std::sync::atomic::AtomicBool,
    pub finished: std::sync::atomic::AtomicBool,
}

impl Default for Progress {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Progress {
    pub fn new(total: u64) -> Self {
        use std::sync::atomic::*;
        Self {
            inner: std::sync::Arc::new(ProgressInner {
                done: AtomicU64::new(0),
                total: AtomicU64::new(total),
                cancel: AtomicBool::new(false),
                finished: AtomicBool::new(false),
            }),
        }
    }

    pub fn set_total(&self, t: u64) {
        self.inner
            .total
            .store(t, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.inner
            .done
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn set_done(&self, n: u64) {
        self.inner
            .done
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn done(&self) -> u64 {
        self.inner.done.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn total(&self) -> u64 {
        self.inner.total.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn fraction(&self) -> f32 {
        let t = self.total();
        if t == 0 {
            return 0.0;
        }
        (self.done() as f64 / t as f64) as f32
    }
    pub fn cancel(&self) {
        self.inner
            .cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn finish(&self) {
        self.inner
            .finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn is_finished(&self) -> bool {
        self.inner
            .finished
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
