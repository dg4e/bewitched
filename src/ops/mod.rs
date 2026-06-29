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
