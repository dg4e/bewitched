//! The ganghex application: state, menus, the interactive hex view and dialogs.

use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Instant;

use egui::{Key, Sense};

use crate::data::{Document, MemRegion, ProcessHandle, ProcessSource, Region, RowItem, ViewMap};
use crate::ops::{
    byteplot, checksum, diff, disasm, export, fileops, inspect, patch, pattern, scan, search,
    signatures, stats, strings, template, transform, Progress,
};

use super::charset::Charset;
use super::hexview::{self, Layout, Pane, ViewMode};
use super::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EditMode {
    Overwrite,
    Insert,
}

/// Outcome delivered from a background worker thread back to the UI.
enum BgOutcome {
    Checksum(Vec<(checksum::Algo, String)>),
    Stats(Box<stats::Stats>),
    Strings(Vec<strings::Found>),
    Scan(Vec<scan::Match>),
    Signatures(Vec<signatures::Hit>),
    Message(String),
}

struct BgTask {
    label: String,
    progress: Progress,
    started: Instant,
    handle: Option<JoinHandle<BgOutcome>>,
}

#[derive(Default)]
struct SearchState {
    open: bool,
    needle: String,
    replace: String,
    data_type: usize, // index into TYPES
    big_endian: bool,
    case_insensitive: bool,
    status: String,
}

const TYPES: &[(&str, search::DataType)] = &[
    ("Text", search::DataType::Text),
    ("Unicode (UTF-16)", search::DataType::Utf16),
    ("Hex values", search::DataType::Hex),
    ("Int8", search::DataType::I8),
    ("Int16", search::DataType::I16),
    ("Int32", search::DataType::I32),
    ("Int64", search::DataType::I64),
    ("Float32", search::DataType::F32),
    ("Float64", search::DataType::F64),
];

#[derive(Default)]
struct GotoState {
    open: bool,
    text: String,
    status: String,
}

struct ChecksumState {
    open: bool,
    selected: Vec<bool>,
    results: Vec<(checksum::Algo, String)>,
    whole_file: bool,
}

impl Default for ChecksumState {
    fn default() -> Self {
        let mut selected = vec![false; checksum::Algo::ALL.len()];
        // sensible defaults: CRC-32, MD5, SHA-1, SHA-256
        for (i, a) in checksum::Algo::ALL.iter().enumerate() {
            selected[i] = matches!(
                a,
                checksum::Algo::Crc32
                    | checksum::Algo::Md5
                    | checksum::Algo::Sha1
                    | checksum::Algo::Sha256
            );
        }
        Self {
            open: false,
            selected,
            results: Vec::new(),
            whole_file: true,
        }
    }
}

#[derive(Default)]
struct StatsState {
    open: bool,
    result: Option<stats::Stats>,
    whole_file: bool,
    emap: Vec<f32>,
}

#[derive(Default)]
struct SignaturesState {
    open: bool,
    results: Vec<signatures::Hit>,
}

struct ByteplotState {
    open: bool,
    texture: Option<egui::TextureHandle>,
    width: usize,
    height: usize,
}

impl Default for ByteplotState {
    fn default() -> Self {
        Self {
            open: false,
            texture: None,
            width: 256,
            height: 256,
        }
    }
}

#[derive(Default)]
struct DiffState {
    open: bool,
    other: Option<PathBuf>,
    ranges: Vec<diff::DiffRange>,
    status: String,
}

#[derive(Default)]
struct ProcessUiState {
    open: bool,
    pid: String,
    base: String,
    len: String,
    regions: Vec<MemRegion>,
    status: String,
}

/// Active live-memory target: the bytes shown are a window of this process at
/// `base`, so edits can be poked straight back.
struct ProcTarget {
    handle: std::sync::Arc<ProcessHandle>,
    base: u64,
}

struct TemplateState {
    open: bool,
    builtin: usize,
    src: String,
    fields: Vec<template::Field>,
    status: String,
}

impl Default for TemplateState {
    fn default() -> Self {
        Self {
            open: false,
            builtin: 0,
            src: template::BUILTINS[0].1.to_string(),
            fields: Vec::new(),
            status: String::new(),
        }
    }
}

struct DisasmState {
    open: bool,
    bits: disasm::Bits,
}

impl Default for DisasmState {
    fn default() -> Self {
        Self {
            open: false,
            bits: disasm::Bits::Bits64,
        }
    }
}

#[derive(Default)]
struct ExportState {
    open: bool,
    fmt: usize,
    whole_file: bool,
    preview: String,
}

struct PatternState {
    open: bool,
    hex: String,
    count: String,
    mode: usize, // 0 insert, 1 overwrite, 2 fill selection
}

impl Default for PatternState {
    fn default() -> Self {
        Self {
            open: false,
            hex: "00".into(),
            count: "16".into(),
            mode: 0,
        }
    }
}

struct TransformState {
    open: bool,
    op: usize, // index into TRANSFORM_OPS
    key: String,
    swap_group: usize,
}

impl Default for TransformState {
    fn default() -> Self {
        Self {
            open: false,
            op: 0,
            key: "FF".into(),
            swap_group: 2,
        }
    }
}

#[derive(Default)]
struct StringsState {
    open: bool,
    min_len: String,
    whole_file: bool,
    results: Vec<strings::Found>,
}

struct ScanState {
    open: bool,
    data_type: usize, // index into TYPES
    big_endian: bool,
    aligned: bool,
    value: String,
    matches: Vec<scan::Match>,
    status: String,
}

impl Default for ScanState {
    fn default() -> Self {
        Self {
            open: false,
            data_type: 5, // Int32
            big_endian: false,
            aligned: true,
            value: String::new(),
            matches: Vec::new(),
            status: String::new(),
        }
    }
}

struct ToolsState {
    open: bool,
    shred_passes: String,
    split_size: String,
    concat_inputs: Vec<PathBuf>,
    status: String,
}

impl Default for ToolsState {
    fn default() -> Self {
        Self {
            open: false,
            shred_passes: "3".into(),
            split_size: "1048576".into(),
            concat_inputs: Vec::new(),
            status: String::new(),
        }
    }
}

pub struct App {
    doc: Document,
    cursor: u64,
    nibble: u8, // 0 = high, 1 = low (hex pane)
    sel_anchor: Option<u64>,
    mode: EditMode,
    pane: Pane,
    bytes_per_row: usize,
    group: usize,
    view_mode: ViewMode,
    charset: Charset,
    bookmarks: [Option<u64>; 10],
    clipboard: Vec<u8>,
    regions: Vec<Region>,
    status: String,
    scroll_to_cursor: bool,
    page_rows: usize,

    bg: Option<BgTask>,

    search: SearchState,
    goto: GotoState,
    checksum: ChecksumState,
    stats: StatsState,
    export: ExportState,
    pattern: PatternState,
    tools: ToolsState,
    transform: TransformState,
    strings: StringsState,
    scan: ScanState,
    signatures: SignaturesState,
    byteplot: ByteplotState,
    diff: DiffState,
    disasm: DisasmState,
    template: TemplateState,
    process_ui: ProcessUiState,
    process_target: Option<ProcTarget>,
    inspector_open: bool,
    inspector_le: bool,
    regions_open: bool,
    about_open: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, startup: Option<PathBuf>) -> Self {
        theme::install(&cc.egui_ctx);
        let (doc, status) = match startup {
            Some(p) => match Document::open_file(&p) {
                Ok(d) => {
                    let s = format!("opened {} ({})", p.display(), human(d.len()));
                    (d, s)
                }
                Err(e) => (Document::empty(), format!("open failed: {e}")),
            },
            None => (
                Document::empty(),
                "ready — open a file, disk, or start typing".to_string(),
            ),
        };
        Self {
            doc,
            cursor: 0,
            nibble: 0,
            sel_anchor: None,
            mode: EditMode::Overwrite,
            pane: Pane::Hex,
            bytes_per_row: 16,
            group: 1,
            view_mode: ViewMode::Both,
            charset: Charset::Ansi,
            bookmarks: [None; 10],
            clipboard: Vec::new(),
            regions: Vec::new(),
            status,
            scroll_to_cursor: false,
            page_rows: 16,
            bg: None,
            search: SearchState {
                data_type: 0,
                ..Default::default()
            },
            goto: GotoState::default(),
            checksum: ChecksumState::default(),
            stats: StatsState::default(),
            export: ExportState::default(),
            pattern: PatternState::default(),
            tools: ToolsState::default(),
            transform: TransformState::default(),
            strings: StringsState {
                min_len: "4".into(),
                whole_file: true,
                ..Default::default()
            },
            scan: ScanState::default(),
            signatures: SignaturesState::default(),
            byteplot: ByteplotState::default(),
            diff: DiffState::default(),
            disasm: DisasmState::default(),
            template: TemplateState::default(),
            process_ui: ProcessUiState {
                len: "4096".into(),
                ..Default::default()
            },
            process_target: None,
            inspector_open: true,
            inspector_le: true,
            regions_open: false,
            about_open: false,
        }
    }

    // ---- document lifecycle ----

    fn new_doc(&mut self) {
        self.doc = Document::empty();
        self.reset_cursor();
        self.status = "new empty document".into();
    }

    fn open_path(&mut self, path: PathBuf) {
        match Document::open_file(&path) {
            Ok(d) => {
                self.doc = d;
                self.reset_cursor();
                self.status = format!("opened {} ({})", path.display(), human(self.doc.len()));
            }
            Err(e) => self.status = format!("open failed: {e}"),
        }
    }

    fn open_dialog(&mut self) {
        if let Some(p) = rfd::FileDialog::new().pick_file() {
            self.open_path(p);
        }
    }

    fn save(&mut self) {
        if let Some(p) = self.doc.path.clone() {
            match self.doc.save_to(&p) {
                Ok(()) => self.status = format!("saved {}", p.display()),
                Err(e) => self.status = format!("save failed: {e}"),
            }
        } else {
            self.save_as();
        }
    }

    fn save_as(&mut self) {
        if let Some(p) = rfd::FileDialog::new().save_file() {
            match self.doc.save_to(&p) {
                Ok(()) => self.status = format!("saved {}", p.display()),
                Err(e) => self.status = format!("save failed: {e}"),
            }
        }
    }

    fn reset_cursor(&mut self) {
        self.cursor = 0;
        self.nibble = 0;
        self.sel_anchor = None;
        self.regions.clear();
        self.process_target = None;
        self.scroll_to_cursor = true;
    }

    // ---- regions / data-folds ----

    fn fold_selection(&mut self, accessible: bool) {
        if let Some((s, e)) = self.selection_range() {
            let label = format!("region @ {:#X}", s);
            let mut r = if accessible {
                Region::new(s, e - s, label)
            } else {
                Region::inaccessible(s, e - s, label)
            };
            r.folded = true;
            self.regions.push(r);
            self.sel_anchor = None;
            self.status = format!("folded {} bytes", e - s);
        } else {
            self.status = "select a range to fold first".into();
        }
    }

    fn unfold_all(&mut self) {
        for r in &mut self.regions {
            r.folded = false;
        }
        self.status = "unfolded all regions".into();
    }

    fn view_map(&self) -> ViewMap {
        ViewMap::build(self.doc.len(), &self.regions, self.bytes_per_row)
    }

    // ---- transforms ----

    fn apply_transform(&mut self) {
        let Some((s, e)) = self.selection_range() else {
            self.status = "select a range to transform".into();
            return;
        };
        let key = u8::from_str_radix(self.transform.key.trim(), 16).unwrap_or(0);
        let n: u32 = self.transform.key.trim().parse().unwrap_or(1);
        let op = match TRANSFORM_OPS[self.transform.op].1 {
            TKind::Not => transform::Op::Not,
            TKind::Xor => transform::Op::Xor(key),
            TKind::And => transform::Op::And(key),
            TKind::Or => transform::Op::Or(key),
            TKind::Add => transform::Op::Add(key),
            TKind::Sub => transform::Op::Sub(key),
            TKind::Rol => transform::Op::Rol(n),
            TKind::Ror => transform::Op::Ror(n),
            TKind::Shl => transform::Op::Shl(n),
            TKind::Shr => transform::Op::Shr(n),
            TKind::Reverse => transform::Op::Reverse,
            TKind::Swap => transform::Op::SwapBytes(self.transform.swap_group),
            TKind::FlipCase => transform::Op::FlipCase,
        };
        let mut data = self.doc.read_range(s, (e - s) as usize);
        transform::apply(&mut data, op);
        self.doc.overwrite(s, &data);
        self.status = format!("transformed {} bytes", e - s);
        self.scroll_to_cursor = true;
    }

    // ---- string extraction ----

    fn do_strings(&mut self) {
        let (off, len) = self.scope(self.strings.whole_file);
        let min_len = self.strings.min_len.trim().parse().unwrap_or(4usize).max(1);
        let reader = self.doc.reader();
        self.start_bg("scanning for strings", len, move |p| {
            BgOutcome::Strings(strings::extract(&reader, off, len, min_len, 100_000, &p))
        });
    }

    // ---- value scanner ----

    fn scan_needle(&self) -> Result<Vec<u8>, String> {
        let endian = if self.scan.big_endian {
            search::Endian::Big
        } else {
            search::Endian::Little
        };
        search::needle_bytes(&self.scan.value, TYPES[self.scan.data_type].1, endian, false)
    }

    fn scan_endian(&self) -> search::Endian {
        if self.scan.big_endian {
            search::Endian::Big
        } else {
            search::Endian::Little
        }
    }

    fn do_first_scan(&mut self) {
        let needle = match self.scan_needle() {
            Ok(n) if !n.is_empty() => n,
            Ok(_) => {
                self.scan.status = "enter a value".into();
                return;
            }
            Err(e) => {
                self.scan.status = e;
                return;
            }
        };
        let align = if self.scan.aligned { needle.len() as u64 } else { 1 };
        let reader = self.doc.reader();
        self.start_bg("scanning for value", self.doc.len(), move |p| {
            BgOutcome::Scan(scan::first_scan(&reader, &needle, align, 1_000_000, &p))
        });
    }

    fn do_refine(&mut self, refine: scan::Refine) {
        if self.scan.matches.is_empty() {
            self.scan.status = "run First scan first".into();
            return;
        }
        let ty = TYPES[self.scan.data_type].1;
        let endian = self.scan_endian();
        let prev = std::mem::take(&mut self.scan.matches);
        self.scan.matches = scan::refine(&self.doc, &prev, &refine, ty, endian);
        self.scan.status = format!("{} match(es)", self.scan.matches.len());
    }

    fn poke_value(&mut self) {
        let needle = match self.scan_needle() {
            Ok(n) if !n.is_empty() => n,
            _ => {
                self.scan.status = "enter a value to write".into();
                return;
            }
        };
        let offsets: Vec<u64> = self.scan.matches.iter().map(|m| m.offset).collect();
        for off in &offsets {
            self.doc.overwrite(*off, &needle);
        }
        // If viewing live memory, poke each location straight into the process.
        if let Some(meta) = &self.process_target {
            for off in &offsets {
                let _ = meta.handle.write(meta.base + off, &needle);
            }
        }
        self.scan.status = format!("wrote value to {} location(s)", offsets.len());
        self.scroll_to_cursor = true;
    }

    // ---- IPS patches ----

    fn create_ips(&mut self) {
        let Some(orig_path) = rfd::FileDialog::new()
            .set_title("Pick the ORIGINAL (unpatched) file")
            .pick_file()
        else {
            return;
        };
        let original = match std::fs::read(&orig_path) {
            Ok(b) => b,
            Err(e) => {
                self.status = format!("read failed: {e}");
                return;
            }
        };
        let modified = self.doc.to_vec();
        match patch::make_ips(&original, &modified) {
            Ok(p) => {
                if let Some(out) = rfd::FileDialog::new().add_filter("IPS", &["ips"]).save_file() {
                    match std::fs::write(&out, &p) {
                        Ok(()) => self.status = format!("wrote IPS patch ({} bytes)", p.len()),
                        Err(e) => self.status = format!("write failed: {e}"),
                    }
                }
            }
            Err(e) => self.status = format!("patch failed: {e}"),
        }
    }

    fn apply_ips(&mut self) {
        let Some(patch_path) = rfd::FileDialog::new()
            .add_filter("IPS", &["ips"])
            .set_title("Pick an IPS patch")
            .pick_file()
        else {
            return;
        };
        let bytes = match std::fs::read(&patch_path) {
            Ok(b) => b,
            Err(e) => {
                self.status = format!("read failed: {e}");
                return;
            }
        };
        match patch::parse_ips(&bytes) {
            Ok(writes) => {
                for w in &writes {
                    self.doc.overwrite(w.offset, &w.data);
                }
                self.status = format!("applied IPS patch ({} record(s))", writes.len());
                self.scroll_to_cursor = true;
            }
            Err(e) => self.status = format!("invalid patch: {e}"),
        }
    }

    // ---- signature scan & entropy map ----

    fn do_signatures(&mut self) {
        let reader = self.doc.reader();
        let len = self.doc.len();
        self.start_bg("scanning signatures", len, move |p| {
            BgOutcome::Signatures(signatures::scan(&reader, 0, len, 100_000, &p))
        });
    }

    fn do_entropy_map(&mut self) {
        let (off, len) = self.scope(self.stats.whole_file);
        self.stats.emap = stats::entropy_map(&self.doc, off, len, 256, &Progress::default());
    }

    /// Write a hex-string digest at the cursor (checksum repair).
    fn write_hex_at_cursor(&mut self, hex: &str) {
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .filter_map(|c| {
                std::str::from_utf8(c)
                    .ok()
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect();
        if bytes.is_empty() {
            return;
        }
        self.doc.overwrite(self.cursor, &bytes);
        self.status = format!("wrote {}-byte digest at {:#X}", bytes.len(), self.cursor);
        self.scroll_to_cursor = true;
    }

    // ---- visualizations ----

    fn build_byteplot(&mut self, ctx: &egui::Context) {
        let (w, h) = (self.byteplot.width, self.byteplot.height);
        let rgba = byteplot::build_rgba(&self.doc, 0, self.doc.len(), w, h, &Progress::default());
        let image = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
        self.byteplot.texture =
            Some(ctx.load_texture("byteplot", image, egui::TextureOptions::NEAREST));
        self.status = "rendered byte map".into();
    }

    fn do_diff(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Compare against…")
            .pick_file()
        else {
            return;
        };
        let other = match Document::open_file(&path) {
            Ok(d) => d,
            Err(e) => {
                self.diff.status = format!("open failed: {e}");
                return;
            }
        };
        let r = diff::diff(&self.doc, &other, 100_000, &Progress::default());
        self.diff.other = Some(path);
        self.diff.status = format!(
            "{} differing range(s); sizes {} vs {}{}",
            r.ranges.len(),
            r.len_a,
            r.len_b,
            if r.truncated { " (truncated)" } else { "" }
        );
        self.diff.ranges = r.ranges;
    }

    // ---- live process memory ----

    fn process_pid(&self) -> Option<u32> {
        self.process_ui.pid.trim().parse().ok()
    }

    fn list_process_regions(&mut self) {
        let Some(pid) = self.process_pid() else {
            self.process_ui.status = "enter a numeric PID".into();
            return;
        };
        match ProcessHandle::open(pid).and_then(|h| h.regions()) {
            Ok(mut r) => {
                r.retain(|x| x.readable);
                self.process_ui.status = format!("{} readable region(s)", r.len());
                self.process_ui.regions = r;
            }
            Err(e) => {
                self.process_ui.status = format!("error: {e}");
                self.process_ui.regions.clear();
            }
        }
    }

    fn open_process(&mut self) {
        let Some(pid) = self.process_pid() else {
            self.process_ui.status = "enter a numeric PID".into();
            return;
        };
        let base = parse_addr(&self.process_ui.base).unwrap_or(0);
        let len = parse_addr(&self.process_ui.len).unwrap_or(0);
        if len == 0 {
            self.process_ui.status = "enter a non-zero length".into();
            return;
        }
        let handle = match ProcessHandle::open(pid) {
            Ok(h) => std::sync::Arc::new(h),
            Err(e) => {
                self.process_ui.status = format!("open failed: {e}");
                return;
            }
        };
        let label = format!("pid {pid} @ {base:#X}");
        let src = ProcessSource::new(handle.clone(), base, len, label.clone());
        self.doc = Document::from_source(std::sync::Arc::new(src));
        self.reset_cursor();
        self.process_target = Some(ProcTarget { handle, base });
        self.status = format!("opened live memory: {label} ({} bytes)", len);
    }

    /// Write the current selection's bytes straight into the target process.
    fn poke_selection_to_process(&mut self) {
        let Some(meta) = &self.process_target else {
            self.status = "not viewing a live process".into();
            return;
        };
        let Some((s, e)) = self.selection_range() else {
            self.status = "select bytes to poke".into();
            return;
        };
        let bytes = self.doc.read_range(s, (e - s) as usize);
        match meta.handle.write(meta.base + s, &bytes) {
            Ok(n) => self.status = format!("poked {n} byte(s) to process at {:#X}", meta.base + s),
            Err(err) => self.status = format!("poke failed: {err}"),
        }
    }

    // ---- binary templates ----

    fn apply_template(&mut self) {
        match template::Template::parse(&self.template.src) {
            Ok(tmpl) => match template::apply(&tmpl, &self.doc, self.cursor) {
                Ok(fields) => {
                    self.template.status = format!("parsed {} field(s)", fields.len());
                    self.template.fields = fields;
                }
                Err(e) => {
                    self.template.status = e;
                    self.template.fields.clear();
                }
            },
            Err(e) => {
                self.template.status = e;
                self.template.fields.clear();
            }
        }
    }

    // ---- printing ----

    /// "Print" by rendering an HTML hex dump and handing it to the OS default
    /// handler (typically the browser, which can print). Cross-platform.
    fn print(&mut self) {
        let (off, len) = self.scope(true);
        let body = export::export(&self.doc, off, len, export::Format::Html);
        let mut path = std::env::temp_dir();
        path.push(format!("ganghex_print_{}.html", self.doc.label().replace('/', "_")));
        match std::fs::write(&path, body.as_bytes()) {
            Ok(()) => {
                if let Err(e) = open_in_default_app(&path) {
                    self.status = format!("print: wrote {} ({e})", path.display());
                } else {
                    self.status = format!("opened print view: {}", path.display());
                }
            }
            Err(e) => self.status = format!("print failed: {e}"),
        }
    }

    // ---- selection helpers ----

    fn selection(&self) -> Option<(u64, u64)> {
        self.sel_anchor.map(|a| {
            if a <= self.cursor {
                (a, self.cursor)
            } else {
                (self.cursor, a)
            }
        })
    }

    /// Inclusive selection as [start, end_exclusive).
    fn selection_range(&self) -> Option<(u64, u64)> {
        self.selection().map(|(a, b)| (a, (b + 1).min(self.doc.len())))
    }

    fn clear_selection(&mut self) {
        self.sel_anchor = None;
    }

    fn delete_selection(&mut self) -> bool {
        if let Some((s, e)) = self.selection_range() {
            self.doc.delete(s, e - s);
            self.cursor = s.min(self.doc.len().saturating_sub(1));
            self.nibble = 0;
            self.sel_anchor = None;
            self.scroll_to_cursor = true;
            true
        } else {
            false
        }
    }

    // ---- cursor movement ----

    fn set_cursor(&mut self, pos: u64, extend: bool) {
        let max = self.doc.len(); // allow one-past-end for insert
        let pos = pos.min(max);
        if extend {
            if self.sel_anchor.is_none() {
                self.sel_anchor = Some(self.cursor);
            }
        } else {
            self.sel_anchor = None;
        }
        self.cursor = pos;
        self.nibble = 0;
        self.scroll_to_cursor = true;
    }

    fn move_by(&mut self, delta: i64, extend: bool) {
        let cur = self.cursor as i64;
        let np = (cur + delta).clamp(0, self.doc.len() as i64);
        self.set_cursor(np as u64, extend);
    }

    // ---- editing ----

    fn byte_at(&self, off: u64) -> u8 {
        let mut b = [0u8; 1];
        if self.doc.read_at(off, &mut b) == 1 {
            b[0]
        } else {
            0
        }
    }

    fn input_hex_nibble(&mut self, d: u8) {
        self.delete_selection();
        match self.mode {
            EditMode::Overwrite => {
                let b = self.byte_at(self.cursor);
                let nb = if self.nibble == 0 {
                    (b & 0x0f) | (d << 4)
                } else {
                    (b & 0xf0) | d
                };
                self.doc.overwrite(self.cursor, &[nb]);
                if self.nibble == 0 {
                    self.nibble = 1;
                } else {
                    self.nibble = 0;
                    self.cursor = (self.cursor + 1).min(self.doc.len());
                }
            }
            EditMode::Insert => {
                if self.nibble == 0 {
                    self.doc.insert(self.cursor, &[d << 4]);
                    self.nibble = 1;
                } else {
                    let b = self.byte_at(self.cursor);
                    self.doc.overwrite(self.cursor, &[(b & 0xf0) | d]);
                    self.nibble = 0;
                    self.cursor += 1;
                }
            }
        }
        self.scroll_to_cursor = true;
    }

    fn input_byte(&mut self, byte: u8) {
        self.delete_selection();
        match self.mode {
            EditMode::Overwrite => self.doc.overwrite(self.cursor, &[byte]),
            EditMode::Insert => self.doc.insert(self.cursor, &[byte]),
        }
        self.cursor += 1;
        self.nibble = 0;
        self.scroll_to_cursor = true;
    }

    fn backspace(&mut self) {
        if self.delete_selection() {
            return;
        }
        if self.cursor > 0 {
            self.doc.delete(self.cursor - 1, 1);
            self.cursor -= 1;
            self.nibble = 0;
            self.scroll_to_cursor = true;
        }
    }

    fn delete_forward(&mut self) {
        if self.delete_selection() {
            return;
        }
        if self.cursor < self.doc.len() {
            self.doc.delete(self.cursor, 1);
            self.scroll_to_cursor = true;
        }
    }

    fn copy(&mut self, ctx: &egui::Context) {
        if let Some((s, e)) = self.selection_range() {
            self.clipboard = self.doc.read_range(s, (e - s) as usize);
            let hex: Vec<String> = self.clipboard.iter().map(|b| format!("{:02X}", b)).collect();
            ctx.copy_text(hex.join(" "));
            self.status = format!("copied {} bytes", self.clipboard.len());
        }
    }

    fn cut(&mut self, ctx: &egui::Context) {
        self.copy(ctx);
        self.delete_selection();
    }

    fn paste(&mut self, write: bool) {
        if self.clipboard.is_empty() {
            return;
        }
        self.delete_selection();
        let data = self.clipboard.clone();
        if write {
            self.doc.overwrite(self.cursor, &data);
        } else {
            self.doc.insert(self.cursor, &data);
        }
        self.cursor += data.len() as u64;
        self.scroll_to_cursor = true;
        self.status = format!("pasted {} bytes", data.len());
    }

    // ---- background tasks ----

    fn poll_bg(&mut self, ctx: &egui::Context) {
        let done = self
            .bg
            .as_ref()
            .map(|b| b.handle.as_ref().map(|h| h.is_finished()).unwrap_or(true))
            .unwrap_or(false);
        if done {
            if let Some(mut task) = self.bg.take() {
                if let Some(h) = task.handle.take() {
                    if let Ok(outcome) = h.join() {
                        self.apply_outcome(outcome);
                    }
                }
            }
        }
        if self.bg.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
    }

    fn apply_outcome(&mut self, outcome: BgOutcome) {
        match outcome {
            BgOutcome::Checksum(v) => {
                self.checksum.results = v;
                self.status = "checksums computed".into();
            }
            BgOutcome::Stats(s) => {
                self.status = format!(
                    "analysis: {} bytes, entropy {:.3} bits/byte, looks like {}",
                    s.total,
                    s.entropy,
                    s.classify()
                );
                self.stats.result = Some(*s);
            }
            BgOutcome::Strings(found) => {
                self.status = format!("found {} string(s)", found.len());
                self.strings.results = found;
            }
            BgOutcome::Scan(matches) => {
                self.scan.status = format!("{} match(es)", matches.len());
                self.status = self.scan.status.clone();
                self.scan.matches = matches;
            }
            BgOutcome::Signatures(hits) => {
                self.status = format!("found {} signature(s)", hits.len());
                self.signatures.results = hits;
            }
            BgOutcome::Message(m) => self.status = m,
        }
    }

    fn start_bg<F>(&mut self, label: impl Into<String>, total: u64, f: F)
    where
        F: FnOnce(Progress) -> BgOutcome + Send + 'static,
    {
        if self.bg.is_some() {
            self.status = "an operation is already running".into();
            return;
        }
        let progress = Progress::new(total);
        let p2 = progress.clone();
        let handle = std::thread::spawn(move || f(p2));
        self.bg = Some(BgTask {
            label: label.into(),
            progress,
            started: Instant::now(),
            handle: Some(handle),
        });
    }

    fn scope(&self, whole_file: bool) -> (u64, u64) {
        if whole_file {
            (0, self.doc.len())
        } else if let Some((s, e)) = self.selection_range() {
            (s, e - s)
        } else {
            (0, self.doc.len())
        }
    }
}

#[derive(Clone, Copy)]
enum TKind {
    Not,
    Xor,
    And,
    Or,
    Add,
    Sub,
    Rol,
    Ror,
    Shl,
    Shr,
    Reverse,
    Swap,
    FlipCase,
}

/// Transform menu entries: (label, kind, needs_hex_key, needs_count).
const TRANSFORM_OPS: &[(&str, TKind, bool, bool)] = &[
    ("XOR with key", TKind::Xor, true, false),
    ("AND with key", TKind::And, true, false),
    ("OR with key", TKind::Or, true, false),
    ("ADD key", TKind::Add, true, false),
    ("SUB key", TKind::Sub, true, false),
    ("NOT (invert)", TKind::Not, false, false),
    ("Rotate left (bits)", TKind::Rol, false, true),
    ("Rotate right (bits)", TKind::Ror, false, true),
    ("Shift left (bits)", TKind::Shl, false, true),
    ("Shift right (bits)", TKind::Shr, false, true),
    ("Reverse bytes", TKind::Reverse, false, false),
    ("Byte-swap (endian)", TKind::Swap, false, false),
    ("Flip ASCII case", TKind::FlipCase, false, false),
];

/// Open a path with the operating system's default handler.
fn open_in_default_app(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");

    cmd.arg(path);
    cmd.spawn().map(|_| ())
}

fn human(n: u64) -> String {
    const U: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    let mut f = n as f64;
    let mut i = 0;
    while f >= 1024.0 && i < U.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", U[0])
    } else {
        format!("{f:.2} {} ({n} bytes)", U[i])
    }
}

include!("app_ui.rs");
