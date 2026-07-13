//! The bewitched application: state, menus, the interactive hex view and dialogs.

use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Instant;

use egui::{Key, Sense};

use crate::data::{Document, MemRegion, ProcessHandle, ProcessSource, Region, RowItem, ViewMap};
use crate::ops::{
    byteplot, checksum, compress, diff, disasm, export, fileops, inspect, parse_u64, patch,
    pattern, pointer, scan, script, search, sidecar, signatures, stats, strings, template,
    transform, Progress,
};

use super::charset::Charset;
use super::donate;
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
    ("text", search::DataType::Text),
    ("Unicode (UTF-16)", search::DataType::Utf16),
    ("hex values", search::DataType::Hex),
    ("int8", search::DataType::I8),
    ("int16", search::DataType::I16),
    ("int32", search::DataType::I32),
    ("int64", search::DataType::I64),
    ("float32", search::DataType::F32),
    ("float64", search::DataType::F64),
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
    // custom CRC parameters (hex strings) + last result
    crc_width: String,
    crc_poly: String,
    crc_init: String,
    crc_xorout: String,
    crc_refin: bool,
    crc_refout: bool,
    crc_result: String,
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
            crc_width: "32".into(),
            crc_poly: "04C11DB7".into(),
            crc_init: "FFFFFFFF".into(),
            crc_xorout: "FFFFFFFF".into(),
            crc_refin: true,
            crc_refout: true,
            crc_result: String::new(),
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

struct ScriptState {
    open: bool,
    src: String,
    output: String,
    whole_file: bool,
    save_name: String,
}

impl Default for ScriptState {
    fn default() -> Self {
        Self {
            open: false,
            save_name: String::new(),
            src: "// Rhai API: read(i) write(i,v) len() push(v) fill(s,n,v) resize(n,v)\n//   insert(i,v) remove(i,n) find_byte(v,from) find_str(s) count(v) sum() hex(s,n)\n//   read_u16/u32/u64/i16/i32/i64(i,le)  write_u16/u32/u64(i,v,le)\n//   read_f32/f64(i,le)  crc32()  to_upper()  to_lower()\n// doc: cursor() doc_len() scope_offset() sel_start() sel_len()\n//      set_cursor(i)  add_region(start,len,label)  add_note(off,len,text)\n// XOR the selection (or whole file) with 0x42:\nfor i in 0..len() {\n    write(i, read(i) ^ 0x42);\n}\n".into(),
            output: String::new(),
            whole_file: false,
        }
    }
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
    edit_idx: Option<usize>,
    edit_buf: String,
}

impl Default for TemplateState {
    fn default() -> Self {
        Self {
            open: false,
            builtin: 0,
            src: template::BUILTINS[0].1.to_string(),
            fields: Vec::new(),
            status: String::new(),
            edit_idx: None,
            edit_buf: String::new(),
        }
    }
}

struct DisasmState {
    open: bool,
    arch: disasm::Arch,
}

impl Default for DisasmState {
    fn default() -> Self {
        Self {
            open: false,
            arch: disasm::Arch::X86_64,
        }
    }
}

struct KStructState {
    open: bool,
    builtin: usize,
    src: String,
    tree: Option<crate::ops::kstruct::Node>,
    status: String,
}

impl Default for KStructState {
    fn default() -> Self {
        Self {
            open: false,
            builtin: 0,
            src: crate::ops::kstruct::BUILTINS[0].1.to_string(),
            tree: None,
            status: String::new(),
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

#[derive(Default)]
struct PtrScanState {
    open: bool,
    target: String,
    base: String,
    max_offset: String,
    results: Vec<(u64, u64)>,
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
    /// Additional carets for multi-cursor editing (overwrite mode).
    extra_cursors: Vec<u64>,
    status: String,
    scroll_to_cursor: bool,
    /// One-shot: hard-center the cursor row (a jump from a tool window / goto),
    /// as opposed to the gentle reveal used by keyboard navigation.
    center_cursor: bool,
    page_rows: usize,
    /// Visible visual-row range from the previous frame [first, last), so a
    /// programmatic jump can tell whether the cursor is off-screen.
    last_row_range: (usize, usize),

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
    ptrscan: PtrScanState,
    signatures: SignaturesState,
    byteplot: ByteplotState,
    diff: DiffState,
    disasm: DisasmState,
    kstruct: KStructState,
    template: TemplateState,
    script: ScriptState,
    process_ui: ProcessUiState,
    process_target: Option<ProcTarget>,
    /// Frozen live-memory values: (document offset, bytes) re-poked every frame.
    frozen: Vec<(u64, Vec<u8>)>,
    notes: Vec<sidecar::Note>,
    notes_open: bool,
    note_input: String,
    inspector_open: bool,
    inspector_le: bool,
    regions_open: bool,
    about_open: bool,
    donate: donate::DonateUi,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, startup: Option<PathBuf>) -> Self {
        theme::install(&cc.egui_ctx);
        // Route the macOS Apple-menu "About bewitched" to our in-app about window.
        #[cfg(target_os = "macos")]
        super::macos::install(&cc.egui_ctx);
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
            extra_cursors: Vec::new(),
            status,
            scroll_to_cursor: false,
            center_cursor: false,
            page_rows: 16,
            last_row_range: (0, 0),
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
            ptrscan: PtrScanState {
                max_offset: "1024".into(),
                ..Default::default()
            },
            signatures: SignaturesState::default(),
            byteplot: ByteplotState::default(),
            diff: DiffState::default(),
            disasm: DisasmState::default(),
            kstruct: KStructState::default(),
            template: TemplateState::default(),
            script: ScriptState::default(),
            process_ui: ProcessUiState {
                len: "4096".into(),
                ..Default::default()
            },
            process_target: None,
            frozen: Vec::new(),
            notes: Vec::new(),
            notes_open: false,
            note_input: String::new(),
            inspector_open: true,
            inspector_le: true,
            regions_open: false,
            about_open: false,
            donate: donate::DonateUi::default(),
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
                self.autoload_annotations();
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
        self.notes.clear();
        self.bookmarks = [None; 10];
        self.extra_cursors.clear();
        self.process_target = None;
        self.frozen.clear();
        self.scroll_to_cursor = true;
        self.clear_analysis();
    }

    /// Discard results held by the analysis/tool windows (statistics, signatures,
    /// strings, scan, checksums, templates, …) so stale output from the previous
    /// document never lingers after a new file/process is loaded. Window
    /// open/closed state and user-entered configuration are preserved; only the
    /// computed-from-the-old-document results are cleared.
    fn clear_analysis(&mut self) {
        self.checksum.results.clear();
        self.checksum.crc_result.clear();
        self.stats.result = None;
        self.stats.emap.clear();
        self.signatures.results.clear();
        self.strings.results.clear();
        self.byteplot.texture = None;
        self.diff.ranges.clear();
        self.diff.status.clear();
        self.scan.matches.clear();
        self.scan.status.clear();
        self.ptrscan.results.clear();
        self.ptrscan.status.clear();
        self.template.fields.clear();
        self.template.status.clear();
        self.template.edit_idx = None;
        self.template.edit_buf.clear();
        self.kstruct.tree = None;
        self.kstruct.status.clear();
        self.export.preview.clear();
        self.script.output.clear();
        self.search.status.clear();
        self.goto.status.clear();
    }

    /// Re-poke every frozen value into the target process. Called each frame.
    fn enforce_frozen(&self) {
        if let Some(meta) = &self.process_target {
            for (off, bytes) in &self.frozen {
                let _ = meta.handle.write(meta.base + off, bytes);
            }
        }
    }

    // ---- multi-cursor ----

    fn toggle_extra_cursor(&mut self, off: u64) {
        if off == self.cursor {
            return;
        }
        if let Some(i) = self.extra_cursors.iter().position(|&c| c == off) {
            self.extra_cursors.remove(i);
        } else {
            self.extra_cursors.push(off);
            self.extra_cursors.sort_unstable();
        }
        self.status = format!("{} cursor(s)", self.extra_cursors.len() + 1);
    }

    /// Keep extra carets distinct, in range, and not coincident with the primary.
    fn dedup_cursors(&mut self) {
        let len = self.doc.len();
        let cur = self.cursor.min(len);
        self.cursor = cur;
        self.extra_cursors.retain(|&c| c <= len && c != cur);
        self.extra_cursors.sort_unstable();
        self.extra_cursors.dedup();
    }

    /// Backspace at the primary and every extra caret (delete the byte before each).
    fn multi_backspace(&mut self) {
        let positions: Vec<u64> = std::iter::once(self.cursor)
            .chain(self.extra_cursors.iter().copied())
            .collect();
        let mut dels: Vec<u64> = positions
            .iter()
            .filter(|&&p| p > 0)
            .map(|p| p - 1)
            .collect();
        dels.sort_unstable_by(|a, b| b.cmp(a)); // high to low
        dels.dedup();
        for d in dels {
            self.doc.delete(d, 1);
        }
        let rebased = rebase_deletes_before(&positions);
        self.cursor = rebased[0];
        self.extra_cursors = rebased[1..].to_vec();
        self.dedup_cursors();
        self.nibble = 0;
        self.scroll_to_cursor = true;
    }

    /// Delete-forward at the primary and every extra caret (delete the byte at each).
    fn multi_delete_forward(&mut self) {
        let len = self.doc.len();
        let positions: Vec<u64> = std::iter::once(self.cursor)
            .chain(self.extra_cursors.iter().copied())
            .collect();
        let mut dels: Vec<u64> = positions.iter().copied().filter(|&p| p < len).collect();
        dels.sort_unstable_by(|a, b| b.cmp(a));
        dels.dedup();
        for d in dels {
            self.doc.delete(d, 1);
        }
        let rebased = rebase_deletes_at(&positions);
        self.cursor = rebased[0];
        self.extra_cursors = rebased[1..].to_vec();
        self.dedup_cursors();
        self.scroll_to_cursor = true;
    }

    /// Insert `bytes` at the primary cursor and every extra cursor, rebasing all
    /// carets afterwards. Applies high-offset-first so earlier offsets stay valid.
    fn multi_insert(&mut self, bytes: &[u8]) {
        let mut positions: Vec<u64> = Vec::with_capacity(self.extra_cursors.len() + 1);
        positions.push(self.cursor);
        positions.extend_from_slice(&self.extra_cursors);

        let mut order: Vec<usize> = (0..positions.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(positions[i]));
        for &i in &order {
            self.doc.insert(positions[i], bytes);
        }
        let rebased = rebase_inserts(&positions, bytes.len() as u64);
        self.cursor = rebased[0];
        self.extra_cursors = rebased[1..].to_vec();
        self.nibble = 0;
        self.scroll_to_cursor = true;
    }

    /// Overwrite `bytes` at every extra cursor (overwrite mode only), advancing
    /// each. Offsets stay valid because overwrite does not change length.
    fn broadcast_overwrite(&mut self, bytes: &[u8]) {
        if self.extra_cursors.is_empty() {
            return;
        }
        let extras = self.extra_cursors.clone();
        for &c in &extras {
            self.doc.overwrite(c, bytes);
            if let Some(meta) = &self.process_target {
                let _ = meta.handle.write(meta.base + c, bytes);
            }
        }
        for c in &mut self.extra_cursors {
            *c += bytes.len() as u64;
        }
    }

    // ---- annotations sidecar ----

    fn current_sidecar(&self) -> sidecar::Sidecar {
        sidecar::Sidecar {
            bookmarks: self.bookmarks,
            regions: self.regions.clone(),
            notes: self.notes.clone(),
        }
    }

    fn apply_sidecar(&mut self, sc: sidecar::Sidecar) {
        self.bookmarks = sc.bookmarks;
        self.regions = sc.regions;
        self.notes = sc.notes;
    }

    /// Save annotations to `<doc>.bw` (or prompt if the doc is unsaved).
    fn save_annotations(&mut self) {
        let path = match &self.doc.path {
            Some(p) => sidecar::sidecar_path(p),
            None => match rfd::FileDialog::new()
                .add_filter("bewitched", &["bw"])
                .save_file()
            {
                Some(p) => p,
                None => return,
            },
        };
        let text = sidecar::serialize(&self.current_sidecar());
        match std::fs::write(&path, text) {
            Ok(()) => self.status = format!("saved annotations to {}", path.display()),
            Err(e) => self.status = format!("save failed: {e}"),
        }
    }

    fn load_annotations_from(&mut self, path: &std::path::Path) -> bool {
        match std::fs::read_to_string(path) {
            Ok(text) => match sidecar::parse(&text) {
                Ok(sc) => {
                    self.apply_sidecar(sc);
                    true
                }
                Err(e) => {
                    self.status = format!("annotations: {e}");
                    false
                }
            },
            Err(_) => false,
        }
    }

    fn load_annotations_dialog(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .add_filter("bewitched", &["bw"])
            .pick_file()
        {
            if self.load_annotations_from(&p) {
                self.status = format!("loaded annotations from {}", p.display());
            }
        }
    }

    /// Auto-load a sibling `<doc>.bw` if present (called after opening a file).
    fn autoload_annotations(&mut self) {
        if let Some(p) = self.doc.path.clone() {
            let side = sidecar::sidecar_path(&p);
            if side.exists() && self.load_annotations_from(&side) {
                self.status = format!("{} — loaded annotations", self.status);
            }
        }
    }

    fn add_note(&mut self) {
        let (offset, len) = self
            .selection_range()
            .map(|(s, e)| (s, e - s))
            .unwrap_or((self.cursor, 1));
        let text = std::mem::take(&mut self.note_input);
        if text.trim().is_empty() {
            self.status = "type note text first".into();
            self.note_input = text;
            return;
        }
        self.notes.push(sidecar::Note { offset, len, text });
        self.notes.sort_by_key(|n| n.offset);
        self.status = "note added".into();
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

    // ---- compression ----

    fn compress_scope(&self) -> (u64, u64) {
        self.selection_range()
            .map(|(s, e)| (s, e - s))
            .unwrap_or((0, self.doc.len()))
    }

    fn do_decompress(&mut self) {
        let (off, len) = self.compress_scope();
        let data = self.doc.read_range(off, len as usize);
        let codec = compress::detect(&data).unwrap_or(compress::Codec::Deflate);
        match compress::decompress(&data, codec) {
            Ok(out) => {
                let m = out.len();
                self.doc.replace(off, len, &out);
                self.status = format!("decompressed {len} → {m} bytes ({})", codec.name());
                self.scroll_to_cursor = true;
            }
            Err(e) => self.status = e,
        }
    }

    fn do_compress(&mut self, codec: compress::Codec) {
        let (off, len) = self.compress_scope();
        let data = self.doc.read_range(off, len as usize);
        let out = compress::compress(&data, codec, 6);
        let m = out.len();
        self.doc.replace(off, len, &out);
        self.status = format!("compressed {len} → {m} bytes ({})", codec.name());
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
        search::needle_bytes(
            &self.scan.value,
            TYPES[self.scan.data_type].1,
            endian,
            false,
        )
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
        let align = if self.scan.aligned {
            needle.len() as u64
        } else {
            1
        };
        let reader = self.doc.reader();
        self.start_bg("scanning for value", self.doc.len(), move |p| {
            BgOutcome::Scan(scan::first_scan(&reader, &needle, align, 1_000_000, &p))
        });
    }

    fn do_refine(&mut self, refine: scan::Refine) {
        if self.scan.matches.is_empty() {
            self.scan.status = "run first scan first".into();
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

    fn freeze_matches(&mut self) {
        if self.process_target.is_none() {
            self.scan.status = "freeze needs a live process".into();
            return;
        }
        let needle = match self.scan_needle() {
            Ok(n) if !n.is_empty() => n,
            _ => {
                self.scan.status = "enter a value to freeze".into();
                return;
            }
        };
        let offsets: Vec<u64> = self.scan.matches.iter().map(|m| m.offset).collect();
        for off in offsets {
            if !self.frozen.iter().any(|(o, _)| *o == off) {
                self.frozen.push((off, needle.clone()));
            }
        }
        self.scan.status = format!("froze {} value(s)", self.frozen.len());
    }

    fn do_ptrscan(&mut self) {
        let Some(target) = parse_u64(&self.ptrscan.target) else {
            self.ptrscan.status = "enter a target address".into();
            return;
        };
        let base = parse_u64(&self.ptrscan.base).unwrap_or(0);
        let max_off = parse_u64(&self.ptrscan.max_offset).unwrap_or(0x400);
        let reader = self.doc.reader();
        self.ptrscan.results = pointer::find_pointers_to(
            &reader,
            base,
            target,
            max_off,
            8,
            100_000,
            &Progress::default(),
        );
        self.ptrscan.status = format!("{} pointer(s)", self.ptrscan.results.len());
    }

    fn unfreeze_all(&mut self) {
        let n = self.frozen.len();
        self.frozen.clear();
        self.scan.status = format!("unfroze {n} value(s)");
    }

    // ---- IPS patches ----

    fn create_ips(&mut self) {
        let Some(orig_path) = rfd::FileDialog::new()
            .set_title("pick the ORIGINAL (unpatched) file")
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
                if let Some(out) = rfd::FileDialog::new()
                    .add_filter("IPS", &["ips"])
                    .save_file()
                {
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
            .set_title("pick an IPS patch")
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
                patch::apply_writes(&mut self.doc, &writes);
                self.status = format!("applied IPS patch ({} record(s))", writes.len());
                self.scroll_to_cursor = true;
            }
            Err(e) => self.status = format!("invalid patch: {e}"),
        }
    }

    fn create_bps(&mut self) {
        let Some(orig_path) = rfd::FileDialog::new()
            .set_title("pick the ORIGINAL (unpatched) file")
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
        let p = patch::make_bps(&original, &modified);
        if let Some(out) = rfd::FileDialog::new()
            .add_filter("BPS", &["bps"])
            .save_file()
        {
            match std::fs::write(&out, &p) {
                Ok(()) => self.status = format!("wrote BPS patch ({} bytes)", p.len()),
                Err(e) => self.status = format!("write failed: {e}"),
            }
        }
    }

    fn apply_bps(&mut self) {
        let Some(patch_path) = rfd::FileDialog::new()
            .add_filter("BPS", &["bps"])
            .set_title("pick a BPS patch")
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
        // BPS validates the source CRC; apply to the current document bytes.
        let source = self.doc.to_vec();
        match patch::apply_bps(&bytes, &source) {
            Ok(target) => {
                self.doc.replace(0, self.doc.len(), &target);
                self.status = format!("applied BPS patch → {} bytes", target.len());
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

    fn compute_custom_crc(&mut self) {
        let pu = |s: &str| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok();
        let width = self.checksum.crc_width.trim().parse::<u32>().unwrap_or(32);
        let params = checksum::CrcParams {
            width,
            poly: pu(&self.checksum.crc_poly).unwrap_or(0),
            init: pu(&self.checksum.crc_init).unwrap_or(0),
            refin: self.checksum.crc_refin,
            refout: self.checksum.crc_refout,
            xorout: pu(&self.checksum.crc_xorout).unwrap_or(0),
        };
        let (off, len) = self.scope(self.checksum.whole_file);
        let data = self.doc.read_range(off, len as usize);
        let v = checksum::custom_crc(&data, &params);
        self.checksum.crc_result = format!("{:0w$X}", v, w = (width as usize).div_ceil(4));
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
            .set_title("compare against…")
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
        // Live memory is fixed-size: insert/delete would desync addresses, so
        // force overwrite mode. Hex-view keystrokes now write through to RAM.
        self.mode = EditMode::Overwrite;
        self.process_ui.open = false;
        self.status = format!("LIVE: {label} ({len} bytes) — edits write through to the process");
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

    // ---- scripting ----

    fn run_script(&mut self) {
        let (off, len) = self.scope(self.script.whole_file);
        let mut data = self.doc.read_range(off, len as usize);
        let orig = data.len() as u64;
        let ctx = script::ScriptCtx {
            cursor: self.cursor,
            sel_start: self.selection_range().map(|(s, _)| s as i64).unwrap_or(-1),
            sel_len: self.selection_range().map(|(s, e)| e - s).unwrap_or(0),
            doc_len: self.doc.len(),
            scope_offset: off,
        };
        match script::run_with_ctx(&self.script.src, &mut data, ctx) {
            Ok(r) => {
                self.doc.replace(off, orig, &data);
                if let Some(meta) = &self.process_target {
                    let _ = meta.handle.write(meta.base + off, &data);
                }
                // Apply requested document side effects.
                for (start, rlen, label) in r.regions {
                    let mut reg = Region::new(start, rlen, label);
                    reg.folded = false;
                    self.regions.push(reg);
                }
                for (offset, nlen, text) in r.notes {
                    self.notes.push(sidecar::Note {
                        offset,
                        len: nlen,
                        text,
                    });
                }
                if let Some(c) = r.set_cursor {
                    self.cursor = c.min(self.doc.len());
                }
                self.script.output = if r.log.trim().is_empty() {
                    format!("ok — wrote {} byte(s)", data.len())
                } else {
                    r.log
                };
                self.scroll_to_cursor = true;
            }
            Err(e) => self.script.output = format!("error: {e}"),
        }
    }

    // ---- struct parser (kstruct) ----

    fn apply_kstruct(&mut self) {
        use crate::ops::kstruct;
        match kstruct::Schema::parse(&self.kstruct.src) {
            Ok(schema) => match kstruct::apply(&schema, &self.doc, self.cursor) {
                Ok(root) => {
                    let n = count_nodes(&root);
                    self.kstruct.status = format!("parsed {n} node(s)");
                    self.kstruct.tree = Some(root);
                }
                Err(e) => {
                    self.kstruct.status = e;
                    self.kstruct.tree = None;
                }
            },
            Err(e) => {
                self.kstruct.status = e;
                self.kstruct.tree = None;
            }
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

    /// Encode the edit buffer and write it over the field at `idx`.
    fn write_template_field(&mut self, idx: usize) {
        let Some(f) = self.template.fields.get(idx).cloned() else {
            return;
        };
        match template::encode(&f.edit, &self.template.edit_buf) {
            Ok(bytes) => {
                self.doc.overwrite(f.offset, &bytes);
                if let Some(meta) = &self.process_target {
                    let _ = meta.handle.write(meta.base + f.offset, &bytes);
                }
                self.template.status = format!("wrote {} ({} bytes)", f.name, bytes.len());
                self.template.edit_idx = None;
                self.scroll_to_cursor = true;
                self.apply_template(); // refresh values
            }
            Err(e) => self.template.status = format!("{}: {e}", f.name),
        }
    }

    // ---- printing ----

    /// "print" by rendering an HTML hex dump and handing it to the OS default
    /// handler (typically the browser, which can print). Cross-platform.
    fn print(&mut self) {
        use std::io::Write as _;
        static PRINT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let (off, len) = self.scope(true);
        let body = export::export(&self.doc, off, len, export::Format::Html);
        // Unique, per-process name + O_EXCL create: on a shared /tmp this avoids
        // both filename collisions and the symlink-precreation attack a fixed,
        // predictable name (e.g. `bewitched_print_<label>.html`) would allow.
        let seq = PRINT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let label = self.doc.label().replace(['/', '\\'], "_");
        let mut path = std::env::temp_dir();
        path.push(format!(
            "bewitched_print_{}_{}_{}.html",
            std::process::id(),
            seq,
            label
        ));
        let write_res = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut f| f.write_all(body.as_bytes()));
        match write_res {
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
        self.selection()
            .map(|(a, b)| (a, (b + 1).min(self.doc.len())))
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

    /// Jump the cursor to `off` (from a tool window / goto): moves the caret and
    /// hard-centers it in the view so the jump is always visible.
    fn jump_to(&mut self, off: u64) {
        self.set_cursor(off, false);
        self.center_cursor = true;
    }

    /// Select `[start, start+len)` and center it in the view.
    fn select(&mut self, start: u64, len: u64) {
        let max = self.doc.len();
        let start = start.min(max);
        if len == 0 {
            self.jump_to(start);
            return;
        }
        self.sel_anchor = Some(start);
        self.cursor = (start + len - 1).min(max.saturating_sub(1));
        self.nibble = 0;
        self.scroll_to_cursor = true;
        self.center_cursor = true;
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

    /// When viewing a live process, mirror an overwritten byte straight to RAM.
    fn live_poke(&self, offset: u64, byte: u8) {
        if let Some(meta) = &self.process_target {
            let _ = meta.handle.write(meta.base + offset, &[byte]);
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
                self.live_poke(self.cursor, nb);
                // Mirror the nibble edit to every extra cursor.
                if !self.extra_cursors.is_empty() {
                    let editing_low = self.nibble == 1;
                    let extras = self.extra_cursors.clone();
                    for &c in &extras {
                        let cb = self.byte_at(c);
                        let cnb = if editing_low {
                            (cb & 0xf0) | d
                        } else {
                            (cb & 0x0f) | (d << 4)
                        };
                        self.doc.overwrite(c, &[cnb]);
                        if let Some(meta) = &self.process_target {
                            let _ = meta.handle.write(meta.base + c, &[cnb]);
                        }
                    }
                    if editing_low {
                        for c in &mut self.extra_cursors {
                            *c += 1;
                        }
                    }
                }
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
                    let nb = (b & 0xf0) | d;
                    self.doc.overwrite(self.cursor, &[nb]);
                    self.live_poke(self.cursor, nb);
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
            EditMode::Overwrite => {
                self.doc.overwrite(self.cursor, &[byte]);
                self.live_poke(self.cursor, byte);
                self.broadcast_overwrite(&[byte]);
            }
            EditMode::Insert => {
                if self.extra_cursors.is_empty() {
                    self.doc.insert(self.cursor, &[byte]);
                } else {
                    self.multi_insert(&[byte]);
                    return;
                }
            }
        }
        self.cursor += 1;
        self.nibble = 0;
        self.scroll_to_cursor = true;
    }

    fn backspace(&mut self) {
        if self.delete_selection() {
            return;
        }
        if !self.extra_cursors.is_empty() {
            self.multi_backspace();
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
        if !self.extra_cursors.is_empty() {
            self.multi_delete_forward();
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
            let hex: Vec<String> = self
                .clipboard
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect();
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
            self.broadcast_overwrite(&data);
            self.cursor += data.len() as u64;
        } else if self.extra_cursors.is_empty() {
            self.doc.insert(self.cursor, &data);
            self.cursor += data.len() as u64;
        } else {
            self.multi_insert(&data);
        }
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
    ("rotate left (bits)", TKind::Rol, false, true),
    ("rotate right (bits)", TKind::Ror, false, true),
    ("Shift left (bits)", TKind::Shl, false, true),
    ("Shift right (bits)", TKind::Shr, false, true),
    ("reverse bytes", TKind::Reverse, false, false),
    ("byte-swap (endian)", TKind::Swap, false, false),
    ("flip ASCII case", TKind::FlipCase, false, false),
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

/// Given caret positions that each insert `n` bytes at their own offset,
/// return where each caret ends up. A caret is shifted right by every insertion
/// at a lower offset, plus `n` for its own insertion. Positions are assumed
/// distinct.
fn rebase_inserts(positions: &[u64], n: u64) -> Vec<u64> {
    positions
        .iter()
        .map(|&p| {
            let before = positions.iter().filter(|&&q| q < p).count() as u64;
            p + n * (before + 1)
        })
        .collect()
}

/// Backspace at each caret: a caret at `p` (>0) deletes the byte at `p-1` and
/// lands at `p-1`, shifted left by every other backspace at a lower offset.
fn rebase_deletes_before(positions: &[u64]) -> Vec<u64> {
    positions
        .iter()
        .map(|&p| {
            if p == 0 {
                return 0;
            }
            let before = positions.iter().filter(|&&q| q > 0 && q < p).count() as u64;
            p - 1 - before
        })
        .collect()
}

/// Delete-forward at each caret: a caret at `p` deletes the byte at `p` and stays
/// at `p`, shifted left by every deletion at a lower offset.
fn rebase_deletes_at(positions: &[u64]) -> Vec<u64> {
    positions
        .iter()
        .map(|&p| {
            let before = positions.iter().filter(|&&q| q < p).count() as u64;
            p - before
        })
        .collect()
}

fn count_nodes(n: &crate::ops::kstruct::Node) -> usize {
    1 + n.children.iter().map(count_nodes).sum::<usize>()
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
