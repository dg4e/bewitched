# ganghex — design journal

This document explains *why* ganghex is built the way it is: the central design
decisions, how the pieces fit together, and the trade-offs behind each choice.
It is meant to be read top-to-bottom by someone who wants to understand or extend
the codebase, not as API reference (the doc-comments in the source serve that).

---

## 1. Goals and the one hard constraint

ganghex is a hex editor for **files, raw disks and RAM**. The product brief asked
for a long feature list, but almost every interesting decision flows from a single
hard constraint:

> Open and edit data of *any* size (up to 8 EB) **instantly**, with unlimited
> undo, without limiting file size for "technical reasons."

That constraint rules out the obvious implementation ("read the file into a
`Vec<u8>`, edit the vec, write it back"). It forces three architectural choices
that everything else is built around:

1. **Never load the whole input.** Back the document with a memory map and read
   on demand.
2. **Never rewrite the backing store on edit.** Represent edits as a *description*
   layered over the original bytes — a piece table.
3. **Never block the UI** on a long operation over a large input. Run those on a
   worker thread against a cheap, immutable snapshot.

Everything in the engine exists to honor those three rules.

---

## 2. Language and GUI toolkit

**Rust** was specified, and it is a good fit: zero-cost abstractions for the hot
read path, a strong type system to keep the piece-table invariants honest, and
fearless concurrency for the background-operation model.

**egui / eframe** for the GUI, chosen over GTK/Qt bindings or `iced` because:

- It is **pure Rust** with no system GUI dependency, so one `cargo build` yields a
  portable binary on Windows, macOS and Linux — directly serving the
  "portable edition" requirement.
- It is **immediate-mode**. A hex view is essentially "redraw the visible rows
  every frame from the current document state." Immediate mode matches that model
  exactly: there is no retained widget tree to keep in sync with the data, which
  is where flicker and staleness bugs usually live. The brief explicitly asked for
  "flicker-free display and fast drawing"; immediate mode gives that for free
  because egui only repaints when something changes and draws to a single buffer.
- Its `ScrollArea::show_rows` provides **row virtualization** out of the box —
  essential for displaying a multi-exabyte document where the number of rows
  vastly exceeds anything that could be laid out eagerly.

The cost of immediate mode is that we re-derive the visible rows each frame, but
"visible rows" is ~40 rows regardless of document size, so this is negligible.

---

## 3. The data layer

### 3.1 `DataSource`: one abstraction for files, disks, RAM and scratch buffers

```rust
trait DataSource: Send + Sync {
    fn len(&self) -> u64;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize;
}
```

A `DataSource` is a flat, addressable, **read-only** stream of bytes with a known
length. This is the seam that makes "drives and memory are presented like a file"
true in code rather than just in the UI: a disk and a file are both just
`DataSource`s, so every higher layer (editing, search, analysis) works on them
identically. There is no sector/region-limited view anywhere in the stack.

Implementations:

- **`FileSource`** — the important one. It **memory-maps** the file (`memmap2`).
  Mapping is O(1) regardless of size, which is what makes "instant open" literally
  true: opening an 8 EB device just records its length and maps it; bytes are
  paged in by the OS only when actually read. Zero-length files and sources that
  refuse to be mapped (some raw devices) fall back to positioned `seek`+`read`
  behind a `Mutex` so the type stays `Sync`.
- **`MemSource`** — an owned `Vec<u8>`, used for synthetic/small documents and for
  test fixtures.
- **`EmptySource`** — length 0, used for "new document."

`read_at` returns a *short count* at end-of-source rather than erroring, because
callers (the view, search windows) routinely ask for a fixed-size window near the
end and just want "however many bytes are actually there."

### 3.2 `Document`: a piece table

This is the heart of the editor. The document is **not** stored as bytes; it is
stored as an ordered list of **pieces**:

```rust
struct Piece { src: Src /* Original | Add */, start: u64, len: u64, modified: bool }
```

Each piece points either into the original `DataSource` or into an append-only
**add buffer** (`Vec<u8>`) that accumulates inserted/overwritten bytes. The
document's bytes are the concatenation of its pieces.

**Why a piece table** (rather than a gap buffer or a rope)?

- The original bytes are never copied or moved. An edit anywhere in an 8 EB file
  costs **O(number of pieces)**, not O(file size). A gap buffer would require
  moving bytes; a rope would still own all the data.
- It composes perfectly with `mmap`: a piece into the original source is just an
  (offset, length) into the map — reading it is a `memcpy` from a paged-in region.
- Undo becomes trivial and cheap (see below).

**The splice primitive.** All three editing operations are one function:

```rust
fn replace(&mut self, offset: u64, del_len: u64, bytes: &[u8])
// insert    = replace(offset, 0, bytes)
// delete    = replace(offset, len, &[])
// overwrite = replace(offset, len, bytes)  with len == bytes.len()
```

`replace` rebuilds the piece list as: *(pieces fully before `offset`)* + *(left
half of the boundary piece)* + *(a new Add piece for `bytes`)* + *(right half of
the boundary piece)* + *(pieces fully after `offset+del_len`)*. Boundary pieces
are split by adjusting `start`/`len` — no data is touched. A `cum[]` vector of
cumulative piece offsets is rebuilt after each edit so that locating the piece for
a given offset is a **binary search** (`locate`).

**Modified-byte highlighting** falls out for free: a piece sourced from the add
buffer is, by definition, bytes the user changed, so it carries `modified: true`.
The view colors those amber by asking `is_byte_modified(offset)`, which just
locates the piece and reads the flag.

### 3.3 Undo/redo: snapshot the description, not the data

Because the document *is* a small list of pieces, undo/redo just snapshots that
list (plus the total length and cursor):

```rust
struct Snapshot { pieces: Vec<Piece>, total: u64, cursor: u64 }
```

Each `replace` pushes the pre-edit snapshot onto the undo stack and clears redo.
Undo/redo swap snapshots between the two stacks. The snapshot is bounded by the
number of *pieces*, not the size of the data, so "unlimited undo" on a huge file
is genuinely cheap.

**Two bugs here shaped the final design** (both caught by unit tests, which is why
the tests exist):

1. *Reads bled across piece boundaries.* The first `read` walked into the
   underlying source past a piece's own extent — after a delete, the bytes
   physically adjacent in the original source no longer belong together. Fix:
   `read_piece` clamps every read to `piece.len - inner` before touching the
   source. (Test: `read_across_piece_boundaries`, `delete_range`.)

2. *Redo lost inserted bytes.* The first version truncated the add buffer on undo
   to reclaim memory. But `Vec::truncate` cannot *grow* a vector, so redoing an
   edit whose bytes had been truncated away resurrected nothing. Fix: the **add
   buffer is append-only and never truncated.** Pieces hold absolute offsets into
   it, so stale trailing bytes from undone edits are simply inert. The memory cost
   is the size of undone insertions — acceptable, and the correctness is absolute.
   (Test: `undo_redo_chain`.)

### 3.4 `ByteReader` + `DocReader`: making the document thread-safe to read

Long read-only operations (digests, statistics, search) must run off the UI
thread, but `Document` is mutated by editing and is not something we want to share
across threads under a lock. The solution is a read-only trait and a cheap,
immutable snapshot:

```rust
trait ByteReader: Send + Sync { fn len(&self)->u64; fn read_at(&self, o:u64, b:&mut[u8])->usize; ... }
```

- `Document` implements `ByteReader` for synchronous use on the UI thread.
- `Document::reader()` returns a **`DocReader`** that clones the `Arc` to the
  original source and wraps the add buffer / piece list / cumulative index in
  `Arc<[_]>`. It is `Clone + Send + Sync`, so a worker thread can read a frozen
  view of the document while the user keeps editing the live one. The read logic
  is factored into free functions (`read_impl`, `locate_in`) shared by both, so
  there is exactly one implementation of the read path.

Operations are written against `&dyn ByteReader`, so the same `checksum::compute`
runs on the live document (in a test) or on a snapshot (on a worker thread)
unchanged.

### 3.5 Saving without loading

`save_to` streams the document to a temp file and atomically renames it over the
target (so a crash can't leave a half-written file). The subtle part is what
happens *after*: the on-disk bytes are now the canonical content, so the document
**re-opens the saved file as a fresh `mmap` source** and collapses edit history
onto it. The earlier version called `to_vec()` here, which would have loaded the
entire file into RAM — defeating the whole point for large files. Reopening the
map keeps saving O(1) in memory.

### 3.6 Regions / data-folds

The brief wants memory sections shown as **foldable regions**, with inaccessible
sections **hidden by default**. This is purely a *presentation* concern — it must
not perturb offsets, editing, or the piece table — so it lives in its own model,
`regions::ViewMap`, separate from `Document`.

A `Region { start, len, label, accessible, folded }` describes a span. Given the
document length, the region set, and the bytes-per-row, `ViewMap::build` produces
the ordered list of **visual rows**: contiguous data spans become runs of data
rows; folded (or inaccessible) regions collapse to a single marker row. It
precomputes per-block row counts and offset ranges so two mappings are fast:

- `row(visual_row) -> Data{base_offset} | Fold{region}` — what to draw for a row
  (binary search by row).
- `offset_to_row(offset) -> visual_row` — where the cursor is, so the view can
  scroll to it even when folds change the row geometry.

Keeping this as a pure function of `(len, regions, bpr)` means it is trivially
unit-testable (folding, hiding, multiple/overlapping/out-of-range regions,
offset↔row round-trips) and the hex view stays a thin renderer over it. Editing
and keyboard navigation deliberately remain in raw offset space; folding only
changes what is *drawn*, never what the bytes *are*.

---

## 4. The operations layer (`ops/`)

Operations are decoupled from the GUI: each takes a reader (or paths) and a
`Progress`, returns data, and is unit-tested. This keeps them reusable (a CLI
could drive them) and testable without a window.

### 4.1 `Progress`: cooperative cancellation and ETA

A small `Arc` of atomics (`done`, `total`, `cancel`, `finished`). Workers update
`done`/check `cancel` in their inner loop; the UI reads `fraction()` for the
progress bar and computes ETA from wall-clock elapsed. Cancellation is
cooperative (no thread killing), which is safe and simple: the worker notices the
flag at the next chunk boundary and returns.

### 4.2 Search: streaming, windowed, multi-type

Search never loads the document. It scans in 1 MiB windows that **overlap by
`needle.len() - 1`** so a match straddling a window boundary is still found
(test: `cross_window_boundary`). Needles are parsed from text, UTF-16, hex,
integers (8/16/32/64) and floats (32/64) with selectable endianness into raw
bytes, so the scanner itself only ever does a byte comparison. `replace_all`
collects match positions first, then applies them **back-to-front** so that
length-changing replacements don't invalidate the offsets of pending matches.

### 4.3 Checksums: one pass, many algorithms

`compute` takes a list of algorithms and feeds each streamed chunk to *all* of
them in a single pass, so computing MD5 + SHA-256 + CRC-32 over a huge file reads
it once, not three times. Each algorithm is a variant of an internal `Engine`
enum wrapping the relevant crate (`sha1`, `sha2`, `md-5`, `crc`, `crc32fast`,
`adler`). Correctness is pinned to published test vectors (e.g. SHA-256 of
`"abc"`, empty-input digests).

### 4.4 Statistics: distribution, entropy, a classification hint

A single streaming pass builds a 256-bin histogram, from which we compute Shannon
entropy (bits/byte) and a coarse classification (text / binary / high-entropy
"compressed-or-encrypted" / uniform). The view draws the histogram with the
painter. This is the "helps identify the data type of a selection" feature.

### 4.5 Export: 25 formats from one builder

Most source-code exporters are the same shape: a header, indented rows of
per-byte literals, a footer. So they are all one function, `array(...)`,
parameterized by header/footer/sep/per-line and a per-byte formatting closure.
Adding Go, Swift, Kotlin, JS, TS, Ruby, PHP, Perl was then nearly free; only the
ones with genuinely different shapes (Pascal `$xx`, VB.NET `&Hxx` with line
continuations, NASM `db` per line, the hex-dump/HTML/RTF/TeX/Markdown text
formats, Base64, Intel HEX and Motorola S-record with their checksums) have
dedicated code. `export_bytes` works on a slice so every format is unit-tested
without a document.

### 4.6 File tools

Path-based, so they are trivially `Send` and run on a worker thread:

- **Shredder** — multi-pass overwrite then delete. The code and the UI are
  *honest* that on SSDs and copy-on-write filesystems an in-place overwrite may
  not reach the original blocks; we don't promise forensic erasure we can't
  guarantee.
- **Split / concat / compare** — straightforward streaming with progress. Compare
  reports the first differing offset and the two lengths.

---

## 5. The GUI layer (`ui/`)

### 5.1 Why `app.rs` + `app_ui.rs` via `include!`

`App` is one struct with a lot of state and a lot of methods. Splitting state and
core logic (`app.rs`) from the rendering methods (`app_ui.rs`) keeps each file
readable, but the two halves are deeply coupled (the rendering methods mutate the
same `App`). Rather than fight Rust's borrow checker across module boundaries with
awkward helper signatures, `app.rs` does `include!("app_ui.rs")`, so both files
compile as **one module** sharing one set of imports and one `impl App`. It is a
pragmatic choice that buys file-level organization without artificial seams.

### 5.2 Rendering the hex view

Each visible row is built as an egui `LayoutJob` — a sequence of colored text
spans. Per-byte coloring (cursor nibble, selection background, modified=amber,
null=dim, non-printable=dim) is expressed as the `background`/`color` of each
span, so there is **no manual painting** of the grid: egui lays out and draws the
monospace text, which is what keeps it flicker-free and fast. `hexview.rs` holds
the pure geometry:

- `Layout` computes column positions from bytes-per-row, byte **grouping**
  (1/2/4/8/16 packed per column), address-digit width (grows with document size),
  and view mode (hex+text / hex-only / text-only).
- `col_to_byte` is the inverse used for **mouse hit-testing**: a click's pixel x is
  divided by the monospace glyph width to get a character column, which maps back
  to (byte, pane, nibble). This is exact because the font is monospace.

Virtualization is `ScrollArea::show_rows`, fed `ViewMap::total_rows()`; only the
visible row range is built each frame.

### 5.3 Input handling

Keyboard handling reads egui's event stream once per frame and splits it:

- **`Event::Text`** drives *content* entry — hex digits in the hex pane, raw bytes
  in the text pane — because text events already handle layout/IME correctly.
- **`Event::Key`** drives *control* (arrows, page up/down, home/end, Tab to switch
  pane, Insert to toggle overwrite/insert, Delete/Backspace) and *shortcuts*
  (`Ctrl` combos, plus bookmark `Ctrl`/`Ctrl+Shift`+digit).

Hex editing tracks an offset **and a nibble** (high/low), so typing `D` then `E`
writes one byte; `Ctrl+←/→` step by a single nibble. Keyboard handling is skipped
entirely when a dialog text field has focus (`ctx.wants_keyboard_input()`) or an
operation is running, so typing in a search box never edits the document.

### 5.4 Background operations and the progress window

`start_bg` spawns a thread that takes a `Progress` and a moved-in `DocReader`
snapshot (or paths) and returns a `BgOutcome`. The UI never blocks: each frame,
`poll_bg` checks `JoinHandle::is_finished()`, joins when done, and applies the
outcome. While a task runs, the app requests repaints (~60 ms) so the progress
bar, elapsed time and ETA animate, and the modal progress window offers Cancel.
This is the "responsive interface with progress indicators and remaining-time for
lengthy operations" requirement, implemented without ever locking the document.

### 5.5 Theme

A dark phosphor-green terminal palette in `theme.rs`, applied once at startup.
Monospace throughout, amber for modified bytes / selections / warnings, red for
error statuses. The "hacker-esque" look is entirely styling over standard egui
widgets, so it costs nothing in complexity.

### 5.6 Printing and CLI

- **Printing** is deliberately not a native print pipeline (there is no good
  cross-platform one in pure Rust). Instead it renders the HTML hex-dump exporter
  to a temp file and opens it with the OS default handler (`open` / `xdg-open` /
  `start`), letting the browser handle print and PDF export. Reuses the export
  layer; zero new heavy dependencies.
- **CLI** is a tiny hand-rolled parser in `run()`: an optional file/device path to
  open on startup, plus `--help`/`--version` that print and exit before creating a
  window. No `clap` dependency for two flags.

---

## 6. Cross-cutting decisions

- **No artificial size limits.** Offsets are `u64` end to end; the address gutter
  widens automatically; nothing reads the whole input except explicit
  "materialize" paths (`to_vec`, used only for small/test cases).
- **Threading model.** Exactly one background task at a time, communicating
  through atomics and a join handle. No shared mutable state, no locks on the hot
  path, no data races possible by construction (read-only snapshots).
- **Errors are surfaced, not hidden.** Failed opens/saves/operations set a status
  message that the status bar renders in red. The shredder's limitations are
  stated in the UI.
- **Dependencies are minimal and load-bearing.** egui/eframe (GUI), memmap2
  (instant open), rfd (native file dialogs), and the hashing crates. Base64 and
  the CLI parser are hand-written to avoid pulling in crates for trivia.

---

## 7. Testing strategy

The engine and operations are covered by **77 tests** because they encode
invariants that are easy to break and expensive to debug through the GUI:

- **Piece table** — every edit shape, reads across piece boundaries,
  overwrite-spanning-pieces, full-delete-then-type, undo/redo chains, save/reopen
  round-trip, snapshot independence, out-of-range clamping. (Two real bugs were
  found this way; the tests are now regression guards.)
- **Operations** — search across window boundaries and all needle types,
  length-changing replace, checksum/digest published vectors, entropy and
  classification, region view-map geometry, file split/concat/compare round-trips.
- **Pure UI helpers** — layout column math and hit-testing, address parsing,
  size formatting — tested directly even though they live in the `ui` module.

The GUI itself is validated by launching it (debug and release) and by keeping the
rendering a thin, mostly-pure function of well-tested models.

---

## 8. Analysis, scanning and patching

A second wave of features was added; all follow the same rule as §4 — pure logic
over `&dyn ByteReader` or byte slices, decoupled from the GUI and unit-tested.

- **Data inspector** (`inspect.rs`) decodes the bytes at the cursor as ~18 types
  at once (ints/floats, ASCII/UTF-8, uLEB128, RGB(A), `time_t`, `FILETIME`, DOS
  date/time, GUID). Date conversion is done **arithmetically** via Howard
  Hinnant's `civil_from_days` rather than pulling in a time-zone library — a few
  lines, no dependency, and exactly testable against known epochs.

- **Value scanner** (`scan.rs`) is the engine behind memory/save editing. The key
  design point is that it is a *two-phase* operation: `first_scan` finds every
  offset equal to a typed value; `refine` then filters a candidate set as the
  data changes (`Eq`/`Changed`/`Unchanged`/`Increased`/`Decreased`/`>`/`<`),
  carrying each candidate's last-seen bytes so comparative predicates work without
  re-reading the whole input. Because it is written against `ByteReader`, the same
  code scans a save file today and will scan live process memory the moment a
  process-backed `DataSource` exists — no scanner changes needed. Results are
  capped to bound memory.

- **Signatures / binwalk** (`signatures.rs`) is a single streaming pass that, at
  each byte, checks only the signatures whose first byte matches (bucketed by
  first byte) — so adding more signatures costs almost nothing per byte. It finds
  embedded formats, archives, executables and crypto constants (the AES S-box and
  SHA-256 round-constant prefixes are strong, low-false-positive fingerprints).

- **Entropy map** (`stats::entropy_map`) samples up to 64 KiB per bucket rather
  than reading every byte, so the overview strip is cheap even on a multi-GB
  input — the visualization's job is to *locate* high-entropy regions, not measure
  them to four decimals.

- **Transforms** (`transform.rs`) are pure in-place byte ops on a selection
  (XOR/rotate/shift/swap/…), applied through the piece table like any edit, so
  they are undoable.

- **IPS patches** (`patch.rs`) implement the classic format: `make_ips` diffs two
  buffers into records (splitting runs at the 0xFFFF size limit, erroring on the
  16 MiB address ceiling and the reserved `EOF` offset), `parse_ips` turns a patch
  back into `(offset, bytes)` writes (expanding RLE records). Applying a patch
  replays those writes through `Document::overwrite`, so it is undoable and
  extends the file when a record runs past the end.

- **Checksum repair** reuses the existing digest engine plus one helper that
  writes a hex digest back at the cursor — the common workflow of fixing a save's
  checksum field after editing.

The GUI wiring stays thin: read-only scans (`scan`, `signatures`, `strings`) run
on a worker thread via the `Send` snapshot and a `BgOutcome` variant; `refine`,
transforms, patch-apply and the inspector are fast and run inline.

## 9. Visualization, disassembly, templates and live memory

A further wave added the "heavy" features. The first three keep the same
pure-core discipline; the fourth required a small engine addition.

- **Byte map** (`byteplot.rs`) maps each pixel to a sampled byte, colored by
  class, so structure is visible at a glance. The color and pixel→offset
  functions are pure and tested; the UI uploads the RGBA buffer as an egui
  texture and reverses the mapping on click.

- **Detailed diff** (`diff.rs`) streams two sources and groups differing bytes
  into ranges (with a length-mismatch tail and a cap), complementing the simple
  first-difference `fileops::compare`.

- **Disassembly** (`disasm.rs`) is the one place a dependency earns its keep:
  `iced-x86` is a pure-Rust x86/x64 decoder (no C toolchain), so it stays within
  the "one `cargo build`" promise. It decodes from a bounded window at the cursor
  and is tested against known encodings, including how bitness changes decoding.

- **Binary templates** (`template.rs`) are the biggest usability lever and were
  built *without* a dependency: a compact line-oriented DSL (`magic`, `le/be`,
  `u8..u64/i8..i64/f32/f64`, `ascii/bytes` with literal-or-field-reference
  lengths, `skip`) plus an interpreter that walks a document into named, typed,
  click-to-jump fields. Field-reference lengths make length-prefixed structures
  parse correctly. Built-ins cover BMP/PNG/ELF/WAV/GIF.

- **Live process memory** (`data/process.rs`) is the only feature that touched
  the engine. `ProcessHandle` reads/writes another process and lists its mapped
  regions — macOS via Mach VM (`task_for_pid`, `mach_vm_read_overwrite/write/
  region`), Linux via `/proc/<pid>/mem` + `maps`, with a graceful stub elsewhere.
  `ProcessSource` implements `DataSource` over a chosen `[base, len)` window, so
  the *entire* editor — view, scanner, inspector, templates, disassembly — works
  on running memory unchanged; that reuse is the payoff of putting `DataSource`
  at the bottom of the stack. Writes are explicit (Edit ▸ Poke selection, and the
  scanner's "write to all matches"), because edits otherwise accumulate in the
  piece-table overlay rather than the process. The catch with cross-process
  access is privilege (root / `task_for_pid` / `ptrace`) and that it can't be
  exercised in CI — so the tests operate on our **own** process memory, which
  needs no privileges and genuinely verifies the read *and* write paths.

## 10. Privileges, persistence, editable structure and scripting

The latest wave rounds out the editing-focused features and is, again, mostly
pure cores with thin UI.

- **Privilege clarity for live memory.** Touching another process needs root /
  Administrator, and the worst experience is finding that out via a cryptic
  failure. So `data/process.rs` exposes `is_elevated()` and a per-OS
  `privilege_note()`, `open()` short-circuits to `open_self()` for our own PID,
  and failures return an explicit "administrator/root required" message *with the
  fix*. The Open-process dialog leads with a red ALL-CAPS banner and shows live
  elevation status; the menu entry itself is labeled "(root/admin for other
  PIDs)". The intent is that you cannot stumble into it unaware.

- **Write-through editing.** When a process is open, overwrite keystrokes poke
  the byte straight to RAM (`live_poke`), opening forces overwrite mode
  (insert/delete would desync addresses), and the status bar shows a red ⏺ LIVE
  chip. Combined with the scanner this is a complete trainer: scan → narrow →
  edit live.

- **Editable template fields.** Templates gained an `EditKind` per field and an
  `encode()` that turns a typed string back into bytes (width/endian-aware
  integers with range checks, floats, ascii, hex). The template window grows an
  inline editor, so a structure view becomes a structure *editor* — and it pokes
  the process too when one is live.

- **Annotations sidecar** (`sidecar.rs`). Bookmarks, regions and notes persist to
  a human-readable `<file>.ghx` next to the document, auto-loaded on reopen. The
  format is line-oriented and forward-compatible (unknown lines are skipped), so
  it hand-edits and diffs cleanly and is trivially round-trip tested.

- **Scripting** (`script.rs`). Embedded **Rhai** (pure Rust, sandboxed) runs a
  script against the selection or whole file via a small byte-buffer API
  (`read/write/len/push/fill/resize`) with captured `print` output. It is bounded
  by operation/size limits so a runaway loop can't hang the UI, and the buffer is
  recovered even when the script errors. Results apply through the piece table
  (undoable) and poke the process when live. This is the "turn the editor into a
  platform" lever — arbitrary batch transforms without recompiling.

## 11. Known limitations and future work

- **Folded cursor.** Navigation stays in offset space, so the cursor can sit
  inside a collapsed region (invisible until unfolded). A future version could
  auto-reveal or skip folded spans during keyboard movement.
- **Concurrent ops.** One background operation at a time. A small task queue would
  allow several.
- **Shredder on modern storage.** As stated, overwrite-in-place is best-effort on
  SSD/CoW; true erasure needs filesystem/device-specific support.
- **Native printing.** Currently delegated to the browser; a real print pipeline
  could be added per-platform.
- **RAM region discovery.** Regions are a general, user-driven feature; populating
  them automatically from OS memory maps (`/proc/.../maps`, Mach VM regions,
  `VirtualQuery`) when opening a memory source is a natural extension.

### Still on the list

Almost everything discussed has shipped (live process memory + write-through,
templates with editable fields, disassembly, byte-map + diff, scripting,
annotations, loud privilege handling). What remains is either unverifiable in
this environment or genuinely optional:

- **Windows process backend.** macOS and Linux are done and tested against our
  own memory; Windows would use `OpenProcess` + `Read/WriteProcessMemory` +
  `VirtualQueryEx` (the `windows`/`windows-sys` crate). It is deliberately a stub
  because there is no Windows target here to compile or test it against —
  shipping unverifiable platform FFI would be dishonest.
- **ARM/RISC-V disassembly.** `iced-x86` is x86-only; other ISAs need another
  decoder (likely `capstone`, a C dependency).
- **Multi-cursor editing.** Several independent carets is mostly a hex-view UI
  change with fiddly edge cases (simultaneous typing, overlapping edits).
- **Scripting reach.** The Rhai API is intentionally small (a byte buffer); it
  could grow document/region/search bindings and a script library.
