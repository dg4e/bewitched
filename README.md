# ganghex

A fast, cross-platform, hacker-esque **hex editor** for files, raw disks and RAM
— written in Rust with an immediate-mode (`egui`) GUI. It edits files of any size
(up to 8 EB) with instant opening, unlimited undo, and a streamlined,
task-oriented interface.

```
┌─ ganghex ─────────────────────────────────────────────────────────┐
│ File  Edit  View  Search  Tools  Help                              │
├───────────────────────────────────────────────────────────────────┤
│ 00000000  48 65 6C 6C 6F 2C 20 67  61 6E 67 68 65 78 21 00  Hello, ganghex!·│
│ 00000010  01 02 DE AD BE EF 20 54  68 65 20 71 75 69 63 6B  ······ The quick│
└───────────────────────────────────────────────────────────────────┘
```

## Why it's fast on huge inputs

The core is a **piece-table over a `DataSource`**:

- Files are **memory-mapped** (`memmap2`) — opening is O(1) regardless of size.
- Edits never rewrite the backing store. Inserts/deletes/overwrites splice a list
  of *pieces* that point into either the original source or an append-only "add"
  buffer. An edit costs O(pieces), not O(file size).
- **Unlimited undo/redo** snapshots the (small) piece list, not the data.
- Disks and RAM are just other `DataSource`s, so they are presented and edited
  *as a whole*, like a file — not a sector/region-limited window.

Long operations (digests, statistics, shred/split/concat/compare) run on a worker
thread against a cheap, `Send` read-only snapshot of the document, with a
**progress window** showing elapsed time, ETA and a cancel button. The UI never
blocks.

## Features

- **Editing** like a text editor: overwrite/insert modes, cut/copy/paste
  (insert & overwrite), selection, unlimited undo/redo, modified bytes
  highlighted in amber.
- **Navigation**: arrows, page up/down, home/end, go-to-address (`Ctrl+G`),
  nibble stepping (`Ctrl+←/→`), 10 bookmarks (`Ctrl+Shift+0–9` to set,
  `Ctrl+0–9` to jump).
- **Search / replace** (`Ctrl+F`) for text, Unicode (UTF-16), hex, integers
  (8/16/32/64) and floats (32/64), little/big-endian, forward / backward /
  from-start, case-insensitive, streaming (never loads the whole file).
- **Checksums & digests**: Checksum-8/16/32, Adler-32, CRC-16, CRC-32, CRC-64,
  MD5, SHA-1, SHA-256, SHA-512 — computed in one streaming pass.
- **Statistics**: byte/character distribution chart, Shannon entropy, and a
  data-type classification hint.
- **Export**: C / Pascal / Java / C# / VB.NET / Python / Rust source,
  plain hex dump / HTML / Markdown / RTF / TeX, and Intel HEX / Motorola
  S-record.
- **Byte patterns**: insert / overwrite / fill-selection with a repeating hex
  pattern.
- **File tools**: secure shredder (multi-pass overwrite + delete), split,
  concatenate, and simple file compare.
- **Views**: ANSI / DOS (CP437) / EBCDIC / Macintosh character sets; byte
  grouping (1/2/4/8/16); hex-only / text-only / both; selectable column count.

## Build & run

```sh
cargo run --release          # launch the GUI
cargo test                   # run the engine/ops test suite
cargo run --release -- ...   # (file argument support is a natural next step)
```

Requires a stable Rust toolchain. Builds on Windows, macOS and Linux.

## Raw disk / RAM access

The **File ▸ Open disk / RAM** menu lists platform device paths
(`/dev/rdiskN`, `\\.\PhysicalDrive0`, `/dev/mem`, …). These require elevated
privileges to open — run with the appropriate permissions. The engine treats a
device exactly like a file, so all editing, searching and analysis features
apply.

## Layout

```
src/
  data/         engine
    source.rs   DataSource trait + mmap/file/memory sources
    document.rs piece-table, undo/redo, ByteReader trait + Send snapshot
  ops/          feature operations (all unit-tested)
    search.rs   streaming multi-type find / replace
    checksum.rs streaming digests
    stats.rs    distribution + entropy
    export.rs   source / text / hex-file exporters
    pattern.rs  byte-pattern generation
    fileops.rs  shred / split / concat / compare
  ui/           egui front-end
    app.rs / app_ui.rs   application state, menus, hex view, dialogs
    hexview.rs  column math, colored row building, click hit-testing
    charset.rs  ANSI / CP437 / EBCDIC / Mac Roman decoders
    theme.rs    phosphor-green terminal theme
```

## Status

Engine and feature operations are implemented and covered by tests. Several
listed capabilities (printing, raw RAM folding regions, portable/installer
packaging) are scaffolded by the architecture but not yet wired into the UI.
