# bewitched

A fast, cross-platform, hacker-esque **hex editor** for files, raw disks and RAM,
written in Rust with an immediate-mode (`egui`) GUI. It edits files of any size
(up to 8 EB) with instant opening, unlimited undo, and a streamlined,
task-oriented interface.

```
┌─ bewitched ──────────────────────────────────────────────────────────────────┐
│ File  Edit  View  Search  Tools  Help                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ 00000000  42 65 77 69 74 63 68 65  64 21 00 01 02 DE AD BE  Bewitched!...... │
│ 00000010  EF 20 54 68 65 20 71 75  69 63 6B 20 62 72 6F 77  . The quick brow │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Why it's fast on huge inputs

The core is a **piece-table over a `DataSource`**:

- Files are **memory-mapped** (`memmap2`) - opening is O(1) regardless of size.
- Edits never rewrite the backing store. Inserts/deletes/overwrites splice a list
  of *pieces* that point into either the original source or an append-only "add"
  buffer. An edit costs O(pieces), not O(file size).
- **Unlimited undo/redo** snapshots the (small) piece list, not the data.
- Disks and RAM are just other `DataSource`s, so they are presented and edited
  *as a whole*, like a file - not a sector/region-limited window.

Long operations (digests, statistics, shred/split/concat/compare) run on a worker
thread against a cheap, `Send` read-only snapshot of the document, with a
**progress window** showing elapsed time, ETA and a cancel button. The UI never
blocks.

## Features

- **Editing** like a text editor: overwrite/insert modes, cut/copy/paste
  (insert & overwrite), selection, unlimited undo/redo, modified bytes
  highlighted in amber.
- **Navigation**: arrows, page up/down, home/end, go-to-address (`Ctrl+G`),
  nibble stepping (`Ctrl+←/→`), 10 bookmarks (`Ctrl+Shift+0-9` to set,
  `Ctrl+0-9` to jump).
- **Search / replace** (`Ctrl+F`) for text, Unicode (UTF-16), hex, integers
  (8/16/32/64) and floats (32/64), little/big-endian, forward / backward /
  from-start, case-insensitive, streaming (never loads the whole file). Hex
  patterns support **`?` wildcards** (AOB scans), e.g. `DE ?? BE EF`.
- **Checksums & digests**: Checksum-8/16/32, Adler-32, CRC-16, CRC-32, CRC-64,
  MD5, SHA-1, SHA-256, SHA-512 - computed in one streaming pass; plus a
  **custom CRC** (Rocksoft model: any width/poly/init/refin/refout/xorout).
- **Statistics**: byte/character distribution chart, Shannon entropy, a
  data-type classification hint, and a sampled **entropy map** strip (click to
  jump) for spotting compressed/encrypted regions.
- **Data inspector**: live side panel decoding the bytes at the cursor as
  int/uint 8-64, float32/64, ASCII/UTF-8, uLEB128, RGB/RGBA, `time_t` (32/64),
  Windows `FILETIME`, DOS date/time and GUID, with LE/BE toggle.
- **Live process memory**: open a running process's memory (by PID + region) as
  a live view; hex-view edits **write through to RAM** (status shows ⏺ LIVE).
  macOS (Mach VM), Linux (`/proc/<pid>/mem`) and Windows
  (`Read/WriteProcessMemory`). ⚠ **Other processes need root / Administrator**
  (your own PID never does) - the dialog shows a loud banner and your current
  elevation status.
- **Value scanner** (memory/save editing): first-scan for a typed value, then
  refine (equal / changed / unchanged / increased / decreased) as the data
  changes - the "Cheat Engine" workflow - plus "write value to all matches" and
  **❄ freeze** (continuously re-poke a value into the live process).
- **Pointer scanning**: find 64-bit pointers that reference a target address
  (Tools ▸ Pointer scan), and **multi-level pointer chains** static→…→target
  (MCP `find_pointers` / `pointer_chains`).
- **Binary templates**: a small DSL parses a file into named, typed,
  click-to-jump fields you can **edit by value** and write back; built-ins for
  BMP/PNG/ELF/WAV/GIF.
- **Struct parser** (Kaitai-inspired, nested): a richer DSL parsing a binary
  into a collapsible **tree** - user-defined sub-types, `repeat`
  (count / end-of-stream / until), conditional fields (`if`), enums, and an
  expression language referencing earlier fields. Built-ins for PNG/GIF/ELF/WAV;
  also `parse_struct` (MCP) and `struct` (CLI).
- **Scripting (Rhai)**: run a sandboxed script over the selection/whole file
  with a rich byte API - `read/write`, typed `read_u16…u64`/`i16…i64`/`f32/f64`
  and `write_*` (with endianness), `insert/remove`, `find_byte/find_str`,
  `count/sum/crc32/hex`, `to_upper/to_lower`, document context
  (`cursor/sel_start/doc_len/…`) and side effects (`set_cursor/add_region/
  add_note`) - plus a **library** of built-in scripts (XOR, ROT13, reverse, …)
  and **user-saved scripts** (`Save script`, persisted to the config dir).
- **MCP server**: `bewitched --mcp` runs a Model Context Protocol server (JSON-RPC
  over stdio) advertising `tools`, `resources` and `prompts`. Read tools
  (read_hex, checksums, statistics, search, strings, signatures, disassemble,
  inspect, export, apply_template), write tools (write_bytes, transform,
  patch_create/apply, **script**), and **editing sessions** (open →
  session_read/write/insert/delete/undo/save/script/close) let an LLM/agent both
  analyze *and* edit binaries; resources expose templates/scripts/reference
  lists and prompts give canned analysis recipes.
- **Annotations**: bookmarks, regions and free-text notes persist to a
  human-readable `<file>.bw` sidecar (auto-loaded on reopen).
- **Disassembly** (14 architectures, pure Rust - no C dependency): x86-16/32/64
  (`iced-x86`), ARM A32 / Thumb / AArch64 (`yaxpeax-arm`), MIPS LE/BE
  (`yaxpeax-mips`), PowerPC (`ppc750cl`), RISC-V 32/64 (`raki`), MSP430
  (`yaxpeax-msp430`), 6502 (`yaxpeax-6502`) and SM83/Game Boy (`yaxpeax-sm83`) -
  pick the architecture in the disassembly window.
- **Multi-cursor editing**: Ctrl/Cmd+click adds extra carets; edits and paste
  (overwrite *and* insert mode) broadcast to all of them; backspace/delete too. Esc clears.
- **Byte map**: visualize the whole file as a colored image to spot structure;
  click a pixel to jump.
- **Transforms** on a selection: XOR/AND/OR/ADD/SUB/NOT, rotate, shift,
  reverse, byte-swap (endian) and ASCII case-flip.
- **Compression**: decompress (auto-detecting gzip/zlib) or compress a
  selection - gzip / zlib / raw deflate, pure Rust (no C dependency).
- **String extraction**: streaming ASCII + UTF-16LE scan with click-to-jump.
- **Signatures (binwalk)**: locate embedded file formats, archives, executables
  and crypto constants (AES S-box, SHA-256 constants).
- **IPS & BPS patches**: create a patch by diffing against an original, or apply
  one - IPS (classic, ≤16 MiB) and BPS (any size, CRC-validated). Standard
  formats for sharing ROM/save mods.
- **Checksum repair**: write a computed digest back at the cursor to fix
  checksum fields after editing.
- **Export** (25 formats): C / C++ / Pascal / Java / C# / VB.NET / Python /
  Rust / Go / Swift / Kotlin / JavaScript / TypeScript / NASM assembly / Ruby /
  PHP / Perl source; plain hex dump / HTML / Markdown / RTF / TeX / Base64; and
  Intel HEX / Motorola S-record.
- **Byte patterns**: insert / overwrite / fill-selection with a repeating hex
  pattern.
- **File tools**: secure shredder (multi-pass overwrite + delete), split,
  concatenate, and simple file compare.
- **Data-folds / regions**: fold any selection into a collapsible region;
  mark regions inaccessible to hide them (e.g. unreadable RAM sections, which
  are hidden by default). Click a fold marker to expand; manage all regions in
  a dialog.
- **Printing**: renders a hex dump and opens it in the system default viewer
  (browser), which can print or save as PDF.
- **Views**: ANSI / DOS (CP437) / EBCDIC / Macintosh character sets; byte
  grouping (1/2/4/8/16); hex-only / text-only / both; selectable column count.

## Build & run

```sh
cargo run --release                 # launch the GUI
cargo run --release -- file.bin     # open a file (or device path) on startup
cargo run --release -- --version    # print version and exit
cargo test                          # run the test suite (282 tests)
```

Requires a stable Rust toolchain. Builds on Windows, macOS and Linux.

### Headless CLI

A subcommand turns bewitched into a scriptable analysis tool (no GUI):

```sh
bewitched sha256 file.bin                  # also: md5 sha1 sha512 crc32 sum
bewitched dump   file.bin 0x40 256         # hex dump a range
bewitched strings file.bin 6               # extract strings (min length 6)
bewitched search file.bin 'DE ?? BE EF'    # wildcard byte search
bewitched disasm file.bin aarch64 0 40     # disassemble
bewitched sigs   firmware.bin              # binwalk-style signature scan
bewitched pointers dump.bin 0x140001000    # find pointers to an address
bewitched crc    file.bin 32 0x04C11DB7 0xFFFFFFFF rr 0xFFFFFFFF
bewitched struct file.png png              # parse a structure into a tree
bewitched bps    orig.bin mod.bin out.bps  # create a BPS patch
bewitched --help                           # full command list
```

### Editions / packaging

- **Portable edition** - `cargo build --release` produces a single,
  self-contained, stripped binary at `target/release/bewitched`. Copy it
  anywhere and run; no installation needed.
- **Installable edition** - native installers are produced from the metadata in
  `Cargo.toml`:
  ```sh
  cargo install cargo-bundle && cargo bundle --release   # .app/.dmg, .deb, .msi
  cargo install cargo-deb    && cargo deb                 # Debian .deb (Linux)
  ```

## MCP server

`bewitched --mcp` speaks the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0), so an LLM/agent can analyze binaries through bewitched's engine.
Point an MCP client at the binary:

```json
{
  "mcpServers": {
    "bewitched": { "command": "/path/to/bewitched", "args": ["--mcp"] }
  }
}
```

Read/analyze tools: `read_hex`, `checksums`, `statistics`, `histogram`,
`entropy_map`, `search`, `search_pattern` (wildcards), `find_pointers`,
`strings`, `signatures`, `disassemble` (14 architectures), `inspect`, `export`,
`apply_template`, `compare`, `custom_crc`, `pointer_chains` - each takes a file/device `path` and returns JSON,
e.g. `disassemble {path, offset, count, arch}`. Write tools: `write_bytes`,
`transform`, `patch_create`, `patch_apply`, `carve`, `decompress`, `compress`,
`script` (run Rhai over a range). Editing
sessions: `open` returns a session id, then
`session_read/write/insert/delete/undo/save/script/close` edit it through the
piece table (undoable; written on `session_save`).

The server also serves **resources** - built-in templates, built-in *and*
user-saved scripts (`bewitched://scripts/…`), reference lists, and a `file://`
template to read any file as a hex dump - plus **prompts** (`identify-file`,
`analyze-binary`, `find-secrets`).

### Security

By default the MCP server has **full filesystem access**: an absolute `path`
argument is passed straight through, so a connected LLM/agent can read and write
any file the process can. Relative paths resolve against a working directory
(`get_working_dir` / `set_working_dir`) but that is only a convenience, not a
sandbox.

To confine the server, set the environment variable `BEWITCHED_MCP_ROOT` to a
directory before launching it (e.g. `BEWITCHED_MCP_ROOT=/data/samples`). When set,
every resolved path argument - for both reads and writes - must stay inside that
root; anything that escapes it (including via `..`) is rejected with a JSON-RPC
error. Leaving the variable unset preserves the default (unconfined) behavior.

## Raw disk / RAM access

The **File ▸ Open disk / RAM** menu lists platform device paths
(`/dev/rdiskN`, `\\.\PhysicalDrive0`, `/dev/mem`, …). These require elevated
privileges to open - run with the appropriate permissions. The engine treats a
device exactly like a file, so all editing, searching and analysis features
apply.

## Layout

```
src/
  data/         engine
    source.rs   DataSource trait + mmap/file/memory sources
    document.rs piece-table, undo/redo, ByteReader trait + Send snapshot
    regions.rs  foldable regions ("data-folds") + offset/row view map
    process.rs  live process memory (Mach VM / proc / Win32) + ProcessSource
  ops/          feature operations (all unit-tested)
    search.rs   streaming multi-type find / replace
    checksum.rs streaming digests
    stats.rs    distribution + entropy
    export.rs   source / text / hex-file exporters
    pattern.rs  byte-pattern generation
    fileops.rs  shred / split / concat / compare
    inspect.rs  data inspector (typed decode of cursor bytes)
    transform.rs in-place byte transforms (xor/rotate/swap/...)
    strings.rs  ASCII + UTF-16 string extraction
    scan.rs     value scanner (first-scan + refine) + freeze
    pointer.rs  pointer scanning + multi-level chains
    signatures.rs binwalk-style format/crypto signature scan
    patch.rs    IPS patch create / parse / apply
    diff.rs     detailed binary diff (all differing ranges)
    byteplot.rs byte-as-pixel visualization
    disasm.rs   multi-arch disasm (14 ISAs, pure Rust): x86/ARM/MIPS/PPC/RISC-V/MSP430/6502/SM83
    template.rs flat binary template DSL + field encode
    kstruct.rs  nested Kaitai-style struct parser (types/repeat/if/enum/expr)
    compress.rs gzip/zlib/deflate (flate2, pure Rust)
    script.rs / script_store.rs  Rhai scripting + user script library
    script.rs   sandboxed Rhai scripting over a byte buffer
    sidecar.rs  persistent annotations (.bw): bookmarks/regions/notes
  cli.rs        headless CLI subcommands - bewitched sha256 FILE ...
  mcp.rs        MCP (Model Context Protocol) server - bewitched --mcp
  ui/           egui front-end
    app.rs / app_ui.rs   application state, menus, hex view, dialogs
    hexview.rs  column math, colored row building, click hit-testing
    charset.rs  ANSI / CP437 / EBCDIC / Mac Roman decoders
    theme.rs    phosphor-green terminal theme
```

## Status

Engine, feature operations and GUI are implemented and covered by **282 tests**
(`cargo test`), and the code is clippy-clean. Printing, data-folds/regions,
CLI file arguments and portable/installable packaging are wired up.

The secure shredder is best-effort: on SSDs and copy-on-write filesystems an
in-place overwrite is not guaranteed to hit the original blocks - the UI says so.
Raw disk/RAM device entries require elevated privileges to open.

## License

Copyright (C) 2026 Digital Gangster Enterprises, LLC.

bewitched is free software licensed under the **GNU General Public License,
version 3 or later** (GPL-3.0-or-later). See the [LICENSE](LICENSE) file for the
full text. You may redistribute and/or modify it under those terms; it comes with
no warranty.

## Credits

bewitched is by **ytcracker and clord**.
