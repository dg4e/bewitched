//! Scripting via embedded Rhai.
//!
//! A script runs against an in-memory byte buffer (the selection, or the whole
//! document materialized) and can read/transform/extend it; the modified buffer
//! is written back by the caller. Execution is sandboxed (no file/OS access) and
//! bounded by an operation limit so a runaway loop can't hang the UI.

use std::cell::RefCell;
use std::rc::Rc;

use rhai::{Engine, EvalAltResult};

/// Built-in reusable scripts: (display name, source).
pub const LIBRARY: &[(&str, &str)] = &[
    (
        "XOR with 0xFF",
        "// invert every byte\nfor i in 0..len() {\n    write(i, read(i) ^ 0xFF);\n}\n",
    ),
    (
        "ROT13 (ASCII letters)",
        "for i in 0..len() {\n    let c = read(i);\n    if c >= 0x41 && c <= 0x5A { write(i, 0x41 + (c - 0x41 + 13) % 26); }\n    else if c >= 0x61 && c <= 0x7A { write(i, 0x61 + (c - 0x61 + 13) % 26); }\n}\n",
    ),
    (
        "Reverse bytes",
        "let n = len();\nfor i in 0..(n / 2) {\n    let a = read(i);\n    write(i, read(n - 1 - i));\n    write(n - 1 - i, a);\n}\n",
    ),
    ("Uppercase (ASCII)", "to_upper();\n"),
    (
        "Increment every byte",
        "for i in 0..len() { write(i, read(i) + 1); }\n",
    ),
    (
        "Report CRC-32 and size",
        "print(\"size: \" + len());\nprint(\"crc32: \" + crc32());\n",
    ),
    (
        "Annotate: fold the selection",
        "// mark the selection as a region named 'blob'\nif sel_len() > 0 {\n    add_region(sel_start(), sel_len(), \"blob\");\n    print(\"folded \" + sel_len() + \" bytes\");\n}\n",
    ),
];

/// Document context made available to a script (read-only).
#[derive(Clone, Copy, Default)]
pub struct ScriptCtx {
    /// Absolute cursor offset in the document.
    pub cursor: u64,
    /// Selection start, or -1 if there is no selection.
    pub sel_start: i64,
    /// Selection length in bytes (0 if no selection).
    pub sel_len: u64,
    /// Total document length.
    pub doc_len: u64,
    /// Offset within the document where the edited buffer (`data`) begins.
    pub scope_offset: u64,
}

/// Side effects a script can request, returned to the caller to apply.
#[derive(Default)]
pub struct ScriptResult {
    pub log: String,
    /// Move the cursor to this absolute offset.
    pub set_cursor: Option<u64>,
    /// Regions to add: (start, len, label).
    pub regions: Vec<(u64, u64, String)>,
    /// Notes to add: (offset, len, text).
    pub notes: Vec<(u64, u64, String)>,
}

/// Run `src` against `data`, mutating it in place. Returns captured `print`
/// output on success, or an error message. (Convenience wrapper that discards
/// document side effects; see [`run_with_ctx`].)
pub fn run(src: &str, data: &mut Vec<u8>) -> Result<String, String> {
    run_with_ctx(src, data, ScriptCtx::default()).map(|r| r.log)
}

/// Run `src` with a document context, returning captured output plus any
/// requested side effects (cursor move, regions, notes).
pub fn run_with_ctx(
    src: &str,
    data: &mut Vec<u8>,
    ctx: ScriptCtx,
) -> Result<ScriptResult, String> {
    let buf = Rc::new(RefCell::new(std::mem::take(data)));
    let log = Rc::new(RefCell::new(String::new()));
    let set_cursor: Rc<RefCell<Option<u64>>> = Rc::new(RefCell::new(None));
    let regions: Rc<RefCell<Vec<(u64, u64, String)>>> = Rc::new(RefCell::new(Vec::new()));
    let notes: Rc<RefCell<Vec<(u64, u64, String)>>> = Rc::new(RefCell::new(Vec::new()));

    // Upper bound on the script's working buffer. Rhai's `set_max_array_size` /
    // `set_max_string_size` only bound *Rhai's own* arrays/strings, NOT our
    // custom `Vec<u8>`, so without this an `resize(huge, 0)` would OOM/abort.
    const MAX_BUF: usize = 256 * 1024 * 1024;

    let mut engine = Engine::new();
    engine.set_max_operations(50_000_000);
    engine.set_max_call_levels(64);
    engine.set_max_string_size(64 * 1024 * 1024);
    engine.set_max_array_size(64 * 1024 * 1024);

    // ---- buffer API ----
    {
        let b = buf.clone();
        engine.register_fn("len", move || b.borrow().len() as i64);
    }
    {
        let b = buf.clone();
        engine.register_fn("read", move |i: i64| {
            b.borrow().get(i as usize).copied().unwrap_or(0) as i64
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("write", move |i: i64, v: i64| {
            let idx = i as usize;
            let mut bb = b.borrow_mut();
            if idx < bb.len() {
                bb[idx] = v as u8;
            }
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("push", move |v: i64| {
            let mut bb = b.borrow_mut();
            if bb.len() < MAX_BUF {
                bb.push(v as u8);
            }
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("fill", move |start: i64, count: i64, v: i64| {
            let mut bb = b.borrow_mut();
            let s = (start.max(0) as usize).min(bb.len());
            let e = (start.saturating_add(count).max(0) as usize).min(bb.len());
            for x in bb[s..e].iter_mut() {
                *x = v as u8;
            }
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("resize", move |n: i64, v: i64| {
            let n = (n.max(0) as usize).min(MAX_BUF);
            b.borrow_mut().resize(n, v as u8)
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("insert", move |i: i64, v: i64| {
            let mut bb = b.borrow_mut();
            if bb.len() >= MAX_BUF {
                return;
            }
            let idx = (i.max(0) as usize).min(bb.len());
            bb.insert(idx, v as u8);
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("remove", move |i: i64, n: i64| {
            let mut bb = b.borrow_mut();
            let start = (i.max(0) as usize).min(bb.len());
            let end = start.saturating_add(n.max(0) as usize).min(bb.len());
            bb.drain(start..end);
        });
    }
    {
        let b = buf.clone();
        // index of byte `v` at or after `from`, or -1
        engine.register_fn("find_byte", move |v: i64, from: i64| {
            let bb = b.borrow();
            let start = (from.max(0) as usize).min(bb.len());
            bb[start..]
                .iter()
                .position(|&x| x == v as u8)
                .map(|p| (p + start) as i64)
                .unwrap_or(-1)
        });
    }
    {
        let b = buf.clone();
        // index of the first occurrence of an ASCII substring, or -1
        engine.register_fn("find_str", move |needle: &str| {
            let bb = b.borrow();
            let n = needle.as_bytes();
            if n.is_empty() || n.len() > bb.len() {
                return -1i64;
            }
            (0..=bb.len() - n.len())
                .find(|&i| &bb[i..i + n.len()] == n)
                .map(|i| i as i64)
                .unwrap_or(-1)
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("count", move |v: i64| {
            b.borrow().iter().filter(|&&x| x == v as u8).count() as i64
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("sum", move || {
            b.borrow().iter().map(|&x| x as i64).sum::<i64>()
        });
    }
    // ---- typed multi-byte accessors ----
    fn rd_uint(bb: &[u8], i: usize, n: usize, le: bool) -> Option<u64> {
        if i + n > bb.len() {
            return None;
        }
        let mut v = 0u64;
        if le {
            for k in (0..n).rev() {
                v = (v << 8) | bb[i + k] as u64;
            }
        } else {
            for k in 0..n {
                v = (v << 8) | bb[i + k] as u64;
            }
        }
        Some(v)
    }
    fn wr_uint(bb: &mut [u8], i: usize, n: usize, le: bool, v: u64) {
        if i + n > bb.len() {
            return;
        }
        for k in 0..n {
            let shift = if le { k } else { n - 1 - k } * 8;
            bb[i + k] = (v >> shift) as u8;
        }
    }
    fn sign_ext(v: u64, n: usize) -> i64 {
        let s = 64 - n * 8;
        ((v << s) as i64) >> s
    }
    for (name, n, signed) in [
        ("read_u16", 2, false),
        ("read_u32", 4, false),
        ("read_u64", 8, false),
        ("read_i16", 2, true),
        ("read_i32", 4, true),
        ("read_i64", 8, true),
    ] {
        let b = buf.clone();
        engine.register_fn(name, move |i: i64, le: bool| {
            match rd_uint(&b.borrow(), i.max(0) as usize, n, le) {
                Some(v) if signed => sign_ext(v, n),
                Some(v) => v as i64,
                None => 0,
            }
        });
    }
    for (name, n) in [("write_u16", 2), ("write_u32", 4), ("write_u64", 8)] {
        let b = buf.clone();
        engine.register_fn(name, move |i: i64, v: i64, le: bool| {
            wr_uint(&mut b.borrow_mut(), i.max(0) as usize, n, le, v as u64);
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("read_f32", move |i: i64, le: bool| {
            rd_uint(&b.borrow(), i.max(0) as usize, 4, le)
                .map(|v| f32::from_bits(v as u32) as f64)
                .unwrap_or(0.0)
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("read_f64", move |i: i64, le: bool| {
            rd_uint(&b.borrow(), i.max(0) as usize, 8, le)
                .map(f64::from_bits)
                .unwrap_or(0.0)
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("crc32", move || {
            crc32fast::hash(&b.borrow()) as i64
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("to_upper", move || {
            b.borrow_mut().iter_mut().for_each(|x| x.make_ascii_uppercase());
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("to_lower", move || {
            b.borrow_mut().iter_mut().for_each(|x| x.make_ascii_lowercase());
        });
    }
    {
        let b = buf.clone();
        // hex dump of a range, for printing
        engine.register_fn("hex", move |start: i64, len: i64| {
            let bb = b.borrow();
            let s = (start.max(0) as usize).min(bb.len());
            let e = (s + len.max(0) as usize).min(bb.len());
            bb[s..e]
                .iter()
                .map(|x| format!("{:02x}", x))
                .collect::<Vec<_>>()
                .join(" ")
        });
    }

    // ---- document context bindings ----
    engine.register_fn("cursor", move || ctx.cursor as i64);
    engine.register_fn("doc_len", move || ctx.doc_len as i64);
    engine.register_fn("scope_offset", move || ctx.scope_offset as i64);
    engine.register_fn("sel_start", move || ctx.sel_start);
    engine.register_fn("sel_len", move || ctx.sel_len as i64);
    {
        let sc = set_cursor.clone();
        engine.register_fn("set_cursor", move |i: i64| {
            *sc.borrow_mut() = Some(i.max(0) as u64);
        });
    }
    {
        let r = regions.clone();
        engine.register_fn("add_region", move |start: i64, len: i64, label: &str| {
            r.borrow_mut()
                .push((start.max(0) as u64, len.max(0) as u64, label.to_string()));
        });
    }
    {
        let n = notes.clone();
        engine.register_fn("add_note", move |off: i64, len: i64, text: &str| {
            n.borrow_mut()
                .push((off.max(0) as u64, len.max(0) as u64, text.to_string()));
        });
    }

    // ---- print capture ----
    {
        let l = log.clone();
        engine.on_print(move |s| {
            let mut log = l.borrow_mut();
            log.push_str(s);
            log.push('\n');
        });
    }
    {
        let l = log.clone();
        engine.on_debug(move |s, _, _| {
            let mut log = l.borrow_mut();
            log.push_str(s);
            log.push('\n');
        });
    }

    let result = engine.run(src);

    // Reclaim the buffer and side-effects regardless of outcome (drop the engine
    // first so the closures holding clones are released).
    drop(engine);
    let recovered = Rc::try_unwrap(buf)
        .map(|c| c.into_inner())
        .unwrap_or_default();
    *data = recovered;

    match result {
        Ok(()) => Ok(ScriptResult {
            log: Rc::try_unwrap(log).map(|c| c.into_inner()).unwrap_or_default(),
            set_cursor: Rc::try_unwrap(set_cursor).map(|c| c.into_inner()).unwrap_or_default(),
            regions: Rc::try_unwrap(regions).map(|c| c.into_inner()).unwrap_or_default(),
            notes: Rc::try_unwrap(notes).map(|c| c.into_inner()).unwrap_or_default(),
        }),
        Err(e) => Err(format_err(&e)),
    }
}

fn format_err(e: &EvalAltResult) -> String {
    let pos = e.position();
    if pos.is_none() {
        e.to_string()
    } else {
        format!("{e} (line {})", pos.line().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_whole_buffer() {
        let mut data = vec![0x00, 0x0F, 0xF0, 0xFF];
        let out = run("for i in 0..len() { write(i, read(i) ^ 0xFF); }", &mut data).unwrap();
        assert_eq!(data, vec![0xFF, 0xF0, 0x0F, 0x00]);
        assert!(out.is_empty());
    }

    #[test]
    fn print_is_captured() {
        let mut data = vec![1, 2, 3];
        let out = run(r#"print("len is " + len());"#, &mut data).unwrap();
        assert_eq!(out.trim(), "len is 3");
    }

    #[test]
    fn push_and_resize_extend() {
        let mut data = vec![1u8];
        run("push(2); push(3); resize(5, 9);", &mut data).unwrap();
        assert_eq!(data, vec![1, 2, 3, 9, 9]);
    }

    #[test]
    fn fill_range() {
        let mut data = vec![0u8; 8];
        run("fill(2, 3, 0xAA);", &mut data).unwrap();
        assert_eq!(data, vec![0, 0, 0xAA, 0xAA, 0xAA, 0, 0, 0]);
    }

    #[test]
    fn out_of_range_write_ignored() {
        let mut data = vec![0u8; 2];
        run("write(100, 1); write(0, 7);", &mut data).unwrap();
        assert_eq!(data, vec![7, 0]);
    }

    #[test]
    fn syntax_error_reports() {
        let mut data = vec![0u8; 1];
        let err = run("this is not valid", &mut data).unwrap_err();
        assert!(!err.is_empty());
        // buffer preserved on error
        assert_eq!(data, vec![0u8]);
    }

    #[test]
    fn insert_and_remove() {
        let mut data = vec![1u8, 2, 3];
        run("insert(1, 9); remove(3, 1);", &mut data).unwrap();
        // insert 9 at idx1 -> [1,9,2,3]; remove 1 at idx3 -> [1,9,2]
        assert_eq!(data, vec![1, 9, 2]);
    }

    #[test]
    fn find_and_count() {
        let mut data = b"abcabc".to_vec();
        let out = run(
            r#"print(find_byte(0x62, 0)); print(find_str("cab")); print(count(0x61));"#,
            &mut data,
        )
        .unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines, vec!["1", "2", "2"]); // 'b'@1, "cab"@2, 'a' x2
    }

    #[test]
    fn sum_and_hex() {
        let mut data = vec![0x01, 0x02, 0xFF];
        let out = run(r#"print(sum()); print(hex(0, 2));"#, &mut data).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "258"); // 1+2+255
        assert_eq!(lines[1], "01 02");
    }

    #[test]
    fn find_missing_returns_minus_one() {
        let mut data = vec![1u8, 2, 3];
        let out = run(r#"print(find_byte(0x99, 0)); print(find_str("zzz"));"#, &mut data).unwrap();
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["-1", "-1"]);
    }

    #[test]
    fn typed_read_write() {
        let mut data = vec![0u8; 8];
        // write 0x1234 LE at 0, read it back; write a u32 BE at 4
        let out = run(
            r#"write_u16(0, 0x1234, true); print(read_u16(0, true)); write_u32(4, 0xDEADBEEF, false); print(read_u32(4, false));"#,
            &mut data,
        )
        .unwrap();
        assert_eq!(data[0], 0x34);
        assert_eq!(data[1], 0x12);
        assert_eq!(&data[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "4660"); // 0x1234
        assert_eq!(lines[1], "3735928559"); // 0xDEADBEEF
    }

    #[test]
    fn signed_read() {
        let mut data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let out = run("print(read_i16(0, true)); print(read_u16(0, true));", &mut data).unwrap();
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["-1", "65535"]);
    }

    #[test]
    fn crc32_and_case() {
        let mut data = b"Hello".to_vec();
        let out = run("print(crc32()); to_lower(); print(crc32());", &mut data).unwrap();
        assert_eq!(data, b"hello");
        let lines: Vec<&str> = out.lines().collect();
        // CRC32 of "Hello" = 0xF7D18982 = 4157704578
        assert_eq!(lines[0], "4157704578");
        assert_ne!(lines[0], lines[1]); // changed after lowercasing
    }

    #[test]
    fn library_scripts_all_run() {
        for (name, src) in LIBRARY {
            let mut data = b"Hello, World! 12345".to_vec();
            let ctx = ScriptCtx { sel_start: 0, sel_len: 4, doc_len: data.len() as u64, ..Default::default() };
            assert!(
                run_with_ctx(src, &mut data, ctx).is_ok(),
                "library script '{name}' failed to run"
            );
        }
    }

    #[test]
    fn context_bindings_readable() {
        let mut data = vec![0u8; 4];
        let ctx = ScriptCtx {
            cursor: 0x40,
            sel_start: 0x10,
            sel_len: 8,
            doc_len: 0x100,
            scope_offset: 0x10,
        };
        let out = run_with_ctx(
            "print(cursor()); print(doc_len()); print(sel_start()); print(scope_offset());",
            &mut data,
            ctx,
        )
        .unwrap();
        assert_eq!(out.log.lines().collect::<Vec<_>>(), vec!["64", "256", "16", "16"]);
    }

    #[test]
    fn script_emits_side_effects() {
        let mut data = vec![0u8; 16];
        let r = run_with_ctx(
            r#"set_cursor(0x80); add_region(0, 8, "header"); add_note(4, 2, "magic");"#,
            &mut data,
            ScriptCtx::default(),
        )
        .unwrap();
        assert_eq!(r.set_cursor, Some(0x80));
        assert_eq!(r.regions, vec![(0, 8, "header".to_string())]);
        assert_eq!(r.notes, vec![(4, 2, "magic".to_string())]);
    }

    #[test]
    fn no_selection_reports_minus_one() {
        let mut data = vec![0u8];
        let ctx = ScriptCtx { sel_start: -1, ..Default::default() };
        let out = run_with_ctx("print(sel_start());", &mut data, ctx).unwrap();
        assert_eq!(out.log.trim(), "-1");
    }

    #[test]
    fn checksum_like_computation() {
        let mut data = vec![1u8, 2, 3, 4, 5];
        let out = run(
            "let s = 0; for i in 0..len() { s += read(i); } print(s);",
            &mut data,
        )
        .unwrap();
        assert_eq!(out.trim(), "15");
    }

    #[test]
    fn resize_growth_is_capped() {
        // A huge resize must clamp to MAX_BUF rather than OOM/abort the process.
        let mut data = vec![0u8; 4];
        assert!(run("resize(999999999999, 0);", &mut data).is_ok());
        assert_eq!(data.len(), 256 * 1024 * 1024);
    }

    #[test]
    fn fill_and_remove_survive_overflowing_args() {
        // start+count / start+n must not overflow-panic on absurd arguments.
        let mut data = vec![1u8; 8];
        assert!(run("fill(0, 99999999999999, 7);", &mut data).is_ok());
        assert_eq!(data, vec![7u8; 8]);
        let mut data2 = vec![1u8; 8];
        assert!(run("remove(0, 99999999999999);", &mut data2).is_ok());
        assert!(data2.is_empty());
    }

    #[test]
    fn cannot_reach_filesystem_or_os() {
        // The sandbox registers only the byte-buffer API; OS/file builtins are
        // absent, so any such call is a compile/runtime error, never an escape.
        let mut data = vec![0u8; 1];
        assert!(run("open_file(\"/etc/passwd\");", &mut data).is_err());
        assert!(run("system(\"id\");", &mut data).is_err());
    }
}
