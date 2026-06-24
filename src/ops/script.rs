//! Scripting via embedded Rhai.
//!
//! A script runs against an in-memory byte buffer (the selection, or the whole
//! document materialized) and can read/transform/extend it; the modified buffer
//! is written back by the caller. Execution is sandboxed (no file/OS access) and
//! bounded by an operation limit so a runaway loop can't hang the UI.

use std::cell::RefCell;
use std::rc::Rc;

use rhai::{Engine, EvalAltResult};

/// Run `src` against `data`, mutating it in place. Returns captured `print`
/// output (one entry per line) on success, or an error message.
pub fn run(src: &str, data: &mut Vec<u8>) -> Result<String, String> {
    let buf = Rc::new(RefCell::new(std::mem::take(data)));
    let log = Rc::new(RefCell::new(String::new()));

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
        engine.register_fn("push", move |v: i64| b.borrow_mut().push(v as u8));
    }
    {
        let b = buf.clone();
        engine.register_fn("fill", move |start: i64, count: i64, v: i64| {
            let mut bb = b.borrow_mut();
            let s = (start.max(0) as usize).min(bb.len());
            let e = ((start + count).max(0) as usize).min(bb.len());
            for x in bb[s..e].iter_mut() {
                *x = v as u8;
            }
        });
    }
    {
        let b = buf.clone();
        engine.register_fn("resize", move |n: i64, v: i64| {
            b.borrow_mut().resize(n.max(0) as usize, v as u8)
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

    // Reclaim the buffer regardless of outcome (drop the engine first so the
    // closures holding clones of `buf` are released).
    drop(engine);
    let recovered = Rc::try_unwrap(buf)
        .map(|c| c.into_inner())
        .unwrap_or_default();
    *data = recovered;
    let out = Rc::try_unwrap(log).map(|c| c.into_inner()).unwrap_or_default();

    match result {
        Ok(()) => Ok(out),
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
    fn checksum_like_computation() {
        let mut data = vec![1u8, 2, 3, 4, 5];
        let out = run(
            "let s = 0; for i in 0..len() { s += read(i); } print(s);",
            &mut data,
        )
        .unwrap();
        assert_eq!(out.trim(), "15");
    }
}
