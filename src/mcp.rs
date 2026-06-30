//! Model Context Protocol (MCP) server.
//!
//! Exposes bewitched's engine to an LLM/agent: read bytes, search, digests,
//! statistics, strings, signatures, disassembly (14 architectures), typed
//! inspection, export, templates, IPS patches, transforms, and full editing
//! **sessions** (open/read/write/insert/delete/undo/save) plus headless Rhai
//! `script` tools. Also serves MCP `resources` (built-in templates, the script
//! library, and reference lists) and `prompts` (canned analysis recipes).
//!
//! Transport is the standard MCP stdio transport: newline-delimited JSON-RPC 2.0
//! on stdin/stdout. Run with `bewitched --mcp`.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::data::Document;
use crate::ops::{
    checksum, diff, disasm, export, inspect, patch, script, search, signatures, stats, strings,
    template, transform, Progress,
};

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run an MCP server over stdio until EOF.
pub fn serve() -> std::io::Result<()> {
    Server::new().run_stdio()
}

/// Path argument keys whose (relative) values are resolved against the server's
/// working directory before a tool runs. Absolute paths are passed through.
const PATH_KEYS: &[&str] = &[
    "path", "output", "original", "modified", "patch", "path_a", "path_b",
];

/// MCP server state. Holds open editing sessions across `tools/call`s plus a
/// working directory that relative path arguments resolve against.
pub struct Server {
    sessions: HashMap<u64, Document>,
    next_id: u64,
    /// Base directory for resolving relative path arguments. The server still
    /// has full filesystem reach — absolute paths bypass it — this just gives
    /// relative paths a stable, agent-controllable anchor (see set_working_dir).
    cwd: PathBuf,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 0,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

impl Server {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a path argument: absolute paths are returned unchanged; relative
    /// ones are joined onto the working directory.
    fn resolve(&self, p: &str) -> PathBuf {
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }

    /// Return a copy of `args` with every known path key resolved to an absolute
    /// path, so downstream tool code (here and in `call_tool`) needs no changes.
    fn resolve_path_args(&self, args: &Value) -> Value {
        let mut a = args.clone();
        if let Some(obj) = a.as_object_mut() {
            for key in PATH_KEYS {
                if let Some(Value::String(s)) = obj.get(*key) {
                    let resolved = self.resolve(s).to_string_lossy().into_owned();
                    obj.insert((*key).to_string(), Value::String(resolved));
                }
            }
        }
        a
    }

    /// Run the server loop over stdin/stdout until EOF.
    pub fn run_stdio(&mut self) -> std::io::Result<()> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let err = error_response(&Value::Null, -32700, &format!("parse error: {e}"));
                    writeln!(out, "{err}")?;
                    out.flush()?;
                    continue;
                }
            };
            if let Some(resp) = self.handle(&req) {
                writeln!(out, "{resp}")?;
                out.flush()?;
            }
        }
        Ok(())
    }

    /// Handle one JSON-RPC request, returning a response (or `None` for notifications).
    pub fn handle(&mut self, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    // Notifications (no id) get no response.
    req.get("id")?;

    match method {
        "initialize" => Some(result_response(
            &id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {}, "resources": {}, "prompts": {} },
                "serverInfo": { "name": "bewitched", "version": env!("CARGO_PKG_VERSION") }
            }),
        )),
        "ping" => Some(result_response(&id, json!({}))),
        "tools/list" => Some(result_response(&id, json!({ "tools": tools_list() }))),
        "resources/list" => Some(result_response(&id, json!({ "resources": resources_list() }))),
        "resources/templates/list" => Some(result_response(
            &id,
            json!({ "resourceTemplates": resource_templates_list() }),
        )),
        "resources/read" => {
            let uri = req
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            match read_resource(uri, &self.cwd) {
                Ok(text) => Some(result_response(
                    &id,
                    json!({ "contents": [ { "uri": uri, "mimeType": "text/plain", "text": text } ] }),
                )),
                Err(e) => Some(error_response(&id, -32602, &e)),
            }
        }
        "prompts/list" => Some(result_response(&id, json!({ "prompts": prompts_list() }))),
        "prompts/get" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let pname = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let pargs = params.get("arguments").cloned().unwrap_or(json!({}));
            match get_prompt(pname, &pargs) {
                Ok(v) => Some(result_response(&id, v)),
                Err(e) => Some(error_response(&id, -32602, &e)),
            }
        }
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match self.dispatch_tool(name, &args) {
                Ok(text) => Some(result_response(
                    &id,
                    json!({ "content": [ { "type": "text", "text": text } ] }),
                )),
                Err(e) => Some(result_response(
                    &id,
                    json!({ "content": [ { "type": "text", "text": e } ], "isError": true }),
                )),
            }
        }
        _ => Some(error_response(&id, -32601, &format!("method not found: {method}"))),
    }
    }

    /// Dispatch a tool call. Session/write tools use server state; everything
    /// else delegates to the stateless `call_tool`.
    fn dispatch_tool(&mut self, name: &str, args: &Value) -> Result<String, String> {
        // Resolve relative path arguments against the working directory up front,
        // so every tool (and `call_tool`) sees absolute paths.
        let args = &self.resolve_path_args(args);
        match name {
            "get_working_dir" => Ok(json!({ "cwd": self.cwd.display().to_string() }).to_string()),
            "set_working_dir" => {
                // `path` is already resolved against the current cwd above, so a
                // relative arg like "samples" works as `cd`.
                let path = str_arg(args, "path")?;
                let meta = std::fs::metadata(path)
                    .map_err(|e| format!("set_working_dir '{path}': {e}"))?;
                if !meta.is_dir() {
                    return Err(format!("not a directory: {path}"));
                }
                self.cwd = std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
                Ok(json!({ "cwd": self.cwd.display().to_string() }).to_string())
            }
            "open" => {
                let path = str_arg(args, "path")?;
                let doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let len = doc.len();
                let id = self.next_id;
                self.next_id += 1;
                self.sessions.insert(id, doc);
                Ok(json!({ "session": id, "length": len }).to_string())
            }
            "session_close" => {
                let id = session_id(args)?;
                self.sessions.remove(&id);
                Ok(json!({ "closed": id }).to_string())
            }
            _ if name.starts_with("session_") => {
                let id = session_id(args)?;
                let off = u64_arg(args, "offset", 0);
                let doc = self.sessions.get_mut(&id).ok_or("no such session")?;
                match name {
                    "session_read" => {
                        let len = u64_arg(args, "length", 256);
                        Ok(export::export(doc, off, len, export::Format::PlainHexDump))
                    }
                    "session_write" => {
                        let bytes = parse_hex_arg(args)?;
                        doc.overwrite(off, &bytes);
                        Ok(json!({ "written": bytes.len(), "length": doc.len() }).to_string())
                    }
                    "session_insert" => {
                        let bytes = parse_hex_arg(args)?;
                        doc.insert(off, &bytes);
                        Ok(json!({ "inserted": bytes.len(), "length": doc.len() }).to_string())
                    }
                    "session_delete" => {
                        let len = u64_arg(args, "length", 0);
                        doc.delete(off, len);
                        Ok(json!({ "deleted": len, "length": doc.len() }).to_string())
                    }
                    "session_undo" => {
                        let ok = doc.can_undo();
                        doc.undo();
                        Ok(json!({ "undone": ok, "length": doc.len() }).to_string())
                    }
                    "session_script" => {
                        let src = resolve_script(args)?;
                        let len = args
                            .get("length")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(doc.len().saturating_sub(off));
                        let mut data = doc.read_range(off, len as usize);
                        let ctx = script::ScriptCtx {
                            cursor: off,
                            sel_start: -1,
                            sel_len: 0,
                            doc_len: doc.len(),
                            scope_offset: off,
                        };
                        let r = script::run_with_ctx(&src, &mut data, ctx)?;
                        doc.replace(off, len, &data);
                        Ok(script_result_json(&r, true).to_string())
                    }
                    "session_save" => {
                        let dest = args.get("path").and_then(|p| p.as_str()).map(String::from);
                        let target = dest.or_else(|| {
                            doc.path.as_ref().map(|p| p.display().to_string())
                        });
                        let target = target.ok_or("no save path (pass 'path')")?;
                        doc.save_to(&target).map_err(|e| format!("save failed: {e}"))?;
                        Ok(json!({ "saved": target }).to_string())
                    }
                    other => Err(format!("unknown session tool: {other}")),
                }
            }
            "write_bytes" => {
                let path = str_arg(args, "path")?;
                let off = u64_arg(args, "offset", 0);
                let bytes = parse_hex_arg(args)?;
                let mut doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                doc.overwrite(off, &bytes);
                doc.save_to(path).map_err(|e| format!("save failed: {e}"))?;
                Ok(json!({ "written": bytes.len() }).to_string())
            }
            "transform" => {
                let path = str_arg(args, "path")?;
                let off = u64_arg(args, "offset", 0);
                let mut doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let len = args
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(doc.len().saturating_sub(off));
                let op = parse_transform(args)?;
                let mut data = doc.read_range(off, len as usize);
                transform::apply(&mut data, op);
                doc.overwrite(off, &data);
                doc.save_to(path).map_err(|e| format!("save failed: {e}"))?;
                Ok(json!({ "transformed": data.len() }).to_string())
            }
            "patch_create" => {
                let orig = str_arg(args, "original")?;
                let modi = str_arg(args, "modified")?;
                let outp = str_arg(args, "output")?;
                let a = std::fs::read(orig).map_err(|e| format!("read original: {e}"))?;
                let b = std::fs::read(modi).map_err(|e| format!("read modified: {e}"))?;
                let p = patch::make_ips(&a, &b)?;
                std::fs::write(outp, &p).map_err(|e| format!("write patch: {e}"))?;
                Ok(json!({ "patch_bytes": p.len() }).to_string())
            }
            "patch_apply" => {
                let path = str_arg(args, "path")?;
                let patch_path = str_arg(args, "patch")?;
                let bytes = std::fs::read(patch_path).map_err(|e| format!("read patch: {e}"))?;
                let writes = patch::parse_ips(&bytes)?;
                let mut doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                patch::apply_writes(&mut doc, &writes);
                doc.save_to(path).map_err(|e| format!("save failed: {e}"))?;
                Ok(json!({ "records": writes.len() }).to_string())
            }
            "compare" => {
                let pa = str_arg(args, "path_a")?;
                let pb = str_arg(args, "path_b")?;
                let a = Document::open_file(pa).map_err(|e| format!("open a: {e}"))?;
                let b = Document::open_file(pb).map_err(|e| format!("open b: {e}"))?;
                let max = u64_arg(args, "max", 1000) as usize;
                let r = diff::diff(&a, &b, max, &Progress::default());
                let ranges: Vec<Value> = r
                    .ranges
                    .iter()
                    .map(|d| json!({"offset": d.offset, "len": d.len}))
                    .collect();
                Ok(json!({
                    "equal": r.ranges.is_empty() && r.len_a == r.len_b,
                    "len_a": r.len_a, "len_b": r.len_b,
                    "truncated": r.truncated, "ranges": ranges
                })
                .to_string())
            }
            "bps_create" => {
                let orig = str_arg(args, "original")?;
                let modi = str_arg(args, "modified")?;
                let outp = str_arg(args, "output")?;
                let a = std::fs::read(orig).map_err(|e| format!("read original: {e}"))?;
                let b = std::fs::read(modi).map_err(|e| format!("read modified: {e}"))?;
                let p = patch::make_bps(&a, &b);
                std::fs::write(outp, &p).map_err(|e| format!("write patch: {e}"))?;
                Ok(json!({ "patch_bytes": p.len() }).to_string())
            }
            "bps_apply" => {
                let path = str_arg(args, "path")?;
                let patch_path = str_arg(args, "patch")?;
                let bytes = std::fs::read(patch_path).map_err(|e| format!("read patch: {e}"))?;
                let source = std::fs::read(path).map_err(|e| format!("read source: {e}"))?;
                let target = patch::apply_bps(&bytes, &source)?;
                std::fs::write(path, &target).map_err(|e| format!("save failed: {e}"))?;
                Ok(json!({ "bytes": target.len() }).to_string())
            }
            "decompress" => {
                let path = str_arg(args, "path")?;
                let doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let off = u64_arg(args, "offset", 0);
                let len = args
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(doc.len().saturating_sub(off));
                let data = doc.read_range(off, len as usize);
                let codec = match args.get("codec").and_then(|v| v.as_str()) {
                    Some(s) => crate::ops::compress::Codec::parse(s).ok_or("unknown codec")?,
                    None => crate::ops::compress::detect(&data)
                        .ok_or("could not detect codec — pass 'codec'")?,
                };
                let out = crate::ops::compress::decompress(&data, codec)?;
                if let Some(outp) = args.get("output").and_then(|p| p.as_str()) {
                    std::fs::write(outp, &out).map_err(|e| format!("write: {e}"))?;
                    Ok(json!({ "codec": codec.name(), "bytes": out.len(), "output": outp }).to_string())
                } else {
                    let preview = out.len().min(64 * 1024);
                    let hex = export::export_bytes(&out[..preview], 0, export::Format::PlainHexDump);
                    Ok(json!({ "codec": codec.name(), "bytes": out.len(), "hex": hex }).to_string())
                }
            }
            "compress" => {
                let path = str_arg(args, "path")?;
                let outp = str_arg(args, "output")?;
                let doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let off = u64_arg(args, "offset", 0);
                let len = args
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(doc.len().saturating_sub(off));
                let codec = crate::ops::compress::Codec::parse(
                    str_or(args, "codec", "zlib"),
                )
                .ok_or("unknown codec")?;
                let level = u64_arg(args, "level", 6) as u32;
                let data = doc.read_range(off, len as usize);
                let out = crate::ops::compress::compress(&data, codec, level);
                std::fs::write(outp, &out).map_err(|e| format!("write: {e}"))?;
                Ok(json!({ "codec": codec.name(), "bytes": out.len(), "output": outp }).to_string())
            }
            "carve" => {
                let path = str_arg(args, "path")?;
                let outp = str_arg(args, "output")?;
                let off = u64_arg(args, "offset", 0);
                let doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let len = args
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(doc.len().saturating_sub(off));
                let data = doc.read_range(off, len as usize);
                std::fs::write(outp, &data).map_err(|e| format!("write: {e}"))?;
                Ok(json!({ "carved": data.len(), "output": outp }).to_string())
            }
            "script" => {
                let path = str_arg(args, "path")?;
                let src = resolve_script(args)?;
                let mut doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
                let off = u64_arg(args, "offset", 0);
                let len = args
                    .get("length")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(doc.len().saturating_sub(off));
                let mut data = doc.read_range(off, len as usize);
                let ctx = script::ScriptCtx {
                    cursor: off,
                    sel_start: -1,
                    sel_len: 0,
                    doc_len: doc.len(),
                    scope_offset: off,
                };
                let r = script::run_with_ctx(&src, &mut data, ctx)?;
                let changed = data.len() as u64 != len || {
                    let cur = doc.read_range(off, data.len());
                    cur != data
                };
                if changed {
                    doc.replace(off, len, &data);
                    doc.save_to(path).map_err(|e| format!("save failed: {e}"))?;
                }
                Ok(script_result_json(&r, changed).to_string())
            }
            _ => call_tool(name, args),
        }
    }
}

/// Required string argument; errors with `missing '<key>'` if absent or non-string.
fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing '{key}'"))
}

/// Optional string argument with a fallback default.
fn str_or<'a>(args: &'a Value, key: &str, default: &'a str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or(default)
}

/// Optional unsigned-integer argument with a fallback default.
fn u64_arg(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn session_id(args: &Value) -> Result<u64, String> {
    args.get("session")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing 'session'".to_string())
}

/// Resolve a script's source from `source`, or by `library` name (substring).
fn resolve_script(args: &Value) -> Result<String, String> {
    if let Some(s) = args.get("source").and_then(|v| v.as_str()) {
        return Ok(s.to_string());
    }
    if let Some(name) = args.get("library").and_then(|v| v.as_str()) {
        let key = name.to_lowercase();
        if let Some((_, s)) = script::LIBRARY.iter().find(|(n, _)| n.to_lowercase().contains(&key)) {
            return Ok(s.to_string());
        }
        // fall back to a saved user script (exact, then case-insensitive)
        if let Some(s) = crate::ops::script_store::load(name) {
            return Ok(s);
        }
        if let Some(s) = crate::ops::script_store::list()
            .into_iter()
            .find(|(n, _)| n.to_lowercase().contains(&key))
            .and_then(|(n, _)| crate::ops::script_store::load(&n))
        {
            return Ok(s);
        }
        return Err(format!("no library script matching '{name}'"));
    }
    Err("provide 'source' or 'library'".into())
}

fn script_result_json(r: &script::ScriptResult, saved: bool) -> Value {
    json!({
        "output": r.log,
        "saved": saved,
        "set_cursor": r.set_cursor,
        "regions": r.regions.iter().map(|(s, l, lab)| json!({"start": s, "len": l, "label": lab})).collect::<Vec<_>>(),
        "notes": r.notes.iter().map(|(o, l, t)| json!({"offset": o, "len": l, "text": t})).collect::<Vec<_>>(),
    })
}

fn parse_hex_arg(args: &Value) -> Result<Vec<u8>, String> {
    let hex = str_arg(args, "hex")?;
    crate::ops::pattern::parse_hex_pattern(hex)
}

fn parse_transform(args: &Value) -> Result<transform::Op, String> {
    let op = str_or(args, "op", "");
    let key = u64_arg(args, "key", 0) as u8;
    let n = u64_arg(args, "key", 1) as u32;
    Ok(match op.to_lowercase().as_str() {
        "not" => transform::Op::Not,
        "xor" => transform::Op::Xor(key),
        "and" => transform::Op::And(key),
        "or" => transform::Op::Or(key),
        "add" => transform::Op::Add(key),
        "sub" => transform::Op::Sub(key),
        "rol" => transform::Op::Rol(n),
        "ror" => transform::Op::Ror(n),
        "shl" => transform::Op::Shl(n),
        "shr" => transform::Op::Shr(n),
        "reverse" => transform::Op::Reverse,
        "swap" => transform::Op::SwapBytes(u64_arg(args, "key", 2) as usize),
        "flipcase" | "flip_case" => transform::Op::FlipCase,
        other => return Err(format!("unknown transform op: {other}")),
    })
}

fn result_response(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

// ---- resources ----

fn resources_list() -> Value {
    let mut out: Vec<Value> = Vec::new();
    for (name, _) in template::BUILTINS {
        out.push(json!({
            "uri": format!("bewitched://templates/{name}"),
            "name": format!("template: {name}"),
            "description": "built-in binary template (DSL source)",
            "mimeType": "text/plain"
        }));
    }
    for (name, _) in crate::ops::script::LIBRARY {
        out.push(json!({
            "uri": format!("bewitched://scripts/{name}"),
            "name": format!("script: {name}"),
            "description": "built-in Rhai script (source)",
            "mimeType": "text/plain"
        }));
    }
    for (name, _) in crate::ops::script_store::list() {
        out.push(json!({
            "uri": format!("bewitched://scripts/{name}"),
            "name": format!("saved script: {name}"),
            "description": "user-saved Rhai script (source)",
            "mimeType": "text/plain"
        }));
    }
    for r in ["architectures", "formats", "checksums"] {
        out.push(json!({
            "uri": format!("bewitched://reference/{r}"),
            "name": format!("reference: {r}"),
            "description": "names accepted by the corresponding tools",
            "mimeType": "text/plain"
        }));
    }
    Value::Array(out)
}

fn resource_templates_list() -> Value {
    json!([
        {
            "uriTemplate": "file://{path}",
            "name": "raw file (hex dump)",
            "description": "Read a file as a hex dump — absolute (file:///tmp/x.bin) or relative to the working directory (file://x.bin).",
            "mimeType": "text/plain"
        }
    ])
}

fn read_resource(uri: &str, cwd: &Path) -> Result<String, String> {
    // file://path -> hex dump (capped). A relative path resolves against cwd.
    if let Some(rest) = uri.strip_prefix("file://") {
        let path = if Path::new(rest).is_absolute() {
            PathBuf::from(rest)
        } else {
            cwd.join(rest)
        };
        let doc = Document::open_file(&path).map_err(|e| format!("open failed: {e}"))?;
        let len = doc.len().min(64 * 1024);
        return Ok(export::export(&doc, 0, len, export::Format::PlainHexDump));
    }
    if let Some(name) = uri.strip_prefix("bewitched://templates/") {
        return template::BUILTINS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, s)| s.to_string())
            .ok_or_else(|| format!("no template '{name}'"));
    }
    if let Some(name) = uri.strip_prefix("bewitched://scripts/") {
        if let Some((_, s)) = crate::ops::script::LIBRARY.iter().find(|(n, _)| *n == name) {
            return Ok(s.to_string());
        }
        return crate::ops::script_store::load(name).ok_or_else(|| format!("no script '{name}'"));
    }
    match uri {
        "bewitched://reference/architectures" => Ok(disasm::Arch::ALL
            .iter()
            .map(|a| a.label())
            .collect::<Vec<_>>()
            .join("\n")),
        "bewitched://reference/formats" => Ok(export::Format::ALL
            .iter()
            .map(|f| format!("{} (.{})", f.name(), f.extension()))
            .collect::<Vec<_>>()
            .join("\n")),
        "bewitched://reference/checksums" => Ok(checksum::Algo::ALL
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join("\n")),
        _ => Err(format!("unknown resource: {uri}")),
    }
}

// ---- prompts ----

fn prompts_list() -> Value {
    let path_arg = json!([{ "name": "path", "description": "file to analyze", "required": true }]);
    json!([
        { "name": "identify-file", "description": "Identify a file's format and structure.", "arguments": path_arg },
        { "name": "analyze-binary", "description": "Full triage of an unknown binary.", "arguments": path_arg },
        { "name": "find-secrets", "description": "Look for embedded strings, keys and crypto constants.", "arguments": path_arg },
    ])
}

fn get_prompt(name: &str, args: &Value) -> Result<Value, String> {
    let path = str_or(args, "path", "<path>");
    let text = match name {
        "identify-file" => format!(
            "Identify the file at `{path}`. Call the `signatures` tool to detect magic numbers, \
             `statistics` for entropy, and `read_hex {{path, offset:0, length:64}}` to inspect the \
             header. If it matches a known container, run `apply_template` with the matching \
             built-in. Report the format, key header fields, and your confidence."
        ),
        "analyze-binary" => format!(
            "Triage the binary at `{path}`. Steps: (1) `signatures` to spot the format and embedded \
             blobs; (2) `statistics` for entropy/packing; (3) `strings` for clues; (4) if it is an \
             executable, `disassemble {{path, offset, count, arch}}` at the entry. Summarize what it \
             is, notable regions, and anything suspicious."
        ),
        "find-secrets" => format!(
            "Search `{path}` for sensitive material. Use `strings` (look for URLs, paths, keys, \
             base64), and `signatures` (the crypto-constant detector flags AES S-boxes and SHA-256 \
             constants). Report offsets and what you found."
        ),
        other => return Err(format!("unknown prompt: {other}")),
    };
    Ok(json!({
        "description": format!("bewitched: {name}"),
        "messages": [ { "role": "user", "content": { "type": "text", "text": text } } ]
    }))
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

// ---- tool definitions ----

fn path_schema(extra: Value) -> Value {
    let mut props = json!({ "path": { "type": "string", "description": "file or device path (absolute, or relative to the working directory — see get_working_dir/set_working_dir)" } });
    if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            p.insert(k.clone(), v.clone());
        }
    }
    json!({ "type": "object", "required": ["path"], "properties": props })
}

fn tools_list() -> Value {
    json!([
        { "name": "read_hex", "description": "Hex dump of a byte range.",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer","description":"start offset (default 0)"},
            "length": {"type":"integer","description":"bytes to read (default 256)"} })) },
        { "name": "checksums", "description": "Compute checksums/CRCs/digests over a range.",
          "inputSchema": path_schema(json!({
            "algorithms": {"type":"array","items":{"type":"string"},"description":"e.g. md5, sha256, crc32 (default common set)"},
            "offset": {"type":"integer"}, "length": {"type":"integer"} })) },
        { "name": "statistics", "description": "Entropy, byte distribution summary and a data-type classification.",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"} })) },
        { "name": "custom_crc", "description": "Compute any CRC via the Rocksoft model (width/poly/init/refin/refout/xorout).",
          "inputSchema": path_schema(json!({
            "width": {"type":"integer","description":"bits, default 32"}, "poly": {"type":"integer"},
            "init": {"type":"integer"}, "refin": {"type":"boolean"}, "refout": {"type":"boolean"},
            "xorout": {"type":"integer"}, "offset": {"type":"integer"}, "length": {"type":"integer"} })) },
        { "name": "histogram", "description": "Full 256-bin byte distribution plus entropy and most-common byte.",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"} })) },
        { "name": "entropy_map", "description": "Per-bucket entropy across the range (locate compressed/encrypted regions).",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"}, "buckets": {"type":"integer","description":"default 64"} })) },
        { "name": "compare", "description": "Byte-diff two files; returns differing ranges.",
          "inputSchema": json!({ "type":"object", "required":["path_a","path_b"], "properties": {
            "path_a": {"type":"string"}, "path_b": {"type":"string"}, "max": {"type":"integer"} } }) },
        { "name": "carve", "description": "Extract a byte range to a new file (e.g. an embedded blob found by signatures).",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"}, "output": {"type":"string"} })) },
        { "name": "decompress", "description": "Decompress a range (gzip/zlib/deflate; auto-detects if 'codec' omitted). Writes 'output' or returns a hex preview.",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"}, "codec": {"type":"string"}, "output": {"type":"string"} })) },
        { "name": "compress", "description": "Compress a range (gzip/zlib/deflate) to a new file.",
          "inputSchema": path_schema(json!({ "offset": {"type":"integer"}, "length": {"type":"integer"}, "codec": {"type":"string"}, "level": {"type":"integer"}, "output": {"type":"string"} })) },
        { "name": "search", "description": "Find occurrences of a typed value; returns match offsets.",
          "inputSchema": path_schema(json!({
            "type": {"type":"string","description":"text|utf16|hex|i8|i16|i32|i64|f32|f64"},
            "value": {"type":"string"},
            "max": {"type":"integer","description":"max results (default 100)"} })) },
        { "name": "search_pattern", "description": "Wildcard 'AOB' search: a hex pattern with '?' wildcards, e.g. 'DE ?? BE EF'. Returns match offsets.",
          "inputSchema": path_schema(json!({ "pattern": {"type":"string"}, "max": {"type":"integer"} })) },
        { "name": "find_pointers", "description": "Find 64-bit pointers into [target-max_offset, target] in a memory image; returns {address, offset} pairs.",
          "inputSchema": path_schema(json!({
            "target": {"type":"integer","description":"address to find pointers to"},
            "base": {"type":"integer","description":"address of byte 0 of the image (default 0)"},
            "max_offset": {"type":"integer","description":"how far before target a pointer may land (default 0x1000)"},
            "align": {"type":"integer","description":"pointer alignment (default 8)"},
            "max": {"type":"integer"} })) },
        { "name": "pointer_chains", "description": "Find multi-level pointer chains static_base→…→target (returns {base, offsets}).",
          "inputSchema": path_schema(json!({
            "target": {"type":"integer"}, "base": {"type":"integer","description":"image base (default 0)"},
            "static_base": {"type":"integer"}, "static_window": {"type":"integer"},
            "max_offset": {"type":"integer"}, "max_depth": {"type":"integer","description":"default 3"},
            "max": {"type":"integer"} })) },
        { "name": "strings", "description": "Extract ASCII/UTF-16 strings.",
          "inputSchema": path_schema(json!({
            "min_length": {"type":"integer","description":"default 4"},
            "max": {"type":"integer","description":"default 200"} })) },
        { "name": "signatures", "description": "Scan for embedded file formats, archives, executables and crypto constants (binwalk-style).",
          "inputSchema": path_schema(json!({})) },
        { "name": "disassemble", "description": "Disassemble instructions at an offset.",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer"},
            "count": {"type":"integer","description":"instructions (default 32)"},
            "arch": {"type":"string","description":"x86-16|x86-32|x86-64|arm|thumb|aarch64|mips-le|mips-be|powerpc|riscv32|riscv64|msp430|6502|sm83 (default x86-64)"} })) },
        { "name": "inspect", "description": "Interpret the bytes at an offset as many data types.",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer"},
            "big_endian": {"type":"boolean","description":"default false (little-endian)"} })) },
        { "name": "export", "description": "Export a byte range to a source/text/hex format.",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer"}, "length": {"type":"integer"},
            "format": {"type":"string","description":"format name, e.g. 'C source', 'Base64', 'Intel HEX'"} })) },
        { "name": "parse_struct", "description": "Parse a structure into a tree with the nested Kaitai-style schema engine (sub-types, repeat, if, enums, expressions).",
          "inputSchema": path_schema(json!({
            "builtin": {"type":"string","description":"PNG|GIF|ELF|WAV (case-insensitive substring)"},
            "schema": {"type":"string","description":"custom schema DSL (overrides builtin)"},
            "offset": {"type":"integer"} })) },
        { "name": "apply_template", "description": "Parse a structure with a built-in or custom binary template (flat fields).",
          "inputSchema": path_schema(json!({
            "builtin": {"type":"string","description":"BMP|PNG|ELF|WAV|GIF (case-insensitive substring)"},
            "template": {"type":"string","description":"custom template DSL source (overrides builtin)"},
            "offset": {"type":"integer"} })) },

        // ---- write / session tools ----
        { "name": "write_bytes", "description": "Overwrite bytes at an offset and save the file.",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer"}, "hex": {"type":"string","description":"bytes as hex, e.g. 'DE AD BE EF'"} })) },
        { "name": "transform", "description": "Apply a byte transform to a range and save (xor/and/or/add/sub/not/rol/ror/shl/shr/reverse/swap/flipcase).",
          "inputSchema": path_schema(json!({
            "offset": {"type":"integer"}, "length": {"type":"integer"},
            "op": {"type":"string"}, "key": {"type":"integer","description":"key/bits/group for the op"} })) },
        { "name": "patch_create", "description": "Diff two files into an IPS patch.",
          "inputSchema": json!({ "type":"object", "required":["original","modified","output"], "properties": {
            "original": {"type":"string"}, "modified": {"type":"string"}, "output": {"type":"string"} } }) },
        { "name": "patch_apply", "description": "Apply an IPS patch to a file and save.",
          "inputSchema": path_schema(json!({ "patch": {"type":"string","description":"path to .ips patch"} })) },
        { "name": "bps_create", "description": "Diff two files into a BPS patch (any size, CRC-checked).",
          "inputSchema": json!({ "type":"object", "required":["original","modified","output"], "properties": {
            "original": {"type":"string"}, "modified": {"type":"string"}, "output": {"type":"string"} } }) },
        { "name": "bps_apply", "description": "Apply a BPS patch to a file and save (validates source/target CRC).",
          "inputSchema": path_schema(json!({ "patch": {"type":"string","description":"path to .bps patch"} })) },
        { "name": "script", "description": "Run a Rhai script over a file range and save (read/write/len/typed accessors/find/crc32/add_region/add_note/...).",
          "inputSchema": path_schema(json!({
            "source": {"type":"string","description":"Rhai source"},
            "library": {"type":"string","description":"or a built-in library script name (substring)"},
            "offset": {"type":"integer"}, "length": {"type":"integer"} })) },
        { "name": "open", "description": "Open a file as an editing session; returns a session id.",
          "inputSchema": path_schema(json!({})) },
        { "name": "session_read", "description": "Hex dump from an open session.",
          "inputSchema": json!({ "type":"object", "required":["session"], "properties": {
            "session": {"type":"integer"}, "offset": {"type":"integer"}, "length": {"type":"integer"} } }) },
        { "name": "session_write", "description": "Overwrite bytes in a session (undoable; not saved until session_save).",
          "inputSchema": json!({ "type":"object", "required":["session","hex"], "properties": {
            "session": {"type":"integer"}, "offset": {"type":"integer"}, "hex": {"type":"string"} } }) },
        { "name": "session_insert", "description": "Insert bytes in a session.",
          "inputSchema": json!({ "type":"object", "required":["session","hex"], "properties": {
            "session": {"type":"integer"}, "offset": {"type":"integer"}, "hex": {"type":"string"} } }) },
        { "name": "session_delete", "description": "Delete bytes in a session.",
          "inputSchema": json!({ "type":"object", "required":["session","length"], "properties": {
            "session": {"type":"integer"}, "offset": {"type":"integer"}, "length": {"type":"integer"} } }) },
        { "name": "session_undo", "description": "Undo the last edit in a session.",
          "inputSchema": json!({ "type":"object", "required":["session"], "properties": { "session": {"type":"integer"} } }) },
        { "name": "session_script", "description": "Run a Rhai script over a session range.",
          "inputSchema": json!({ "type":"object", "required":["session"], "properties": {
            "session": {"type":"integer"}, "source": {"type":"string"}, "library": {"type":"string"},
            "offset": {"type":"integer"}, "length": {"type":"integer"} } }) },
        { "name": "session_save", "description": "Save a session to disk (its path, or a given 'path').",
          "inputSchema": json!({ "type":"object", "required":["session"], "properties": {
            "session": {"type":"integer"}, "path": {"type":"string"} } }) },
        { "name": "session_close", "description": "Close an editing session.",
          "inputSchema": json!({ "type":"object", "required":["session"], "properties": { "session": {"type":"integer"} } }) },

        // ---- workspace ----
        { "name": "get_working_dir", "description": "Return the current working directory that relative path arguments resolve against.",
          "inputSchema": json!({ "type":"object", "properties": {} }) },
        { "name": "set_working_dir", "description": "Set the working directory (like 'cd'); relative path arguments resolve against it afterward. Absolute paths always work regardless.",
          "inputSchema": json!({ "type":"object", "required":["path"], "properties": {
            "path": {"type":"string","description":"directory (absolute, or relative to the current working directory)"} } }) },
    ])
}

// ---- tool dispatch ----

fn call_tool(name: &str, args: &Value) -> Result<String, String> {
    let path = args
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("missing 'path'")?;
    let doc = Document::open_file(path).map_err(|e| format!("open failed: {e}"))?;
    let off = u64_arg(args, "offset", 0);
    let total = doc.len();

    match name {
        "read_hex" => {
            let len = u64_arg(args, "length", 256);
            Ok(export::export(&doc, off, len, export::Format::PlainHexDump))
        }
        "checksums" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let algos = parse_algos(args.get("algorithms"));
            let results = checksum::compute(&doc, off, len, &algos, &Progress::default());
            let map: serde_json::Map<String, Value> = results
                .into_iter()
                .map(|(a, v)| (a.name().to_string(), Value::String(v)))
                .collect();
            Ok(Value::Object(map).to_string())
        }
        "statistics" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let s = stats::analyze(&doc, off, len, &Progress::default());
            let mc = s.most_common().map(|(b, c)| json!({"byte": b, "count": c}));
            Ok(json!({
                "total": s.total,
                "entropy_bits_per_byte": s.entropy,
                "classification": s.classify(),
                "most_common": mc
            })
            .to_string())
        }
        "custom_crc" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let params = checksum::CrcParams {
                width: u64_arg(args, "width", 32) as u32,
                poly: args.get("poly").and_then(|v| v.as_u64()).ok_or("missing 'poly'")?,
                init: u64_arg(args, "init", 0),
                refin: args.get("refin").and_then(|v| v.as_bool()).unwrap_or(false),
                refout: args.get("refout").and_then(|v| v.as_bool()).unwrap_or(false),
                xorout: u64_arg(args, "xorout", 0),
            };
            let data = doc.read_range(off, len as usize);
            let v = checksum::custom_crc(&data, &params);
            Ok(json!({ "value": v, "hex": format!("{:X}", v) }).to_string())
        }
        "histogram" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let s = stats::analyze(&doc, off, len, &Progress::default());
            Ok(json!({
                "total": s.total,
                "entropy_bits_per_byte": s.entropy,
                "counts": s.counts.to_vec(),
                "most_common": s.most_common().map(|(b, c)| json!({"byte": b, "count": c}))
            })
            .to_string())
        }
        "entropy_map" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let buckets = u64_arg(args, "buckets", 64) as usize;
            let map = stats::entropy_map(&doc, off, len, buckets, &Progress::default());
            Ok(json!({ "buckets": buckets, "entropy": map }).to_string())
        }
        "search" => {
            let ty = search::DataType::from_name(str_or(args, "type", "hex"))?;
            let value = str_or(args, "value", "");
            let max = u64_arg(args, "max", 100) as usize;
            let needle = search::needle_bytes(value, ty, search::Endian::Little, false)?;
            let mut hits = Vec::new();
            let mut from = 0u64;
            while hits.len() < max {
                match search::find(&doc, &needle, from, search::Direction::Forward, false) {
                    Some(o) => {
                        hits.push(o);
                        from = o + 1;
                    }
                    None => break,
                }
            }
            Ok(json!({ "matches": hits, "count": hits.len() }).to_string())
        }
        "search_pattern" => {
            let pattern = str_or(args, "pattern", "");
            let max = u64_arg(args, "max", 100) as usize;
            let (pat, mask) = search::parse_hex_mask(pattern)?;
            let hits = search::find_all_masked(&doc, &pat, &mask, max);
            Ok(json!({ "matches": hits, "count": hits.len() }).to_string())
        }
        "find_pointers" => {
            let target = args.get("target").and_then(|v| v.as_u64()).ok_or("missing 'target'")?;
            let base = u64_arg(args, "base", 0);
            let max_offset = u64_arg(args, "max_offset", 0x1000);
            let align = u64_arg(args, "align", 8);
            let max = u64_arg(args, "max", 1000) as usize;
            let hits = crate::ops::pointer::find_pointers_to(
                &doc, base, target, max_offset, align, max, &Progress::default(),
            );
            let arr: Vec<Value> = hits
                .iter()
                .map(|(addr, off)| json!({"address": addr, "offset": off}))
                .collect();
            Ok(json!({ "pointers": arr, "count": arr.len() }).to_string())
        }
        "pointer_chains" => {
            let target = args.get("target").and_then(|v| v.as_u64()).ok_or("missing 'target'")?;
            let base = u64_arg(args, "base", 0);
            let static_base = u64_arg(args, "static_base", 0);
            let static_window = u64_arg(args, "static_window", 0x10000);
            let max_offset = u64_arg(args, "max_offset", 0x400);
            let max_depth = u64_arg(args, "max_depth", 3) as usize;
            let max = u64_arg(args, "max", 50) as usize;
            let chains = crate::ops::pointer::find_chains(
                &doc, base, target, static_base, static_window, max_offset, max_depth, max,
                &Progress::default(),
            );
            let arr: Vec<Value> = chains
                .iter()
                .map(|c| json!({"base": c.base, "offsets": c.offsets}))
                .collect();
            Ok(json!({ "chains": arr, "count": arr.len() }).to_string())
        }
        "strings" => {
            let min = u64_arg(args, "min_length", 4) as usize;
            let max = u64_arg(args, "max", 200) as usize;
            let found = strings::extract(&doc, 0, total, min, max, &Progress::default());
            let arr: Vec<Value> = found
                .into_iter()
                .map(|f| json!({"offset": f.offset, "kind": format!("{:?}", f.kind), "text": f.text}))
                .collect();
            Ok(json!({ "strings": arr }).to_string())
        }
        "signatures" => {
            let hits = signatures::scan(&doc, 0, total, 1000, &Progress::default());
            let arr: Vec<Value> = hits
                .into_iter()
                .map(|h| json!({"offset": h.offset, "category": h.category.label(), "name": h.name}))
                .collect();
            Ok(json!({ "signatures": arr }).to_string())
        }
        "disassemble" => {
            let count = u64_arg(args, "count", 32) as usize;
            let arch = disasm::Arch::from_name(str_or(args, "arch", "x86-64"))?;
            let ins = disasm::disassemble(&doc, off, count, arch);
            let arr: Vec<Value> = ins
                .into_iter()
                .map(|i| {
                    let bytes = i.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                    json!({"offset": i.offset, "bytes": bytes, "text": i.text})
                })
                .collect();
            Ok(json!({ "instructions": arr }).to_string())
        }
        "inspect" => {
            let le = !args.get("big_endian").and_then(|v| v.as_bool()).unwrap_or(false);
            let window = doc.read_range(off, 16);
            let interps = inspect::inspect(&window, le);
            let map: serde_json::Map<String, Value> = interps
                .into_iter()
                .map(|i| (i.label.to_string(), Value::String(i.value)))
                .collect();
            Ok(Value::Object(map).to_string())
        }
        "export" => {
            let len = u64_arg(args, "length", total - off.min(total));
            let fmt = export::Format::from_name(str_or(args, "format", "Hex dump (plain text)"))?;
            Ok(export::export(&doc, off, len, fmt))
        }
        "parse_struct" => {
            use crate::ops::kstruct;
            let src = if let Some(s) = args.get("schema").and_then(|v| v.as_str()) {
                s.to_string()
            } else {
                let key = str_or(args, "builtin", "PNG").to_lowercase();
                kstruct::BUILTINS
                    .iter()
                    .find(|(n, _)| n.to_lowercase().contains(&key))
                    .map(|(_, s)| s.to_string())
                    .ok_or_else(|| format!("no built-in schema matching '{key}'"))?
            };
            let schema = kstruct::Schema::parse(&src)?;
            let root = kstruct::apply(&schema, &doc, off)?;
            fn node_to_json(n: &kstruct::Node) -> Value {
                let mut o = json!({
                    "name": n.name, "offset": n.offset, "size": n.size,
                    "type": n.kind, "value": n.value,
                });
                if !n.children.is_empty() {
                    o["children"] = Value::Array(n.children.iter().map(node_to_json).collect());
                }
                o
            }
            Ok(node_to_json(&root).to_string())
        }
        "apply_template" => {
            let src = if let Some(s) = args.get("template").and_then(|v| v.as_str()) {
                s.to_string()
            } else {
                let key = str_or(args, "builtin", "PNG").to_lowercase();
                template::BUILTINS
                    .iter()
                    .find(|(n, _)| n.to_lowercase().contains(&key))
                    .map(|(_, s)| s.to_string())
                    .ok_or_else(|| format!("no built-in template matching '{key}'"))?
            };
            let tmpl = template::Template::parse(&src)?;
            let fields = template::apply(&tmpl, &doc, off)?;
            let arr: Vec<Value> = fields
                .into_iter()
                .map(|f| json!({"name": f.name, "offset": f.offset, "size": f.size, "type": f.kind, "value": f.value}))
                .collect();
            Ok(json!({ "fields": arr }).to_string())
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

fn parse_algos(v: Option<&Value>) -> Vec<checksum::Algo> {
    let default = vec![
        checksum::Algo::Crc32,
        checksum::Algo::Md5,
        checksum::Algo::Sha1,
        checksum::Algo::Sha256,
    ];
    let Some(arr) = v.and_then(|x| x.as_array()) else {
        return default;
    };
    let mut out = Vec::new();
    for item in arr {
        if let Some(name) = item.as_str() {
            let n = name.to_lowercase().replace(['-', '_', '/'], "");
            for a in checksum::Algo::ALL {
                if a.name().to_lowercase().replace(['-', '_', '/'], "").contains(&n) {
                    out.push(*a);
                    break;
                }
            }
        }
    }
    if out.is_empty() {
        default
    } else {
        out
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile(bytes: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bewitched_mcp_{:?}_{}.bin",
            std::thread::current().id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn initialize_advertises_server() {
        let resp = Server::new().handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "bewitched");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(Server::new().handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
    }

    #[test]
    fn tools_list_nonempty() {
        let resp = Server::new().handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert!(tools.len() >= 10);
        assert!(tools.iter().any(|t| t["name"] == "disassemble"));
    }

    #[test]
    fn initialize_advertises_resources_and_prompts() {
        let resp = Server::new().handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).unwrap();
        let caps = &resp["result"]["capabilities"];
        assert!(caps.get("resources").is_some());
        assert!(caps.get("prompts").is_some());
    }

    #[test]
    fn resources_list_and_read() {
        let mut s = Server::new();
        let list = s.handle(&json!({"jsonrpc":"2.0","id":1,"method":"resources/list"})).unwrap();
        let res = list["result"]["resources"].as_array().unwrap();
        assert!(res.iter().any(|r| r["uri"] == "bewitched://reference/architectures"));
        // read the template PNG source
        let read = s.handle(&json!({
            "jsonrpc":"2.0","id":2,"method":"resources/read",
            "params":{"uri":"bewitched://templates/PNG image"}
        })).unwrap();
        let text = read["result"]["contents"][0]["text"].as_str().unwrap();
        assert!(text.contains("ihdr_type"));
        // read the arch reference
        let arch = s.handle(&json!({
            "jsonrpc":"2.0","id":3,"method":"resources/read",
            "params":{"uri":"bewitched://reference/architectures"}
        })).unwrap();
        assert!(arch["result"]["contents"][0]["text"].as_str().unwrap().contains("ARM64"));
    }

    #[test]
    fn parse_struct_tool_tree() {
        // a minimal WAV header
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(b"fmt ");
        data.extend_from_slice(&16u32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // audio_format
        data.extend_from_slice(&2u16.to_le_bytes()); // channels
        data.extend_from_slice(&44100u32.to_le_bytes());
        data.resize(44, 0);
        let p = tmpfile(&data);
        let resp = call(&mut Server::new(), "parse_struct", json!({
            "path": p.to_str().unwrap(), "builtin": "WAV"
        }));
        // find the channels field in the tree
        let chans = resp["children"].as_array().unwrap().iter()
            .find(|c| c["name"] == "channels").unwrap();
        assert_eq!(chans["value"], "2");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn file_resource_template_and_read() {
        let mut s = Server::new();
        let tl = s.handle(&json!({"jsonrpc":"2.0","id":1,"method":"resources/templates/list"})).unwrap();
        let temps = tl["result"]["resourceTemplates"].as_array().unwrap();
        assert!(temps.iter().any(|t| t["uriTemplate"] == "file://{path}"));

        let p = tmpfile(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let uri = format!("file://{}", p.to_str().unwrap());
        let read = s.handle(&json!({
            "jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri": uri}
        })).unwrap();
        assert!(read["result"]["contents"][0]["text"].as_str().unwrap().contains("DE AD BE EF"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resources_read_unknown_errors() {
        let resp = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"bewitched://nope"}
        })).unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn prompts_list_and_get() {
        let mut s = Server::new();
        let list = s.handle(&json!({"jsonrpc":"2.0","id":1,"method":"prompts/list"})).unwrap();
        assert!(list["result"]["prompts"].as_array().unwrap().iter().any(|p| p["name"] == "analyze-binary"));
        let got = s.handle(&json!({
            "jsonrpc":"2.0","id":2,"method":"prompts/get",
            "params":{"name":"identify-file","arguments":{"path":"/tmp/x.bin"}}
        })).unwrap();
        let text = got["result"]["messages"][0]["content"]["text"].as_str().unwrap();
        assert!(text.contains("/tmp/x.bin"));
        assert!(text.contains("signatures"));
    }

    #[test]
    fn unknown_method_errors() {
        let resp = Server::new().handle(&json!({"jsonrpc":"2.0","id":3,"method":"bogus"})).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn tools_call_checksums() {
        let p = tmpfile(b"abc");
        let resp = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params": {"name":"checksums","arguments":{"path": p.to_str().unwrap(),"algorithms":["sha256","crc32"]}}
        }))
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["SHA-256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(v["CRC-32"], "352441C2");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tools_call_read_hex_and_disasm() {
        let p = tmpfile(&[0x48, 0x31, 0xC0, 0x90, 0xC3]);
        let hex = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"read_hex","arguments":{"path": p.to_str().unwrap(),"length":5}}
        })).unwrap();
        assert!(hex["result"]["content"][0]["text"].as_str().unwrap().contains("48 31 C0"));

        let dis = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{"name":"disassemble","arguments":{"path": p.to_str().unwrap(),"arch":"x86-64","count":3}}
        })).unwrap();
        let text = dis["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("xor rax,rax"), "got {text}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn find_pointers_tool() {
        // two 64-bit pointers near target 0x1000
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        data.extend_from_slice(&0x0FF0u64.to_le_bytes());
        let p = tmpfile(&data);
        let resp = call(&mut Server::new(), "find_pointers", json!({
            "path": p.to_str().unwrap(), "target": 0x1000, "max_offset": 0x20
        }));
        assert_eq!(resp["count"], 2);
        assert_eq!(resp["pointers"][1], json!({"address": 8, "offset": 0x10}));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pointer_chains_tool() {
        let d = 0x1000u64.to_le_bytes();
        let p = tmpfile(&d);
        let resp = call(&mut Server::new(), "pointer_chains", json!({
            "path": p.to_str().unwrap(), "target": 0x1010, "static_base": 0,
            "static_window": 0, "max_offset": 0x20, "max_depth": 1
        }));
        assert_eq!(resp["count"], 1);
        assert_eq!(resp["chains"][0]["offsets"], json!([0x10]));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn compare_and_carve_tools() {
        let a = tmpfile(b"AAAAAAAA");
        let b = tmpfile(b"AABBAAAA");
        let mut s = Server::new();
        let cmp = call(&mut s, "compare", json!({"path_a": a.to_str().unwrap(), "path_b": b.to_str().unwrap()}));
        assert_eq!(cmp["equal"], false);
        assert_eq!(cmp["ranges"][0]["offset"], 2);
        assert_eq!(cmp["ranges"][0]["len"], 2);

        // carve bytes 2..4 of b into a new file
        let out = tmpfile(b"");
        let carved = call(&mut s, "carve", json!({
            "path": b.to_str().unwrap(), "offset": 2, "length": 2, "output": out.to_str().unwrap()
        }));
        assert_eq!(carved["carved"], 2);
        assert_eq!(std::fs::read(&out).unwrap(), b"BB");
        for f in [a, b, out] { let _ = std::fs::remove_file(&f); }
    }

    #[test]
    fn bps_create_and_apply_tools() {
        let orig = tmpfile(b"the quick brown fox");
        let modi = tmpfile(b"the QUICK brown fox!");
        let patch = tmpfile(b"");
        let mut s = Server::new();
        let made = call(&mut s, "bps_create", json!({
            "original": orig.to_str().unwrap(),
            "modified": modi.to_str().unwrap(),
            "output": patch.to_str().unwrap(),
        }));
        assert!(made["patch_bytes"].as_u64().unwrap() > 16);
        // apply onto a copy of the original
        let target = tmpfile(b"the quick brown fox");
        let applied = call(&mut s, "bps_apply", json!({
            "path": target.to_str().unwrap(),
            "patch": patch.to_str().unwrap(),
        }));
        assert_eq!(applied["bytes"], 20);
        assert_eq!(std::fs::read(&target).unwrap(), b"the QUICK brown fox!");
        for f in [orig, modi, patch, target] { let _ = std::fs::remove_file(&f); }
    }

    #[test]
    fn compress_decompress_tools_roundtrip() {
        let original = b"PAYLOAD ".repeat(64);
        let p = tmpfile(&original);
        let zp = tmpfile(b"");
        let out = tmpfile(b"");
        let mut s = Server::new();
        // compress p -> zp (zlib)
        let c = call(&mut s, "compress", json!({
            "path": p.to_str().unwrap(), "codec": "zlib", "output": zp.to_str().unwrap()
        }));
        assert_eq!(c["codec"], "zlib");
        assert!((c["bytes"].as_u64().unwrap() as usize) < original.len());
        // decompress zp -> out (auto-detect)
        let d = call(&mut s, "decompress", json!({
            "path": zp.to_str().unwrap(), "output": out.to_str().unwrap()
        }));
        assert_eq!(d["codec"], "zlib");
        assert_eq!(std::fs::read(&out).unwrap(), original);
        for f in [p, zp, out] { let _ = std::fs::remove_file(&f); }
    }

    #[test]
    fn custom_crc_tool() {
        let p = tmpfile(b"123456789");
        let resp = call(&mut Server::new(), "custom_crc", json!({
            "path": p.to_str().unwrap(), "width": 32, "poly": 0x04C11DB7,
            "init": 0xFFFFFFFFu64, "refin": true, "refout": true, "xorout": 0xFFFFFFFFu64
        }));
        assert_eq!(resp["hex"], "CBF43926");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn histogram_and_entropy_map_tools() {
        let p = tmpfile(&[0u8; 100]);
        let mut s = Server::new();
        let h = call(&mut s, "histogram", json!({"path": p.to_str().unwrap()}));
        assert_eq!(h["counts"][0], 100);
        assert_eq!(h["entropy_bits_per_byte"], 0.0);
        let em = call(&mut s, "entropy_map", json!({"path": p.to_str().unwrap(), "buckets": 4}));
        assert_eq!(em["entropy"].as_array().unwrap().len(), 4);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tool_error_is_reported() {
        let resp = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"read_hex","arguments":{"path":"/nonexistent/xyz"}}
        }))
        .unwrap();
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn search_pattern_wildcards() {
        let p = tmpfile(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0x99, 0xBE, 0xEF]);
        let resp = call(&mut Server::new(), "search_pattern", json!({
            "path": p.to_str().unwrap(), "pattern": "DE ?? BE EF"
        }));
        assert_eq!(resp["matches"], json!([1, 5]));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn search_finds_bytes() {
        let p = tmpfile(b"--needle--needle--");
        let resp = Server::new().handle(&json!({
            "jsonrpc":"2.0","id":8,"method":"tools/call",
            "params":{"name":"search","arguments":{"path": p.to_str().unwrap(),"type":"text","value":"needle"}}
        }))
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["matches"], json!([2, 10]));
        let _ = std::fs::remove_file(&p);
    }

    fn call(s: &mut Server, name: &str, args: Value) -> Value {
        let resp = s
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}))
            .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap_or(Value::String(text.to_string()))
    }

    #[test]
    fn session_edit_lifecycle() {
        let p = tmpfile(b"AAAAAAAA");
        let mut s = Server::new();
        // open
        let opened = call(&mut s, "open", json!({"path": p.to_str().unwrap()}));
        let id = opened["session"].as_u64().unwrap();
        assert_eq!(opened["length"], 8);
        // overwrite 2 bytes at offset 2
        let w = call(&mut s, "session_write", json!({"session": id, "offset": 2, "hex": "4242"}));
        assert_eq!(w["written"], 2);
        // insert grows the doc
        let ins = call(&mut s, "session_insert", json!({"session": id, "offset": 0, "hex": "FF"}));
        assert_eq!(ins["length"], 9);
        // undo the insert
        let u = call(&mut s, "session_undo", json!({"session": id}));
        assert_eq!(u["length"], 8);
        // save and verify on disk
        call(&mut s, "session_save", json!({"session": id}));
        let saved = std::fs::read(&p).unwrap();
        assert_eq!(saved, b"AABBAAAA"); // bytes 2,3 overwritten with 0x42
        call(&mut s, "session_close", json!({"session": id}));
        // session is gone now
        let resp = s.handle(&json!({
            "jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"session_read","arguments":{"session": id}}
        })).unwrap();
        assert_eq!(resp["result"]["isError"], true);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn script_tool_runs_and_saves() {
        let p = tmpfile(&[0x00, 0x0F, 0xF0, 0xFF]);
        let mut s = Server::new();
        // XOR every byte with 0xFF via inline source
        let r = call(&mut s, "script", json!({
            "path": p.to_str().unwrap(),
            "source": "for i in 0..len() { write(i, read(i) ^ 0xFF); }",
        }));
        assert_eq!(r["saved"], true);
        assert_eq!(std::fs::read(&p).unwrap(), vec![0xFF, 0xF0, 0x0F, 0x00]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn script_tool_by_library_name_and_side_effects() {
        let p = tmpfile(b"abcdef");
        let mut s = Server::new();
        // library lookup + a script that prints and adds a region
        let r = call(&mut s, "script", json!({
            "path": p.to_str().unwrap(),
            "source": "print(\"len \" + len()); add_region(0, 3, \"head\");",
        }));
        assert!(r["output"].as_str().unwrap().contains("len 6"));
        assert_eq!(r["regions"][0]["label"], "head");
        // library by name
        let r2 = call(&mut s, "script", json!({
            "path": p.to_str().unwrap(), "library": "uppercase",
        }));
        assert_eq!(r2["saved"], true);
        assert_eq!(std::fs::read(&p).unwrap(), b"ABCDEF");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn session_script_tool() {
        let p = tmpfile(b"hello");
        let mut s = Server::new();
        let id = call(&mut s, "open", json!({"path": p.to_str().unwrap()}))["session"].as_u64().unwrap();
        call(&mut s, "session_script", json!({"session": id, "library": "uppercase"}));
        call(&mut s, "session_save", json!({"session": id}));
        assert_eq!(std::fs::read(&p).unwrap(), b"HELLO");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn write_bytes_and_transform_tools() {
        let p = tmpfile(&[0x00, 0x0F, 0xF0, 0xFF]);
        let mut s = Server::new();
        call(&mut s, "write_bytes", json!({"path": p.to_str().unwrap(), "offset": 0, "hex": "AA"}));
        assert_eq!(std::fs::read(&p).unwrap(), vec![0xAA, 0x0F, 0xF0, 0xFF]);
        // XOR the whole file with 0xFF
        call(&mut s, "transform", json!({"path": p.to_str().unwrap(), "op": "xor", "key": 0xFF}));
        assert_eq!(std::fs::read(&p).unwrap(), vec![0x55, 0xF0, 0x0F, 0x00]);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn patch_create_and_apply_tools() {
        let orig = tmpfile(b"the quick brown fox");
        let modi = tmpfile(b"the QUICK brown fox");
        let patch = tmpfile(b""); // reuse path
        let mut s = Server::new();
        let made = call(&mut s, "patch_create", json!({
            "original": orig.to_str().unwrap(),
            "modified": modi.to_str().unwrap(),
            "output": patch.to_str().unwrap(),
        }));
        assert!(made["patch_bytes"].as_u64().unwrap() > 8);
        // apply the patch back onto a copy of the original
        let target = tmpfile(b"the quick brown fox");
        let applied = call(&mut s, "patch_apply", json!({
            "path": target.to_str().unwrap(),
            "patch": patch.to_str().unwrap(),
        }));
        assert!(applied["records"].as_u64().unwrap() >= 1);
        assert_eq!(std::fs::read(&target).unwrap(), b"the QUICK brown fox");
        for f in [orig, modi, patch, target] {
            let _ = std::fs::remove_file(&f);
        }
    }

    fn tmpdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bewitched_mcpdir_{:?}_{}",
            std::thread::current().id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn working_dir_resolves_relative_paths() {
        let dir = tmpdir();
        std::fs::write(dir.join("sample.bin"), b"ABCD").unwrap();
        let mut s = Server::new();

        // get_working_dir reports a directory by default.
        assert!(call(&mut s, "get_working_dir", json!({}))["cwd"].as_str().is_some());

        // cd into the temp dir.
        let set = call(&mut s, "set_working_dir", json!({ "path": dir.to_str().unwrap() }));
        assert!(set["cwd"].as_str().is_some());

        // A RELATIVE path now resolves against the working dir, identically to the
        // absolute path — proving relative resolution works while absolute still
        // works "wild" regardless of cwd.
        let rel = call(&mut s, "read_hex", json!({ "path": "sample.bin", "length": 4 }));
        let abs = call(
            &mut s,
            "read_hex",
            json!({ "path": dir.join("sample.bin").to_str().unwrap(), "length": 4 }),
        );
        assert_eq!(rel, abs);
        assert!(rel.as_str().unwrap().contains("41")); // 'A' — a real dump, not an error

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_working_dir_rejects_non_directory() {
        let p = tmpfile(b"x");
        let mut s = Server::new();
        let resp = s
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"set_working_dir","arguments":{"path": p.to_str().unwrap()}}}))
            .unwrap();
        assert_eq!(resp["result"]["isError"], json!(true));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn set_working_dir_then_relative_missing_file_errors() {
        let dir = tmpdir();
        let mut s = Server::new();
        call(&mut s, "set_working_dir", json!({ "path": dir.to_str().unwrap() }));
        let resp = s
            .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"read_hex","arguments":{"path":"nope.bin"}}}))
            .unwrap();
        assert_eq!(resp["result"]["isError"], json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
