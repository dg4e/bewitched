//! Headless command-line mode for scripting and pipelines.
//!
//! Invoked when bewitched is run with a recognized subcommand (anything other than
//! a bare file path or `--mcp`). Returns the process exit code. All operations
//! reuse the same `ops` engine as the GUI and MCP server.

use crate::data::Document;
use crate::ops::{
    checksum, compress, disasm, export, patch, pointer, scan, search, signatures, stats, strings,
    Progress,
};

/// Result of parsing argv: either a CLI command to run, or "not a CLI command"
/// (so the caller falls through to the GUI / MCP paths).
pub enum Mode {
    /// Run this CLI command and exit with the returned code.
    Run(i32),
    /// Not a CLI invocation; continue to GUI.
    NotCli,
}

const USAGE: &str = "\
bewitched — hex editor & binary analysis

GUI:
  bewitched [FILE|DEVICE]         open the editor (optionally on a file/device)

MCP server:
  bewitched --mcp                 run as a Model Context Protocol server (stdio)

Headless commands (read FILE, print to stdout):
  bewitched dump   FILE [OFF] [LEN]          hex dump
  bewitched sha256 FILE                      SHA-256 (also: md5 sha1 sha512 crc32)
  bewitched sum    FILE [ALGO...]            one or more digests
  bewitched strings FILE [MINLEN]            extract ASCII/UTF-16 strings
  bewitched search FILE PATTERN              wildcard hex search, e.g. 'DE ?? EF'
  bewitched find   FILE TEXT                 plain text search
  bewitched stats  FILE                      entropy + classification
  bewitched scan   FILE TYPE VALUE           value scan (i32/f32/text/hex/...)
  bewitched sigs   FILE                      detect embedded formats (binwalk)
  bewitched disasm FILE ARCH [OFF] [COUNT]   disassemble
  bewitched pointers FILE TARGET [MAXOFF]    find 64-bit pointers to TARGET
  bewitched export FILE FORMAT [OFF] [LEN]   export (e.g. 'C source', base64)
  bewitched struct FILE BUILTIN [OFF]        parse a structure tree (PNG/GIF/ELF/WAV)
  bewitched gunzip FILE                      decompress (auto-detect) to stdout
  bewitched crc    FILE W POLY INIT R X      custom CRC (W bits, R='rr'/'--')
  bewitched bps    ORIG MOD OUT              create a BPS patch ORIG→MOD
  bewitched --help | --version
";

/// Inspect argv (excluding the program name) and decide whether this is a CLI run.
pub fn dispatch(args: &[String]) -> Mode {
    let Some(cmd) = args.first() else {
        return Mode::NotCli;
    };
    // A bare path or the GUI/MCP flags are handled elsewhere.
    if cmd == "--mcp" || !is_command(cmd) {
        return Mode::NotCli;
    }
    let rest = &args[1..];
    let code = match run(cmd, rest) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("bewitched: {e}");
            1
        }
    };
    Mode::Run(code)
}

fn is_command(s: &str) -> bool {
    matches!(
        s,
        "dump"
            | "sha256"
            | "md5"
            | "sha1"
            | "sha512"
            | "crc32"
            | "sum"
            | "strings"
            | "search"
            | "find"
            | "stats"
            | "scan"
            | "sigs"
            | "disasm"
            | "pointers"
            | "export"
            | "gunzip"
            | "bps"
            | "crc"
            | "struct"
            | "help"
            | "--help"
            | "-h"
    )
}

fn run(cmd: &str, args: &[String]) -> Result<(), String> {
    if cmd == "help" || cmd == "--help" || cmd == "-h" {
        print!("{USAGE}");
        return Ok(());
    }
    // bps takes three file paths rather than the standard single FILE.
    if cmd == "bps" {
        let orig = args.first().ok_or("usage: bps ORIG MOD OUT")?;
        let modi = args.get(1).ok_or("usage: bps ORIG MOD OUT")?;
        let outp = args.get(2).ok_or("usage: bps ORIG MOD OUT")?;
        let a = std::fs::read(orig).map_err(|e| format!("read {orig}: {e}"))?;
        let b = std::fs::read(modi).map_err(|e| format!("read {modi}: {e}"))?;
        let p = patch::make_bps(&a, &b);
        std::fs::write(outp, &p).map_err(|e| format!("write {outp}: {e}"))?;
        eprintln!("wrote {} bytes", p.len());
        return Ok(());
    }
    let path = args.first().ok_or("missing FILE argument")?;
    let doc = Document::open_file(path).map_err(|e| format!("open {path}: {e}"))?;
    let total = doc.len();

    match cmd {
        "dump" => {
            let off = parse_u64(args.get(1)).unwrap_or(0);
            let len = parse_u64(args.get(2)).unwrap_or(256);
            print!(
                "{}",
                export::export(&doc, off, len, export::Format::PlainHexDump)
            );
        }
        "sha256" | "md5" | "sha1" | "sha512" | "crc32" => {
            let algo = digest_algo(cmd).unwrap();
            let r = checksum::compute(&doc, 0, total, &[algo], &Progress::default());
            println!("{}  {}", r[0].1, path);
        }
        "sum" => {
            let algos: Vec<checksum::Algo> = if args.len() > 1 {
                args[1..]
                    .iter()
                    .map(|a| digest_algo(a).ok_or(format!("unknown algorithm '{a}'")))
                    .collect::<Result<_, _>>()?
            } else {
                vec![
                    checksum::Algo::Md5,
                    checksum::Algo::Sha1,
                    checksum::Algo::Sha256,
                ]
            };
            let r = checksum::compute(&doc, 0, total, &algos, &Progress::default());
            for (a, v) in r {
                println!("{:<12} {}", a.name(), v);
            }
        }
        "strings" => {
            let min = parse_u64(args.get(1)).unwrap_or(4) as usize;
            let found =
                strings::extract(&doc, 0, total, min.max(1), 1_000_000, &Progress::default());
            for f in found {
                println!("{:#010X}  {}", f.offset, f.text);
            }
        }
        "search" => {
            let pat = args.get(1).ok_or("missing PATTERN")?;
            let (bytes, mask) = search::parse_hex_mask(pat)?;
            let hits = search::find_all_masked(&doc, &bytes, &mask, 1_000_000);
            for h in &hits {
                println!("{h:#010X}");
            }
            eprintln!("{} match(es)", hits.len());
        }
        "find" => {
            let text = args.get(1).ok_or("missing TEXT")?;
            let needle = text.as_bytes();
            let mut from = 0u64;
            let mut count = 0;
            while let Some(o) = search::find(&doc, needle, from, search::Direction::Forward, false)
            {
                println!("{o:#010X}");
                from = o + 1;
                count += 1;
            }
            eprintln!("{count} match(es)");
        }
        "stats" => {
            let s = stats::analyze(&doc, 0, total, &Progress::default());
            println!("bytes:          {}", s.total);
            println!("entropy:        {:.4} bits/byte", s.entropy);
            println!("classification: {}", s.classify());
            if let Some((b, c)) = s.most_common() {
                println!("most common:    {b:#04X} ({c} times)");
            }
        }
        "scan" => {
            let ty = search::DataType::from_name(args.get(1).map(|s| s.as_str()).unwrap_or(""))?;
            let value = args.get(2).ok_or("missing VALUE")?;
            let needle = search::needle_bytes(value, ty, search::Endian::Little, false)?;
            let m = scan::first_scan(
                &doc,
                &needle,
                needle.len() as u64,
                1_000_000,
                &Progress::default(),
            );
            for hit in &m {
                println!("{:#010X}", hit.offset);
            }
            eprintln!("{} match(es)", m.len());
        }
        "sigs" => {
            let hits = signatures::scan(&doc, 0, total, 100_000, &Progress::default());
            for h in hits {
                println!("{:#010X}  {:<12} {}", h.offset, h.category.label(), h.name);
            }
        }
        "disasm" => {
            let arch =
                disasm::Arch::from_name(args.get(1).map(|s| s.as_str()).unwrap_or("x86-64"))?;
            let off = parse_u64(args.get(2)).unwrap_or(0);
            let count = parse_u64(args.get(3)).unwrap_or(32) as usize;
            for i in disasm::disassemble(&doc, off, count, arch) {
                let bytes: String = i.bytes.iter().map(|b| format!("{b:02x}")).collect();
                println!("{:#010X}  {:<20} {}", i.offset, bytes, i.text);
            }
        }
        "pointers" => {
            let target = parse_u64(args.get(1)).ok_or("missing TARGET address")?;
            let max_off = parse_u64(args.get(2)).unwrap_or(0x1000);
            let hits = pointer::find_pointers_to(
                &doc,
                0,
                target,
                max_off,
                8,
                1_000_000,
                &Progress::default(),
            );
            for (addr, off) in &hits {
                println!("{addr:#010X}  +{off:#X}");
            }
            eprintln!("{} pointer(s)", hits.len());
        }
        "export" => {
            let fmt = export::Format::from_name(args.get(1).map(|s| s.as_str()).unwrap_or(""))?;
            let off = parse_u64(args.get(2)).unwrap_or(0);
            let len = parse_u64(args.get(3)).unwrap_or(total.saturating_sub(off));
            print!("{}", export::export(&doc, off, len, fmt));
        }
        "gunzip" => {
            use std::io::Write;
            let data = doc.read_range(0, total as usize);
            let codec = compress::detect(&data).ok_or("could not detect gzip/zlib header")?;
            let out = compress::decompress(&data, codec)?;
            std::io::stdout()
                .write_all(&out)
                .map_err(|e| e.to_string())?;
        }
        "struct" => {
            use crate::ops::kstruct;
            let key = args
                .get(1)
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| "png".into());
            let off = parse_u64(args.get(2)).unwrap_or(0);
            let src = kstruct::BUILTINS
                .iter()
                .find(|(n, _)| n.to_lowercase().contains(&key))
                .map(|(_, s)| *s)
                .ok_or_else(|| format!("no built-in schema matching '{key}'"))?;
            let schema = kstruct::Schema::parse(src)?;
            let root = kstruct::apply(&schema, &doc, off)?;
            let mut out = String::new();
            kstruct::render_tree(&root, 0, &mut out);
            print!("{out}");
        }
        "crc" => {
            // crc FILE WIDTH POLY INIT REFL XOROUT  (REFL = 'rr','--','r-','-r')
            let width = parse_u64(args.get(1)).ok_or("missing WIDTH")? as u32;
            let poly = parse_u64(args.get(2)).ok_or("missing POLY")?;
            let init = parse_u64(args.get(3)).unwrap_or(0);
            let refl = args.get(4).map(|s| s.as_str()).unwrap_or("--");
            let xorout = parse_u64(args.get(5)).unwrap_or(0);
            let params = checksum::CrcParams {
                width,
                poly,
                init,
                refin: refl.starts_with('r'),
                refout: refl.chars().nth(1) == Some('r'),
                xorout,
            };
            let data = doc.read_range(0, total as usize);
            let v = checksum::custom_crc(&data, &params);
            println!("{:0w$X}", v, w = (width as usize).div_ceil(4));
        }
        _ => return Err(format!("unknown command '{cmd}' (try --help)")),
    }
    Ok(())
}

fn parse_u64(s: Option<&String>) -> Option<u64> {
    crate::ops::parse_u64(s?)
}

fn digest_algo(name: &str) -> Option<checksum::Algo> {
    Some(match name.to_lowercase().as_str() {
        "md5" => checksum::Algo::Md5,
        "sha1" => checksum::Algo::Sha1,
        "sha256" => checksum::Algo::Sha256,
        "sha512" => checksum::Algo::Sha512,
        "crc32" => checksum::Algo::Crc32,
        "crc64" => checksum::Algo::Crc64,
        "adler32" => checksum::Algo::Adler32,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpfile(bytes: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bewitched_cli_{:?}_{}.bin",
            std::thread::current().id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn is_command_recognizes_subcommands() {
        assert!(is_command("sha256"));
        assert!(is_command("disasm"));
        assert!(!is_command("/tmp/file.bin"));
        assert!(!is_command("--mcp"));
    }

    #[test]
    fn dispatch_non_command_is_notcli() {
        assert!(matches!(dispatch(&["somefile.bin".into()]), Mode::NotCli));
        assert!(matches!(dispatch(&["--mcp".into()]), Mode::NotCli));
        assert!(matches!(dispatch(&[]), Mode::NotCli));
    }

    #[test]
    fn sha256_command_runs() {
        let p = tmpfile(b"abc");
        let r = run("sha256", &[p.to_string_lossy().into_owned()]);
        assert!(r.is_ok());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn search_wildcard_and_pointers() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&0x1000u64.to_le_bytes());
        let p = tmpfile(&data);
        let path = p.to_string_lossy().into_owned();
        assert!(run("pointers", &[path.clone(), "0x1000".into()]).is_ok());
        assert!(run("search", &[path, "00 ?? 00".into()]).is_ok());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn unknown_format_errors() {
        let p = tmpfile(b"x");
        let r = run(
            "export",
            &[p.to_string_lossy().into_owned(), "nonsense".into()],
        );
        assert!(r.is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_file_errors() {
        assert!(run("sha256", &["/no/such/file".into()]).is_err());
        assert!(run("sha256", &[]).is_err());
    }

    #[test]
    fn parse_helpers() {
        assert_eq!(parse_u64(Some(&"0x10".to_string())), Some(16));
        assert_eq!(parse_u64(Some(&"255".to_string())), Some(255));
        assert!(disasm::Arch::from_name("aarch64").is_ok());
        assert!(search::DataType::from_name("i32").is_ok());
        assert!(digest_algo("sha512").is_some());
    }
}
