//! Persistent annotations sidecar.
//!
//! Bookmarks, regions/data-folds and free-text notes are saved next to a file as
//! `<file>.bw` so they survive across sessions. The format is a simple,
//! human-readable, line-oriented text format (no external serializer), which is
//! easy to diff, hand-edit and unit-test.

use std::path::{Path, PathBuf};

use crate::data::Region;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub offset: u64,
    pub len: u64,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sidecar {
    pub bookmarks: [Option<u64>; 10],
    pub regions: Vec<Region>,
    pub notes: Vec<Note>,
}

const HEADER: &str = "bewitched-sidecar 1";

/// The sidecar path for a document path: `foo.bin` -> `foo.bin.bw`.
pub fn sidecar_path(doc: &Path) -> PathBuf {
    let mut s = doc.as_os_str().to_os_string();
    s.push(".bw");
    PathBuf::from(s)
}

pub fn serialize(s: &Sidecar) -> String {
    let mut out = String::new();
    out.push_str(HEADER);
    out.push('\n');
    for (slot, bm) in s.bookmarks.iter().enumerate() {
        if let Some(off) = bm {
            out.push_str(&format!("bookmark {slot} {off:X}\n"));
        }
    }
    for r in &s.regions {
        out.push_str(&format!(
            "region {:X} {:X} {} {} {}\n",
            r.start,
            r.len,
            if r.accessible { 'a' } else { 'i' },
            if r.folded { 'f' } else { 'u' },
            r.label.replace('\n', " ")
        ));
    }
    for n in &s.notes {
        out.push_str(&format!("note {:X} {:X} {}\n", n.offset, n.len, n.text.replace('\n', " ")));
    }
    out
}

pub fn parse(src: &str) -> Result<Sidecar, String> {
    let mut lines = src.lines();
    match lines.next() {
        Some(h) if h.trim() == HEADER => {}
        _ => return Err("not a bewitched sidecar (bad header)".into()),
    }
    let mut sc = Sidecar::default();
    for (i, raw) in lines.enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lineno = i + 2;
        let mut it = line.splitn(2, ' ');
        let kw = it.next().unwrap_or("");
        let rest = it.next().unwrap_or("");
        match kw {
            "bookmark" => {
                let mut p = rest.splitn(2, ' ');
                let slot: usize = p
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| format!("line {lineno}: bad bookmark slot"))?;
                let off = u64::from_str_radix(p.next().unwrap_or("").trim(), 16)
                    .map_err(|_| format!("line {lineno}: bad bookmark offset"))?;
                if slot < 10 {
                    sc.bookmarks[slot] = Some(off);
                }
            }
            "region" => {
                // region <start> <len> <a|i> <f|u> <label...>
                let mut p = rest.splitn(5, ' ');
                let start = hex(p.next(), lineno, "region start")?;
                let len = hex(p.next(), lineno, "region len")?;
                let acc = p.next().unwrap_or("a") == "a";
                let folded = p.next().unwrap_or("u") == "f";
                let label = p.next().unwrap_or("").to_string();
                sc.regions.push(Region {
                    start,
                    len,
                    label,
                    accessible: acc,
                    folded,
                });
            }
            "note" => {
                let mut p = rest.splitn(3, ' ');
                let offset = hex(p.next(), lineno, "note offset")?;
                let len = hex(p.next(), lineno, "note len")?;
                let text = p.next().unwrap_or("").to_string();
                sc.notes.push(Note { offset, len, text });
            }
            _ => {} // ignore unknown lines for forward compatibility
        }
    }
    Ok(sc)
}

fn hex(tok: Option<&str>, lineno: usize, what: &str) -> Result<u64, String> {
    u64::from_str_radix(tok.unwrap_or("").trim(), 16)
        .map_err(|_| format!("line {lineno}: bad {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sidecar {
        let mut bookmarks = [None; 10];
        bookmarks[0] = Some(0x10);
        bookmarks[3] = Some(0xDEAD);
        Sidecar {
            bookmarks,
            regions: vec![
                Region {
                    start: 0,
                    len: 16,
                    label: "header bytes".into(),
                    accessible: true,
                    folded: false,
                },
                Region::inaccessible(0x1000, 0x800, "kernel area"),
            ],
            notes: vec![
                Note { offset: 0x20, len: 4, text: "magic number".into() },
                Note { offset: 0x40, len: 8, text: "timestamp field".into() },
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let s = sample();
        let text = serialize(&s);
        let back = parse(&text).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn header_required() {
        assert!(parse("nope\nbookmark 0 10\n").is_err());
        assert!(parse(&serialize(&Sidecar::default())).is_ok());
    }

    #[test]
    fn labels_with_spaces_survive() {
        let s = parse("bewitched-sidecar 1\nregion 0 10 a u my long label here\n").unwrap();
        assert_eq!(s.regions[0].label, "my long label here");
        assert_eq!(s.regions[0].len, 0x10);
    }

    #[test]
    fn unknown_lines_ignored() {
        let s = parse("bewitched-sidecar 1\nfuture_thing 1 2 3\nnote 5 1 hi\n").unwrap();
        assert_eq!(s.notes.len(), 1);
        assert_eq!(s.notes[0].text, "hi");
    }

    #[test]
    fn bad_values_error() {
        assert!(parse("bewitched-sidecar 1\nbookmark x y\n").is_err());
        assert!(parse("bewitched-sidecar 1\nnote zz 1 oops\n").is_err());
    }

    #[test]
    fn sidecar_path_appends() {
        assert_eq!(
            sidecar_path(Path::new("/tmp/foo.bin")),
            PathBuf::from("/tmp/foo.bin.bw")
        );
    }

    #[test]
    fn disk_roundtrip() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "bewitched_side_{:?}_{}",
            std::thread::current().id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let doc = dir.join("data.bin");
        std::fs::write(&doc, b"payload").unwrap();

        let path = sidecar_path(&doc);
        assert_eq!(path.file_name().unwrap(), "data.bin.bw");
        std::fs::write(&path, serialize(&sample())).unwrap();

        let back = parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, sample());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inaccessible_region_flag_roundtrips() {
        let s = sample();
        let back = parse(&serialize(&s)).unwrap();
        assert!(!back.regions[1].accessible);
        assert!(back.regions[1].folded);
    }
}
