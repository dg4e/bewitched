//! Binary templates — a tiny structure-description DSL (010-editor / Kaitai
//! flavored) that parses a document into named, typed fields.
//!
//! A template is a line-oriented script. Each statement reads from the current
//! position and (usually) names the value, advancing the cursor:
//!
//! ```text
//! magic "BM"          # assert literal bytes (ascii "..." or hex bytes)
//! le                  # little-endian (default) / be for big-endian
//! u8 / u16 / u32 / u64        name      # unsigned integer
//! i8 / i16 / i32 / i64        name      # signed integer
//! f32 / f64                   name      # float
//! ascii  N    name     # N-byte string (N is a literal or a prior field name)
//! bytes  N    name     # N raw bytes (hex preview)
//! skip   N             # advance N bytes
//! ```
//!
//! `N` may reference a previously-read integer field, so length-prefixed
//! structures parse correctly.

use crate::data::ByteReader;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NumTy {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl NumTy {
    fn width(self) -> usize {
        match self {
            NumTy::U8 | NumTy::I8 => 1,
            NumTy::U16 | NumTy::I16 => 2,
            NumTy::U32 | NumTy::I32 | NumTy::F32 => 4,
            NumTy::U64 | NumTy::I64 | NumTy::F64 => 8,
        }
    }
    fn parse(s: &str) -> Option<NumTy> {
        Some(match s {
            "u8" => NumTy::U8,
            "u16" => NumTy::U16,
            "u32" => NumTy::U32,
            "u64" => NumTy::U64,
            "i8" => NumTy::I8,
            "i16" => NumTy::I16,
            "i32" => NumTy::I32,
            "i64" => NumTy::I64,
            "f32" => NumTy::F32,
            "f64" => NumTy::F64,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
enum Count {
    Lit(u64),
    Ref(String),
}

#[derive(Clone, Debug)]
enum Stmt {
    Magic(Vec<u8>),
    Endian(bool), // true = little
    Num { ty: NumTy, name: String },
    Ascii { count: Count, name: String },
    Bytes { count: Count, name: String },
    Skip(Count),
}

#[derive(Debug)]
pub struct Template {
    stmts: Vec<Stmt>,
}

/// How an edited field value is encoded back to bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditKind {
    /// Unsigned integer of `width` bytes, little-endian if true.
    Uint(usize, bool),
    /// Signed integer of `width` bytes.
    Sint(usize, bool),
    F32(bool),
    F64(bool),
    Ascii,
    Hex,
    /// Not editable (e.g. a magic marker).
    None,
}

/// A parsed field produced by applying a template.
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub kind: String,
    pub value: String,
    pub edit: EditKind,
}

use super::parse_int_lit;

/// Encode an edited field value back into bytes per its [`EditKind`].
pub fn encode(kind: &EditKind, input: &str) -> Result<Vec<u8>, String> {
    let pack = |v: u128, w: usize, le: bool| -> Vec<u8> {
        let le_bytes = v.to_le_bytes();
        if le {
            le_bytes[..w].to_vec()
        } else {
            le_bytes[..w].iter().rev().copied().collect()
        }
    };
    match kind {
        EditKind::Uint(w, le) => {
            let n = parse_int_lit(input).ok_or("invalid integer")?;
            if n < 0 {
                return Err("value is negative".into());
            }
            let n = n as u128;
            if *w < 16 && n >= (1u128 << (w * 8)) {
                return Err(format!("value too large for {w} byte(s)"));
            }
            Ok(pack(n, *w, *le))
        }
        EditKind::Sint(w, le) => {
            let n = parse_int_lit(input).ok_or("invalid integer")?;
            let bits = (*w * 8) as u32;
            let min = -(1i128 << (bits - 1));
            let max = (1i128 << (bits - 1)) - 1;
            if n < min || n > max {
                return Err(format!("value out of range for i{bits}"));
            }
            // two's complement: low `bits` of the wrapped unsigned value
            let mask = (1u128 << bits) - 1;
            Ok(pack((n as u128) & mask, *w, *le))
        }
        EditKind::F32(le) => {
            let f: f32 = input.trim().parse().map_err(|_| "invalid float")?;
            let b = f.to_le_bytes();
            Ok(if *le {
                b.to_vec()
            } else {
                b.iter().rev().copied().collect()
            })
        }
        EditKind::F64(le) => {
            let f: f64 = input.trim().parse().map_err(|_| "invalid float")?;
            let b = f.to_le_bytes();
            Ok(if *le {
                b.to_vec()
            } else {
                b.iter().rev().copied().collect()
            })
        }
        EditKind::Ascii => Ok(input.as_bytes().to_vec()),
        EditKind::Hex => crate::ops::search::needle_bytes(
            input,
            crate::ops::search::DataType::Hex,
            crate::ops::search::Endian::Little,
            false,
        ),
        EditKind::None => Err("field is not editable".into()),
    }
}

fn parse_count(tok: &str) -> Count {
    if let Some(h) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(h, 16) {
            return Count::Lit(n);
        }
    }
    match tok.parse::<u64>() {
        Ok(n) => Count::Lit(n),
        Err(_) => Count::Ref(tok.to_string()),
    }
}

fn parse_magic(rest: &str) -> Result<Vec<u8>, String> {
    let rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(inner.as_bytes().to_vec());
    }
    // hex byte list
    let mut out = Vec::new();
    for tok in rest.split_whitespace() {
        let t = tok.strip_prefix("0x").unwrap_or(tok);
        out.push(u8::from_str_radix(t, 16).map_err(|_| format!("bad magic byte '{tok}'"))?);
    }
    if out.is_empty() {
        return Err("empty magic".into());
    }
    Ok(out)
}

impl Template {
    pub fn parse(src: &str) -> Result<Template, String> {
        let mut stmts = Vec::new();
        for (lineno, raw) in src.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let err = |m: &str| format!("line {}: {}", lineno + 1, m);
            let mut it = line.splitn(2, char::is_whitespace);
            let kw = it.next().unwrap();
            let rest = it.next().unwrap_or("").trim();
            match kw {
                "le" => stmts.push(Stmt::Endian(true)),
                "be" => stmts.push(Stmt::Endian(false)),
                "magic" => stmts.push(Stmt::Magic(parse_magic(rest).map_err(|e| err(&e))?)),
                "skip" => {
                    if rest.is_empty() {
                        return Err(err("skip needs a count"));
                    }
                    stmts.push(Stmt::Skip(parse_count(rest)));
                }
                "ascii" | "bytes" => {
                    let mut parts = rest.split_whitespace();
                    let count = parts.next().ok_or_else(|| err("missing count"))?;
                    let name = parts.next().ok_or_else(|| err("missing name"))?;
                    let count = parse_count(count);
                    if kw == "ascii" {
                        stmts.push(Stmt::Ascii {
                            count,
                            name: name.into(),
                        });
                    } else {
                        stmts.push(Stmt::Bytes {
                            count,
                            name: name.into(),
                        });
                    }
                }
                other => {
                    if let Some(ty) = NumTy::parse(other) {
                        let name = rest
                            .split_whitespace()
                            .next()
                            .ok_or_else(|| err("missing name"))?;
                        stmts.push(Stmt::Num {
                            ty,
                            name: name.into(),
                        });
                    } else {
                        return Err(err(&format!("unknown statement '{other}'")));
                    }
                }
            }
        }
        Ok(Template { stmts })
    }
}

fn read_uint(bytes: &[u8], le: bool) -> u64 {
    let mut v = 0u64;
    if le {
        for &b in bytes.iter().rev() {
            v = (v << 8) | b as u64;
        }
    } else {
        for &b in bytes {
            v = (v << 8) | b as u64;
        }
    }
    v
}

/// Apply a template to `reader` starting at `start`, producing parsed fields.
pub fn apply(tmpl: &Template, reader: &dyn ByteReader, start: u64) -> Result<Vec<Field>, String> {
    let mut pos = start;
    let mut le = true;
    let mut fields: Vec<Field> = Vec::new();
    let mut vals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    let resolve =
        |c: &Count, vals: &std::collections::HashMap<String, u64>| -> Result<u64, String> {
            match c {
                Count::Lit(n) => Ok(*n),
                Count::Ref(name) => vals
                    .get(name)
                    .copied()
                    .ok_or_else(|| format!("unknown length field '{name}'")),
            }
        };

    let read = |pos: u64, n: usize| -> Result<Vec<u8>, String> {
        let buf = reader.read_range(pos, n);
        if buf.len() < n {
            Err(format!("unexpected end of data at {:#X}", pos))
        } else {
            Ok(buf)
        }
    };

    for stmt in &tmpl.stmts {
        match stmt {
            Stmt::Endian(l) => le = *l,
            Stmt::Magic(m) => {
                let got = read(pos, m.len())?;
                if &got != m {
                    return Err(format!("magic mismatch at {:#X}", pos));
                }
                fields.push(Field {
                    name: "magic".into(),
                    offset: pos,
                    size: m.len() as u64,
                    kind: "magic".into(),
                    value: String::from_utf8_lossy(m).into_owned(),
                    edit: EditKind::None,
                });
                pos += m.len() as u64;
            }
            // `skip` advances without reading, so a huge count could overflow
            // `pos`; saturate (a past-EOF cursor just makes later reads fail).
            Stmt::Skip(c) => pos = pos.saturating_add(resolve(c, &vals)?),
            Stmt::Num { ty, name } => {
                let w = ty.width();
                let raw = read(pos, w)?;
                let (value, store) = match ty {
                    NumTy::F32 => {
                        let bits = read_uint(&raw, le) as u32;
                        (f32::from_bits(bits).to_string(), None)
                    }
                    NumTy::F64 => {
                        let bits = read_uint(&raw, le);
                        (f64::from_bits(bits).to_string(), None)
                    }
                    NumTy::I8 | NumTy::I16 | NumTy::I32 | NumTy::I64 => {
                        let u = read_uint(&raw, le);
                        let shift = 64 - w * 8;
                        let s = ((u << shift) as i64) >> shift;
                        (s.to_string(), Some(u))
                    }
                    _ => {
                        let u = read_uint(&raw, le);
                        (u.to_string(), Some(u))
                    }
                };
                if let Some(u) = store {
                    vals.insert(name.clone(), u);
                }
                let edit = match ty {
                    NumTy::U8 | NumTy::U16 | NumTy::U32 | NumTy::U64 => EditKind::Uint(w, le),
                    NumTy::I8 | NumTy::I16 | NumTy::I32 | NumTy::I64 => EditKind::Sint(w, le),
                    NumTy::F32 => EditKind::F32(le),
                    NumTy::F64 => EditKind::F64(le),
                };
                fields.push(Field {
                    name: name.clone(),
                    offset: pos,
                    size: w as u64,
                    kind: format!("{:?}", ty).to_lowercase(),
                    value,
                    edit,
                });
                pos += w as u64;
            }
            Stmt::Ascii { count, name } => {
                let n = resolve(count, &vals)? as usize;
                let raw = read(pos, n)?;
                let s = String::from_utf8_lossy(&raw)
                    .trim_end_matches('\0')
                    .to_string();
                fields.push(Field {
                    name: name.clone(),
                    offset: pos,
                    size: n as u64,
                    kind: "ascii".into(),
                    value: s,
                    edit: EditKind::Ascii,
                });
                pos += n as u64;
            }
            Stmt::Bytes { count, name } => {
                let n = resolve(count, &vals)? as usize;
                let raw = read(pos, n)?;
                let preview: String = raw
                    .iter()
                    .take(16)
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                let value = if n > 16 {
                    format!("{preview} … ({n} bytes)")
                } else {
                    preview
                };
                fields.push(Field {
                    name: name.clone(),
                    offset: pos,
                    size: n as u64,
                    kind: "bytes".into(),
                    value,
                    edit: EditKind::Hex,
                });
                pos += n as u64;
            }
        }
    }
    Ok(fields)
}

/// Built-in templates: (display name, source).
pub const BUILTINS: &[(&str, &str)] = &[
    (
        "BMP image",
        "magic \"BM\"\nle\nu32 file_size\nu16 reserved1\nu16 reserved2\nu32 pixel_offset\nu32 dib_header_size\ni32 width\ni32 height\nu16 planes\nu16 bpp\n",
    ),
    (
        "PNG image",
        "magic 89 50 4E 47 0D 0A 1A 0A\nbe\nu32 ihdr_length\nascii 4 ihdr_type\nu32 width\nu32 height\nu8 bit_depth\nu8 color_type\nu8 compression\nu8 filter\nu8 interlace\n",
    ),
    (
        "ELF header (64-bit)",
        "magic 7F 45 4C 46\nu8 ei_class\nu8 ei_data\nu8 ei_version\nu8 ei_osabi\nskip 8\nle\nu16 e_type\nu16 e_machine\nu32 e_version\nu64 e_entry\nu64 e_phoff\nu64 e_shoff\n",
    ),
    (
        "WAV / RIFF",
        "magic \"RIFF\"\nle\nu32 chunk_size\nascii 4 format\nascii 4 subchunk1_id\nu32 subchunk1_size\nu16 audio_format\nu16 num_channels\nu32 sample_rate\nu32 byte_rate\nu16 block_align\nu16 bits_per_sample\n",
    ),
    (
        "GIF header",
        "magic \"GIF\"\nascii 3 version\nle\nu16 width\nu16 height\n",
    ),
    (
        "Length-prefixed blob (demo)",
        "# u32 length, then that many bytes\nle\nu32 length\nbytes length payload\n",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn doc(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    fn field<'a>(f: &'a [Field], name: &str) -> &'a Field {
        f.iter().find(|x| x.name == name).unwrap()
    }

    #[test]
    fn parses_bmp_header() {
        // "BM", file_size=70 (LE), reserved 0,0, pixel_offset=54,
        // dib=40, width=2, height=2, planes=1, bpp=24
        let mut data = Vec::new();
        data.extend_from_slice(b"BM");
        data.extend_from_slice(&70u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&54u32.to_le_bytes());
        data.extend_from_slice(&40u32.to_le_bytes());
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&24u16.to_le_bytes());
        let d = doc(&data);

        let tmpl = Template::parse(BUILTINS[0].1).unwrap();
        let f = apply(&tmpl, &d, 0).unwrap();
        assert_eq!(field(&f, "file_size").value, "70");
        assert_eq!(field(&f, "width").value, "2");
        assert_eq!(field(&f, "bpp").value, "24");
        assert_eq!(field(&f, "bpp").offset, data.len() as u64 - 2);
    }

    #[test]
    fn skip_huge_count_saturates_not_panics() {
        // `skip` advances without reading; a u64-overflowing count must saturate
        // (then the next read fails cleanly) rather than panic.
        let tmpl = Template::parse("skip 0xffffffffffffffff\nu8 x\n").unwrap();
        let r = apply(&tmpl, &doc(&[1, 2, 3, 4]), 0);
        assert!(r.is_err());
    }

    #[test]
    fn big_endian_png() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&13u32.to_be_bytes()); // ihdr_length
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&1920u32.to_be_bytes()); // width
        data.extend_from_slice(&1080u32.to_be_bytes()); // height
        data.push(8); // bit_depth
        data.push(6); // color_type
        data.push(0); // compression
        data.push(0); // filter
        data.push(0); // interlace
        let d = doc(&data);
        let tmpl = Template::parse(BUILTINS[1].1).unwrap();
        let f = apply(&tmpl, &d, 0).unwrap();
        assert_eq!(field(&f, "ihdr_type").value, "IHDR");
        assert_eq!(field(&f, "width").value, "1920");
        assert_eq!(field(&f, "height").value, "1080");
    }

    #[test]
    fn length_reference() {
        let mut data = Vec::new();
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(b"hello");
        let d = doc(&data);
        let tmpl = Template::parse("le\nu32 length\nbytes length payload\n").unwrap();
        let f = apply(&tmpl, &d, 0).unwrap();
        assert_eq!(field(&f, "length").value, "5");
        assert_eq!(field(&f, "payload").size, 5);
        assert_eq!(field(&f, "payload").value, "68 65 6C 6C 6F");
    }

    #[test]
    fn magic_mismatch_errors() {
        let d = doc(b"XX\x00\x00");
        let tmpl = Template::parse("magic \"BM\"\n").unwrap();
        assert!(apply(&tmpl, &d, 0).unwrap_err().contains("magic mismatch"));
    }

    #[test]
    fn signed_values() {
        let d = doc(&(-5i32).to_le_bytes());
        let tmpl = Template::parse("le\ni32 v\n").unwrap();
        let f = apply(&tmpl, &d, 0).unwrap();
        assert_eq!(field(&f, "v").value, "-5");
    }

    #[test]
    fn truncated_data_errors() {
        let d = doc(b"BM\x01"); // not enough for the u32 after magic
        let tmpl = Template::parse("magic \"BM\"\nle\nu32 file_size\n").unwrap();
        assert!(apply(&tmpl, &d, 0).unwrap_err().contains("end of data"));
    }

    #[test]
    fn parse_errors_report_line() {
        let e = Template::parse("le\nbogus thing\n").unwrap_err();
        assert!(e.contains("line 2"));
        assert!(e.contains("unknown statement"));
    }

    #[test]
    fn all_builtins_parse() {
        for (name, src) in BUILTINS {
            assert!(
                Template::parse(src).is_ok(),
                "builtin {name} failed to parse"
            );
        }
    }

    #[test]
    fn encode_roundtrips() {
        assert_eq!(
            encode(&EditKind::Uint(2, true), "258").unwrap(),
            vec![0x02, 0x01]
        );
        assert_eq!(
            encode(&EditKind::Uint(2, false), "258").unwrap(),
            vec![0x01, 0x02]
        );
        assert_eq!(encode(&EditKind::Sint(1, true), "-1").unwrap(), vec![0xFF]);
        assert_eq!(
            encode(&EditKind::Sint(2, true), "-2").unwrap(),
            vec![0xFE, 0xFF]
        );
        assert_eq!(
            encode(&EditKind::F32(true), "1.5").unwrap(),
            1.5f32.to_le_bytes().to_vec()
        );
        assert_eq!(encode(&EditKind::Ascii, "Hi").unwrap(), b"Hi".to_vec());
        assert_eq!(encode(&EditKind::Hex, "DE AD").unwrap(), vec![0xDE, 0xAD]);
        assert_eq!(
            encode(&EditKind::Uint(4, true), "0x100").unwrap(),
            vec![0, 1, 0, 0]
        );
    }

    #[test]
    fn encode_rejects_out_of_range() {
        assert!(encode(&EditKind::Uint(1, true), "300").is_err());
        assert!(encode(&EditKind::Uint(1, true), "-5").is_err());
        assert!(encode(&EditKind::Sint(1, true), "200").is_err());
        assert!(encode(&EditKind::None, "x").is_err());
        assert!(encode(&EditKind::F32(true), "notnum").is_err());
    }

    #[test]
    fn fields_carry_edit_kind() {
        let d = doc(&[1u8, 0, 0, 0]);
        let f = apply(&Template::parse("le\nu32 x\n").unwrap(), &d, 0).unwrap();
        assert_eq!(field(&f, "x").edit, EditKind::Uint(4, true));
    }

    #[test]
    fn edit_then_write_changes_bytes() {
        // round-trip an edit: read field, encode a new value, verify bytes
        let kind = EditKind::Uint(2, true);
        let bytes = encode(&kind, "4660").unwrap(); // 0x1234
        assert_eq!(bytes, vec![0x34, 0x12]);
    }

    #[test]
    fn apply_at_offset() {
        let mut data = vec![0xAA; 4];
        data.extend_from_slice(&7u16.to_le_bytes());
        let d = doc(&data);
        let tmpl = Template::parse("le\nu16 v\n").unwrap();
        let f = apply(&tmpl, &d, 4).unwrap();
        assert_eq!(field(&f, "v").value, "7");
        assert_eq!(field(&f, "v").offset, 4);
    }
}
