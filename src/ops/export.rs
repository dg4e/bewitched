//! Export a document range to source code, formatted text, or hex file formats.

use crate::data::ByteReader;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    // Source code
    C,
    Cpp,
    Pascal,
    Java,
    CSharp,
    VbNet,
    Python,
    Rust,
    Go,
    Swift,
    Kotlin,
    JavaScript,
    TypeScript,
    Assembly,
    Ruby,
    Php,
    Perl,
    // Formatted text
    PlainHexDump,
    Html,
    Markdown,
    RichText,
    Tex,
    Base64,
    // Hex file formats
    IntelHex,
    MotorolaSRecord,
}

impl Format {
    pub const ALL: &'static [Format] = &[
        Format::C,
        Format::Cpp,
        Format::Pascal,
        Format::Java,
        Format::CSharp,
        Format::VbNet,
        Format::Python,
        Format::Rust,
        Format::Go,
        Format::Swift,
        Format::Kotlin,
        Format::JavaScript,
        Format::TypeScript,
        Format::Assembly,
        Format::Ruby,
        Format::Php,
        Format::Perl,
        Format::PlainHexDump,
        Format::Html,
        Format::Markdown,
        Format::RichText,
        Format::Tex,
        Format::Base64,
        Format::IntelHex,
        Format::MotorolaSRecord,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Format::C => "C source",
            Format::Cpp => "C++ source",
            Format::Pascal => "Pascal source",
            Format::Java => "Java source",
            Format::CSharp => "C# source",
            Format::VbNet => "VB.NET source",
            Format::Python => "Python source",
            Format::Rust => "Rust source",
            Format::Go => "Go source",
            Format::Swift => "Swift source",
            Format::Kotlin => "Kotlin source",
            Format::JavaScript => "JavaScript source",
            Format::TypeScript => "TypeScript source",
            Format::Assembly => "Assembly (NASM)",
            Format::Ruby => "Ruby source",
            Format::Php => "PHP source",
            Format::Perl => "Perl source",
            Format::PlainHexDump => "Hex dump (plain text)",
            Format::Html => "HTML",
            Format::Markdown => "Markdown",
            Format::RichText => "Rich Text (RTF)",
            Format::Tex => "TeX",
            Format::Base64 => "Base64",
            Format::IntelHex => "Intel HEX",
            Format::MotorolaSRecord => "Motorola S-record",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::C => "c",
            Format::Cpp => "cpp",
            Format::Pascal => "pas",
            Format::Java => "java",
            Format::CSharp => "cs",
            Format::VbNet => "vb",
            Format::Python => "py",
            Format::Rust => "rs",
            Format::Go => "go",
            Format::Swift => "swift",
            Format::Kotlin => "kt",
            Format::JavaScript => "js",
            Format::TypeScript => "ts",
            Format::Assembly => "asm",
            Format::Ruby => "rb",
            Format::Php => "php",
            Format::Perl => "pl",
            Format::PlainHexDump => "txt",
            Format::Html => "html",
            Format::Markdown => "md",
            Format::RichText => "rtf",
            Format::Tex => "tex",
            Format::Base64 => "b64",
            Format::IntelHex => "hex",
            Format::MotorolaSRecord => "srec",
        }
    }
}

fn collect(doc: &dyn ByteReader, offset: u64, len: u64) -> Vec<u8> {
    let end = (offset + len).min(doc.len());
    doc.read_range(offset, (end.saturating_sub(offset)) as usize)
}

pub fn export(doc: &dyn ByteReader, offset: u64, len: u64, fmt: Format) -> String {
    let data = collect(doc, offset, len);
    export_bytes(&data, offset, fmt)
}

/// Export an in-memory byte slice (kept separate so it is trivially testable).
pub fn export_bytes(data: &[u8], base: u64, fmt: Format) -> String {
    match fmt {
        Format::C => array(data, "unsigned char data[] = {", "};", &hx("0x"), ", ", 12),
        Format::Cpp => array(
            data,
            "const std::vector<uint8_t> data = {",
            "};",
            &hx("0x"),
            ", ",
            12,
        ),
        Format::Java => array(data, "byte[] data = {", "};", &|b| format!("(byte)0x{b:02X}"), ", ", 10),
        Format::CSharp => array(data, "byte[] data = {", "};", &hx("0x"), ", ", 12),
        Format::Rust => array(data, "let data: &[u8] = &[", "];", &hx("0x"), ", ", 12),
        Format::Go => array(data, "var data = []byte{", "}", &hx("0x"), ", ", 12),
        Format::Swift => array(data, "let data: [UInt8] = [", "]", &hx("0x"), ", ", 12),
        Format::Kotlin => array(
            data,
            "val data = byteArrayOf(",
            ")",
            &|b| format!("0x{b:02X}.toByte()"),
            ", ",
            8,
        ),
        Format::JavaScript => array(data, "const data = new Uint8Array([", "]);", &hx("0x"), ", ", 12),
        Format::TypeScript => array(
            data,
            "const data: Uint8Array = new Uint8Array([",
            "]);",
            &hx("0x"),
            ", ",
            12,
        ),
        Format::Python => array(data, "data = bytes([", "])", &hx("0x"), ", ", 12),
        Format::Ruby => array(data, "data = [", "].pack(\"C*\")", &hx("0x"), ", ", 12),
        Format::Perl => array(data, "my @data = (", ");", &hx("0x"), ", ", 12),
        Format::Php => array(data, "$data = array(", ");", &hx("0x"), ", ", 12),
        Format::Assembly => assembly(data),
        Format::VbNet => vbnet(data),
        Format::Pascal => pascal(data),
        Format::PlainHexDump => hexdump(data, base),
        Format::Html => html(data, base),
        Format::Markdown => markdown(data, base),
        Format::RichText => rtf(data, base),
        Format::Tex => tex(data, base),
        Format::Base64 => base64(data),
        Format::IntelHex => intel_hex(data, base),
        Format::MotorolaSRecord => srecord(data, base),
    }
}

/// Closure producing a per-byte literal with the given prefix.
fn hx(prefix: &'static str) -> impl Fn(u8) -> String {
    move |b| format!("{prefix}{b:02X}")
}

/// Generic C-family array emitter: header line, indented rows of `per_line`
/// byte literals separated by `sep`, then a footer line.
fn array(
    data: &[u8],
    header: &str,
    footer: &str,
    fmt_byte: &dyn Fn(u8) -> String,
    sep: &str,
    per_line: usize,
) -> String {
    let mut s = String::with_capacity(header.len() + data.len() * 6 + footer.len());
    s.push_str(header);
    s.push('\n');
    for (i, chunk) in data.chunks(per_line).enumerate() {
        if i > 0 {
            s.push_str(sep.trim_end());
            s.push('\n');
        }
        s.push_str("    ");
        let line: Vec<String> = chunk.iter().map(|&b| fmt_byte(b)).collect();
        s.push_str(&line.join(sep));
    }
    s.push('\n');
    s.push_str(footer);
    if !footer.is_empty() {
        s.push('\n');
    }
    s
}

fn assembly(data: &[u8]) -> String {
    let mut s = String::from("data:\n");
    for chunk in data.chunks(12) {
        let line: Vec<String> = chunk.iter().map(|b| format!("0x{:02X}", b)).collect();
        s.push_str("    db ");
        s.push_str(&line.join(", "));
        s.push('\n');
    }
    s
}

fn pascal(data: &[u8]) -> String {
    let mut s = format!(
        "const Data: array[0..{}] of Byte = (\n",
        data.len().saturating_sub(1)
    );
    for chunk in data.chunks(12) {
        s.push_str("  ");
        let line: Vec<String> = chunk.iter().map(|b| format!("${:02X}", b)).collect();
        s.push_str(&line.join(", "));
        s.push_str(",\n");
    }
    if s.ends_with(",\n") {
        s.truncate(s.len() - 2);
        s.push('\n');
    }
    s.push_str(");\n");
    s
}

fn vbnet(data: &[u8]) -> String {
    let mut s = String::from("Dim data As Byte() = New Byte() { _\n");
    for chunk in data.chunks(12) {
        s.push_str("    ");
        let line: Vec<String> = chunk.iter().map(|b| format!("&H{:02X}", b)).collect();
        s.push_str(&line.join(", "));
        s.push_str(", _\n");
    }
    s.push_str("}\n");
    s
}

fn hex_row(addr: u64, chunk: &[u8]) -> String {
    let mut hex = String::new();
    let mut asc = String::new();
    for i in 0..16 {
        if i == 8 {
            hex.push(' ');
        }
        if let Some(&b) = chunk.get(i) {
            hex.push_str(&format!("{:02X} ", b));
            asc.push(if (0x20..0x7f).contains(&b) { b as char } else { '.' });
        } else {
            hex.push_str("   ");
        }
    }
    format!("{:08X}  {} |{}|", addr, hex.trim_end(), asc)
}

fn hexdump(data: &[u8], base: u64) -> String {
    let mut s = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        s.push_str(&hex_row(base + (i * 16) as u64, chunk));
        s.push('\n');
    }
    s
}

fn markdown(data: &[u8], base: u64) -> String {
    let mut s = String::from("| Offset | Hex | ASCII |\n|---|---|---|\n");
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let asc: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect();
        s.push_str(&format!(
            "| `{:08X}` | `{}` | `{}` |\n",
            base + (i * 16) as u64,
            hex.join(" "),
            asc.replace('|', "\\|")
        ));
    }
    s
}

fn html(data: &[u8], base: u64) -> String {
    let mut s = String::from(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\
<style>body{background:#0b0e0b;color:#33ff66;font-family:monospace}\
.a{color:#557755}.m{color:#88aa88}</style></head><body><pre>\n",
    );
    for (i, chunk) in data.chunks(16).enumerate() {
        let line = hex_row(base + (i * 16) as u64, chunk);
        s.push_str(&line.replace('&', "&amp;").replace('<', "&lt;"));
        s.push('\n');
    }
    s.push_str("</pre></body></html>\n");
    s
}

fn rtf(data: &[u8], base: u64) -> String {
    let mut s = String::from("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Courier New;}}\\f0\\fs18\n");
    for (i, chunk) in data.chunks(16).enumerate() {
        s.push_str(&hex_row(base + (i * 16) as u64, chunk));
        s.push_str("\\line\n");
    }
    s.push_str("}\n");
    s
}

fn tex(data: &[u8], base: u64) -> String {
    let mut s = String::from("\\begin{verbatim}\n");
    s.push_str(&hexdump(data, base));
    s.push_str("\\end{verbatim}\n");
    s
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(B64[(n >> 18 & 63) as usize] as char);
        s.push(B64[(n >> 12 & 63) as usize] as char);
        s.push(if chunk.len() > 1 {
            B64[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    s.push('\n');
    s
}

/// Intel HEX: records of up to 16 bytes, with extended-address records as needed.
fn intel_hex(data: &[u8], base: u64) -> String {
    let mut s = String::new();
    let mut upper = u16::MAX; // force an initial extended-address record
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        let cur_upper = ((addr >> 16) & 0xFFFF) as u16;
        if cur_upper != upper {
            upper = cur_upper;
            let bytes = [0x02u8, 0x00, 0x00, 0x04, (upper >> 8) as u8, upper as u8];
            s.push_str(&ihex_line(&bytes));
        }
        let low = (addr & 0xFFFF) as u16;
        let mut rec = vec![chunk.len() as u8, (low >> 8) as u8, low as u8, 0x00];
        rec.extend_from_slice(chunk);
        s.push_str(&ihex_line(&rec));
    }
    s.push_str(":00000001FF\n"); // EOF record
    s
}

fn ihex_line(body: &[u8]) -> String {
    let sum = body.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let crc = (!sum).wrapping_add(1);
    let mut s = String::from(":");
    for &b in body {
        s.push_str(&format!("{:02X}", b));
    }
    s.push_str(&format!("{:02X}\n", crc));
    s
}

/// Motorola S-record using 32-bit addresses (S3/S7).
fn srecord(data: &[u8], base: u64) -> String {
    let mut s = String::from("S00600004844521B\n"); // header "HDR"
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = (base + (i * 16) as u64) as u32;
        let count = (chunk.len() + 5) as u8; // 4 addr + data + 1 checksum
        let mut body = vec![
            count,
            (addr >> 24) as u8,
            (addr >> 16) as u8,
            (addr >> 8) as u8,
            addr as u8,
        ];
        body.extend_from_slice(chunk);
        let sum = body.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        s.push_str("S3");
        for &b in &body {
            s.push_str(&format!("{:02X}", b));
        }
        s.push_str(&format!("{:02X}\n", !sum));
    }
    s.push_str("S70500000000FA\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn d(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    #[test]
    fn c_source() {
        let out = export_bytes(&[0xDE, 0xAD, 0xBE, 0xEF], 0, Format::C);
        assert!(out.contains("0xDE, 0xAD, 0xBE, 0xEF"));
        assert!(out.starts_with("unsigned char data[] = {"));
        assert!(out.trim_end().ends_with("};"));
    }

    #[test]
    fn java_casts_bytes() {
        let out = export_bytes(&[0xFF], 0, Format::Java);
        assert!(out.contains("(byte)0xFF"));
    }

    #[test]
    fn kotlin_tobyte() {
        let out = export_bytes(&[0x80], 0, Format::Kotlin);
        assert!(out.contains("0x80.toByte()"));
        assert!(out.contains("byteArrayOf("));
    }

    #[test]
    fn go_swift_js_ts_headers() {
        assert!(export_bytes(&[1], 0, Format::Go).starts_with("var data = []byte{"));
        assert!(export_bytes(&[1], 0, Format::Swift).starts_with("let data: [UInt8] = ["));
        assert!(export_bytes(&[1], 0, Format::JavaScript).contains("new Uint8Array(["));
        assert!(export_bytes(&[1], 0, Format::TypeScript).contains(": Uint8Array"));
    }

    #[test]
    fn assembly_db() {
        let out = export_bytes(&[0x90, 0x90], 0, Format::Assembly);
        assert!(out.contains("data:"));
        assert!(out.contains("db 0x90, 0x90"));
    }

    #[test]
    fn ruby_php_perl() {
        assert!(export_bytes(&[1], 0, Format::Ruby).contains(".pack(\"C*\")"));
        assert!(export_bytes(&[1], 0, Format::Php).contains("$data = array("));
        assert!(export_bytes(&[1], 0, Format::Perl).contains("my @data = ("));
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(base64(b"").trim_end(), "");
        assert_eq!(base64(b"f").trim_end(), "Zg==");
        assert_eq!(base64(b"fo").trim_end(), "Zm8=");
        assert_eq!(base64(b"foo").trim_end(), "Zm9v");
        assert_eq!(base64(b"foobar").trim_end(), "Zm9vYmFy");
    }

    #[test]
    fn intel_hex_checksum_and_eof() {
        let out = export_bytes(&[0u8; 4], 0, Format::IntelHex);
        assert!(out.contains(":0400000000000000FC"));
        assert!(out.trim_end().ends_with(":00000001FF"));
    }

    #[test]
    fn srecord_header_present() {
        let out = export_bytes(&[1, 2, 3], 0, Format::MotorolaSRecord);
        assert!(out.starts_with("S0"));
        assert!(out.contains("S3"));
    }

    #[test]
    fn all_formats_nonempty_and_distinct_ext() {
        let doc = d(&[0x00, 0x41, 0x7f, 0xff]);
        let mut exts = std::collections::HashSet::new();
        for f in Format::ALL {
            let out = export(&doc, 0, doc.len(), *f);
            assert!(!out.is_empty(), "{:?} produced empty output", f);
            exts.insert(f.extension());
        }
        // a healthy spread of extensions
        assert!(exts.len() > 15);
    }

    #[test]
    fn export_respects_offset_in_dump() {
        let doc = d(&[0u8; 32]);
        let out = export(&doc, 16, 16, Format::PlainHexDump);
        assert!(out.contains("00000010"));
    }
}
