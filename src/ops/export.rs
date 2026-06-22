//! Export a document range to source code, formatted text, or hex file formats.

use crate::data::ByteReader;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    // Source code
    C,
    Pascal,
    Java,
    CSharp,
    VbNet,
    Python,
    Rust,
    // Formatted text
    PlainHexDump,
    Html,
    Markdown,
    RichText,
    Tex,
    // Hex file formats
    IntelHex,
    MotorolaSRecord,
}

impl Format {
    pub const ALL: &'static [Format] = &[
        Format::C,
        Format::Pascal,
        Format::Java,
        Format::CSharp,
        Format::VbNet,
        Format::Python,
        Format::Rust,
        Format::PlainHexDump,
        Format::Html,
        Format::Markdown,
        Format::RichText,
        Format::Tex,
        Format::IntelHex,
        Format::MotorolaSRecord,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Format::C => "C source",
            Format::Pascal => "Pascal source",
            Format::Java => "Java source",
            Format::CSharp => "C# source",
            Format::VbNet => "VB.NET source",
            Format::Python => "Python source",
            Format::Rust => "Rust source",
            Format::PlainHexDump => "Hex dump (plain text)",
            Format::Html => "HTML",
            Format::Markdown => "Markdown",
            Format::RichText => "Rich Text (RTF)",
            Format::Tex => "TeX",
            Format::IntelHex => "Intel HEX",
            Format::MotorolaSRecord => "Motorola S-record",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Format::C => "c",
            Format::Pascal => "pas",
            Format::Java => "java",
            Format::CSharp => "cs",
            Format::VbNet => "vb",
            Format::Python => "py",
            Format::Rust => "rs",
            Format::PlainHexDump => "txt",
            Format::Html => "html",
            Format::Markdown => "md",
            Format::RichText => "rtf",
            Format::Tex => "tex",
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
    match fmt {
        Format::C => carray(&data, "unsigned char data[]", "0x", ", ", ";", "{", "}"),
        Format::Java => carray(
            &data,
            "byte[] data =",
            "(byte)0x",
            ", ",
            ";",
            "{",
            "}",
        ),
        Format::CSharp => carray(&data, "byte[] data =", "0x", ", ", ";", "{", "}"),
        Format::Rust => carray(&data, "let data: &[u8] =", "0x", ", ", ";", "&[", "]"),
        Format::Python => pyarray(&data),
        Format::Pascal => pascal(&data),
        Format::VbNet => vbnet(&data),
        Format::PlainHexDump => hexdump(&data, offset),
        Format::Html => html(&data, offset),
        Format::Markdown => markdown(&data, offset),
        Format::RichText => rtf(&data, offset),
        Format::Tex => tex(&data, offset),
        Format::IntelHex => intel_hex(&data, offset),
        Format::MotorolaSRecord => srecord(&data, offset),
    }
}

fn carray(
    data: &[u8],
    decl: &str,
    prefix: &str,
    sep: &str,
    term: &str,
    open: &str,
    close: &str,
) -> String {
    let mut s = format!("{} {}\n", decl, open);
    for (i, chunk) in data.chunks(12).enumerate() {
        if i > 0 {
            s.push_str(",\n");
        }
        s.push_str("    ");
        let line: Vec<String> = chunk.iter().map(|b| format!("{}{:02X}", prefix, b)).collect();
        s.push_str(&line.join(sep));
    }
    s.push('\n');
    s.push_str(close);
    s.push_str(term);
    s.push('\n');
    s
}

fn pyarray(data: &[u8]) -> String {
    let mut s = String::from("data = bytes([\n");
    for chunk in data.chunks(12) {
        s.push_str("    ");
        let line: Vec<String> = chunk.iter().map(|b| format!("0x{:02X}", b)).collect();
        s.push_str(&line.join(", "));
        s.push_str(",\n");
    }
    s.push_str("])\n");
    s
}

fn pascal(data: &[u8]) -> String {
    let mut s = format!("const Data: array[0..{}] of Byte = (\n", data.len().saturating_sub(1));
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
        let doc = d(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let out = export(&doc, 0, 4, Format::C);
        assert!(out.contains("0xDE"));
        assert!(out.contains("unsigned char data[]"));
    }

    #[test]
    fn intel_hex_checksum_and_eof() {
        let doc = d(&[0x00u8; 4]);
        let out = export(&doc, 0, 4, Format::IntelHex);
        // data record for 4 zero bytes at 0x0000: :0400000000000000FC
        assert!(out.contains(":0400000000000000FC"));
        assert!(out.trim_end().ends_with(":00000001FF"));
    }

    #[test]
    fn srecord_header_present() {
        let doc = d(&[1, 2, 3]);
        let out = export(&doc, 0, 3, Format::MotorolaSRecord);
        assert!(out.starts_with("S0"));
        assert!(out.contains("S3"));
    }
}
