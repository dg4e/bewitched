//! x86 / x86-64 disassembly at the cursor, via the pure-Rust `iced-x86` crate.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

use crate::data::ByteReader;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bits {
    Bits16,
    Bits32,
    Bits64,
}

impl Bits {
    pub fn bitness(self) -> u32 {
        match self {
            Bits::Bits16 => 16,
            Bits::Bits32 => 32,
            Bits::Bits64 => 64,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Bits::Bits16 => "16-bit",
            Bits::Bits32 => "32-bit",
            Bits::Bits64 => "64-bit",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Insn {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Disassemble up to `count` instructions starting at `offset`. Reads a bounded
/// window from the document, so it is cheap to call every frame for the visible
/// pane. Treats `offset` as the instruction pointer for relative operands.
pub fn disassemble(reader: &dyn ByteReader, offset: u64, count: usize, bits: Bits) -> Vec<Insn> {
    // Enough bytes for `count` instructions; x86 instructions are <= 15 bytes.
    let window = (count * 16).max(64);
    let code = reader.read_range(offset, window);
    if code.is_empty() {
        return Vec::new();
    }
    let mut decoder = Decoder::with_ip(bits.bitness(), &code, offset, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut out = Vec::with_capacity(count);
    let mut instr = Instruction::default();
    let mut text = String::new();
    while decoder.can_decode() && out.len() < count {
        let start_ip = decoder.ip();
        decoder.decode_out(&mut instr);
        text.clear();
        formatter.format(&instr, &mut text);
        let start = (start_ip - offset) as usize;
        let len = instr.len();
        // Stop if the instruction would run past what we actually read.
        if start + len > code.len() {
            break;
        }
        out.push(Insn {
            offset: start_ip,
            bytes: code[start..start + len].to_vec(),
            text: text.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn doc(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    #[test]
    fn x64_basic_instructions() {
        // 48 31 C0       xor rax, rax
        // 90             nop
        // C3             ret
        let d = doc(&[0x48, 0x31, 0xC0, 0x90, 0xC3]);
        let ins = disassemble(&d, 0, 16, Bits::Bits64);
        assert_eq!(ins.len(), 3);
        assert_eq!(ins[0].text, "xor rax,rax");
        assert_eq!(ins[0].offset, 0);
        assert_eq!(ins[0].bytes, vec![0x48, 0x31, 0xC0]);
        assert_eq!(ins[1].text, "nop");
        assert_eq!(ins[2].text, "ret");
    }

    #[test]
    fn offsets_follow_lengths() {
        // `offset` is the file offset, also used as the instruction pointer.
        let d = doc(&[0x48, 0x31, 0xC0, 0x90, 0xC3]);
        let ins = disassemble(&d, 0, 16, Bits::Bits64);
        assert_eq!(ins[0].offset, 0);
        assert_eq!(ins[1].offset, 3); // after 3-byte xor
        assert_eq!(ins[2].offset, 4); // after 1-byte nop
    }

    #[test]
    fn bitness_changes_decoding() {
        // 0x40 is "inc eax" in 32-bit, but a REX prefix in 64-bit.
        let d = doc(&[0x40, 0x90]); // REX.B + nop  => "nop" in 64-bit
        let i64 = disassemble(&d, 0, 4, Bits::Bits64);
        assert!(i64[0].text.contains("nop"));
        let i32 = disassemble(&d, 0, 4, Bits::Bits32);
        assert_eq!(i32[0].text, "inc eax");
    }

    #[test]
    fn empty_input() {
        let d = Document::empty();
        assert!(disassemble(&d, 0, 16, Bits::Bits64).is_empty());
    }

    #[test]
    fn respects_count() {
        let d = doc(&[0x90; 32]); // many nops
        let ins = disassemble(&d, 0, 5, Bits::Bits64);
        assert_eq!(ins.len(), 5);
    }
}
