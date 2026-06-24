//! Multi-architecture disassembly at the cursor — all pure Rust.
//!
//! x86/x86-64 via `iced-x86`; ARM (A32) and AArch64 (A64) via the `yaxpeax`
//! decoders. No C dependency, so the build stays a single `cargo build`.

use crate::data::ByteReader;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86_16,
    X86_32,
    X86_64,
    Arm,
    Aarch64,
}

impl Arch {
    pub const ALL: &'static [Arch] = &[
        Arch::X86_16,
        Arch::X86_32,
        Arch::X86_64,
        Arch::Arm,
        Arch::Aarch64,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Arch::X86_16 => "x86-16",
            Arch::X86_32 => "x86-32",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "ARM (A32)",
            Arch::Aarch64 => "ARM64 (A64)",
        }
    }

    fn x86_bitness(self) -> Option<u32> {
        match self {
            Arch::X86_16 => Some(16),
            Arch::X86_32 => Some(32),
            Arch::X86_64 => Some(64),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Insn {
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Disassemble up to `count` instructions starting at `offset`, treating
/// `offset` as the instruction pointer. Reads a bounded window from the document.
pub fn disassemble(reader: &dyn ByteReader, offset: u64, count: usize, arch: Arch) -> Vec<Insn> {
    let window = (count * 16).max(64);
    let code = reader.read_range(offset, window);
    if code.is_empty() {
        return Vec::new();
    }
    match arch {
        Arch::X86_16 | Arch::X86_32 | Arch::X86_64 => {
            disasm_x86(&code, offset, count, arch.x86_bitness().unwrap())
        }
        Arch::Arm => disasm_arm(&code, offset, count),
        Arch::Aarch64 => disasm_aarch64(&code, offset, count),
    }
}

fn disasm_x86(code: &[u8], base: u64, count: usize, bitness: u32) -> Vec<Insn> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
    let mut decoder = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut out = Vec::with_capacity(count);
    let mut instr = Instruction::default();
    let mut text = String::new();
    while decoder.can_decode() && out.len() < count {
        let start_ip = decoder.ip();
        decoder.decode_out(&mut instr);
        text.clear();
        formatter.format(&instr, &mut text);
        let start = (start_ip - base) as usize;
        let len = instr.len();
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

/// ARM (A32) and AArch64 (A64) are fixed 4-byte instructions, so we step the
/// window in 4-byte words; an undecodable word becomes a `.inst` placeholder so
/// the listing keeps going.
fn disasm_arm(code: &[u8], base: u64, count: usize) -> Vec<Insn> {
    use yaxpeax_arch::{Decoder, U8Reader};
    use yaxpeax_arm::armv7::InstDecoder;
    let decoder = InstDecoder::default();
    fixed4(code, base, count, |chunk| {
        let mut reader = U8Reader::new(chunk);
        match decoder.decode(&mut reader) {
            Ok(inst) => inst.to_string(),
            Err(_) => word_placeholder(chunk),
        }
    })
}

fn disasm_aarch64(code: &[u8], base: u64, count: usize) -> Vec<Insn> {
    use yaxpeax_arch::{Decoder, U8Reader};
    use yaxpeax_arm::armv8::a64::InstDecoder;
    let decoder = InstDecoder::default();
    fixed4(code, base, count, |chunk| {
        let mut reader = U8Reader::new(chunk);
        match decoder.decode(&mut reader) {
            Ok(inst) => inst.to_string(),
            Err(_) => word_placeholder(chunk),
        }
    })
}

fn fixed4(code: &[u8], base: u64, count: usize, mut decode: impl FnMut(&[u8]) -> String) -> Vec<Insn> {
    let mut out = Vec::with_capacity(count);
    let mut pos = 0usize;
    while pos + 4 <= code.len() && out.len() < count {
        let chunk = &code[pos..pos + 4];
        out.push(Insn {
            offset: base + pos as u64,
            bytes: chunk.to_vec(),
            text: decode(chunk),
        });
        pos += 4;
    }
    out
}

fn word_placeholder(chunk: &[u8]) -> String {
    let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    format!(".inst 0x{:08x}", w)
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
        // 48 31 C0  xor rax,rax ; 90 nop ; C3 ret
        let d = doc(&[0x48, 0x31, 0xC0, 0x90, 0xC3]);
        let ins = disassemble(&d, 0, 16, Arch::X86_64);
        assert_eq!(ins.len(), 3);
        assert_eq!(ins[0].text, "xor rax,rax");
        assert_eq!(ins[1].text, "nop");
        assert_eq!(ins[2].text, "ret");
    }

    #[test]
    fn x86_offsets_and_bitness() {
        let d = doc(&[0x48, 0x31, 0xC0, 0x90, 0xC3]);
        let ins = disassemble(&d, 0, 16, Arch::X86_64);
        assert_eq!(ins[1].offset, 3);
        assert_eq!(ins[2].offset, 4);
        // 0x40 0x90 -> "inc eax" in 32-bit, REX+nop in 64-bit
        let d2 = doc(&[0x40, 0x90]);
        assert_eq!(disassemble(&d2, 0, 4, Arch::X86_32)[0].text, "inc eax");
        assert!(disassemble(&d2, 0, 4, Arch::X86_64)[0].text.contains("nop"));
    }

    #[test]
    fn aarch64_ret_nop() {
        // ret = 0xD65F03C0, nop = 0xD503201F (little-endian on disk)
        let d = doc(&[0xC0, 0x03, 0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5]);
        let ins = disassemble(&d, 0, 8, Arch::Aarch64);
        assert_eq!(ins.len(), 2);
        assert_eq!(ins[0].offset, 0);
        assert_eq!(ins[1].offset, 4);
        assert_eq!(ins[0].bytes, vec![0xC0, 0x03, 0x5F, 0xD6]);
        assert!(ins[0].text.contains("ret"), "got {:?}", ins[0].text);
        assert!(ins[1].text.contains("nop") || ins[1].text.contains("hint"), "got {:?}", ins[1].text);
    }

    #[test]
    fn arm_a32_bx_lr() {
        // bx lr = 0xE12FFF1E (little-endian on disk)
        let d = doc(&[0x1E, 0xFF, 0x2F, 0xE1]);
        let ins = disassemble(&d, 0, 4, Arch::Arm);
        assert_eq!(ins.len(), 1);
        assert!(ins[0].text.contains("bx"), "got {:?}", ins[0].text);
    }

    #[test]
    fn undecodable_word_placeholder() {
        let d = doc(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let ins = disassemble(&d, 0, 1, Arch::Aarch64);
        assert_eq!(ins.len(), 1);
        // either a valid decode or our placeholder, but never empty
        assert!(!ins[0].text.is_empty());
    }

    #[test]
    fn count_and_empty() {
        let d = doc(&[0x90; 32]);
        assert_eq!(disassemble(&d, 0, 5, Arch::X86_64).len(), 5);
        assert!(disassemble(&Document::empty(), 0, 8, Arch::Aarch64).is_empty());
    }
}
