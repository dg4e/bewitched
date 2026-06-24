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
    ArmThumb,
    Aarch64,
    MipsLe,
    MipsBe,
    PowerPc,
    RiscV32,
    RiscV64,
}

impl Arch {
    pub const ALL: &'static [Arch] = &[
        Arch::X86_16,
        Arch::X86_32,
        Arch::X86_64,
        Arch::Arm,
        Arch::ArmThumb,
        Arch::Aarch64,
        Arch::MipsLe,
        Arch::MipsBe,
        Arch::PowerPc,
        Arch::RiscV32,
        Arch::RiscV64,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Arch::X86_16 => "x86-16",
            Arch::X86_32 => "x86-32",
            Arch::X86_64 => "x86-64",
            Arch::Arm => "ARM (A32)",
            Arch::ArmThumb => "ARM Thumb",
            Arch::Aarch64 => "ARM64 (A64)",
            Arch::MipsLe => "MIPS (LE)",
            Arch::MipsBe => "MIPS (BE)",
            Arch::PowerPc => "PowerPC",
            Arch::RiscV32 => "RISC-V 32",
            Arch::RiscV64 => "RISC-V 64",
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
        Arch::ArmThumb => disasm_thumb(&code, offset, count),
        Arch::Aarch64 => disasm_aarch64(&code, offset, count),
        Arch::MipsLe => disasm_mips(&code, offset, count, false),
        Arch::MipsBe => disasm_mips(&code, offset, count, true),
        Arch::PowerPc => disasm_ppc(&code, offset, count),
        Arch::RiscV32 => disasm_riscv(&code, offset, count, raki::Isa::Rv32),
        Arch::RiscV64 => disasm_riscv(&code, offset, count, raki::Isa::Rv64),
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

/// Variable-length stepping: `step(remaining)` returns `(byte_len, text)` for the
/// instruction at the front, or `None` to stop.
fn variable(
    code: &[u8],
    base: u64,
    count: usize,
    mut step: impl FnMut(&[u8]) -> Option<(usize, String)>,
) -> Vec<Insn> {
    let mut out = Vec::with_capacity(count);
    let mut pos = 0usize;
    while pos < code.len() && out.len() < count {
        match step(&code[pos..]) {
            Some((len, text)) if len > 0 && pos + len <= code.len() => {
                out.push(Insn {
                    offset: base + pos as u64,
                    bytes: code[pos..pos + len].to_vec(),
                    text,
                });
                pos += len;
            }
            _ => break,
        }
    }
    out
}

/// MIPS (fixed 4 bytes). The decoder reads little-endian words, so for big-endian
/// MIPS we byte-swap each word before decoding; the displayed raw bytes stay as
/// they appear on disk.
fn disasm_mips(code: &[u8], base: u64, count: usize, big_endian: bool) -> Vec<Insn> {
    use yaxpeax_arch_02::{Decoder, U8Reader};
    use yaxpeax_mips::MipsDecoder;
    let decoder = MipsDecoder::default();
    fixed4(code, base, count, |chunk| {
        let ordered = if big_endian {
            [chunk[3], chunk[2], chunk[1], chunk[0]]
        } else {
            [chunk[0], chunk[1], chunk[2], chunk[3]]
        };
        let mut reader = U8Reader::new(&ordered);
        match decoder.decode(&mut reader) {
            Ok(inst) => inst.to_string(),
            Err(_) => word_placeholder(chunk),
        }
    })
}

/// PowerPC (fixed 4 bytes, big-endian).
fn disasm_ppc(code: &[u8], base: u64, count: usize) -> Vec<Insn> {
    fixed4(code, base, count, |chunk| {
        let w = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        ppc750cl::Ins::new(w).simplified().to_string()
    })
}

/// ARM Thumb (variable 2/4 bytes). The top 5 bits of the first halfword decide
/// whether it is a 32-bit Thumb-2 instruction.
fn disasm_thumb(code: &[u8], base: u64, count: usize) -> Vec<Insn> {
    use yaxpeax_arch::{Decoder, U8Reader};
    use yaxpeax_arm::armv7::InstDecoder;
    let decoder = InstDecoder::default_thumb();
    variable(code, base, count, move |rem| {
        if rem.len() < 2 {
            return None;
        }
        let hw = u16::from_le_bytes([rem[0], rem[1]]);
        let len = if (hw >> 11) >= 0x1d { 4 } else { 2 };
        if rem.len() < len {
            return None;
        }
        let mut reader = U8Reader::new(&rem[..len]);
        let text = match decoder.decode(&mut reader) {
            Ok(inst) => inst.to_string(),
            Err(_) if len == 2 => format!(".hword 0x{:04x}", hw),
            Err(_) => format!(
                ".word 0x{:08x}",
                u32::from_le_bytes([rem[0], rem[1], rem[2], rem[3]])
            ),
        };
        Some((len, text))
    })
}

/// RISC-V (variable 2/4 bytes). A low 2-bit field of `0b11` marks a 32-bit
/// instruction; otherwise it is a 16-bit compressed (C-extension) instruction.
fn disasm_riscv(code: &[u8], base: u64, count: usize, isa: raki::Isa) -> Vec<Insn> {
    use raki::Decode;
    variable(code, base, count, move |rem| {
        if rem.is_empty() {
            return None;
        }
        if rem[0] & 0b11 != 0b11 {
            if rem.len() < 2 {
                return None;
            }
            let hw = u16::from_le_bytes([rem[0], rem[1]]);
            let text = match hw.decode(isa) {
                Ok(inst) => inst.to_string(),
                Err(_) => format!(".hword 0x{:04x}", hw),
            };
            Some((2, text))
        } else {
            if rem.len() < 4 {
                return None;
            }
            let w = u32::from_le_bytes([rem[0], rem[1], rem[2], rem[3]]);
            let text = match w.decode(isa) {
                Ok(inst) => inst.to_string(),
                Err(_) => format!(".word 0x{:08x}", w),
            };
            Some((4, text))
        }
    })
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

    #[test]
    fn arm_thumb_variable_length() {
        // bx lr = 0x4770 (16-bit thumb); push {r7,lr} = 0xB580 (16-bit)
        let d = doc(&[0x70, 0x47, 0x80, 0xB5]);
        let ins = disassemble(&d, 0, 8, Arch::ArmThumb);
        assert_eq!(ins.len(), 2);
        assert_eq!(ins[0].bytes.len(), 2); // 16-bit
        assert_eq!(ins[1].offset, 2);
        assert!(ins[0].text.contains("bx"), "got {:?}", ins[0].text);
    }

    #[test]
    fn riscv_addi() {
        // 0xEEC28293 = addi t0, t0, -276 (32-bit); little-endian on disk
        let d = doc(&[0x93, 0x82, 0xC2, 0xEE]);
        let ins = disassemble(&d, 0, 4, Arch::RiscV64);
        assert_eq!(ins.len(), 1);
        assert_eq!(ins[0].bytes.len(), 4);
        assert!(ins[0].text.contains("addi"), "got {:?}", ins[0].text);
    }

    #[test]
    fn riscv_compressed_is_two_bytes() {
        // a C-extension instruction has low bits != 0b11 -> 16-bit step
        // 0x0001 = c.nop; place it then a 32-bit addi after to check lengths
        let d = doc(&[0x01, 0x00, 0x93, 0x82, 0xC2, 0xEE]);
        let ins = disassemble(&d, 0, 8, Arch::RiscV64);
        assert_eq!(ins[0].bytes.len(), 2);
        assert_eq!(ins[1].offset, 2);
        assert_eq!(ins[1].bytes.len(), 4);
    }

    #[test]
    fn powerpc_blr_big_endian() {
        // blr = 0x4E800020, big-endian on disk
        let d = doc(&[0x4E, 0x80, 0x00, 0x20]);
        let ins = disassemble(&d, 0, 4, Arch::PowerPc);
        assert_eq!(ins.len(), 1);
        assert!(ins[0].text.contains("blr"), "got {:?}", ins[0].text);
    }

    #[test]
    fn mips_decodes_word() {
        // 0x00000000 = nop (sll zero,zero,0) — valid in both endiannesses
        let d = doc(&[0x00, 0x00, 0x00, 0x00]);
        let le = disassemble(&d, 0, 1, Arch::MipsLe);
        assert_eq!(le.len(), 1);
        assert!(!le[0].text.is_empty());
        assert!(!le[0].text.starts_with(".inst"), "got {:?}", le[0].text);
        // big-endian path also yields a decode for the same all-zero word
        let be = disassemble(&d, 0, 1, Arch::MipsBe);
        assert_eq!(be[0].bytes, vec![0, 0, 0, 0]);
    }
}
