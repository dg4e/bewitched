//! In-place byte transforms applied to a selection.
//!
//! Pure functions on a byte buffer so they are trivially testable; the UI reads
//! the selection, applies a transform, and writes it back via `Document`.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Not,
    Xor(u8),
    And(u8),
    Or(u8),
    Add(u8),
    Sub(u8),
    /// Rotate each byte left by `n` bits.
    Rol(u32),
    /// Rotate each byte right by `n` bits.
    Ror(u32),
    /// Logical shift each byte left by `n` bits.
    Shl(u32),
    /// Logical shift each byte right by `n` bits.
    Shr(u32),
    /// Reverse the whole buffer.
    Reverse,
    /// Reverse bytes within each group of `n` (endianness swap).
    SwapBytes(usize),
    /// Flip ASCII letter case.
    FlipCase,
}

/// Apply `op` to `data` in place.
pub fn apply(data: &mut [u8], op: Op) {
    match op {
        Op::Not => data.iter_mut().for_each(|b| *b = !*b),
        Op::Xor(k) => data.iter_mut().for_each(|b| *b ^= k),
        Op::And(k) => data.iter_mut().for_each(|b| *b &= k),
        Op::Or(k) => data.iter_mut().for_each(|b| *b |= k),
        Op::Add(k) => data.iter_mut().for_each(|b| *b = b.wrapping_add(k)),
        Op::Sub(k) => data.iter_mut().for_each(|b| *b = b.wrapping_sub(k)),
        Op::Rol(n) => {
            let n = n % 8;
            data.iter_mut().for_each(|b| *b = b.rotate_left(n));
        }
        Op::Ror(n) => {
            let n = n % 8;
            data.iter_mut().for_each(|b| *b = b.rotate_right(n));
        }
        Op::Shl(n) => {
            let n = n.min(8);
            data.iter_mut()
                .for_each(|b| *b = if n >= 8 { 0 } else { *b << n });
        }
        Op::Shr(n) => {
            let n = n.min(8);
            data.iter_mut()
                .for_each(|b| *b = if n >= 8 { 0 } else { *b >> n });
        }
        Op::Reverse => data.reverse(),
        Op::SwapBytes(n) if n > 1 => {
            for chunk in data.chunks_mut(n) {
                chunk.reverse();
            }
        }
        Op::SwapBytes(_) => {}
        Op::FlipCase => data.iter_mut().for_each(|b| {
            if b.is_ascii_alphabetic() {
                *b ^= 0x20;
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(data: &[u8], op: Op) -> Vec<u8> {
        let mut v = data.to_vec();
        apply(&mut v, op);
        v
    }

    #[test]
    fn logic_ops() {
        assert_eq!(t(&[0x00, 0xFF], Op::Not), vec![0xFF, 0x00]);
        assert_eq!(t(&[0xAA], Op::Xor(0xFF)), vec![0x55]);
        assert_eq!(t(&[0xFF], Op::And(0x0F)), vec![0x0F]);
        assert_eq!(t(&[0xF0], Op::Or(0x0F)), vec![0xFF]);
    }

    #[test]
    fn arithmetic_wraps() {
        assert_eq!(t(&[0xFF], Op::Add(1)), vec![0x00]);
        assert_eq!(t(&[0x00], Op::Sub(1)), vec![0xFF]);
    }

    #[test]
    fn rotations_and_shifts() {
        assert_eq!(t(&[0b1000_0001], Op::Rol(1)), vec![0b0000_0011]);
        assert_eq!(t(&[0b1000_0001], Op::Ror(1)), vec![0b1100_0000]);
        assert_eq!(t(&[0b0000_0001], Op::Shl(1)), vec![0b0000_0010]);
        assert_eq!(t(&[0b1000_0000], Op::Shr(1)), vec![0b0100_0000]);
    }

    #[test]
    fn reverse_and_swap() {
        assert_eq!(t(&[1, 2, 3, 4], Op::Reverse), vec![4, 3, 2, 1]);
        assert_eq!(t(&[1, 2, 3, 4], Op::SwapBytes(2)), vec![2, 1, 4, 3]);
        assert_eq!(t(&[1, 2, 3, 4], Op::SwapBytes(4)), vec![4, 3, 2, 1]);
        // odd tail is reversed within its short chunk
        assert_eq!(t(&[1, 2, 3], Op::SwapBytes(2)), vec![2, 1, 3]);
    }

    #[test]
    fn flip_case() {
        assert_eq!(t(b"Hello, World!", Op::FlipCase), b"hELLO, wORLD!".to_vec());
    }

    #[test]
    fn xor_is_involution() {
        let original = b"secret payload".to_vec();
        let mut v = original.clone();
        apply(&mut v, Op::Xor(0x5A));
        assert_ne!(v, original);
        apply(&mut v, Op::Xor(0x5A));
        assert_eq!(v, original);
    }
}
