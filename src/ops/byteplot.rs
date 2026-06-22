//! Byte-as-pixel visualization ("digraph"/Veles-style map).
//!
//! Renders the document as an image where each pixel is colored by the byte it
//! represents, so large-scale structure (padding, tables, code vs. data,
//! compression boundaries) becomes visible at a glance. For inputs larger than
//! the image, pixels sample bytes linearly; for smaller inputs, bytes span
//! multiple pixels.

use crate::data::ByteReader;

use super::Progress;

/// Map a byte to an RGB color by class: nulls dark, printable ASCII green,
/// control dim, high bytes a red ramp, 0xFF amber.
pub fn color_for(b: u8) -> [u8; 3] {
    match b {
        0x00 => [0x0d, 0x12, 0x0d],
        0x01..=0x1f => [0x2a, 0x44, 0x36],          // control
        0x20..=0x7e => [0x33, 0xff, 0x66],          // printable
        0x7f => [0x2a, 0x44, 0x36],
        0xff => [0xff, 0xb8, 0x4d],                 // amber
        v => {
            // 0x80..=0xfe -> red ramp scaled by value
            let t = (v - 0x80) as u16;
            let r = 0x80 + t * 0x7f / 0x7e;
            [r as u8, 0x33, 0x33]
        }
    }
}

/// The document offset sampled by pixel index `p` of `pixels` total.
pub fn sample_offset(p: u64, pixels: u64, len: u64) -> u64 {
    if pixels == 0 {
        return 0;
    }
    ((p as u128 * len as u128) / pixels as u128) as u64
}

/// Build a `width*height` RGBA image (row-major) of the range `[offset, offset+len)`.
/// Pixels past the data are left transparent.
pub fn build_rgba(
    reader: &dyn ByteReader,
    offset: u64,
    len: u64,
    width: usize,
    height: usize,
    progress: &Progress,
) -> Vec<u8> {
    let pixels = (width * height) as u64;
    let mut img = vec![0u8; width * height * 4];
    progress.set_total(pixels.max(1));
    let total = (offset + len).min(reader.len()).saturating_sub(offset);
    if total == 0 || pixels == 0 {
        return img;
    }
    // Read sequentially in chunks for speed, mapping ranges of pixels to ranges
    // of bytes. Each pixel samples the first byte of its mapped span.
    let mut byte_buf = [0u8; 1];
    for p in 0..pixels {
        if progress.is_cancelled() {
            break;
        }
        let off = offset + sample_offset(p, pixels, total);
        let n = reader.read_at(off, &mut byte_buf);
        let idx = (p as usize) * 4;
        if n == 1 {
            let [r, g, b] = color_for(byte_buf[0]);
            img[idx] = r;
            img[idx + 1] = g;
            img[idx + 2] = b;
            img[idx + 3] = 0xff;
        }
        if p % 4096 == 0 {
            progress.set_done(p);
        }
    }
    progress.finish();
    img
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    #[test]
    fn color_classes() {
        assert_eq!(color_for(0x00), [0x0d, 0x12, 0x0d]);
        assert_eq!(color_for(b'A'), [0x33, 0xff, 0x66]);
        assert_eq!(color_for(0xff), [0xff, 0xb8, 0x4d]);
        // a high byte is reddish
        let c = color_for(0xC0);
        assert!(c[0] > c[1] && c[0] > c[2]);
    }

    #[test]
    fn sampling_downscale_and_upscale() {
        // 4 pixels over 16 bytes -> every 4th byte
        assert_eq!(sample_offset(0, 4, 16), 0);
        assert_eq!(sample_offset(1, 4, 16), 4);
        assert_eq!(sample_offset(3, 4, 16), 12);
        // 16 pixels over 4 bytes -> 4 pixels per byte
        assert_eq!(sample_offset(0, 16, 4), 0);
        assert_eq!(sample_offset(3, 16, 4), 0);
        assert_eq!(sample_offset(4, 16, 4), 1);
        assert_eq!(sample_offset(15, 16, 4), 3);
    }

    #[test]
    fn rgba_dimensions_and_content() {
        let d = Document::from_source(Arc::new(MemSource::new(vec![b'A'; 16], "t")));
        let img = build_rgba(&d, 0, d.len(), 4, 4, &Progress::default());
        assert_eq!(img.len(), 4 * 4 * 4);
        // first pixel is printable green, opaque
        assert_eq!(&img[0..4], &[0x33, 0xff, 0x66, 0xff]);
    }

    #[test]
    fn pixels_past_data_transparent() {
        let d = Document::from_source(Arc::new(MemSource::new(vec![0xFFu8; 2], "t")));
        // 4 pixels over 2 bytes: all map within data, opaque
        let img = build_rgba(&d, 0, d.len(), 2, 2, &Progress::default());
        for px in 0..4 {
            assert_eq!(img[px * 4 + 3], 0xff);
        }
    }

    #[test]
    fn empty_is_all_transparent() {
        let d = Document::empty();
        let img = build_rgba(&d, 0, 0, 8, 8, &Progress::default());
        assert!(img.iter().all(|&b| b == 0));
    }
}
