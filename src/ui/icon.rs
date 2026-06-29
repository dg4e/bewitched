//! The application icon: a pixel-art witch flying on a broom, built from a
//! character grid so it stays in-tree and dependency-free. The base grid is
//! scaled up with nearest-neighbour so it keeps crisp pixel edges at any size.

/// Base art, 32×32. Legend:
///   `.` transparent   `K` outline   `P` purple cloak/hat   `M` light purple
///   `G` witch-green skin   `B` broom handle   `Y` straw bristles
///   `W` moon   `A` amber star
const ART: &[&str] = &[
    "................................", // 0
    "....WW.................A.........", // 1
    "...WWWW.........KK...............", // 2
    "...WWW........KKPPKK.............", // 3
    "...WWWW......KKPPPPKK............", // 4
    "....WW......KPPPPPPPK............", // 5
    "...........KPPPPPPPPK....A.......", // 6
    "..........KPPPPPPPPPK............", // 7
    ".........KPPPPPPPPPPPK...........", // 8
    "........KPPPPPPPPPPPPPK..........", // 9
    ".......KKKKKKKKKKKKKKKKK.........", // 10
    "..........KGGGGGGK...............", // 11
    ".........KGGGGGGGGK..............", // 12
    ".........KGKKGGKKGK......Y.......", // 13
    ".........KGGGGGGGGK....YYYYY.....", // 14
    "..........KGGGGGGK...YYYYYYYY....", // 15
    "..........KGWWGGK..YYYYYYYYYY....", // 16
    ".........KPPPPPPPK.YYYYYYYYY.....", // 17
    "........KPPPMMPPPPK.YYYYYYY......", // 18
    ".......KPPPPMPPPPPPK..YYYY.......", // 19
    "BBBBBBKKPPPPPPPPPPPPKYYY.........", // 20
    ".....BBBKPPPPPPPPPPPK............", // 21
    "........KPPPPPPPPPPK.............", // 22
    ".......KPPPK.KPPPPK..............", // 23
    "......KPPPK...KPPPK..............", // 24
    "......KKKK....KKKK...............", // 25
    "................................", // 26
    "..........A.....................", // 27
    "...............................A", // 28
    "................................", // 29
    "...............A................", // 30
    "................................", // 31
];

fn palette(c: char) -> [u8; 4] {
    match c {
        'K' => [20, 16, 28, 255],     // near-black outline
        'P' => [104, 56, 148, 255],   // purple
        'M' => [170, 110, 210, 255],  // light purple highlight
        'G' => [120, 205, 130, 255],  // witch green
        'B' => [150, 100, 52, 255],   // broom handle (brown)
        'Y' => [226, 182, 92, 255],   // straw bristles
        'W' => [236, 236, 250, 255],  // moon / eye whites
        'A' => [255, 200, 80, 255],   // amber star
        _ => [0, 0, 0, 0],            // transparent
    }
}

/// Build the icon as `(rgba, width, height)`, scaled by `scale` (nearest-neighbour).
pub fn rgba(scale: usize) -> (Vec<u8>, u32, u32) {
    let scale = scale.max(1);
    let bw = ART[0].len();
    let bh = ART.len();
    let w = bw * scale;
    let h = bh * scale;
    let mut out = vec![0u8; w * h * 4];
    for (y, row) in ART.iter().enumerate() {
        for (x, c) in row.chars().enumerate() {
            let col = palette(c);
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = x * scale + dx;
                    let py = y * scale + dy;
                    let i = (py * w + px) * 4;
                    out[i..i + 4].copy_from_slice(&col);
                }
            }
        }
    }
    (out, w as u32, h as u32)
}

/// Encode an RGBA buffer as a PNG (used to render the icon for inspection and to
/// produce a bundle icon file). Pure Rust: zlib via the shared compress backend.
pub fn to_png(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut crc_in = Vec::with_capacity(4 + data.len());
        crc_in.extend_from_slice(kind);
        crc_in.extend_from_slice(data);
        out.extend_from_slice(&crc32fast::hash(&crc_in).to_be_bytes());
    }

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit, RGBA, no interlace
    chunk(&mut png, b"IHDR", &ihdr);

    // filtered scanlines: each row prefixed with filter type 0 (None)
    let mut raw = Vec::with_capacity((w as usize * 4 + 1) * h as usize);
    for y in 0..h as usize {
        raw.push(0);
        let start = y * w as usize * 4;
        raw.extend_from_slice(&rgba[start..start + w as usize * 4]);
    }
    let idat = crate::ops::compress::compress(&raw, crate::ops::compress::Codec::Zlib, 6);
    chunk(&mut png, b"IDAT", &idat);
    chunk(&mut png, b"IEND", &[]);
    png
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_dimensions_and_opaque_pixels() {
        let (buf, w, h) = rgba(8);
        assert_eq!((w, h), (256, 256));
        assert_eq!(buf.len(), 256 * 256 * 4);
        // there is some non-transparent content
        assert!(buf.chunks(4).any(|p| p[3] == 255));
    }

    #[test]
    fn png_has_signature_and_chunks() {
        let (buf, w, h) = rgba(1);
        let png = to_png(&buf, w, h);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR right after the signature, IEND at the end
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[png.len() - 8..png.len() - 4], b"IEND");
    }

    /// Writes the icon to a PNG for visual inspection: `cargo test render_icon -- --nocapture`.
    #[test]
    #[ignore]
    fn render_icon() {
        let (buf, w, h) = rgba(8);
        let png = to_png(&buf, w, h);
        let path = std::env::temp_dir().join("bewitched_icon.png");
        std::fs::write(&path, &png).unwrap();
        println!("wrote {}", path.display());
    }
}
