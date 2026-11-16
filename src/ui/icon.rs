//! The application icon: a green-phosphor CRT "b" over a hex dump, embedded
//! from `assets/icon.png` so the window/taskbar icon matches the bundle icon.

/// The icon artwork (512×512 RGBA PNG).
pub const PNG: &[u8] = include_bytes!("../../assets/icon.png");

/// Decode the icon as `(rgba, width, height)`.
pub fn rgba() -> (Vec<u8>, u32, u32) {
    match image::load_from_memory_with_format(PNG, image::ImageFormat::Png) {
        Ok(img) => {
            let img = img.into_rgba8();
            let (w, h) = img.dimensions();
            (img.into_raw(), w, h)
        }
        // Unreachable with the bundled asset; fall back to a 1×1 transparent pixel
        // rather than refusing to start.
        Err(_) => (vec![0, 0, 0, 0], 1, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_decodes() {
        let (buf, w, h) = rgba();
        assert_eq!((w, h), (512, 512));
        assert_eq!(buf.len(), (w * h * 4) as usize);
        // opaque artwork in the middle, transparent rounded corners
        assert!(buf.chunks(4).any(|p| p[3] == 255));
        assert_eq!(buf[3], 0);
    }
}
