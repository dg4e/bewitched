//! Hex view layout: column arithmetic, colored row construction and click
//! hit-testing. Pure/stateless helpers — scrolling and input live in `app.rs`.

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId};

use super::charset::Charset;
use super::theme;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewMode {
    Both,
    HexOnly,
    TextOnly,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    Hex,
    Text,
}

#[derive(Clone, Copy)]
pub struct Layout {
    pub bytes_per_row: usize,
    pub group: usize,
    pub addr_digits: usize,
    pub mode: ViewMode,
}

impl Layout {
    pub fn new(bytes_per_row: usize, group: usize, total_len: u64, mode: ViewMode) -> Self {
        let mut digits = 8usize;
        let mut t = total_len.max(1) - 1;
        let mut d = 0;
        while t > 0 {
            d += 1;
            t >>= 4;
        }
        digits = digits.max(d).max(1);
        Self {
            bytes_per_row,
            group: group.max(1),
            addr_digits: digits,
            mode,
        }
    }

    fn groups(&self) -> usize {
        (self.bytes_per_row + self.group - 1) / self.group
    }

    fn group_stride(&self) -> usize {
        self.group * 2 + 1 // 2 hex chars per byte + 1 separator space per group
    }

    /// Character column (from start of the hex area) of byte `i`'s first nibble.
    #[allow(dead_code)]
    pub fn hex_col(&self, i: usize) -> usize {
        let gi = i / self.group;
        let within = i % self.group;
        gi * self.group_stride() + within * 2
    }

    fn hex_width(&self) -> usize {
        // groups*(2*group chars) + (groups-1) separators
        self.bytes_per_row * 2 + self.groups().saturating_sub(1)
    }

    fn addr_end(&self) -> usize {
        self.addr_digits + 2
    }

    fn hex_start(&self) -> usize {
        self.addr_end()
    }

    fn ascii_start(&self) -> usize {
        match self.mode {
            ViewMode::TextOnly => self.addr_end(),
            _ => self.hex_start() + self.hex_width() + 2,
        }
    }

    /// Total row width in characters (for sizing the scroll area).
    #[allow(dead_code)]
    pub fn total_chars(&self) -> usize {
        match self.mode {
            ViewMode::HexOnly => self.hex_start() + self.hex_width(),
            ViewMode::TextOnly => self.ascii_start() + self.bytes_per_row,
            ViewMode::Both => self.ascii_start() + self.bytes_per_row,
        }
    }

    /// Map a character column (relative to row start) to (byte_in_row, pane, nibble).
    pub fn col_to_byte(&self, col: usize) -> Option<(usize, Pane, u8)> {
        if self.mode != ViewMode::TextOnly {
            let hs = self.hex_start();
            if col >= hs && col < hs + self.hex_width() {
                let h = col - hs;
                let stride = self.group_stride();
                let gi = h / stride;
                let rem = h % stride;
                if rem >= self.group * 2 {
                    // on a separator; snap to last byte of group
                    let i = (gi * self.group + self.group - 1).min(self.bytes_per_row - 1);
                    return Some((i, Pane::Hex, 1));
                }
                let within = rem / 2;
                let nibble = (rem % 2) as u8;
                let i = gi * self.group + within;
                if i < self.bytes_per_row {
                    return Some((i, Pane::Hex, nibble));
                }
            }
        }
        if self.mode != ViewMode::HexOnly {
            let as_ = self.ascii_start();
            if col >= as_ && col < as_ + self.bytes_per_row {
                return Some((col - as_, Pane::Text, 0));
            }
        }
        None
    }
}

/// Per-byte rendering context for a row.
pub struct RowCtx<'a> {
    pub bytes: &'a [Option<u8>],
    pub modified: &'a [bool],
    pub selected: &'a [bool],
    pub base_addr: u64,
    pub charset: Charset,
    /// Active cursor cell in this row, if any: (byte_index, nibble, pane).
    pub cursor: Option<(usize, u8, Pane)>,
    pub editing_pane: Pane,
    pub font: FontId,
}

fn fmt(font: &FontId, color: Color32, bg: Color32) -> TextFormat {
    TextFormat {
        font_id: font.clone(),
        color,
        background: bg,
        ..Default::default()
    }
}

const HEXD: &[u8; 16] = b"0123456789ABCDEF";

fn byte_color(b: u8, modified: bool) -> Color32 {
    if modified {
        theme::MOD_FG
    } else if b == 0 {
        theme::NULL_FG
    } else {
        theme::GREEN
    }
}

/// Build a colored `LayoutJob` for one row.
pub fn build_row(layout: &Layout, ctx: &RowCtx) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.wrap.max_width = f32::INFINITY;
    let font = &ctx.font;

    // Address gutter.
    let addr = format!(
        "{:0width$X}  ",
        ctx.base_addr,
        width = layout.addr_digits
    );
    job.append(&addr, 0.0, fmt(font, theme::ADDR, Color32::TRANSPARENT));

    let bpr = layout.bytes_per_row;

    // Hex area.
    if layout.mode != ViewMode::TextOnly {
        for i in 0..bpr {
            if i > 0 && i % layout.group == 0 {
                job.append(" ", 0.0, fmt(font, theme::GREEN_DIM, Color32::TRANSPARENT));
            }
            let sel = ctx.selected.get(i).copied().unwrap_or(false);
            let modi = ctx.modified.get(i).copied().unwrap_or(false);
            match ctx.bytes.get(i).copied().flatten() {
                None => job.append("  ", 0.0, fmt(font, theme::NULL_FG, Color32::TRANSPARENT)),
                Some(b) => {
                    let base = byte_color(b, modi);
                    let hi = HEXD[(b >> 4) as usize] as char;
                    let lo = HEXD[(b & 0xf) as usize] as char;
                    let cur = ctx.cursor.filter(|c| c.0 == i && c.2 == Pane::Hex);
                    let selbg = if sel { theme::SEL_BG } else { Color32::TRANSPARENT };
                    // high nibble
                    let (hc, hb) = nib_style(cur, 0, base, selbg, ctx.editing_pane);
                    job.append(&hi.to_string(), 0.0, fmt(font, hc, hb));
                    // low nibble
                    let (lc, lb) = nib_style(cur, 1, base, selbg, ctx.editing_pane);
                    job.append(&lo.to_string(), 0.0, fmt(font, lc, lb));
                }
            }
        }
    }

    // Separator between hex and ascii.
    if layout.mode == ViewMode::Both {
        job.append("  ", 0.0, fmt(font, theme::GREEN_DIM, Color32::TRANSPARENT));
    }

    // ASCII / charset area.
    if layout.mode != ViewMode::HexOnly {
        for i in 0..bpr {
            let sel = ctx.selected.get(i).copied().unwrap_or(false);
            let modi = ctx.modified.get(i).copied().unwrap_or(false);
            match ctx.bytes.get(i).copied().flatten() {
                None => job.append(" ", 0.0, fmt(font, theme::NULL_FG, Color32::TRANSPARENT)),
                Some(b) => {
                    let glyph = ctx.charset.decode(b).unwrap_or('·');
                    let printable = ctx.charset.decode(b).is_some();
                    let mut color = if !printable {
                        theme::NULL_FG
                    } else {
                        byte_color(b, modi)
                    };
                    let mut bg = if sel { theme::SEL_BG } else { Color32::TRANSPARENT };
                    if let Some((_, _, _)) = ctx.cursor.filter(|c| c.0 == i && c.2 == Pane::Text) {
                        if ctx.editing_pane == Pane::Text {
                            bg = theme::CURSOR_BG;
                            color = theme::CURSOR_FG;
                        } else {
                            bg = theme::GREEN_FAINT;
                        }
                    }
                    job.append(&glyph.to_string(), 0.0, fmt(font, color, bg));
                }
            }
        }
    }

    job
}

fn nib_style(
    cur: Option<(usize, u8, Pane)>,
    this_nibble: u8,
    base: Color32,
    selbg: Color32,
    editing_pane: Pane,
) -> (Color32, Color32) {
    match cur {
        Some((_, n, _)) if editing_pane == Pane::Hex && n == this_nibble => {
            (theme::CURSOR_FG, theme::CURSOR_BG)
        }
        Some(_) => {
            // cursor is on this byte but the other nibble / hex pane inactive
            if editing_pane == Pane::Hex {
                (base, selbg)
            } else {
                (base, theme::GREEN_FAINT)
            }
        }
        None => (base, selbg),
    }
}
