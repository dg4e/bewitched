//! Visual theme — a dark, phosphor-green "hacker terminal" look.

use egui::{Color32, FontFamily, FontId, Rounding, Stroke};

pub const BG: Color32 = Color32::from_rgb(0x0a, 0x0e, 0x0a);
pub const BG_ALT: Color32 = Color32::from_rgb(0x10, 0x16, 0x10);
pub const PANEL: Color32 = Color32::from_rgb(0x07, 0x0a, 0x07);
pub const GREEN: Color32 = Color32::from_rgb(0x33, 0xff, 0x66);
pub const GREEN_DIM: Color32 = Color32::from_rgb(0x33, 0x88, 0x55);
pub const GREEN_FAINT: Color32 = Color32::from_rgb(0x2a, 0x55, 0x3a);
pub const ADDR: Color32 = Color32::from_rgb(0x55, 0x99, 0x77);
pub const AMBER: Color32 = Color32::from_rgb(0xff, 0xb8, 0x4d);
pub const RED: Color32 = Color32::from_rgb(0xff, 0x55, 0x55);

/// Pick a status-line color: red for failures, dim green otherwise.
pub fn status_color(msg: &str) -> Color32 {
    let m = msg.to_ascii_lowercase();
    if m.contains("fail") || m.contains("error") || m.contains("invalid") || m.contains("not found")
    {
        RED
    } else {
        GREEN_DIM
    }
}
pub const CURSOR_BG: Color32 = Color32::from_rgb(0x33, 0xff, 0x66);
pub const CURSOR_FG: Color32 = Color32::from_rgb(0x05, 0x10, 0x08);
/// The cursor byte mirrored onto the *inactive* pane (text side when editing
/// hex, and vice versa) — clearly visible but dimmer than the active caret.
pub const CURSOR_MIRROR: Color32 = Color32::from_rgb(0x1f, 0x80, 0x4a);
pub const SEL_BG: Color32 = Color32::from_rgb(0x1f, 0x52, 0x39);
pub const MOD_FG: Color32 = Color32::from_rgb(0xff, 0xb8, 0x4d);
pub const NULL_FG: Color32 = Color32::from_rgb(0x2c, 0x44, 0x36);

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// Install the theme into the egui context.
pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(GREEN);
    v.panel_fill = PANEL;
    v.window_fill = BG;
    v.extreme_bg_color = BG;
    v.faint_bg_color = BG_ALT;
    v.window_stroke = Stroke::new(1.0, GREEN_FAINT);
    v.window_rounding = Rounding::same(2.0);
    v.selection.bg_fill = SEL_BG;
    v.selection.stroke = Stroke::new(1.0, GREEN);
    v.hyperlink_color = AMBER;

    let w = &mut v.widgets;
    w.noninteractive.bg_fill = PANEL;
    w.noninteractive.fg_stroke = Stroke::new(1.0, GREEN_DIM);
    w.noninteractive.bg_stroke = Stroke::new(1.0, GREEN_FAINT);
    w.inactive.bg_fill = BG_ALT;
    w.inactive.weak_bg_fill = BG_ALT;
    w.inactive.fg_stroke = Stroke::new(1.0, GREEN_DIM);
    w.inactive.rounding = Rounding::same(2.0);
    w.hovered.bg_fill = GREEN_FAINT;
    w.hovered.weak_bg_fill = GREEN_FAINT;
    w.hovered.fg_stroke = Stroke::new(1.0, GREEN);
    w.hovered.bg_stroke = Stroke::new(1.0, GREEN);
    w.hovered.rounding = Rounding::same(2.0);
    w.active.bg_fill = GREEN_FAINT;
    w.active.fg_stroke = Stroke::new(1.0, GREEN);
    w.active.rounding = Rounding::same(2.0);

    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    style.spacing.button_padding = egui::vec2(6.0, 3.0);

    // Make body/button text monospace for the terminal feel.
    use egui::TextStyle::*;
    style.text_styles.insert(Body, mono(13.0));
    style.text_styles.insert(Button, mono(13.0));
    style.text_styles.insert(Monospace, mono(13.0));
    style.text_styles.insert(Small, mono(11.0));
    style.text_styles.insert(Heading, mono(17.0));

    ctx.set_style(style);
}
