//! The "support the scene" donation chips shown in the about cracktro:
//! payment links (paypal/venmo/cashapp) and crypto addresses (btc/eth/sol)
//! that copy to the clipboard with a brief "✓ copied" confirmation.
//!
//! Brand logos are from Simple Icons (<https://simpleicons.org>, CC0),
//! pre-rendered to 48×48 PNGs in `assets/donate/`.

use super::theme;

/// What clicking a chip does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Open a donation page in the browser.
    Open(&'static str),
    /// Copy an address to the clipboard.
    Copy(&'static str),
}

/// One donation chip: logo + lowercase label + click action.
pub struct Chip {
    pub label: &'static str,
    /// Hover text (the account/address, plus "click to copy" for crypto).
    pub tip: &'static str,
    pub action: Action,
    /// Embedded 48×48 RGBA PNG (Simple Icons, CC0).
    pub png: &'static [u8],
}

pub const CHIPS: [Chip; 6] = [
    Chip {
        label: "paypal",
        tip: "sales@digitalgangster.com",
        action: Action::Open("https://www.paypal.com/donate/?business=sales%40digitalgangster.com"),
        png: include_bytes!("../../assets/donate/paypal.png"),
    },
    Chip {
        label: "venmo",
        tip: "@dge-llc",
        action: Action::Open("https://venmo.com/u/dge-llc"),
        png: include_bytes!("../../assets/donate/venmo.png"),
    },
    Chip {
        label: "cashapp",
        tip: "$dgeternal",
        action: Action::Open("https://cash.app/$dgeternal"),
        png: include_bytes!("../../assets/donate/cashapp.png"),
    },
    Chip {
        label: "btc",
        tip: "1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ — click to copy",
        action: Action::Copy("1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ"),
        png: include_bytes!("../../assets/donate/bitcoin.png"),
    },
    Chip {
        label: "eth",
        tip: "ytcracker.eth — click to copy",
        action: Action::Copy("ytcracker.eth"),
        png: include_bytes!("../../assets/donate/ethereum.png"),
    },
    Chip {
        label: "sol",
        tip: "1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ — click to copy",
        action: Action::Copy("1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ"),
        png: include_bytes!("../../assets/donate/solana.png"),
    },
];

/// How long the "✓ copied" confirmation stays up, in seconds.
const COPIED_SECS: f64 = 1.6;

/// Per-app donation UI state: the logo textures (uploaded once, on first
/// show) and the transient copy confirmation.
#[derive(Default)]
pub struct DonateUi {
    textures: Vec<egui::TextureHandle>,
    /// `(chip index, time of click)` for the "✓ copied" flash.
    copied: Option<(usize, f64)>,
}

impl DonateUi {
    /// Decode and upload the logo textures. Called once, lazily.
    fn load_textures(&mut self, ctx: &egui::Context) {
        for chip in &CHIPS {
            // The embedded PNGs are validated by unit tests; a decode failure
            // here would be a build-asset bug.
            let img = image::load_from_memory(chip.png)
                .expect("embedded donation logo PNG must decode")
                .to_rgba8();
            let (w, h) = (img.width() as usize, img.height() as usize);
            let color = egui::ColorImage::from_rgba_unmultiplied([w, h], img.as_raw());
            self.textures.push(ctx.load_texture(
                format!("donate/{}", chip.label),
                color,
                egui::TextureOptions::LINEAR,
            ));
        }
    }

    /// Render the "support the scene" row of donation chips.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        if self.textures.is_empty() {
            self.load_textures(ui.ctx());
        }
        let now = ui.input(|i| i.time);
        // Expire the copy confirmation.
        if let Some((_, t0)) = self.copied {
            if now - t0 > COPIED_SECS {
                self.copied = None;
            }
        }

        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new("* support the scene *")
                    .monospace()
                    .color(theme::GREEN_DIM),
            );
        });
        ui.add_space(2.0);
        ui.columns(CHIPS.len(), |cols| {
            for (i, (chip, tex)) in CHIPS.iter().zip(&self.textures).enumerate() {
                cols[i].vertical_centered(|ui| {
                    let button = egui::ImageButton::new(
                        egui::Image::new(tex).fit_to_exact_size(egui::vec2(22.0, 22.0)),
                    )
                    .frame(false);
                    let resp = ui.add(button).on_hover_text(chip.tip);
                    if resp.clicked() {
                        match chip.action {
                            Action::Open(url) => {
                                ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                            }
                            Action::Copy(addr) => {
                                ui.ctx().copy_text(addr.to_string());
                                self.copied = Some((i, now));
                            }
                        }
                    }
                    let (text, color) = if self.copied.is_some_and(|(c, _)| c == i) {
                        ("✓ copied", theme::GREEN)
                    } else {
                        (chip.label, theme::GREEN_DIM)
                    };
                    ui.label(egui::RichText::new(text).monospace().small().color(color));
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_chips_with_expected_actions() {
        assert_eq!(CHIPS.len(), 6);
        let by_label = |l: &str| CHIPS.iter().find(|c| c.label == l).unwrap();
        assert_eq!(
            by_label("paypal").action,
            Action::Open("https://www.paypal.com/donate/?business=sales%40digitalgangster.com")
        );
        assert_eq!(
            by_label("venmo").action,
            Action::Open("https://venmo.com/u/dge-llc")
        );
        assert_eq!(
            by_label("cashapp").action,
            Action::Open("https://cash.app/$dgeternal")
        );
        assert_eq!(
            by_label("btc").action,
            Action::Copy("1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ")
        );
        assert_eq!(by_label("eth").action, Action::Copy("ytcracker.eth"));
        assert_eq!(
            by_label("sol").action,
            Action::Copy("1ytcdgNzF3ygR8faAcFhu3SjoexhmwdAJ")
        );
    }

    #[test]
    fn labels_are_lowercase_and_tips_mention_copy_for_crypto() {
        for chip in &CHIPS {
            assert!(
                !chip.label.chars().any(|c| c.is_uppercase()),
                "cracktro labels stay lowercase: {}",
                chip.label
            );
            if let Action::Copy(addr) = chip.action {
                assert!(chip.tip.contains(addr), "tip shows the address");
                assert!(chip.tip.contains("click to copy"));
            }
        }
    }

    #[test]
    fn embedded_logos_decode_as_48x48() {
        for chip in &CHIPS {
            let img = image::load_from_memory(chip.png)
                .unwrap_or_else(|e| panic!("{} logo failed to decode: {e}", chip.label));
            assert_eq!((img.width(), img.height()), (48, 48), "{}", chip.label);
        }
    }
}
