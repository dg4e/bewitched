//! GUI layer (egui/eframe).

mod app;
mod charset;
mod hexview;
mod theme;

use app::App;
use std::path::PathBuf;

pub fn run() -> eframe::Result<()> {
    // CLI: an optional file/device path to open on startup. `--help`/`--version`
    // print and exit without launching the GUI.
    let mut startup: Option<PathBuf> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("ganghex — a fast, cross-platform hex editor");
                println!("usage: ganghex [FILE|DEVICE]");
                return Ok(());
            }
            "--version" | "-V" => {
                println!("ganghex {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ if !arg.starts_with('-') => startup = Some(PathBuf::from(arg)),
            _ => {}
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([640.0, 360.0])
            .with_title("ganghex"),
        ..Default::default()
    };
    eframe::run_native(
        "ganghex",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, startup)))),
    )
}
