//! GUI layer (egui/eframe).

mod app;
mod charset;
mod hexview;
pub mod icon;
mod theme;

use app::App;
use std::path::PathBuf;

pub fn run() -> eframe::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // Headless CLI subcommands (dump/sha256/disasm/...) run and exit.
    if let crate::cli::Mode::Run(code) = crate::cli::dispatch(&argv) {
        std::process::exit(code);
    }

    // CLI: an optional file/device path to open on startup. `--help`/`--version`
    // print and exit without launching the GUI.
    let mut startup: Option<PathBuf> = None;
    for arg in &argv {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("bewitched {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--mcp" => {
                // Headless MCP server over stdio; never opens a window.
                if let Err(e) = crate::mcp::serve() {
                    eprintln!("mcp server error: {e}");
                }
                return Ok(());
            }
            _ if !arg.starts_with('-') => startup = Some(PathBuf::from(arg)),
            _ => {}
        }
    }

    let (rgba, iw, ih) = icon::rgba(8);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([640.0, 360.0])
            .with_title("bewitched")
            .with_icon(egui::IconData {
                rgba,
                width: iw,
                height: ih,
            }),
        ..Default::default()
    };
    eframe::run_native(
        "bewitched",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, startup)))),
    )
}
