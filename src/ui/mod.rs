//! GUI layer (egui/eframe).

mod app;
mod charset;
mod hexview;
mod theme;

use app::App;

pub fn run() -> eframe::Result<()> {
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
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
