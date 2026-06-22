// ganghex — a fast, cross-platform, hacker-esque hex editor.
// Hide the console window on Windows for the GUI build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    ganghex::ui::run()
}
