mod app;
mod backup;
mod blob_text;
mod catalog;
mod catalog_loader;
mod config;
mod conflict;
mod deploy;
mod edit_history;
mod fonts;
mod localization;
mod mod_io;
mod mod_library;
mod mod_package;
mod notes;
mod paloc_editor;
mod paseq_editor;
mod profile;
mod restore;
mod state;
mod steam;
mod table_loader;
mod table_registry;
mod templates;
mod theme;
mod toast;
mod ui;
mod validation;
mod wizards;
mod worker;
mod xml_editor;
mod xml_patcher;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_title("Crimson Desert Mod Workbench"),
        ..Default::default()
    };
    eframe::run_native(
        "Crimson Desert Mod Workbench",
        options,
        Box::new(|cc| Ok(Box::new(app::WorkbenchApp::new(cc)))),
    )
}
