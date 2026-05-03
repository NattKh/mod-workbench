use crate::edit_history::{get_at_path, set_at_path, EditOp};
use crate::state::{ActiveTable, AppState, MainView};
use crate::ui;
use crate::worker;

/// Render-friendly label for a history op's field path. Empty paths (used
/// for whole-entry resets) get a more readable substitute so toast messages
/// don't read as "Undid change to ".
fn describe_history_path(path: &str) -> String {
    if path.is_empty() {
        "<entire entry>".to_string()
    } else {
        path.to_string()
    }
}

/// Replace characters that can't appear in a Windows or POSIX directory
/// name with underscores. Used by `action_export_dmm` to derive a subfolder
/// name from the user-supplied mod name without forcing the user to think
/// about the rules.
fn sanitize_folder(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "mod".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\n' | '\r' | '\t')
        {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    out
}

/// Apply a recorded edit op to a single tab. Returns `false` when the op
/// can't be applied (entry no longer exists, path wrong shape, etc.).
///
/// Used by `action_undo` and `action_redo` — the only difference between the
/// two is which side of the op (`old_value` vs `new_value`) gets installed.
/// Lives outside the `impl` block so it can take a `&mut ActiveTable` borrow
/// without conflicting with `&mut self`.
fn apply_history_op_to_tab(active: &mut ActiveTable, op: &EditOp, use_old: bool) -> bool {
    // Find entry by key — the tab's index list may have shifted since the op
    // was recorded if the user added/removed entries elsewhere.
    let entry_idx = active
        .entries
        .iter()
        .position(|e| crate::mod_io::extract_entry_key(e) == op.entry_key);
    let Some(entry_idx) = entry_idx else {
        return false;
    };
    let target_value = if use_old { &op.old_value } else { &op.new_value };

    if op.field_path.is_empty() {
        // Whole-entry op (e.g. full reset): replace the entire entry.
        active.entries[entry_idx] = target_value.clone();
        // Re-derive change-tracker state by diffing each top-level field
        // against vanilla.
        active.changes.unrecord_entry(op.entry_key);
        if let Some(vanilla) = active.vanilla.get(entry_idx) {
            let cur = &active.entries[entry_idx];
            if let (Some(cur_obj), Some(van_obj)) = (cur.as_object(), vanilla.as_object()) {
                for (k, v) in cur_obj {
                    if van_obj.get(k) != Some(v) {
                        active.changes.record_change(op.entry_key, k.clone());
                    }
                }
            }
        }
        return true;
    }

    if !set_at_path(&mut active.entries[entry_idx], &op.field_path, target_value.clone()) {
        return false;
    }
    // Sync change tracker: if the new value matches vanilla, drop the path;
    // otherwise record it.
    let vanilla_match = active
        .vanilla
        .get(entry_idx)
        .and_then(|v| get_at_path(v, &op.field_path))
        .map(|vv| vv == target_value)
        .unwrap_or(false);
    if vanilla_match {
        active.changes.unrecord_field(op.entry_key, &op.field_path);
    } else {
        active
            .changes
            .record_change(op.entry_key, op.field_path.clone());
    }
    true
}

pub struct WorkbenchApp {
    pub state: AppState,
}

impl WorkbenchApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let state = AppState::new();
        // Apply the user's saved theme up front (or the default) so the very
        // first frame already shows in the right palette, instead of flashing
        // dark for one frame before the View menu picks something else.
        let theme = state
            .config
            .theme
            .as_deref()
            .map(crate::theme::from_str)
            .unwrap_or_default();
        crate::theme::apply_theme(&cc.egui_ctx, theme);
        // Install CJK fonts (Korean / Japanese / Chinese) so game data with
        // raw Hangul / Kana / Hanzi renders as text instead of boxes. The
        // report tells us whether anything actually loaded; surfaced as a
        // toast in `update()` once on the first frame so the user can see
        // any "font missing" failures (eprintln goes nowhere on a Windows
        // GUI exe).
        let cjk_report = crate::fonts::install_cjk_fonts(&cc.egui_ctx);
        let mut me = Self { state };
        me.state.cjk_report_pending = Some(cjk_report);
        me
    }
}

impl eframe::App for WorkbenchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // First-frame: surface the CJK font load result so the user can
        // see whether Korean / Japanese / Chinese rendering is going to
        // work at all. eprintln output isn't visible on a Windows GUI exe.
        if let Some(report) = self.state.cjk_report_pending.take() {
            if !report.installed.is_empty() {
                self.state.toasts.info(format!(
                    "CJK fonts loaded: {}",
                    report.installed.join(", ")
                ));
            }
            if !report.errors.is_empty() {
                self.state.toasts.error_with_details(
                    "Some CJK fonts failed to load",
                    report.errors.join("\n"),
                );
            }
            if report.installed.is_empty() && report.errors.is_empty() {
                self.state.toasts.warn(
                    "No CJK fonts available — Korean/Japanese/Chinese will render as boxes",
                );
            }
        }

        // Drain background worker replies first so subsequent panels see
        // up-to-date state. Each terminal reply also decrements
        // `worker.in_flight` inside `poll`.
        let replies = self.state.worker.poll();
        for reply in replies {
            self.handle_worker_reply(reply);
        }
        // Repaint while jobs are in flight so progress/status updates land
        // promptly without requiring a mouse move from the user.
        if self.state.worker.in_flight > 0 {
            ctx.request_repaint();
        }

        // Keyboard shortcuts:
        //
        //   F                  -> focus the entry table search box
        //   F3                 -> advance to the next match in the filtered list
        //   Ctrl+S             -> save / export the current changes
        //   Ctrl+Shift+S       -> "export as..." (opens the metadata dialog)
        //   Ctrl+D             -> deploy to game
        //   Ctrl+R             -> restore (with confirmation modal)
        //   Ctrl+Z             -> undo
        //   Ctrl+Y / Ctrl+Shift+Z -> redo
        //   Ctrl+W             -> close active tab
        //   Ctrl+Tab           -> cycle to next tab
        //   Ctrl+Shift+Tab     -> cycle to previous tab
        //   Ctrl+, (Comma)     -> open Settings panel
        //   Ctrl+P             -> open command palette (state flag; UI is A7.4)
        //   Ctrl+L             -> run lint check
        //   Esc                -> dismiss popup or clear selection
        //
        // We read all shortcut intents once per frame *before* any panel
        // renders so the actions fire even when a text input has focus
        // elsewhere — input is checked at context level rather than widget
        // level. Plain-letter shortcuts (`F`, plain Esc) defer to text-input
        // widgets via `ctx.wants_keyboard_input()` so typing those characters
        // into a field doesn't double-fire the global handler.
        struct Shortcuts {
            undo: bool,
            redo: bool,
            close_tab: bool,
            next_tab: bool,
            prev_tab: bool,
            save: bool,
            save_as: bool,
            deploy: bool,
            restore: bool,
            settings: bool,
            command_palette: bool,
            lint: bool,
            focus_search: bool,
            find_next: bool,
            escape: bool,
        }
        let s = ctx.input(|i| {
            let ctrl = i.modifiers.ctrl;
            let shift = i.modifiers.shift;
            Shortcuts {
                undo: ctrl && !shift && i.key_pressed(egui::Key::Z),
                redo: ctrl
                    && (i.key_pressed(egui::Key::Y)
                        || (shift && i.key_pressed(egui::Key::Z))),
                close_tab: ctrl && i.key_pressed(egui::Key::W),
                next_tab: ctrl && !shift && i.key_pressed(egui::Key::Tab),
                prev_tab: ctrl && shift && i.key_pressed(egui::Key::Tab),
                save: ctrl && !shift && i.key_pressed(egui::Key::S),
                save_as: ctrl && shift && i.key_pressed(egui::Key::S),
                deploy: ctrl && i.key_pressed(egui::Key::D),
                restore: ctrl && i.key_pressed(egui::Key::R),
                settings: ctrl && i.key_pressed(egui::Key::Comma),
                command_palette: ctrl && i.key_pressed(egui::Key::P),
                lint: ctrl && i.key_pressed(egui::Key::L),
                focus_search: i.key_pressed(egui::Key::F)
                    && !ctrl
                    && !shift
                    && !i.modifiers.alt,
                find_next: i.key_pressed(egui::Key::F3),
                escape: i.key_pressed(egui::Key::Escape),
            }
        });
        let text_input_focused = ctx.wants_keyboard_input();

        if s.undo {
            self.action_undo();
        }
        if s.redo {
            self.action_redo();
        }
        if s.close_tab {
            if let Some(idx) = self.state.active_tab_idx {
                self.state.close_tab(idx);
            }
        }
        if s.save {
            // Treat Ctrl+S as the existing v3 JSON export flow. If nothing
            // has changed the action emits its own warning toast.
            self.action_export_v3_json();
        }
        if s.save_as {
            // "Export as..." opens the metadata dialog so the user can
            // attach attribution and pick a format (JSON / .modpkg / DMM).
            self.begin_export_flow(ui::metadata_dialog::ExportAction::SaveJson);
        }
        if s.deploy {
            self.action_deploy();
        }
        if s.restore {
            // Restore wipes the overlay group, so we gate it behind a
            // confirmation modal instead of firing immediately.
            self.state.restore_confirm_pending = true;
        }
        if s.settings {
            self.state.main_view = MainView::Settings;
        }
        if s.command_palette {
            self.state.command_palette.toggle();
        }
        if s.lint {
            self.action_run_lint();
        }
        if s.focus_search && !text_input_focused {
            // Switch to the PABGB tables view first if the user is somewhere
            // else, so the search box they want to focus actually exists.
            if !matches!(self.state.main_view, MainView::PabgbTables) {
                self.state.main_view = MainView::PabgbTables;
            }
            self.state.entry_search_focus_pending = true;
        }
        if s.find_next {
            self.state.entry_search_advance_pending = true;
        }
        if s.escape && !text_input_focused {
            // Priority: close any popup-style state, falling back to clearing
            // the active selection. We chain the if/else so a single Esc only
            // closes one thing — the user can press it repeatedly to peel
            // back nested modal-ish state.
            if self.state.command_palette.open {
                self.state.command_palette.close();
            } else if self.state.deploy_confirm_pending {
                self.state.deploy_confirm_pending = false;
            } else if self.state.restore_confirm_pending {
                self.state.restore_confirm_pending = false;
            } else if self.state.metadata_dialog.open {
                self.state.metadata_dialog.open = false;
            } else if let Some(active) = self.state.active_table_mut() {
                active.selected_entry_idx = None;
            }
        }
        if s.next_tab && !self.state.open_tabs.is_empty() {
            // Wrap around to the first tab when we hit the end.
            let next = self
                .state
                .active_tab_idx
                .map_or(0, |i| (i + 1) % self.state.open_tabs.len());
            self.state.active_tab_idx = Some(next);
        }
        if s.prev_tab && !self.state.open_tabs.is_empty() {
            let len = self.state.open_tabs.len();
            let prev = self
                .state
                .active_tab_idx
                .map_or(len - 1, |i| (i + len - 1) % len);
            self.state.active_tab_idx = Some(prev);
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Set Game Dir...").clicked() {
                        ui.close_menu();
                        if let Some(path) = rfd::FileDialog::new()
                            .set_title("Select Crimson Desert Game Directory")
                            .pick_folder()
                        {
                            // Validate: must contain meta/0.papgt
                            if path.join("meta/0.papgt").exists() {
                                self.state.status =
                                    format!("Game dir: {}", path.display());
                                self.state
                                    .toasts
                                    .info(format!("Game dir set: {}", path.display()));
                                self.state.game_dir = Some(path.clone());
                                self.state.config.game_dir = Some(path.clone());
                                self.state.config.save().ok();
                                // Newly-set game dir? Kick off a localization
                                // load so the field panel can resolve hashes
                                // for this game version. Skips the worker if
                                // we already have a populated cache from a
                                // prior session.
                                if self.state.localization.is_none() {
                                    self.state.worker.submit(
                                        worker::Job::LoadLocalization {
                                            game_dir: path,
                                        },
                                    );
                                }
                            } else {
                                self.state.status =
                                    "Invalid game dir (meta/0.papgt not found)".to_string();
                                self.state
                                    .toasts
                                    .error("Invalid game dir (meta/0.papgt not found)");
                            }
                        }
                    }

                    // Reload Localization — refresh the EN+KR string maps
                    // from disk. Useful after a game patch where the cache
                    // is out of date but the user doesn't want to manually
                    // delete localization.json from %APPDATA%.
                    if ui
                        .button("Reload Localization")
                        .on_hover_text(
                            "Re-extract English + Korean strings from the \
                             game's PAZ archives. Use after a game update.",
                        )
                        .clicked()
                    {
                        ui.close_menu();
                        // Drop the in-memory copy so the worker reply
                        // installs the fresh tables. We don't delete the
                        // cache file here; the worker rewrites it as part
                        // of `load_or_build`.
                        self.state.localization = None;
                        if let Some(dir) = self.state.game_dir.clone() {
                            self.state.worker.submit(worker::Job::LoadLocalization {
                                game_dir: dir,
                            });
                            self.state.toasts.info("Reloading localization...");
                        } else {
                            self.state
                                .toasts
                                .warn("Set game dir first");
                        }
                    }

                    ui.separator();

                    if ui.button("Import Mod...").clicked() {
                        ui.close_menu();
                        self.action_import_mod();
                    }

                    // Export submenu — three flavours, one for each
                    // shipping format. All three share the metadata dialog
                    // before the user picks an output path.
                    ui.menu_button("Export Mod", |ui| {
                        if ui.button("As JSON...").clicked() {
                            ui.close_menu();
                            self.begin_export_flow(
                                ui::metadata_dialog::ExportAction::SaveJson,
                            );
                        }
                        if ui.button("As .modpkg...").clicked() {
                            ui.close_menu();
                            self.begin_export_flow(
                                ui::metadata_dialog::ExportAction::SaveModpkg,
                            );
                        }
                        if ui.button("As DMM bundle...").clicked() {
                            ui.close_menu();
                            self.begin_export_flow(
                                ui::metadata_dialog::ExportAction::SaveDmm,
                            );
                        }
                    });

                    ui.separator();

                    if ui.button("Deploy to Game").clicked() {
                        ui.close_menu();
                        self.action_deploy();
                    }

                    if ui.button("Restore").clicked() {
                        ui.close_menu();
                        self.action_restore();
                    }

                    ui.separator();

                    // Backups view — auto-snapshots are taken before every
                    // deploy; this opens the browser so the user can roll
                    // back to any prior state if a deploy turned out badly.
                    if ui.button("Backups").clicked() {
                        ui.close_menu();
                        self.state.main_view = MainView::Backups;
                        // Force a refresh on next frame so opening the view
                        // always shows the freshest list (e.g. right after
                        // a deploy created a new snapshot).
                        self.state.backup_loaded_once = false;
                    }

                    // Mod library + profile manager. Same lazy-refresh
                    // pattern as Backups so opening the view always shows
                    // the on-disk state, even after the user dropped files
                    // into the library directory directly.
                    if ui.button("Mod Library").clicked() {
                        ui.close_menu();
                        self.state.main_view = MainView::Library;
                        self.state.library_loaded = false;
                    }

                    ui.separator();

                    if ui
                        .button("Settings")
                        .on_hover_text(
                            "Game dir, catalog, theme, and snapshot retention. (Ctrl+,)",
                        )
                        .clicked()
                    {
                        ui.close_menu();
                        self.state.main_view = MainView::Settings;
                    }

                    ui.separator();

                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                // View menu — toggle between the PABGB tables editor, the
                // PALOC string editor, the PASEQ/PASTAGE editor, the backup
                // browser, and the mod conflict viewer. Each option shows a
                // checkmark on the active view so the menu is self-describing.
                ui.menu_button("View", |ui| {
                    let mut is_pabgb = matches!(self.state.main_view, MainView::PabgbTables);
                    if ui.checkbox(&mut is_pabgb, "PABGB Tables").clicked() {
                        self.state.main_view = MainView::PabgbTables;
                        ui.close_menu();
                    }
                    let mut is_paloc = matches!(self.state.main_view, MainView::Paloc);
                    if ui.checkbox(&mut is_paloc, "PALOC Editor").clicked() {
                        self.state.main_view = MainView::Paloc;
                        ui.close_menu();
                    }
                    let mut is_paseq = matches!(self.state.main_view, MainView::Paseq);
                    if ui.checkbox(&mut is_paseq, "PASEQ Editor").clicked() {
                        self.state.main_view = MainView::Paseq;
                        ui.close_menu();
                    }
                    let mut is_backups = matches!(self.state.main_view, MainView::Backups);
                    if ui.checkbox(&mut is_backups, "Backups").clicked() {
                        self.state.main_view = MainView::Backups;
                        // Same lazy-refresh flag flip as the File menu entry
                        // so the Backups view always opens with fresh data.
                        self.state.backup_loaded_once = false;
                        ui.close_menu();
                    }
                    let mut is_conflicts =
                        matches!(self.state.main_view, MainView::Conflicts);
                    if ui.checkbox(&mut is_conflicts, "Mod Conflicts").clicked() {
                        self.state.main_view = MainView::Conflicts;
                        ui.close_menu();
                    }
                    let mut is_lint = matches!(self.state.main_view, MainView::Lint);
                    if ui
                        .checkbox(&mut is_lint, "Lint Panel")
                        .on_hover_text(
                            "Run validation rules against the active table and \
                             review findings (with one-click fixes for known issues).",
                        )
                        .clicked()
                    {
                        self.state.main_view = MainView::Lint;
                        ui.close_menu();
                    }
                    let mut is_templates =
                        matches!(self.state.main_view, MainView::Templates);
                    if ui
                        .checkbox(&mut is_templates, "Templates")
                        .on_hover_text(
                            "Apply preset field changes (built-in and \
                             user-saved) to the selected entry.",
                        )
                        .clicked()
                    {
                        self.state.main_view = MainView::Templates;
                        // Lazy-load user templates on first navigation so a
                        // missing/corrupt directory doesn't crash startup.
                        if self.state.user_templates.is_empty() {
                            match crate::templates::load_user_templates() {
                                Ok(list) => self.state.user_templates = list,
                                Err(e) => self.state.toasts.error_with_details(
                                    "Failed to load user templates",
                                    e.to_string(),
                                ),
                            }
                        }
                        ui.close_menu();
                    }
                    let mut is_wizards =
                        matches!(self.state.main_view, MainView::Wizards);
                    if ui
                        .checkbox(&mut is_wizards, "Wizards")
                        .on_hover_text(
                            "Step-by-step guided flows for common mod tasks \
                             (stat boost, NPC swap, etc.).",
                        )
                        .clicked()
                    {
                        self.state.main_view = MainView::Wizards;
                        ui.close_menu();
                    }
                    let mut is_library =
                        matches!(self.state.main_view, MainView::Library);
                    if ui
                        .checkbox(&mut is_library, "Mod Library")
                        .on_hover_text(
                            "Browse the local mod library and switch between \
                             named profiles that batch-deploy a chosen subset \
                             of mods.",
                        )
                        .clicked()
                    {
                        self.state.main_view = MainView::Library;
                        // Force a re-scan on next render so newly imported
                        // files (or files added directly to the library
                        // directory between sessions) are visible.
                        self.state.library_loaded = false;
                        ui.close_menu();
                    }

                    ui.separator();

                    // Theme submenu — radio-style picker, persisted to
                    // config and applied immediately so the user sees the
                    // change without leaving the menu.
                    let current_theme = self
                        .state
                        .config
                        .theme
                        .as_deref()
                        .map(crate::theme::from_str)
                        .unwrap_or_default();
                    ui.menu_button("Theme", |ui| {
                        for option in [
                            crate::theme::Theme::Dark,
                            crate::theme::Theme::Light,
                            crate::theme::Theme::Crimson,
                        ] {
                            let label = ui::settings_panel::theme_label(option);
                            if ui
                                .radio(current_theme == option, label)
                                .clicked()
                                && current_theme != option
                            {
                                self.state.config.theme =
                                    Some(crate::theme::to_str(option).to_string());
                                crate::theme::apply_theme(ui.ctx(), option);
                                if let Err(e) = self.state.config.save() {
                                    self.state.toasts.error_with_details(
                                        "Failed to save theme",
                                        e.to_string(),
                                    );
                                }
                                ui.close_menu();
                            }
                        }
                    });
                });
            });
        });

        // Bottom status bar
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui::bottom_bar::show(ui, &self.state);
        });

        // Side panels are PABGB-specific (table list / field editor / xref).
        // Skip them entirely in the PALOC and PASEQ views so the editor takes
        // the full window width and the user isn't tempted to click into a
        // sidebar that's wired to a different data model.
        if matches!(self.state.main_view, MainView::PabgbTables) {
            // Left panel: table list
            egui::SidePanel::left("table_list_panel")
                .default_width(200.0)
                .show(ctx, |ui| {
                    ui::table_list::show(ui, &mut self.state);
                });

            // Right panel: field editor on top, xref panel docked at the bottom.
            // The xref panel is rendered first via `TopBottomPanel::bottom` so
            // it's reserved at the bottom of the right column; the remaining
            // space is filled by the field editor above it.
            // Right column: xref docked at the bottom, history panel above it,
            // and the field editor filling the remaining vertical space. Reading
            // top-to-bottom you get: fields -> history -> xref.
            egui::SidePanel::right("field_panel")
                .default_width(400.0)
                .show(ctx, |ui| {
                    egui::TopBottomPanel::bottom("xref_panel")
                        .resizable(true)
                        .default_height(180.0)
                        .show_inside(ui, |ui| {
                            ui::xref_panel::show(ui, &mut self.state);
                        });
                    // History panel: collapsible, docked just above the xref pane
                    // so it's discoverable without swallowing fixed real estate
                    // when collapsed. The panel returns the user's intent (jump
                    // / undo / redo / clear) which we apply *after* the panel
                    // call to avoid taking a second mutable borrow on state from
                    // inside the closure.
                    let mut history_action: Option<ui::history_panel::HistoryAction> = None;
                    egui::TopBottomPanel::bottom("history_panel")
                        .resizable(true)
                        .default_height(140.0)
                        .show_inside(ui, |ui| {
                            history_action = ui::history_panel::show(ui, &self.state);
                        });
                    if let Some(action) = history_action {
                        match action {
                            ui::history_panel::HistoryAction::JumpTo(pos) => {
                                self.action_jump_to_history(pos);
                            }
                            ui::history_panel::HistoryAction::Undo => self.action_undo(),
                            ui::history_panel::HistoryAction::Redo => self.action_redo(),
                            ui::history_panel::HistoryAction::Clear => {
                                if let Some(active) = self.state.active_table_mut() {
                                    active.history.clear();
                                    self.state.toasts.info("Cleared history");
                                }
                            }
                        }
                    }
                    ui::field_panel::show(ui, &mut self.state);
                });
        }

        // Lint panel returns the user's intent inside the closure; we
        // collect it here and apply after the panel call so we don't take
        // a second mutable borrow on `state` from inside the closure.
        let mut lint_action: Option<ui::lint_panel::LintAction> = None;

        // Central panel content depends on the active view.
        egui::CentralPanel::default().show(ctx, |ui| match self.state.main_view {
            MainView::PabgbTables => {
                ui::tab_bar::show(ui, &mut self.state);
                ui.separator();
                if self.state.active_tab_idx.is_some() {
                    ui::entry_table::show(ui, &mut self.state);
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label("Select a table from the left panel");
                    });
                }
            }
            MainView::Paloc => {
                ui::paloc_panel::show(ui, &mut self.state);
            }
            MainView::Paseq => {
                ui::paseq_panel::show(ui, &mut self.state);
            }
            MainView::Backups => {
                ui::backup_panel::show(ui, &mut self.state);
            }
            MainView::Conflicts => {
                ui::conflict_panel::show(ui, &mut self.state);
            }
            MainView::Lint => {
                // The panel returns the user's intent; we apply it after
                // the closure ends so we don't take a second mutable
                // borrow on `state` from inside the panel.
                lint_action = ui::lint_panel::show(ui, &mut self.state);
            }
            MainView::Settings => {
                ui::settings_panel::show(ui, &mut self.state);
            }
            MainView::Library => {
                ui::library_panel::show(ui, &mut self.state);
            }
            MainView::Templates => {
                ui::templates_panel::show(ui, &mut self.state);
            }
            MainView::Wizards => {
                ui::wizards_panel::show(ui, &mut self.state);
            }
        });

        // Apply any deferred lint-panel action.
        if let Some(action) = lint_action {
            match action {
                ui::lint_panel::LintAction::Run => self.action_run_lint(),
                ui::lint_panel::LintAction::Clear => {
                    self.state.lint_findings.clear();
                    self.state.toasts.info("Lint findings cleared");
                }
                ui::lint_panel::LintAction::ApplyFix(idx) => self.action_apply_lint_fix(idx),
            }
        }

        // Deploy confirmation modal: shown when action_deploy() finds Errors
        // and the user hasn't yet confirmed they want to ship anyway. We
        // render after the central panel so the window draws on top.
        if self.state.deploy_confirm_pending {
            self.render_deploy_confirm_modal(ctx);
        }

        // Restore confirmation modal: gated behind Ctrl+R because restore
        // wipes the overlay group. The menu's "Restore" button still bypasses
        // this and goes straight to action_restore() — keeping the original
        // click-driven flow uninterrupted.
        if self.state.restore_confirm_pending {
            self.render_restore_confirm_modal(ctx);
        }

        // Metadata dialog: rendered after the central panel so the modal
        // window draws on top of the regular UI. The dialog returns its
        // outcome inside its own closure; we apply that outcome (file
        // dialog + export) outside the render borrow.
        if self.state.metadata_dialog.open {
            let outcome = ui::metadata_dialog::show(ctx, &mut self.state.metadata_dialog);
            if let Some(outcome) = outcome {
                self.handle_metadata_dialog_outcome(outcome);
            }
        }

        // Command palette: rendered after every panel so the modal window
        // draws on top. Returns a PaletteAction when the user confirms a
        // row; we route that into the existing app handlers (Deploy /
        // Restore / Lint / view switches / table jumps / entry jumps /
        // library mod opens). The palette closes itself on dispatch so
        // the user's next Ctrl+P opens fresh.
        if let Some(action) = ui::command_palette::show(ctx, &mut self.state) {
            self.dispatch_palette_action(action);
        }

        // Toast overlay (rendered last so it sits on top of all panels).
        self.state.toasts.show(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Persist config on shutdown. Errors are logged inside save() and
        // intentionally swallowed here so a write failure can't block exit.
        self.state.config.save().ok();
    }
}

impl WorkbenchApp {
    /// Apply a single reply from the background worker to app state.
    ///
    /// Called once per reply from the per-frame `worker.poll()` drain in
    /// `update`. Keep this routine cheap and non-blocking — it runs on the
    /// UI thread.
    fn handle_worker_reply(&mut self, reply: worker::Reply) {
        match reply {
            worker::Reply::TableLoaded {
                dispatch_name,
                result,
            } => match result {
                Ok(payload) => {
                    // The worker already cloned vanilla and detected columns
                    // on its thread, so this handler is essentially a move —
                    // no expensive per-entry work happens on the UI thread.
                    let entries = payload.entries;
                    let vanilla = payload.vanilla;
                    let column_names = payload.column_names;
                    let count = entries.len();

                    // If the xref panel asked for this table, look up the
                    // requested entry now (before we lose the matching
                    // dispatch_name) and stash the resolved index.
                    let xref_target_idx = match &self.state.pending_xref_nav {
                        Some((target_dispatch, target_key)) if target_dispatch == &dispatch_name => {
                            entries.iter().position(|e| {
                                crate::mod_io::extract_entry_key(e) == *target_key
                            })
                        }
                        _ => None,
                    };

                    // Either focus an already-open tab and refresh its
                    // contents, or push a brand-new tab. Either way we end up
                    // with the freshly loaded data sitting at
                    // `active_tab_idx`.
                    let mut tab = crate::state::ActiveTable::new(
                        dispatch_name.clone(),
                        entries,
                        vanilla,
                        column_names,
                    );
                    tab.selected_entry_idx = xref_target_idx;
                    if let Some(idx) = self
                        .state
                        .open_tabs
                        .iter()
                        .position(|t| t.dispatch_name == dispatch_name)
                    {
                        // Reload existing tab in place; per-tab change tracker
                        // and history reset because the underlying entries
                        // have just been reread from disk.
                        self.state.open_tabs[idx] = tab;
                        self.state.active_tab_idx = Some(idx);
                    } else {
                        self.state.open_tabs.push(tab);
                        self.state.active_tab_idx = Some(self.state.open_tabs.len() - 1);
                    }
                    self.state.entry_filter.clear();
                    // Mark this table as "loaded at least once this session"
                    // so the table list can show a checkmark next to it even
                    // after the user navigates away to a different table.
                    self.state.loaded_tables.insert(dispatch_name.clone());

                    // Build the status message — note whether we honored an
                    // xref jump so the user has feedback on multi-step nav.
                    let pending = self.state.pending_xref_nav.take();
                    let status = match (pending, xref_target_idx) {
                        (Some((d, k)), Some(_)) if d == dispatch_name => format!(
                            "Loaded {}: {} entries (jumped to key {})",
                            dispatch_name, count, k
                        ),
                        (Some((d, k)), None) if d == dispatch_name => format!(
                            "Loaded {}: {} entries (key {} not found)",
                            dispatch_name, count, k
                        ),
                        _ => format!("Loaded {}: {} entries", dispatch_name, count),
                    };
                    self.state.status = status.clone();
                    self.state.toasts.info(status);
                }
                Err(e) => {
                    // Replace the loading placeholder (if any) with an
                    // error placeholder so the user sees the failure
                    // inline in the tab strip + central panel — no need
                    // to read toasts to understand what happened.
                    let error_tab = crate::state::ActiveTable::placeholder_error(
                        dispatch_name.clone(),
                        e.clone(),
                    );
                    if let Some(idx) = self
                        .state
                        .open_tabs
                        .iter()
                        .position(|t| t.dispatch_name == dispatch_name)
                    {
                        self.state.open_tabs[idx] = error_tab;
                        self.state.active_tab_idx = Some(idx);
                    } else {
                        self.state.open_tabs.push(error_tab);
                        self.state.active_tab_idx = Some(self.state.open_tabs.len() - 1);
                    }

                    self.state.status = format!("Error loading {}: {}", dispatch_name, e);
                    self.state.toasts.error_with_details(
                        format!("Failed to load {}", dispatch_name),
                        e,
                    );
                    // The pending nav is no longer reachable; clear it so a
                    // future unrelated load doesn't accidentally consume it.
                    if let Some((target_dispatch, _)) = &self.state.pending_xref_nav {
                        if target_dispatch == &dispatch_name {
                            self.state.pending_xref_nav = None;
                        }
                    }
                }
            },
            worker::Reply::CatalogLoaded { result } => match result {
                Ok(catalog) => {
                    self.state.status = "Catalog loaded".to_string();
                    self.state.toasts.info("Catalog loaded");
                    self.state.catalog = Some(catalog);
                }
                Err(e) => {
                    self.state.status = format!("Catalog load error: {}", e);
                    self.state
                        .toasts
                        .error_with_details("Catalog load failed", e);
                }
            },
            worker::Reply::DeployComplete { result } => match result {
                Ok(()) => {
                    self.state.status = "Deploy complete".to_string();
                    self.state.toasts.info("Deploy complete");
                }
                Err(e) => {
                    self.state.status = format!("Deploy error: {}", e);
                    self.state
                        .toasts
                        .error_with_details("Deploy failed", e);
                }
            },
            worker::Reply::RestoreComplete { result } => match result {
                Ok(()) => {
                    self.state.status = "Restore complete".to_string();
                    self.state.toasts.info("Restore complete");
                }
                Err(e) => {
                    self.state.status = format!("Restore error: {}", e);
                    self.state
                        .toasts
                        .error_with_details("Restore failed", e);
                }
            },
            worker::Reply::LocalizationLoaded { result } => match result {
                Ok(loc) => {
                    let msg = format!(
                        "Localization loaded: {} EN + {} KR strings",
                        loc.eng_len(),
                        loc.kor_len(),
                    );
                    self.state.status = msg.clone();
                    self.state.toasts.info(msg);
                    self.state.localization = Some(loc);
                }
                Err(e) => {
                    self.state.status = format!("Localization load error: {}", e);
                    self.state
                        .toasts
                        .error_with_details("Failed to load localization", e);
                }
            },
            worker::Reply::Progress {
                job_label,
                message,
                fraction: _,
            } => {
                // For now just surface progress as the bottom-bar status.
                // A future pass can render a per-job progress bar somewhere.
                self.state.status = format!("{}: {}", job_label, message);
            }
        }
    }

    /// Roll the most recent applied edit on the active tab back, restoring
    /// the prior value at the recorded path and updating the change tracker
    /// if the field now matches vanilla.
    ///
    /// Each tab owns its own history, so undo only operates on the focused
    /// tab — switching tabs doesn't risk applying a foreign undo.
    pub fn action_undo(&mut self) {
        let active = match self.state.active_table_mut() {
            Some(t) => t,
            None => {
                self.state.status = "Nothing to undo (no table loaded)".to_string();
                return;
            }
        };
        let op = match active.history.undo() {
            Some(op) => op.clone(),
            None => {
                self.state.status = "Nothing to undo".to_string();
                return;
            }
        };
        if !apply_history_op_to_tab(active, &op, /* use_old = */ true) {
            // Couldn't apply — put the cursor back so the next undo retries.
            let pos = active.history.current_position();
            active.history.jump_to(pos + 1);
            self.state.status =
                format!("Failed to undo op at path '{}'", op.field_path);
            return;
        }
        let label = describe_history_path(&op.field_path);
        self.state.status = format!("Undid change to {}", label);
        self.state.toasts.info(format!("Undid change to {}", label));
    }

    /// Reapply the next op in the redo tail of the active tab.
    pub fn action_redo(&mut self) {
        let active = match self.state.active_table_mut() {
            Some(t) => t,
            None => {
                self.state.status = "Nothing to redo (no table loaded)".to_string();
                return;
            }
        };
        let op = match active.history.redo() {
            Some(op) => op.clone(),
            None => {
                self.state.status = "Nothing to redo".to_string();
                return;
            }
        };
        if !apply_history_op_to_tab(active, &op, /* use_old = */ false) {
            // Couldn't apply — undo the cursor advance.
            let pos = active.history.current_position();
            if pos > 0 {
                active.history.jump_to(pos - 1);
            }
            self.state.status =
                format!("Failed to redo op at path '{}'", op.field_path);
            return;
        }
        let label = describe_history_path(&op.field_path);
        self.state.status = format!("Redid change to {}", label);
        self.state.toasts.info(format!("Redid change to {}", label));
    }

    /// Walk the active tab's history cursor to `target_pos`, applying or
    /// reverting ops one at a time so the entry data stays consistent with
    /// the cursor.
    ///
    /// `target_pos == 0` reverts every op back to the tab's initial state
    /// (relative to history); `target_pos == ops.len()` reapplies everything.
    /// Out-of-range targets are clamped. If a single op fails to apply we
    /// stop in place so the user gets a partial-undo state instead of a
    /// silently corrupt one.
    pub fn action_jump_to_history(&mut self, target_pos: usize) {
        let total_ops = match self.state.active_table() {
            Some(t) => t.history.ops().len(),
            None => return,
        };
        let target = target_pos.min(total_ops);

        loop {
            let active = match self.state.active_table_mut() {
                Some(t) => t,
                None => return,
            };
            let current = active.history.current_position();
            if current == target {
                break;
            }
            let going_back = current > target;
            let op_opt = if going_back {
                active.history.undo().cloned()
            } else {
                active.history.redo().cloned()
            };
            let op = match op_opt {
                Some(op) => op,
                None => break,
            };
            if !apply_history_op_to_tab(active, &op, going_back) {
                // Restore the cursor since the op didn't apply, then bail.
                let pos = active.history.current_position();
                let restored = if going_back {
                    pos + 1
                } else {
                    pos.saturating_sub(1)
                };
                active.history.jump_to(restored);
                self.state.status =
                    format!("History jump aborted at op '{}'", op.field_path);
                self.state
                    .toasts
                    .warn("History jump aborted: an entry/path went missing");
                return;
            }
        }

        let final_pos = self
            .state
            .active_table()
            .map(|t| t.history.current_position())
            .unwrap_or(0);
        self.state.status = format!(
            "Jumped to history position {} of {}",
            final_pos, total_ops
        );
    }

    fn action_import_mod(&mut self) {
        let active = match self.state.active_table() {
            Some(t) => t,
            None => {
                self.state.status = "Load a table first before importing".to_string();
                self.state
                    .toasts
                    .warn("Load a table first before importing");
                return;
            }
        };
        let table_name = active.dispatch_name.clone();

        let path = match rfd::FileDialog::new()
            .set_title("Import Field JSON Mod")
            .add_filter("JSON", &["json"])
            .pick_file()
        {
            Some(p) => p,
            None => return,
        };

        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                self.state.status = format!("Read error: {}", e);
                self.state.toasts.error_with_details(
                    "Failed to read mod file",
                    format!("{}\nPath: {}", e, path.display()),
                );
                return;
            }
        };

        let mod_json: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.state.status = format!("JSON parse error: {}", e);
                self.state
                    .toasts
                    .error_with_details("JSON parse error", e.to_string());
                return;
            }
        };

        // Validate the mod targets the active table
        let mod_table = mod_json
            .get("table")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if mod_table != table_name {
            let msg = format!(
                "Mod targets '{}' but '{}' is loaded",
                mod_table, table_name
            );
            self.state.status = msg.clone();
            self.state.toasts.warn(msg);
            return;
        }

        // Round-trip metadata: if the imported mod ships an `_meta` block,
        // pre-populate the dialog scratchpad so the user sees the original
        // attribution next time they export. Missing metadata leaves the
        // existing dialog state alone.
        if let Some(meta) = crate::mod_io::ModMetadata::from_json(&mod_json) {
            let deps = meta.dependencies.join(", ");
            self.state.metadata_dialog.metadata = meta;
            self.state.metadata_dialog.dependencies_input = deps;
        }

        // Round-trip notes: if the mod ships a `_notes` block, merge it
        // into the workbench's NoteStore so users see the imported author's
        // annotations next to each entry. Existing notes for unrelated
        // entries stay untouched.
        let imported_notes =
            crate::mod_io::import_notes(&mod_json, &table_name, &mut self.state.notes);

        let active = self.state.active_table_mut().unwrap();
        match crate::mod_io::import_mod(&mod_json, &mut active.entries) {
            Ok(count) => {
                let msg = if imported_notes > 0 {
                    format!(
                        "Imported {} entries and {} note(s) from {}",
                        count,
                        imported_notes,
                        path.display()
                    )
                } else {
                    format!("Imported {} entries from {}", count, path.display())
                };
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Import error: {}", e);
                self.state
                    .toasts
                    .error_with_details("Import failed", e.to_string());
            }
        }
    }

    /// Open the metadata dialog targeting `action`. Validates that there
    /// is something to export (a loaded table with at least one tracked
    /// change) before showing the dialog so the user gets immediate
    /// feedback if the action is a no-op.
    fn begin_export_flow(&mut self, action: ui::metadata_dialog::ExportAction) {
        // Snapshot the bits we need from the active table, then drop the
        // borrow so we can mutate `metadata_dialog` below without taking
        // overlapping borrows on `state`.
        let dispatch_name = match self.state.active_table() {
            Some(t) => {
                if t.changes.change_count() == 0 {
                    self.state.status = "No changes to export".to_string();
                    self.state.toasts.warn("No changes to export");
                    return;
                }
                t.dispatch_name.clone()
            }
            None => {
                self.state.status = "No table loaded".to_string();
                self.state.toasts.warn("No table loaded");
                return;
            }
        };
        // Default the version field to "1.0.0" the first time the dialog
        // is opened — most users want a sane starting point and this saves
        // a typing roundtrip.
        if self.state.metadata_dialog.metadata.version.is_empty() {
            self.state.metadata_dialog.metadata.version = "1.0.0".into();
        }
        // Default the name to the dispatch label so the dialog isn't
        // blank — users still tend to overwrite it but it's a useful seed.
        if self.state.metadata_dialog.metadata.name.is_empty() {
            self.state.metadata_dialog.metadata.name = dispatch_name;
        }
        self.state.metadata_dialog.open_for(action);
    }

    /// Apply a confirmed [`ui::metadata_dialog::MetadataDialogOutcome`].
    /// Cancel just dismisses the dialog (no toast — the user already
    /// knows what they did); Confirm dispatches to the matching exporter.
    fn handle_metadata_dialog_outcome(
        &mut self,
        outcome: ui::metadata_dialog::MetadataDialogOutcome,
    ) {
        match outcome {
            ui::metadata_dialog::MetadataDialogOutcome::Cancel => {
                // Quiet dismissal — no toast, status untouched.
            }
            ui::metadata_dialog::MetadataDialogOutcome::Confirm(action) => match action {
                ui::metadata_dialog::ExportAction::SaveJson => self.action_export_v3_json(),
                ui::metadata_dialog::ExportAction::SaveModpkg => self.action_export_modpkg(),
                ui::metadata_dialog::ExportAction::SaveDmm => self.action_export_dmm(),
            },
        }
    }

    /// Export as a single `.json` file. Driven by the metadata dialog;
    /// the dialog has already populated `self.state.metadata_dialog.metadata`.
    fn action_export_v3_json(&mut self) {
        let active = match self.state.active_table() {
            Some(t) => t,
            None => return,
        };
        let dispatch_name = active.dispatch_name.clone();
        let path = match rfd::FileDialog::new()
            .set_title("Export Field JSON Mod")
            .add_filter("JSON", &["json"])
            .set_file_name(format!("{}_mod.json", dispatch_name))
            .save_file()
        {
            Some(p) => p,
            None => return,
        };

        let active = self.state.active_table().unwrap();
        let metadata = self.state.metadata_dialog.metadata.clone();
        let change_count = active.changes.change_count();
        // Embed any user-authored notes for this table so the reasoning
        // travels with the export.
        let result = crate::mod_package::export_v3_json_full(
            &metadata,
            &active.dispatch_name,
            &active.entries,
            &active.vanilla,
            &active.changes,
            Some(&self.state.notes),
            &path,
        );
        match result {
            Ok(()) => {
                let msg = format!(
                    "Exported {} changes to {}",
                    change_count,
                    path.display()
                );
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Write error: {}", e);
                self.state.toasts.error_with_details(
                    "Failed to write mod file",
                    format!("{}\nPath: {}", e, path.display()),
                );
            }
        }
    }

    /// Export as a `.modpkg` zip bundle (mod.json + README.md + manifest.json).
    fn action_export_modpkg(&mut self) {
        let active = match self.state.active_table() {
            Some(t) => t,
            None => return,
        };
        let dispatch_name = active.dispatch_name.clone();
        let path = match rfd::FileDialog::new()
            .set_title("Export Mod Package (.modpkg)")
            .add_filter(".modpkg", &["modpkg"])
            .set_file_name(format!("{}_mod.modpkg", dispatch_name))
            .save_file()
        {
            Some(p) => p,
            None => return,
        };

        let active = self.state.active_table().unwrap();
        let metadata = self.state.metadata_dialog.metadata.clone();
        let change_count = active.changes.change_count();
        let result = crate::mod_package::export_modpkg_full(
            &metadata,
            &active.dispatch_name,
            &active.entries,
            &active.vanilla,
            &active.changes,
            Some(&self.state.notes),
            &path,
        );
        match result {
            Ok(()) => {
                let msg = format!(
                    "Exported {} changes to {}",
                    change_count,
                    path.display()
                );
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Write error: {}", e);
                self.state.toasts.error_with_details(
                    "Failed to write .modpkg",
                    format!("{}\nPath: {}", e, path.display()),
                );
            }
        }
    }

    /// Export as a DMM-compatible bundle directory. The user picks the
    /// DMM mods directory (or any parent folder) and we lay down a new
    /// subfolder containing `mod.json`, `metadata.json`, and `README.md`.
    fn action_export_dmm(&mut self) {
        let active = match self.state.active_table() {
            Some(t) => t,
            None => return,
        };
        let dispatch_name = active.dispatch_name.clone();
        let folder = match rfd::FileDialog::new()
            .set_title("Pick DMM Mods Directory (a new subfolder will be created)")
            .pick_folder()
        {
            Some(p) => p,
            None => return,
        };
        let mod_name = if !self.state.metadata_dialog.metadata.name.is_empty() {
            sanitize_folder(&self.state.metadata_dialog.metadata.name)
        } else {
            sanitize_folder(&dispatch_name)
        };
        let out_dir = folder.join(&mod_name);

        let active = self.state.active_table().unwrap();
        let metadata = self.state.metadata_dialog.metadata.clone();
        let change_count = active.changes.change_count();
        let result = crate::mod_package::export_dmm_full(
            &metadata,
            &active.dispatch_name,
            &active.entries,
            &active.vanilla,
            &active.changes,
            Some(&self.state.notes),
            &out_dir,
        );
        match result {
            Ok(()) => {
                let msg = format!(
                    "Exported {} changes to {}",
                    change_count,
                    out_dir.display()
                );
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Write error: {}", e);
                self.state.toasts.error_with_details(
                    "Failed to write DMM bundle",
                    format!("{}\nPath: {}", e, out_dir.display()),
                );
            }
        }
    }

    /// Top-level entry for the "Deploy to Game" menu item.
    ///
    /// Runs the validation rules pre-flight: if any Errors are found we
    /// stop, populate `state.lint_findings`, raise the deploy-confirm
    /// modal, and let the user decide whether to ship anyway. Warnings /
    /// info findings don't block the deploy — they're surfaced via the
    /// lint panel without interrupting the flow.
    fn action_deploy(&mut self) {
        // Pre-flight lint. We always run, even when the panel hasn't been
        // opened — the whole point is to catch e.g. the infinite-loading
        // crash before bytes touch the game directory.
        if let Some(active) = self.state.active_table() {
            let runner = crate::validation::LintRunner::with_default_rules();
            let findings = runner.check_table(
                &active.dispatch_name,
                &active.entries,
                self.state.catalog.as_ref(),
            );
            let (errors, warns, _) = crate::validation::LintRunner::count_by_severity(&findings);
            self.state.lint_findings = findings;
            if errors > 0 {
                self.state.deploy_confirm_pending = true;
                let msg = format!(
                    "Lint found {} error(s) and {} warning(s). Confirm before deploy.",
                    errors, warns
                );
                self.state.status = msg.clone();
                self.state.toasts.warn(msg);
                return;
            }
        }
        // No errors -> ship.
        self.action_deploy_confirmed();
    }

    /// Actually perform the deploy. Called either directly when lint clears
    /// or from the confirmation modal when the user clicks "Deploy anyway".
    fn action_deploy_confirmed(&mut self) {
        // Make sure we don't leave the modal up after the deploy finishes
        // (success or failure).
        self.state.deploy_confirm_pending = false;

        let game_dir = match &self.state.game_dir {
            Some(d) => d.clone(),
            None => {
                self.state.status = "Set game dir first".to_string();
                self.state.toasts.warn("Set game dir first");
                return;
            }
        };

        let active = match self.state.active_table() {
            Some(t) => t,
            None => {
                self.state.status = "No table loaded".to_string();
                self.state.toasts.warn("No table loaded");
                return;
            }
        };

        let dispatch_name = active.dispatch_name.clone();

        // Find the TableMeta for this table
        let meta_idx = self
            .state
            .tables
            .iter()
            .position(|m| m.dispatch_name == dispatch_name);
        let meta_idx = match meta_idx {
            Some(i) => i,
            None => {
                self.state.status = "Internal error: table meta not found".to_string();
                self.state
                    .toasts
                    .error("Internal error: table meta not found");
                return;
            }
        };

        // Use overlay group 0058 (standard for iteminfo-related mods)
        // TODO: allow user to pick overlay group per table
        let overlay_group = "0058";

        let entries = &self.state.active_table().unwrap().entries;

        match crate::deploy::deploy(
            &game_dir,
            &dispatch_name,
            &self.state.tables[meta_idx],
            entries,
            overlay_group,
        ) {
            Ok(()) => {
                let msg = format!(
                    "Deployed '{}' to {}/{}",
                    dispatch_name,
                    game_dir.display(),
                    overlay_group,
                );
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Deploy error: {}", e);
                self.state.toasts.error_with_details(
                    format!("Deploy failed for '{}'", dispatch_name),
                    e.to_string(),
                );
            }
        }
    }

    /// Run the lint runner over the active tab and store the resulting
    /// findings on `state.lint_findings`. Wired to the lint panel's
    /// "Run Lint Check" button.
    fn action_run_lint(&mut self) {
        let Some(active) = self.state.active_table() else {
            self.state.status = "No table loaded — load a table first".to_string();
            self.state.toasts.warn("No table loaded");
            return;
        };
        let runner = crate::validation::LintRunner::with_default_rules();
        let findings = runner.check_table(
            &active.dispatch_name,
            &active.entries,
            self.state.catalog.as_ref(),
        );
        let (errors, warns, infos) =
            crate::validation::LintRunner::count_by_severity(&findings);
        let count = findings.len();
        self.state.lint_findings = findings;
        let msg = format!(
            "Lint complete: {} finding(s) ({} error / {} warn / {} info)",
            count, errors, warns, infos
        );
        self.state.status = msg.clone();
        if errors > 0 {
            self.state.toasts.warn(msg);
        } else if count > 0 {
            self.state.toasts.info(msg);
        } else {
            self.state.toasts.info("Lint complete: no findings");
        }
    }

    /// Apply a single lint finding's auto-fix to the right tab/entry.
    ///
    /// We clone the finding before applying so the underlying vec stays
    /// borrowable. After a successful fix we drop the finding from the
    /// list — re-running lint will surface it again if the issue persists,
    /// but more often the fix actually clears it.
    fn action_apply_lint_fix(&mut self, idx: usize) {
        let Some(finding) = self.state.lint_findings.get(idx).cloned() else {
            self.state.status = "Lint finding no longer exists".to_string();
            return;
        };
        match crate::ui::lint_panel::apply_fix(&mut self.state, &finding) {
            Ok(()) => {
                let label = finding
                    .entry_name
                    .clone()
                    .unwrap_or_else(|| format!("key={}", finding.entry_key));
                let msg = format!(
                    "Applied fix for {} ({})",
                    finding.rule_name, label
                );
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
                // Drop the finding so the panel stops nagging the user.
                if idx < self.state.lint_findings.len() {
                    self.state.lint_findings.remove(idx);
                }
            }
            Err(e) => {
                self.state.status = format!("Apply Fix failed: {}", e);
                self.state
                    .toasts
                    .error_with_details("Apply Fix failed", e);
            }
        }
    }

    /// Render the modal confirmation window shown after `action_deploy`
    /// found Errors. The modal blocks interaction with the rest of the UI
    /// only by being on top — since we're a single-thread egui app and the
    /// caller renders the modal after the central panel, this is enough.
    fn render_deploy_confirm_modal(&mut self, ctx: &egui::Context) {
        let (errors, warns, _) =
            crate::validation::LintRunner::count_by_severity(&self.state.lint_findings);
        let mut deploy_anyway = false;
        let mut cancel = false;
        let mut review = false;

        egui::Window::new("Deploy with errors?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(format!(
                    "{} error(s) and {} warning(s) were found by the lint check.",
                    errors, warns,
                ));
                ui.label(
                    "Deploying with errors can crash the game (infinite loading + RAM \
                     spiral on save load). Review the findings before continuing.",
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .button("Review Findings")
                        .on_hover_text("Open the Lint panel to inspect each finding.")
                        .clicked()
                    {
                        review = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if ui
                        .button(
                            egui::RichText::new("Deploy anyway")
                                .color(egui::Color32::from_rgb(230, 80, 80)),
                        )
                        .on_hover_text("Ship the build despite the errors. Use with care.")
                        .clicked()
                    {
                        deploy_anyway = true;
                    }
                });
            });

        if review {
            self.state.deploy_confirm_pending = false;
            self.state.main_view = MainView::Lint;
        }
        if cancel {
            self.state.deploy_confirm_pending = false;
            self.state.status = "Deploy cancelled".to_string();
            self.state.toasts.info("Deploy cancelled");
        }
        if deploy_anyway {
            self.action_deploy_confirmed();
        }
    }

    /// Confirmation modal raised by the Ctrl+R keyboard shortcut before we
    /// fire [`Self::action_restore`]. The menu-driven Restore still goes
    /// straight to the action — only the keyboard path takes the gated
    /// route, since fat-fingering Ctrl+R while typing in a field would
    /// otherwise wipe the overlay without warning.
    fn render_restore_confirm_modal(&mut self, ctx: &egui::Context) {
        let mut confirm = false;
        let mut cancel = false;

        egui::Window::new("Restore overlay?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(
                    "This will remove the overlay group from the game directory \
                     and revert the PAPGT registration, returning the game to \
                     vanilla state for that overlay.",
                );
                ui.label("Snapshots are unaffected — you can re-deploy at any time.");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                    if ui
                        .button(
                            egui::RichText::new("Restore")
                                .color(egui::Color32::from_rgb(230, 80, 80)),
                        )
                        .clicked()
                    {
                        confirm = true;
                    }
                });
            });

        if cancel {
            self.state.restore_confirm_pending = false;
            self.state.status = "Restore cancelled".to_string();
        }
        if confirm {
            self.state.restore_confirm_pending = false;
            self.action_restore();
        }
    }

    fn action_restore(&mut self) {
        let game_dir = match &self.state.game_dir {
            Some(d) => d.clone(),
            None => {
                self.state.status = "Set game dir first".to_string();
                self.state.toasts.warn("Set game dir first");
                return;
            }
        };

        let overlay_group = "0058";

        match crate::restore::restore(&game_dir, overlay_group) {
            Ok(()) => {
                let msg = format!("Restored: removed overlay {}", overlay_group);
                self.state.status = msg.clone();
                self.state.toasts.info(msg);
            }
            Err(e) => {
                self.state.status = format!("Restore error: {}", e);
                self.state.toasts.error_with_details(
                    format!("Restore failed for overlay {}", overlay_group),
                    e.to_string(),
                );
            }
        }
    }

    /// Route a confirmed command-palette row to the matching app handler.
    ///
    /// Each variant maps to an existing `action_*` method or a direct state
    /// mutation — the palette is intentionally a thin shell over the same
    /// surface the menu bar already uses, so behaviour is identical no
    /// matter how the user invokes the command.
    ///
    /// `JumpToTable` and `JumpToEntry` need the same lazy-load semantics as
    /// the table list: if the table isn't yet open we focus it directly
    /// when it has an open tab, otherwise we submit a `LoadTable` job to
    /// the worker so the entries fault in off the UI thread.
    fn dispatch_palette_action(&mut self, action: ui::command_palette::PaletteAction) {
        use ui::command_palette::PaletteAction;
        match action {
            PaletteAction::Deploy => self.action_deploy(),
            PaletteAction::Restore => {
                // Honour the same confirmation gate the Ctrl+R shortcut
                // uses so the palette can't silently wipe the overlay.
                self.state.restore_confirm_pending = true;
            }
            PaletteAction::RunLint => self.action_run_lint(),
            PaletteAction::ImportMod => self.action_import_mod(),
            PaletteAction::ExportMod => {
                self.begin_export_flow(ui::metadata_dialog::ExportAction::SaveJson);
            }
            PaletteAction::OpenView(view) => {
                self.state.main_view = view;
                // Mirror the lazy-refresh flag the menu uses for views
                // that load their own state on first navigation.
                if matches!(view, MainView::Backups) {
                    self.state.backup_loaded_once = false;
                }
            }
            PaletteAction::JumpToTable(name) => {
                // If the tab is already open, just focus it. Otherwise
                // kick off the same `LoadTable` worker job the table list
                // would submit. The reply handler in `handle_worker_reply`
                // already deals with first-time loads vs reloads.
                self.state.main_view = MainView::PabgbTables;
                if self.state.open_or_focus_tab(&name).is_some() {
                    return;
                }
                let Some(meta) = self
                    .state
                    .tables
                    .iter()
                    .find(|m| m.dispatch_name == name)
                    .cloned()
                else {
                    self.state.toasts.warn(format!("Unknown table: {}", name));
                    return;
                };
                let Some(game_dir) = self.state.game_dir.clone() else {
                    self.state.toasts.warn("Set game dir first");
                    return;
                };
                self.state.status = format!("Loading {}...", name);
                self.state.worker.submit(crate::worker::Job::LoadTable {
                    dispatch_name: name,
                    game_dir,
                    pabgb_filename: meta.pabgb_filename,
                    pabgh_filename: meta.pabgh_filename,
                });
            }
            PaletteAction::JumpToEntry { table, entry_idx } => {
                self.state.main_view = MainView::PabgbTables;
                // The palette only emits this for entries in the active
                // table, so a focus-or-noop is enough — we don't need to
                // re-load anything.
                if self.state.open_or_focus_tab(&table).is_none() {
                    self.state.toasts.warn(format!(
                        "Table '{}' is no longer loaded",
                        table
                    ));
                    return;
                }
                if let Some(active) = self.state.active_table_mut() {
                    if entry_idx < active.entries.len() {
                        active.selected_entry_idx = Some(entry_idx);
                    }
                }
            }
            PaletteAction::OpenLibraryMod(path) => {
                // Reuse the conflict viewer as the canonical "open mod
                // file" surface so library mods plug into the same
                // analysis pipeline.
                match crate::conflict::load_mod(&path) {
                    Ok(loaded) => {
                        self.state.loaded_mods.push(loaded);
                        // Conflict report is no longer accurate now that
                        // the mod set has changed.
                        self.state.conflict_report = None;
                        self.state.main_view = MainView::Conflicts;
                        self.state.toasts.info(format!(
                            "Opened {}",
                            path.file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("(unnamed)")
                        ));
                    }
                    Err(e) => {
                        self.state
                            .toasts
                            .error_with_details("Failed to open mod", e.to_string());
                    }
                }
            }
        }
    }
}
