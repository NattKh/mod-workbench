//! Multi-format global search panel.
//!
//! Searches a single substring across every supported game-data format
//! and surfaces the hits grouped by source. Per-format toggles let the
//! user scope the scan up front (e.g. "I only care about PALOC") and
//! the slow byte-level scan is opt-in so a curious "type 'kliff' and
//! see what happens" doesn't immediately walk 4000 binary files.
//!
//! Independent of the per-PABGB-table-list quick-scan checkbox in the
//! entry-table — that flow lives on [`crate::state::GlobalSearchSession`]
//! and [`crate::worker::Job::SearchAllPabgb`]. This panel uses
//! [`crate::state::MultiFormatSearchSession`] +
//! [`crate::worker::Job::MultiFormatSearch`]. They coexist so the user
//! can have either, both, or neither active without conflict.
//!
//! ## Workflow
//!
//! 1. Type a query in the search box.
//! 2. Pick which formats to scan (every fast format on by default,
//!    BinaryByte off until the user opts in).
//! 3. Hit Run. Worker streams hits as it walks each format; progress
//!    text updates per file inside large formats.
//! 4. Results group by source format inside collapsing headers.
//!    Clicking a row expands the full payload (entry JSON for PABGB,
//!    paged hex for binaries, etc.). The "Open in editor" button on
//!    each hit switches `MainView` to the matching editor and
//!    pre-positions when practical (e.g. PABGB hits load the table and
//!    select the entry).
//!
//! ## Hit caps
//!
//! Each format is capped at 500 hits per scan in the worker so a
//! short query doesn't generate a runaway list. The cap is per format,
//! not global — a 500-cap on PALOC doesn't block PABGB hits from
//! arriving. Users hitting the cap should narrow their query.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::state::{
    AppState, MainView, MultiFormatSearchSession, PendingNav, SearchFormat, SearchMode,
};
use crate::worker::{
    parse_hex_pattern, ByteHitKind, HitSource, Job, KoreanEncoding, MultiFormatHit,
    SearchQueryKind,
};

pub fn show(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.heading("Global Search");
    });
    ui.label(
        "Search a substring across every supported format — PABGB \
         tables, PALOC localization, XML configs, the small-file \
         editors (.paatt / .paac / .pappt / .pamhc), and an opt-in \
         byte-level scan across schedule/AI/level/etc. files. Each \
         format is capped at 500 hits per scan; narrow the query if \
         you need more.",
    );
    ui.separator();

    mode_selector(ui, state);
    search_controls(ui, state);
    if state.multi_search.search_mode == SearchMode::Text {
        // Jenkins-hash opt-in only makes sense for text queries —
        // hex mode is already raw bytes, Korean-strings mode walks
        // text runs directly.
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut state.multi_search.match_jenkins_hash,
                "Also match Jenkins hash of query (4-byte LE)",
            )
            .on_hover_text(
                "Computes Jenkins hashlittle of the query and \
                 searches for those bytes across every byte-level \
                 format. Tries lowercase / uppercase / as-typed \
                 (deduped). Catches strings stored as 4-byte hashes \
                 — item keys, paloc IDs, character keys, etc.",
            );
        });
    }
    ui.separator();
    formats_grid(ui, state);
    ui.separator();
    progress_row(ui, state);

    if let Some(err) = &state.multi_search.error {
        ui.label(
            egui::RichText::new(format!("Partial scan error: {}", err))
                .color(egui::Color32::from_rgb(230, 180, 80))
                .small(),
        );
    }
    ui.add_space(6.0);
    results_panel(ui, state);
}

/// Segmented Text / Hex / KoreanStrings mode selector. Switching
/// modes leaves all query strings intact so the user can flick
/// between modes without retyping.
fn mode_selector(ui: &mut egui::Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Mode:").strong().small());
        let mut mode = state.multi_search.search_mode;
        if ui
            .selectable_value(&mut mode, SearchMode::Text, SearchMode::Text.label())
            .on_hover_text(
                "Substring search — runs over every text-bearing \
                 format (PABGB / PALOC / XML) plus byte-level UTF-8 \
                 / UTF-16 LE scans of the binary formats.",
            )
            .clicked()
        {}
        if ui
            .selectable_value(&mut mode, SearchMode::Hex, SearchMode::Hex.label())
            .on_hover_text(
                "Raw byte-pattern search. Type hex digits (e.g. \
                 '5A 4C 00 00') and the worker memmems for those bytes \
                 across binary formats only.",
            )
            .clicked()
        {}
        if ui
            .selectable_value(
                &mut mode,
                SearchMode::KoreanStrings,
                SearchMode::KoreanStrings.label(),
            )
            .on_hover_text(
                "CJK string discovery — walks every binary file and \
                 surfaces every Hangul / Kana / Hanzi run inside, in \
                 both UTF-8 and UTF-16 LE form. Optional filter \
                 narrows by substring. Useful for browsing Korean \
                 text hidden in pabgb / paatt / paac / etc. blobs.",
            )
            .clicked()
        {}
        if mode != state.multi_search.search_mode {
            // Mode change resets the in-progress scan / hit list so a
            // running text scan doesn't bleed into a fresh hex search.
            state.multi_search.search_mode = mode;
            cancel_scan(state);
            state.multi_search.hits.clear();
            state.multi_search.error = None;
            state.multi_search.expanded_hit = None;
            state.multi_search.progress_message.clear();
            // The unfiltered-Korean-scan confirm flag must reset on
            // every mode switch so dropping back into KoreanStrings
            // re-arms the two-step gate.
            state.multi_search.confirm_no_filter = false;
            // Hex mode and Korean-strings mode both target binary
            // formats only — the text-only formats can't contribute.
            // Toggle them off to keep the scope honest; the user can
            // re-enable them when flipping back to Text.
            if matches!(mode, SearchMode::Hex | SearchMode::KoreanStrings) {
                state.multi_search.formats_enabled.remove(&SearchFormat::Pabgb);
                state.multi_search.formats_enabled.remove(&SearchFormat::Paloc);
                state.multi_search.formats_enabled.remove(&SearchFormat::Xml);
            }
            // Korean-strings mode only operates on the binary
            // inspector allow-list — auto-tick BinaryByte so the
            // user doesn't get a no-op Run when they first switch.
            if mode == SearchMode::KoreanStrings {
                state
                    .multi_search
                    .formats_enabled
                    .insert(SearchFormat::BinaryByte);
            }
        }
    });
}

/// Top row: search box + Run / Cancel + hit-count summary.
///
/// In text mode this is a plain `query` string field. In hex mode it
/// swaps to a `hex_query` field whose parse status is rendered on a
/// second line — Run is gated on the parse succeeding. In Korean
/// mode the search box doubles as an optional filter — empty input
/// is allowed but gated behind a two-step confirmation
/// (`confirm_no_filter`) so an accidental click doesn't kick a
/// huge scan.
fn search_controls(ui: &mut egui::Ui, state: &mut AppState) {
    let mode = state.multi_search.search_mode;
    // Pre-parse the hex query so we can both validate Run and render
    // the parsed-bytes feedback below the box. Cheap — short string.
    let hex_parsed = if mode == SearchMode::Hex {
        Some(parse_hex_pattern(&state.multi_search.hex_query))
    } else {
        None
    };

    // Capture the pre-edit query for KoreanStrings mode so we can
    // detect any change after the text edit and re-arm the
    // confirm-no-filter guard if the user typed something.
    let pre_edit_query = state.multi_search.query.clone();

    let korean_filter_empty =
        mode == SearchMode::KoreanStrings && state.multi_search.query.trim().is_empty();

    ui.horizontal(|ui| {
        let enter_pressed = match mode {
            SearchMode::Text => {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.multi_search.query)
                        .hint_text("Search query (e.g. kliff)")
                        .desired_width(360.0),
                );
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            }
            SearchMode::Hex => {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.multi_search.hex_query)
                        .hint_text("Hex pattern (e.g. 5A 4C 00 00)")
                        .desired_width(360.0)
                        .font(egui::TextStyle::Monospace),
                );
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            }
            SearchMode::KoreanStrings => {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.multi_search.query)
                        .hint_text("Optional filter (CJK substring) — empty = browse all")
                        .desired_width(360.0),
                );
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            }
        };

        // KoreanStrings mode: any edit to the filter resets the
        // confirm-no-filter guard, even if the result is still empty
        // (e.g. user typed and erased). We compare the post-edit
        // value to the pre-edit snapshot — any difference means the
        // user touched the field, so the guard must re-arm.
        if mode == SearchMode::KoreanStrings && state.multi_search.query != pre_edit_query {
            state.multi_search.confirm_no_filter = false;
        }

        // Run-enable rule per mode. KoreanStrings allows empty
        // filter — the two-step confirmation handles the warning,
        // not the disable state.
        let run_enabled = !state.multi_search.in_progress
            && !state.multi_search.formats_enabled.is_empty()
            && match mode {
                SearchMode::Text => !state.multi_search.query.trim().is_empty(),
                SearchMode::Hex => matches!(&hex_parsed, Some(Ok(b)) if !b.is_empty()),
                SearchMode::KoreanStrings => true,
            };

        // Run button label: in KoreanStrings mode with an empty
        // filter, swap to "Run anyway" once the user has armed the
        // two-step guard (i.e. clicked Run once already). The first
        // Run click sets `confirm_no_filter`; the second actually
        // fires. Other modes always show the plain "Run" label.
        let run_label = if mode == SearchMode::KoreanStrings
            && korean_filter_empty
            && state.multi_search.confirm_no_filter
        {
            "Run anyway"
        } else {
            "Run"
        };
        let mut should_run = false;
        if ui
            .add_enabled(run_enabled, egui::Button::new(run_label))
            .on_hover_text(
                "Submit a fresh scan against the enabled formats. \
                 Stops any scan currently in progress.",
            )
            .clicked()
        {
            should_run = true;
        }
        if enter_pressed && run_enabled {
            should_run = true;
        }

        let cancel_enabled = state.multi_search.in_progress;
        if ui
            .add_enabled(cancel_enabled, egui::Button::new("Cancel"))
            .on_hover_text(
                "Discard the in-flight scan's pending hits. The worker \
                 keeps running until it sees the next reply boundary, \
                 but stale replies are dropped.",
            )
            .clicked()
        {
            cancel_scan(state);
        }
        // Reset button — escape hatch for any stuck session state.
        // Bumps the request id (so any straggler replies are dropped),
        // clears the result list / error / progress / expanded-hit
        // bookkeeping, and re-arms the Korean confirm gate. Crucially
        // does NOT touch the user's typed query, hex query, mode,
        // format set, or jenkins-hash toggle — those stay so the next
        // Run can use the same setup.
        if ui
            .button("Reset")
            .on_hover_text(
                "Clear results and reset session — useful if a previous \
                 scan got stuck.",
            )
            .clicked()
        {
            reset_session(state);
        }
        ui.label(
            egui::RichText::new(format!(
                "{} hit(s) so far",
                state.multi_search.hits.len()
            ))
            .small()
            .weak(),
        );
        if should_run {
            // Two-step confirm gate for unfiltered Korean scans. The
            // first click flips the flag; the second click (with the
            // flag already set) actually kicks the scan.
            if mode == SearchMode::KoreanStrings && korean_filter_empty {
                if state.multi_search.confirm_no_filter {
                    state.multi_search.confirm_no_filter = false;
                    kick_scan(state);
                } else {
                    state.multi_search.confirm_no_filter = true;
                }
            } else {
                kick_scan(state);
            }
        }
    });

    // Hex parse-status feedback line. Shown only in hex mode and only
    // when the user has typed something — empty input is too noisy to
    // call out as an error.
    if let Some(parsed) = hex_parsed {
        if !state.multi_search.hex_query.trim().is_empty() {
            match parsed {
                Ok(bytes) => {
                    let preview = bytes
                        .iter()
                        .take(16)
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let trail = if bytes.len() > 16 { " ..." } else { "" };
                    ui.label(
                        egui::RichText::new(format!(
                            "parsed: {} byte(s) — {}{}",
                            bytes.len(),
                            preview,
                            trail
                        ))
                        .small()
                        .color(egui::Color32::from_gray(170)),
                    );
                }
                Err(msg) => {
                    ui.label(
                        egui::RichText::new(format!("error: {}", msg))
                            .small()
                            .color(egui::Color32::from_rgb(230, 120, 120)),
                    );
                }
            }
        }
    }

    // KoreanStrings mode: warn when the filter is empty. Two stages:
    //   - Initial: a friendly hint that empty == browse mode.
    //   - Armed (after first Run click): a strong yellow warning row,
    //     drawn directly under the Run button so the user can't miss
    //     that their click flipped the gate. Without this, the only
    //     signal that a click happened is the Run-button label flip
    //     to "Run anyway" — easy to miss, especially since the user
    //     may already be hovering off the button by the time the
    //     re-render lands. We render the warning with a leading "⚠"
    //     and a contrasting yellow fill so it reads as a real prompt
    //     instead of background helper text.
    if mode == SearchMode::KoreanStrings && korean_filter_empty {
        if state.multi_search.confirm_no_filter {
            // Strong, eye-grabbing two-step prompt. Yellow background
            // frame plus the warning glyph makes it clear this row is
            // demanding a second click, not just narrating state.
            egui::Frame::group(ui.style())
                .fill(egui::Color32::from_rgb(80, 60, 0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("\u{26A0}")
                                .color(egui::Color32::from_rgb(255, 220, 60))
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(
                                "Click \"Run anyway\" to confirm — empty filter will \
                                 return the first 500 CJK runs from each format.",
                            )
                            .color(egui::Color32::from_rgb(255, 230, 120))
                            .strong(),
                        );
                    });
                });
        } else {
            ui.label(
                egui::RichText::new(
                    "Empty filter = browse mode (every CJK run, capped at 500 per \
                     format). Add a substring to narrow.",
                )
                .small()
                .color(egui::Color32::from_gray(170)),
            );
        }
    }
}

/// Format toggle grid — checkbox + name + helper note per format.
///
/// Hex and Korean-strings modes both grey out the text-only formats
/// (PABGB / PALOC / XML) since neither can pull raw bytes nor extract
/// CJK runs from those formats. In Korean-strings mode the per-byte-
/// format toggles (.paatt / .paac / .pappt / .pamhc) are also greyed
/// out — only the BinaryByte allow-list (which already covers schedule
/// / AI / level / etc.) is meaningful.
fn formats_grid(ui: &mut egui::Ui, state: &mut AppState) {
    ui.label(
        egui::RichText::new("Formats to scan")
            .strong()
            .small(),
    );
    let mode = state.multi_search.search_mode;
    let hex_mode = mode == SearchMode::Hex;
    let korean_mode = mode == SearchMode::KoreanStrings;
    egui::Grid::new("multi_search_formats")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .striped(false)
        .show(ui, |ui| {
            for fmt in SearchFormat::all() {
                let disabled =
                    (hex_mode && is_text_only_format(*fmt)) || (korean_mode && !is_korean_format(*fmt));
                let mut checked = state.multi_search.formats_enabled.contains(fmt);
                let response = ui.add_enabled(
                    !disabled,
                    egui::Checkbox::new(&mut checked, fmt.display_name()),
                );
                let response = if disabled {
                    let tooltip = if korean_mode {
                        "Korean-strings mode walks the binary inspector \
                         allow-list directly — only Binary Byte Scan \
                         applies."
                    } else {
                        "Hex mode only scans binary formats — this \
                         format carries text and can't contain raw \
                         bytes."
                    };
                    response.on_disabled_hover_text(tooltip)
                } else {
                    response
                };
                if response.changed() {
                    if checked {
                        state.multi_search.formats_enabled.insert(*fmt);
                    } else {
                        state.multi_search.formats_enabled.remove(fmt);
                    }
                }
                ui.label(
                    egui::RichText::new(fmt.note())
                        .small()
                        .color(egui::Color32::from_gray(150)),
                );
                ui.end_row();
            }
        });
    ui.horizontal(|ui| {
        if ui.small_button("All").clicked() {
            for f in SearchFormat::all() {
                if hex_mode && is_text_only_format(*f) {
                    continue;
                }
                if korean_mode && !is_korean_format(*f) {
                    continue;
                }
                state.multi_search.formats_enabled.insert(*f);
            }
        }
        if ui.small_button("None").clicked() {
            state.multi_search.formats_enabled.clear();
        }
        if ui
            .small_button("Fast only")
            .on_hover_text(
                "Re-tick every format except the slow Binary Byte scan.",
            )
            .clicked()
        {
            state.multi_search.formats_enabled.clear();
            for f in SearchFormat::all() {
                if matches!(f, SearchFormat::BinaryByte) {
                    continue;
                }
                if hex_mode && is_text_only_format(*f) {
                    continue;
                }
                if korean_mode && !is_korean_format(*f) {
                    continue;
                }
                state.multi_search.formats_enabled.insert(*f);
            }
        }
    });
}

/// True for the formats that only carry text and therefore can't
/// possibly match a raw byte pattern. Used to disable their toggles in
/// hex mode.
fn is_text_only_format(f: SearchFormat) -> bool {
    matches!(
        f,
        SearchFormat::Pabgb | SearchFormat::Paloc | SearchFormat::Xml
    )
}

/// True for formats the Korean-strings scan actually operates on. The
/// scan walks the binary inspector's `ALLOWED_EXTENSIONS` list directly
/// (schedule / AI / level / pappt / paatt / etc.), so the only
/// SearchFormat row that's meaningful in this mode is `BinaryByte` —
/// the other byte-format toggles would do nothing because the worker
/// dispatches them through a separate code path that wouldn't run a
/// Korean extraction.
fn is_korean_format(f: SearchFormat) -> bool {
    matches!(f, SearchFormat::BinaryByte)
}

/// Threshold above which an in-progress scan is considered "stuck"
/// for UX-hint purposes. Worker progress messages tick on every file
/// boundary and most formats are sub-second, so 5 s of silence is an
/// extremely strong signal that something has gone wrong (either a
/// worker panic or a wedged scanner). Keep generous to avoid false
/// positives on a slow disk.
const STUCK_THRESHOLD_SECS: u64 = 5;

/// Progress / status line. Repaints periodically while a scan is
/// running so the user sees per-file progress without nudging the UI.
///
/// Also surfaces a stuck-state hint when `in_progress` is true but the
/// progress label hasn't advanced for [`STUCK_THRESHOLD_SECS`] seconds.
/// The hint is a defensive complement to the explicit Reset button —
/// the user has the button available always, but the hint nudges them
/// at it once the panel can confidently say "this scan is going
/// nowhere."
fn progress_row(ui: &mut egui::Ui, state: &mut AppState) {
    if state.multi_search.in_progress {
        ui.horizontal(|ui| {
            ui.add(egui::Spinner::new());
            ui.label(
                egui::RichText::new(&state.multi_search.progress_message)
                    .small(),
            );
        });
        // Stuck-state hint. Only fires when we've been in_progress
        // long enough that the timestamp is well past the threshold.
        // We don't gate on the message being non-empty because a scan
        // can land in_progress before the worker emits its first
        // Progress reply — if that first reply never lands, the user
        // would otherwise see a forever-spinning spinner with no
        // recovery path.
        if let Some(updated_at) = state.multi_search.progress_updated_at {
            let elapsed = updated_at.elapsed();
            if elapsed.as_secs() >= STUCK_THRESHOLD_SECS {
                ui.label(
                    egui::RichText::new(format!(
                        "\u{26A0} No progress for {}s — looks stuck. Click \
                         Reset above to recover.",
                        elapsed.as_secs()
                    ))
                    .small()
                    .color(egui::Color32::from_rgb(230, 180, 80)),
                );
            }
        }
        ui.ctx().request_repaint_after(Duration::from_millis(120));
    } else if !state.multi_search.progress_message.is_empty() {
        ui.label(
            egui::RichText::new(&state.multi_search.progress_message)
                .small()
                .weak(),
        );
    }
}

/// Results panel — collapsing headers per source format, each
/// containing a list of hit rows.
fn results_panel(ui: &mut egui::Ui, state: &mut AppState) {
    if state.multi_search.hits.is_empty() {
        if !state.multi_search.in_progress {
            ui.label(
                egui::RichText::new(
                    "No hits yet. Type a query above, pick formats, and click Run.",
                )
                .color(egui::Color32::from_gray(160)),
            );
        }
        return;
    }

    // Group hit indices by source group label for stable rendering.
    // Use a Vec<(group, indices)> rather than a HashMap so the order
    // matches `HitSource::group_label`'s declaration order.
    let mut groups: Vec<(&'static str, Vec<usize>)> = Vec::new();
    for (idx, hit) in state.multi_search.hits.iter().enumerate() {
        let g = hit.source.group_label();
        if let Some(slot) = groups.iter_mut().find(|(name, _)| *name == g) {
            slot.1.push(idx);
        } else {
            groups.push((g, vec![idx]));
        }
    }

    let mut clicked_open: Option<usize> = None;
    let mut toggle_expanded: Option<usize> = None;

    egui::ScrollArea::vertical()
        .id_salt("multi_search_results")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for (group_name, indices) in &groups {
                egui::CollapsingHeader::new(format!(
                    "{} ({})",
                    group_name,
                    indices.len()
                ))
                .id_salt(format!("multi_search_group_{}", group_name))
                .default_open(true)
                .show(ui, |ui| {
                    for hit_idx in indices {
                        let i = *hit_idx;
                        let hit = &state.multi_search.hits[i];
                        let expanded = state.multi_search.expanded_hit == Some(i);
                        ui.horizontal(|ui| {
                            let label = if expanded { "[-]" } else { "[+]" };
                            if ui
                                .small_button(label)
                                .on_hover_text("Toggle expand for full match context")
                                .clicked()
                            {
                                toggle_expanded = Some(i);
                            }
                            // Source-specific row prefix so the user sees
                            // the table / language / file at a glance
                            // without having to expand.
                            if let Some(prefix) = source_row_prefix(&hit.source) {
                                ui.label(
                                    egui::RichText::new(prefix)
                                        .strong()
                                        .small(),
                                );
                            }
                            ui.label(&hit.snippet);
                            if ui
                                .small_button("Open in editor")
                                .on_hover_text(
                                    "Switch to the editor view for this hit's source format.",
                                )
                                .clicked()
                            {
                                clicked_open = Some(i);
                            }
                        });
                        if expanded {
                            ui.add_space(2.0);
                            render_expanded(ui, hit);
                            ui.add_space(4.0);
                        }
                    }
                });
            }
        });

    if let Some(i) = toggle_expanded {
        let cur = state.multi_search.expanded_hit;
        state.multi_search.expanded_hit = if cur == Some(i) { None } else { Some(i) };
    }
    if let Some(i) = clicked_open {
        if let Some(hit) = state.multi_search.hits.get(i).cloned() {
            jump_to_hit(state, &hit);
            // Force a redraw next frame so the destination editor's
            // first draw runs immediately and consumes
            // `pending_global_nav` without waiting on idle.
            ui.ctx().request_repaint();
        }
    }
}

/// One-line context prefix for the result row, format-specific. Reads
/// the carrying fields off `HitSource` so the user can see the table
/// name / language / extension without expanding the row.
fn source_row_prefix(source: &HitSource) -> Option<String> {
    match source {
        HitSource::Pabgb {
            dispatch_name,
            string_key,
            entry_key,
            ..
        } => {
            let key_part = if string_key.is_empty() {
                format!("key={}", entry_key)
            } else {
                format!("{} (key={})", string_key, entry_key)
            };
            Some(format!("{} → {}: ", dispatch_name, key_part))
        }
        HitSource::Paloc { lang, hash_id, .. } => Some(format!("{}[{}]: ", lang, hash_id)),
        HitSource::Xml { paz_group, dir_path, filename } => {
            Some(format!("[{}/{}/{}] ", paz_group, dir_path, filename))
        }
        HitSource::Paatt { paz_group, dir_path, filename }
        | HitSource::Paac { paz_group, dir_path, filename }
        | HitSource::Pappt { paz_group, dir_path, filename }
        | HitSource::Pamhc { paz_group, dir_path, filename } => {
            Some(format!("[{}/{}/{}] ", paz_group, dir_path, filename))
        }
        HitSource::Binary {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            ..
        } => Some(format!(
            "[{}/{}/{}] .{} @0x{:X}: ",
            paz_group, dir_path, filename, ext, byte_offset
        )),
        HitSource::JenkinsHash {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            hash,
            case_label,
            ..
        } => Some(format!(
            "[{}/{}/{}] .{} @0x{:X} hash=0x{:08X} ({}): ",
            paz_group, dir_path, filename, ext, byte_offset, hash, case_label
        )),
        HitSource::HexPattern {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            pattern_len,
            ..
        } => Some(format!(
            "[{}/{}/{}] .{} @0x{:X} ({}B pattern): ",
            paz_group, dir_path, filename, ext, byte_offset, pattern_len
        )),
        HitSource::KoreanString {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            encoding,
            ..
        } => {
            let enc_label = match encoding {
                KoreanEncoding::Utf8 => "UTF-8",
                KoreanEncoding::Utf16Le => "UTF-16 LE",
            };
            Some(format!(
                "[{}/{}/{}] .{} @0x{:X} {}: ",
                paz_group, dir_path, filename, ext, byte_offset, enc_label
            ))
        }
    }
}

/// Render the rich expand-data payload for a single hit. PABGB hits
/// show pretty-printed JSON; everything else shows the worker-supplied
/// excerpt verbatim.
fn render_expanded(ui: &mut egui::Ui, hit: &MultiFormatHit) {
    if let Some(data) = &hit.expand_data {
        // Cap render width so a 4KB excerpt doesn't push the layout
        // around. The internal scroll handles overflow.
        egui::ScrollArea::vertical()
            .id_salt(format!(
                "multi_search_expand_{}",
                ui.next_auto_id().short_debug_format()
            ))
            .max_height(220.0)
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut data.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
    }
    // Source-specific extras: byte-kind annotation for binary hits.
    if let HitSource::Binary { kind, .. } = &hit.source {
        let kind_label = match kind {
            ByteHitKind::Utf8 => "UTF-8 / ASCII match",
            ByteHitKind::Utf16Le => "UTF-16 LE wide-string match",
        };
        ui.label(
            egui::RichText::new(kind_label)
                .small()
                .weak(),
        );
    }
    // PALOC hits — show the full untruncated value as a hover tooltip
    // on the language label, since the snippet truncates at 80 chars.
    if let HitSource::Paloc { lang, value, .. } = &hit.source {
        ui.label(
            egui::RichText::new(format!("Language: {}", lang))
                .small()
                .weak(),
        )
        .on_hover_text(value.as_str());
    }
    // KoreanString hits — show the full decoded text and encoding so
    // the user can read the run without the snippet's 80-char cap.
    if let HitSource::KoreanString {
        text,
        encoding,
        byte_offset,
        ..
    } = &hit.source
    {
        let enc_label = match encoding {
            KoreanEncoding::Utf8 => "UTF-8",
            KoreanEncoding::Utf16Le => "UTF-16 LE",
        };
        ui.label(
            egui::RichText::new(format!(
                "Encoding: {} | offset 0x{:X} | run length: {} chars",
                enc_label,
                byte_offset,
                text.chars().count(),
            ))
            .small()
            .weak(),
        );
        ui.label(
            egui::RichText::new(format!("Decoded: {}", text))
                .strong(),
        );
    }
}

/// Submit a fresh `Job::MultiFormatSearch`. Bumps the request id so
/// any in-flight replies from a prior scan get filtered out by the
/// reply handler.
fn kick_scan(state: &mut AppState) {
    let Some(game_dir) = state.game_dir.clone() else {
        state
            .toasts
            .warn("Set the Game Directory first (Settings panel).");
        return;
    };
    let formats = state.multi_search.formats_enabled.clone();
    if formats.is_empty() {
        state.toasts.warn("Pick at least one format to scan.");
        return;
    }

    // Build the right query payload for the active mode. Hex mode
    // relies on the parser succeeding — we re-validate here so a
    // race between toggling modes and clicking Run can't ship a bad
    // payload.
    let (query_for_label, query_kind, match_jenkins_hash) = match state.multi_search.search_mode {
        SearchMode::Text => {
            let query = state.multi_search.query.trim().to_string();
            if query.is_empty() {
                return;
            }
            (
                query.clone(),
                SearchQueryKind::Text(query),
                state.multi_search.match_jenkins_hash,
            )
        }
        SearchMode::Hex => {
            let raw = state.multi_search.hex_query.clone();
            match parse_hex_pattern(&raw) {
                Ok(bytes) if !bytes.is_empty() => (
                    raw,
                    SearchQueryKind::HexBytes(bytes),
                    // Jenkins hashing of a hex string makes no sense;
                    // hard-disable regardless of checkbox state.
                    false,
                ),
                Ok(_) | Err(_) => {
                    state
                        .toasts
                        .warn("Hex pattern is invalid or empty — fix it before running.");
                    return;
                }
            }
        }
        SearchMode::KoreanStrings => {
            // Empty filter is valid here — the worker treats `None`
            // as "emit every CJK run". The two-step confirm guard in
            // `search_controls` is what stops accidental clicks.
            let trimmed = state.multi_search.query.trim().to_string();
            let label = if trimmed.is_empty() {
                "(no filter — all CJK runs)".to_string()
            } else {
                trimmed.clone()
            };
            let filter = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            };
            (label, SearchQueryKind::KoreanScan { filter }, false)
        }
    };

    state.multi_search.request_id = state.multi_search.request_id.wrapping_add(1);
    state.multi_search.in_progress = true;
    state.multi_search.hits.clear();
    state.multi_search.error = None;
    state.multi_search.progress_message = "Starting scan...".to_string();
    // Arm the stuck-detector clock now — if the worker dies between
    // here and the first progress reply, the panel will surface a
    // hint after the 5 s threshold instead of spinning forever.
    state.multi_search.progress_updated_at = Some(std::time::Instant::now());
    state.multi_search.expanded_hit = None;

    // Rotate the cancellation flag to a fresh `Arc` before submitting
    // the new job. Reusing the previous Arc would let a stale `true`
    // from the prior cancel short-circuit the new scan instantly —
    // the worker would see the flipped flag at its first check and
    // exit before doing any work. The clone we hand the worker is
    // independent of the session's copy from the cancel side; both
    // halves of the Arc point at the same `AtomicBool`, which is
    // exactly what we want for the cancel signal.
    let cancel_flag_for_job = rotate_cancel_flag(&mut state.multi_search);

    // `filter_as_number` only applies to text mode (numeric `key`
    // matching against PABGB entries); hex mode has its own pattern
    // shape, no point parsing it as a number.
    let filter_as_number = if matches!(state.multi_search.search_mode, SearchMode::Text) {
        parse_user_number(&query_for_label.to_lowercase())
    } else {
        None
    };
    let queued = state.worker.submit(Job::MultiFormatSearch {
        request_id: state.multi_search.request_id,
        game_dir,
        query: query_for_label,
        filter_as_number,
        formats,
        tables: state.tables.clone(),
        query_kind,
        match_jenkins_hash,
        cancel_flag: cancel_flag_for_job,
    });
    // Worker channel is closed (background thread died). Without this
    // recovery the panel would sit on `in_progress=true` forever
    // because no `MultiFormatComplete` reply will ever arrive. Surface
    // a toast and reset the in-progress flag so the user can at least
    // restart the workbench. We don't try to respawn the worker — that
    // requires re-plumbing every job kind and is well outside this
    // panel's scope.
    if !queued {
        state.multi_search.in_progress = false;
        state.multi_search.progress_message =
            "Worker channel closed — restart the workbench.".to_string();
        state.multi_search.progress_updated_at = None;
        state.toasts.error(
            "Worker channel closed — restart the workbench to recover.",
        );
    }
}

/// Reset the multi-format search session to a clean idle state without
/// touching the user's typed query / mode / format set. Intended as the
/// escape hatch for a stuck `in_progress=true` (e.g. a worker thread
/// that died mid-scan, or the user is just confused about which gate
/// they tripped).
///
/// Bumps `request_id` so any straggler replies from the dead scan are
/// dropped by the reply handler. Clears the hit list, error, progress
/// label, and expanded-hit selection. Re-arms the Korean confirm gate
/// so the next click won't accidentally fire an unfiltered scan. Also
/// signals cancellation through the current cancel flag — if the
/// worker is still grinding, this lets it exit at its next iteration
/// boundary so subsequent jobs don't queue behind a phantom scan.
fn reset_session(state: &mut AppState) {
    // Flip the current cancel flag so a still-running worker exits
    // promptly. Subsequent kick_scan calls rotate to a fresh Arc, so
    // this doesn't leak into the next run.
    state
        .multi_search
        .cancel_flag
        .store(true, Ordering::Relaxed);
    state.multi_search.request_id = state.multi_search.request_id.wrapping_add(1);
    state.multi_search.in_progress = false;
    state.multi_search.hits.clear();
    state.multi_search.error = None;
    state.multi_search.progress_message.clear();
    state.multi_search.progress_updated_at = None;
    state.multi_search.expanded_hit = None;
    state.multi_search.confirm_no_filter = false;
    state.toasts.info("Search session reset.");
}

/// Cancel the in-flight scan.
///
/// Flips the shared cancellation flag (`Ordering::Relaxed` is enough —
/// the worker only ever loads it, no read-after-write sequencing needed)
/// so the worker thread bails at its next iteration boundary instead of
/// grinding through the rest of the scan. The request_id bump is
/// retained on top of the flag so any straggler `MultiFormatHit` /
/// `MultiFormatProgress` replies the worker emits before it sees the
/// cancel are filtered by the reply handler. UI state (`in_progress`,
/// progress label, stuck-detector clock) resets immediately so the
/// panel reflects the user's intent without waiting for the terminal
/// `MultiFormatComplete` reply.
fn cancel_scan(state: &mut AppState) {
    // Signal the worker. This MUST happen first so even if the rest
    // of the function panics (it shouldn't, but defence in depth) the
    // background scan still wakes up and exits.
    state
        .multi_search
        .cancel_flag
        .store(true, Ordering::Relaxed);
    state.multi_search.request_id = state.multi_search.request_id.wrapping_add(1);
    state.multi_search.in_progress = false;
    state.multi_search.progress_message = "Cancelled.".to_string();
    // Drop the stuck-detector clock — we're back in idle, there's
    // nothing to measure for staleness.
    state.multi_search.progress_updated_at = None;
}

/// Switch the active view to the right editor for the given hit and,
/// where practical, pre-position the editor on the matched item.
///
/// If a scan is still running, we cancel it before submitting any
/// editor-side load. The worker is single-threaded — without this
/// step the destination editor's `LoadTable` / `load_xml_from_paz` /
/// etc. job sits queued behind the multi-format scan for the rest of
/// the scan's runtime, which can be minutes for the BinaryByte /
/// Korean modes. The user clicked "Open in editor" because they want
/// to inspect the hit *now*; let the search go.
fn jump_to_hit(state: &mut AppState, hit: &MultiFormatHit) {
    if state.multi_search.in_progress {
        cancel_scan(state);
    }
    match &hit.source {
        HitSource::Pabgb {
            dispatch_name,
            entry_idx,
            entry_key,
            ..
        } => {
            // Reuse the existing PABGB jump-to-entry plumbing — focus
            // the tab if open, otherwise submit a load with the
            // pending-xref hook so the entry is selected on arrival.
            state.main_view = MainView::PabgbTables;
            if let Some(idx) = state
                .open_tabs
                .iter()
                .position(|t| &t.dispatch_name == dispatch_name)
            {
                state.active_tab_idx = Some(idx);
                if let Some(tab) = state.open_tabs.get_mut(idx) {
                    if *entry_idx < tab.entries.len() {
                        tab.selected_entry_idx = Some(*entry_idx);
                    }
                }
                return;
            }
            // Not open — submit a load and remember which entry to focus.
            let Some(meta) = state
                .tables
                .iter()
                .find(|m| &m.dispatch_name == dispatch_name)
                .cloned()
            else {
                state.toasts.warn(format!(
                    "Table '{}' isn't in the registry — can't open.",
                    dispatch_name
                ));
                return;
            };
            let Some(game_dir) = state.game_dir.clone() else {
                state.toasts.warn("Set the Game Directory first.");
                return;
            };
            let placeholder =
                crate::state::ActiveTable::placeholder_loading(dispatch_name.clone());
            state.open_tabs.push(placeholder);
            state.active_tab_idx = Some(state.open_tabs.len() - 1);
            state.pending_xref_nav = Some((dispatch_name.clone(), *entry_key));
            state.worker.submit(crate::worker::Job::LoadTable {
                dispatch_name: meta.dispatch_name.clone(),
                game_dir,
                pabgb_filename: meta.pabgb_filename.clone(),
                pabgh_filename: meta.pabgh_filename.clone(),
            });
        }
        HitSource::Paloc { lang, hash_id, .. } => {
            // The PALOC editor consumes `pending_global_nav` on its
            // next draw — sets the language, runs a load if needed,
            // and scrolls the table to the row whose unk_id matches.
            //
            // The worker emits 2-letter codes ("en" / "kr") but the
            // editor's loader keys off the 3-letter ones ("eng" / "kor"
            // / etc.). Translate here so the load doesn't 404.
            let editor_lang = paloc_editor_lang_for_hit(lang).to_string();
            state.pending_global_nav = Some(PendingNav::Paloc {
                lang: editor_lang.clone(),
                hash_id: *hash_id,
            });
            state.main_view = MainView::Paloc;
            state.toasts.info(format!(
                "Opening PALOC editor at {}[{}].",
                editor_lang, hash_id
            ));
        }
        HitSource::Xml {
            paz_group,
            dir_path,
            filename,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::Xml {
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
            });
            state.main_view = MainView::Xml;
            state.toasts.info(format!(
                "Opening XML editor on [{}] {}.",
                paz_group, filename
            ));
        }
        HitSource::Paatt {
            paz_group,
            dir_path,
            filename,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::Paatt {
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
            });
            state.main_view = MainView::Paatt;
            state.toasts.info(format!(
                "Opening PAATT editor on [{}] {}.",
                paz_group, filename
            ));
        }
        HitSource::Paac {
            paz_group,
            dir_path,
            filename,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::Paac {
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
            });
            state.main_view = MainView::Paac;
            state.toasts.info(format!(
                "Opening PAAC editor on [{}] {}.",
                paz_group, filename
            ));
        }
        HitSource::Pappt {
            paz_group,
            dir_path,
            filename,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::Pappt {
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
            });
            state.main_view = MainView::Pappt;
            state.toasts.info(format!(
                "Opening PAPPT editor on [{}] {}.",
                paz_group, filename
            ));
        }
        HitSource::Pamhc {
            paz_group,
            dir_path,
            filename,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::Pamhc {
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
            });
            state.main_view = MainView::Pamhc;
            state.toasts.info(format!(
                "Opening PAMHC editor on [{}] {}.",
                paz_group, filename
            ));
        }
        HitSource::Binary {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::BinaryInspector {
                ext: ext.clone(),
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
                byte_offset: Some(*byte_offset),
            });
            state.main_view = MainView::BinaryInspector;
            state.toasts.info(format!(
                "Opening Binary Inspector on [{}] {} @0x{:X}.",
                paz_group, filename, byte_offset
            ));
        }
        HitSource::JenkinsHash {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            hash,
            case_label,
            ..
        } => {
            // Jenkins-hash hits live in binary files — same editor as
            // a regular Binary hit. Surface the hash + case so the
            // user can correlate it with whatever they were looking
            // for.
            state.pending_global_nav = Some(PendingNav::BinaryInspector {
                ext: ext.clone(),
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
                byte_offset: Some(*byte_offset),
            });
            state.main_view = MainView::BinaryInspector;
            state.toasts.info(format!(
                "Opening Binary Inspector — [{}] {} @0x{:X}, hash=0x{:08X} ({}).",
                paz_group, filename, byte_offset, hash, case_label
            ));
        }
        HitSource::HexPattern {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            pattern_len,
            ..
        } => {
            state.pending_global_nav = Some(PendingNav::BinaryInspector {
                ext: ext.clone(),
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
                byte_offset: Some(*byte_offset),
            });
            state.main_view = MainView::BinaryInspector;
            state.toasts.info(format!(
                "Opening Binary Inspector — [{}] {} @0x{:X} ({}B pattern).",
                paz_group, filename, byte_offset, pattern_len
            ));
        }
        HitSource::KoreanString {
            ext,
            paz_group,
            dir_path,
            filename,
            byte_offset,
            encoding,
            ..
        } => {
            // Korean-string hits live in binary files — same editor
            // as a regular Binary hit. Surface the encoding label so
            // the user can correlate the hex dump with the decoded
            // string they were browsing.
            let enc_label = match encoding {
                KoreanEncoding::Utf8 => "UTF-8",
                KoreanEncoding::Utf16Le => "UTF-16 LE",
            };
            state.pending_global_nav = Some(PendingNav::BinaryInspector {
                ext: ext.clone(),
                paz_group: paz_group.clone(),
                dir_path: dir_path.clone(),
                filename: filename.clone(),
                byte_offset: Some(*byte_offset),
            });
            state.main_view = MainView::BinaryInspector;
            state.toasts.info(format!(
                "Opening Binary Inspector — [{}] {} @0x{:X} ({} CJK run).",
                paz_group, filename, byte_offset, enc_label
            ));
        }
    }
}

/// Translate the worker's short PALOC language code (`"en"` / `"kr"`,
/// what `Localization::load_or_build` keys its `eng` and `kor` maps as)
/// into the 3-letter code the editor's loader expects (`"eng"` /
/// `"kor"` — see [`crate::paloc_editor::LANGUAGES`]).
///
/// Anything unknown passes through verbatim — current scans only emit
/// the two codes above, but a future expansion adding e.g. `"jp"` /
/// `"de"` shouldn't crash the jump just because the helper is missing
/// a row.
fn paloc_editor_lang_for_hit(short: &str) -> &str {
    match short {
        "en" => "eng",
        "kr" => "kor",
        other => other,
    }
}

/// Parse a user-typed number — same shape as the entry table's helper
/// (`123`, `0xABCD`). Returns `None` for anything that isn't a clean
/// decimal or hex literal.
fn parse_user_number(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if rest.is_empty() {
            return None;
        }
        return u64::from_str_radix(rest, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

// `MultiFormatSearchSession` lives on `AppState`, so this panel only
// touches state via the `state.multi_search` field. The struct itself
// is referenced here purely to keep the import noise small.
#[allow(dead_code)]
fn _unused_typeref(_: &MultiFormatSearchSession) {}

/// Rotate the session's cancellation flag to a fresh `Arc`. Pulled
/// out of [`kick_scan`] so the rotation invariant is unit-testable
/// without standing up a full [`AppState`].
///
/// The previous `cancel_flag` may or may not be flipped to `true` —
/// either way we drop our reference and install a brand-new one with
/// flag=false. That guarantees a stale cancel can't short-circuit the
/// next scan, and the worker for the previous scan (still alive
/// somewhere in the loop checking *its* clone of the old Arc) keeps
/// seeing the cancel signal until it exits naturally.
fn rotate_cancel_flag(session: &mut MultiFormatSearchSession) -> Arc<AtomicBool> {
    session.cancel_flag = Arc::new(AtomicBool::new(false));
    Arc::clone(&session.cancel_flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_number_basic() {
        assert_eq!(parse_user_number(""), None);
        assert_eq!(parse_user_number(" 42 "), Some(42));
        assert_eq!(parse_user_number("0x10"), Some(16));
        assert_eq!(parse_user_number("0X10"), Some(16));
        assert_eq!(parse_user_number("0x"), None);
        assert_eq!(parse_user_number("notanumber"), None);
    }

    #[test]
    fn paloc_editor_lang_for_hit_translates_short_codes() {
        // The worker emits 2-letter codes; the editor expects 3-letter.
        assert_eq!(paloc_editor_lang_for_hit("en"), "eng");
        assert_eq!(paloc_editor_lang_for_hit("kr"), "kor");
        // Unknown codes pass through verbatim so a future expansion
        // doesn't silently swallow the request.
        assert_eq!(paloc_editor_lang_for_hit("jp"), "jp");
        assert_eq!(paloc_editor_lang_for_hit(""), "");
    }

    #[test]
    fn is_korean_format_only_binary_byte() {
        // KoreanStrings mode walks the binary inspector allow-list
        // directly — only `BinaryByte` is meaningful. Every other
        // SearchFormat variant must report false so the UI greys
        // them out and the All / Fast-only buttons don't tick them.
        assert!(is_korean_format(SearchFormat::BinaryByte));
        assert!(!is_korean_format(SearchFormat::Pabgb));
        assert!(!is_korean_format(SearchFormat::Paloc));
        assert!(!is_korean_format(SearchFormat::Xml));
        assert!(!is_korean_format(SearchFormat::Paatt));
        assert!(!is_korean_format(SearchFormat::Paac));
        assert!(!is_korean_format(SearchFormat::Pappt));
        assert!(!is_korean_format(SearchFormat::Pamhc));
    }

    /// Rotation contract for [`rotate_cancel_flag`] — invoked by
    /// `kick_scan` before each `Job::MultiFormatSearch` submit.
    ///
    /// The session's `cancel_flag` field MUST be replaced with a brand
    /// new `Arc<AtomicBool>` whose value is `false`, even when the
    /// previous flag was flipped to `true`. Without this, a click on
    /// Cancel followed by a fresh Run would short-circuit instantly:
    /// the worker would see the stale `true` at its first check and
    /// emit a zero-hit `MultiFormatComplete` before doing any work.
    ///
    /// We assert both halves: pointer identity (the new Arc is not the
    /// same allocation as the prior one) and value (the new flag is
    /// `false`). Pointer identity via `Arc::ptr_eq` is the strict
    /// guarantee — `Arc::strong_count` checks would be racy if the
    /// worker thread were holding its own clone.
    #[test]
    fn kick_scan_replaces_cancel_flag() {
        let mut session = MultiFormatSearchSession::default();
        // Hold a clone of the original Arc so we can compare pointer
        // identity after the rotation. This simulates a worker thread
        // that's still alive and holding its copy when the user
        // clicks Run again.
        let original = Arc::clone(&session.cancel_flag);
        // Simulate the user clicking Cancel between runs — flips the
        // shared flag through the original Arc.
        original.store(true, Ordering::Relaxed);
        assert!(
            session.cancel_flag.load(Ordering::Relaxed),
            "precondition: the cancel flag is observable via the session before rotation"
        );

        let new_clone = rotate_cancel_flag(&mut session);

        // The session's flag must be a different allocation now.
        assert!(
            !Arc::ptr_eq(&session.cancel_flag, &original),
            "rotation must install a fresh Arc — same allocation would let stale cancel leak forward"
        );
        // The new flag must be false so the next scan starts with a
        // clean signal.
        assert!(
            !session.cancel_flag.load(Ordering::Relaxed),
            "rotated cancel flag must be false so the next scan can run"
        );
        // The clone we hand the worker must point at the same fresh
        // allocation as the session — that's the channel the UI will
        // use to cancel the next run.
        assert!(
            Arc::ptr_eq(&session.cancel_flag, &new_clone),
            "the clone returned to the caller must be the same Arc the session holds"
        );
        // The original Arc must still report flipped (we never touched
        // it). A worker thread still holding `original` keeps seeing
        // the cancel signal until it exits.
        assert!(
            original.load(Ordering::Relaxed),
            "previous cancel flag must remain flipped — the running worker depends on it"
        );
    }
}
