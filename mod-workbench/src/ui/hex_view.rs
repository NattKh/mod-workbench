//! Hex editor view fallback.
//!
//! Renders raw pabgb bytes in a paged hex layout: 16 bytes per row, offset
//! column on the left, ASCII gutter on the right. Used as a fallback when
//! a table fails to parse, or as an opt-in "Show Hex" toggle for any loaded
//! table when users want byte-level inspection without leaving the app.
//!
//! Editing is intentionally NOT supported here — egui makes byte-level
//! cursor tracking expensive and the field panel already handles typed
//! edits. The hex view is read-only by design.

/// Per-table hex view state. Lives on [`crate::state::ActiveTable`] so that
/// switching tabs preserves each table's page position independently.
#[derive(Clone)]
pub struct HexViewState {
    /// Currently displayed page, zero-indexed.
    pub page: usize,
    /// Number of bytes shown per page. Defaults to 1024 (64 rows × 16
    /// bytes). Configurable so future code can resize for very large /
    /// very small tables, but the UI doesn't expose this in v1.
    pub bytes_per_page: usize,
    /// Selected byte offset (relative to the start of the underlying
    /// `bytes` slice). `None` until the user clicks a row. Surfaced in
    /// the side panel's status label so users can read the offset and
    /// the byte at it.
    pub selected_offset: Option<usize>,
}

impl Default for HexViewState {
    fn default() -> Self {
        Self {
            page: 0,
            bytes_per_page: 1024,
            selected_offset: None,
        }
    }
}

/// Render the hex viewer for `bytes`. Caller owns `state` and is
/// responsible for keeping it across frames.
pub fn show(ui: &mut egui::Ui, bytes: &[u8], state: &mut HexViewState) {
    if bytes.is_empty() {
        ui.label(
            egui::RichText::new("(no bytes loaded for this table yet)")
                .color(egui::Color32::from_gray(160)),
        );
        return;
    }

    let total_pages = total_pages(bytes.len(), state.bytes_per_page);
    if state.page >= total_pages {
        state.page = total_pages.saturating_sub(1);
    }

    page_navigation_bar(ui, state, total_pages, bytes.len());

    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);

    page_grid(ui, bytes, state);

    ui.add_space(4.0);
    ui.separator();

    selection_status_label(ui, bytes, state);
}

fn total_pages(byte_count: usize, bytes_per_page: usize) -> usize {
    if bytes_per_page == 0 {
        return 1;
    }
    (byte_count + bytes_per_page - 1) / bytes_per_page
}

fn page_navigation_bar(
    ui: &mut egui::Ui,
    state: &mut HexViewState,
    total_pages: usize,
    total_bytes: usize,
) {
    ui.horizontal(|ui| {
        let at_first = state.page == 0;
        let at_last = state.page + 1 >= total_pages;

        if ui
            .add_enabled(!at_first, egui::Button::new("|< First"))
            .clicked()
        {
            state.page = 0;
        }
        if ui
            .add_enabled(!at_first, egui::Button::new("< Prev"))
            .clicked()
        {
            state.page = state.page.saturating_sub(1);
        }
        if ui
            .add_enabled(!at_last, egui::Button::new("Next >"))
            .clicked()
        {
            state.page += 1;
        }
        if ui
            .add_enabled(!at_last, egui::Button::new("Last >|"))
            .clicked()
        {
            state.page = total_pages.saturating_sub(1);
        }

        ui.separator();
        ui.label(format!(
            "Page {}/{} — {} bytes total",
            state.page + 1,
            total_pages.max(1),
            total_bytes
        ));

        let page_start = state.page * state.bytes_per_page;
        let page_end = (page_start + state.bytes_per_page).min(total_bytes);
        ui.label(format!(
            "Range 0x{:08X} – 0x{:08X}",
            page_start,
            page_end.saturating_sub(1)
        ));
    });
}

fn page_grid(ui: &mut egui::Ui, bytes: &[u8], state: &mut HexViewState) {
    let page_start = state.page * state.bytes_per_page;
    let page_end = (page_start + state.bytes_per_page).min(bytes.len());
    let page_bytes = &bytes[page_start..page_end];

    // Build the entire page as a single monospace string so egui's
    // virtualization stays cheap. Each row is laid out as
    // "OFFSET  HH HH HH ... HH  AAAA" so it lines up under a fixed-width
    // font without needing per-cell layout.
    let mut text = String::with_capacity(page_bytes.len() * 4 + 16);
    for (row_idx, chunk) in page_bytes.chunks(16).enumerate() {
        let row_offset = page_start + row_idx * 16;
        text.push_str(&format!("{:08X}  ", row_offset));
        for i in 0..16 {
            if i == 8 {
                text.push(' '); // mid-row spacer for readability
            }
            if i < chunk.len() {
                text.push_str(&format!("{:02X} ", chunk[i]));
            } else {
                text.push_str("   ");
            }
        }
        text.push(' ');
        for &b in chunk {
            text.push(printable(b));
        }
        text.push('\n');
    }

    // Read-only TextEdit gives us monospace rendering + selectable text
    // for free, without dragging in a custom layouter.
    egui::ScrollArea::both()
        .id_salt("hex_view_page")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text.as_str())
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(32),
            );
        });

    // Lightweight "click an offset to select" mechanism. We render a
    // small header form below the grid so the user can type the absolute
    // offset they care about; mouse-clicking individual bytes inside a
    // monospace TextEdit isn't reliable across egui platforms, and per
    // task spec we just need offset+byte info, not pointer selection.
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Inspect offset (hex):");
        let mut input = state
            .selected_offset
            .map(|o| format!("{:X}", o))
            .unwrap_or_default();
        let response = ui.add(
            egui::TextEdit::singleline(&mut input)
                .desired_width(120.0)
                .hint_text("e.g. 1A0"),
        );
        if response.changed() {
            let trimmed = input.trim().trim_start_matches("0x");
            if trimmed.is_empty() {
                state.selected_offset = None;
            } else if let Ok(off) = usize::from_str_radix(trimmed, 16) {
                if off < bytes.len() {
                    state.selected_offset = Some(off);
                    state.page = off / state.bytes_per_page;
                }
            }
        }
    });
}

fn selection_status_label(ui: &mut egui::Ui, bytes: &[u8], state: &HexViewState) {
    match state.selected_offset {
        Some(off) if off < bytes.len() => {
            let b = bytes[off];
            ui.label(format!(
                "Selected offset 0x{:08X} ({}): byte = 0x{:02X} ({}) ({:#010b})",
                off,
                off,
                b,
                printable_label(b),
                b,
            ));
        }
        _ => {
            ui.label(
                egui::RichText::new("(no offset selected — type an offset above)")
                    .color(egui::Color32::from_gray(160)),
            );
        }
    }
}

fn printable(b: u8) -> char {
    if (0x20..0x7F).contains(&b) {
        b as char
    } else {
        '.'
    }
}

fn printable_label(b: u8) -> String {
    if (0x20..0x7F).contains(&b) {
        format!("'{}'", b as char)
    } else {
        ".".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_pages_basic() {
        assert_eq!(total_pages(0, 1024), 0);
        assert_eq!(total_pages(1, 1024), 1);
        assert_eq!(total_pages(1024, 1024), 1);
        assert_eq!(total_pages(1025, 1024), 2);
        assert_eq!(total_pages(2048, 1024), 2);
        assert_eq!(total_pages(2049, 1024), 3);
    }

    #[test]
    fn printable_filters_control_bytes() {
        assert_eq!(printable(0x00), '.');
        assert_eq!(printable(0x1F), '.');
        assert_eq!(printable(0x20), ' ');
        assert_eq!(printable(b'A'), 'A');
        assert_eq!(printable(0x7E), '~');
        assert_eq!(printable(0x7F), '.');
    }

    #[test]
    fn default_state_is_safe_at_zero_bytes() {
        let mut state = HexViewState::default();
        assert_eq!(state.page, 0);
        assert_eq!(state.bytes_per_page, 1024);
        assert_eq!(state.selected_offset, None);
        // Show should clamp page if the data shrinks.
        let bytes: &[u8] = &[];
        // We can't render egui in unit tests, but we can call total_pages
        // through to confirm no panic on zero bytes.
        assert_eq!(total_pages(bytes.len(), state.bytes_per_page), 0);
    }
}
