//! CJK font loading.
//!
//! egui's default font set (Ubuntu Mono / Hack / NotoEmoji) has no CJK glyphs,
//! so Korean / Japanese / Chinese text in the game data renders as missing-glyph
//! boxes. This module loads system CJK fonts at startup so Hangul / Kana / Hanzi
//! display correctly in tables, field editors, tooltips, and toasts.
//!
//! Strategy on Windows: probe `C:\Windows\Fonts` for known CJK font files and
//! register the first set we find as fallbacks under both Proportional and
//! Monospace families. We don't replace the default Latin font — the new fonts
//! sit *after* the defaults so ASCII still renders with the egui defaults and
//! falls through to CJK only when the default font has no glyph for a code
//! point.
//!
//! On non-Windows we skip gracefully; CJK rendering will revert to boxes but
//! the app still runs.

use std::fs;
use std::path::PathBuf;

/// Paths to system CJK fonts on Windows. Ordered from "best general coverage"
/// (Malgun Gothic — Korean primary, full CJK Unified Ideographs) downward.
///
/// We register multiple so a glyph missing from the first font still gets
/// resolved by the next one in the family list.
#[cfg(target_os = "windows")]
const WINDOWS_CJK_CANDIDATES: &[&str] = &[
    // Korean — primary target since Crimson Desert is a Korean game and most
    // raw strings in the data are Hangul.
    r"C:\Windows\Fonts\malgun.ttf",
    // Japanese fallback for any Kana / Kanji that Malgun doesn't carry.
    r"C:\Windows\Fonts\YuGothR.ttc",
    // Chinese fallback — covers the rest of CJK Unified Ideographs.
    r"C:\Windows\Fonts\simsun.ttc",
];

#[cfg(not(target_os = "windows"))]
const WINDOWS_CJK_CANDIDATES: &[&str] = &[];

/// Result of attempting to load CJK fonts. Reported back to the UI so we can
/// surface success/failure in a visible toast (eprintln! goes nowhere on a
/// Windows GUI binary).
pub struct CjkLoadReport {
    pub installed: Vec<String>,
    pub errors: Vec<String>,
}

/// Load any available CJK fonts from the system into the egui context.
///
/// Call once during app startup, after `cc.egui_ctx` is available. Errors are
/// captured into the report so the caller can display them; a missing font
/// shouldn't crash the app, it just degrades to box-glyphs for the affected
/// scripts.
///
/// Implementation notes (egui 0.31):
/// - `font_data` map values are `Arc<FontData>`; we wrap explicitly so the
///   conversion can't silently pick the wrong impl.
/// - We INSERT the CJK font as the first entry in each family vector (not
///   append). egui resolves glyphs by walking the family vec in order; the
///   default Proportional font has zero CJK glyphs, so if it sits ahead of
///   our font we'd never reach the fallback. Putting CJK first means ASCII
///   still renders fine (Malgun Gothic has all of Basic Latin) and Hangul
///   resolves immediately too.
/// - `.ttc` (TrueType Collection) files contain multiple faces. egui's font
///   pipeline (ab_glyph) accepts a "face index" via FontTweak / via the
///   font_data structure in newer egui, but in 0.31 we set the index via
///   `FontData::tweak.face_index`. Most .ttc files we use here have face 0
///   = the regular weight which is what we want.
pub fn install_cjk_fonts(ctx: &egui::Context) -> CjkLoadReport {
    let mut report = CjkLoadReport {
        installed: Vec::new(),
        errors: Vec::new(),
    };
    let mut fonts = egui::FontDefinitions::default();
    let mut new_keys: Vec<String> = Vec::new();

    for path_str in WINDOWS_CJK_CANDIDATES {
        let path = PathBuf::from(path_str);
        if !path.exists() {
            report
                .errors
                .push(format!("not found: {}", path.display()));
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                report
                    .errors
                    .push(format!("read failed for {}: {}", path.display(), e));
                continue;
            }
        };

        let key = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("cjk_fallback")
            .to_string();

        // Build FontData; ttc face index 0 = Regular for the families we use.
        let mut font_data = egui::FontData::from_owned(bytes);
        font_data.tweak.scale = 1.0;
        let arc_data = std::sync::Arc::new(font_data);
        fonts.font_data.insert(key.clone(), arc_data);

        new_keys.push(key);
    }

    if new_keys.is_empty() {
        return report;
    }

    // Prepend the CJK keys to each family so the resolver finds them BEFORE
    // the default font that lacks CJK coverage. We still keep the existing
    // entries afterward as fallbacks for emoji / icon fonts.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        let entry = fonts.families.entry(family).or_default();
        // Insert in reverse so the first listed candidate ends up at index 0.
        for key in new_keys.iter().rev() {
            entry.insert(0, key.clone());
        }
    }

    ctx.set_fonts(fonts);
    report.installed = new_keys;
    report
}
