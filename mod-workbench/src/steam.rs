//! Steam game directory auto-detection.
//!
//! Walks Steam library folders to find the Crimson Desert install. The flow is:
//!  1. Read Steam install path from the Windows registry.
//!  2. Parse `steamapps/libraryfolders.vdf` to enumerate every Steam library.
//!  3. For each library, check if `steamapps/common/Crimson Desert` exists.
//!  4. Validate that the candidate path contains `meta/0.papgt`.
//!
//! On non-Windows platforms the registry read is a no-op and detection falls
//! back to the hardcoded paths only.
//!
//! Used by `state::AppState::new()` to auto-populate the game directory on
//! first launch.

use std::path::{Path, PathBuf};

/// Hardcoded fallback paths to probe if registry / VDF parsing yields nothing.
const FALLBACK_PATHS: &[&str] = &[
    r"C:\Program Files (x86)\Steam\steamapps\common\Crimson Desert",
    r"C:\Program Files\Steam\steamapps\common\Crimson Desert",
    r"D:\SteamLibrary\steamapps\common\Crimson Desert",
];

/// Try to find the Crimson Desert install directory by walking Steam libraries.
///
/// Returns `Some(path)` only if `path/meta/0.papgt` exists (validates it's a
/// real install and not just an empty leftover folder).
pub fn detect_crimson_desert() -> Option<PathBuf> {
    // 1. Registry-driven Steam path -> libraryfolders.vdf -> per-library probe.
    if let Some(steam_path) = read_steam_install_path() {
        for library in read_library_folders(&steam_path) {
            if let Some(found) = check_library(&library) {
                return Some(found);
            }
        }
    }

    // 2. Hardcoded fallbacks (covers non-Windows dev and unusual installs).
    for raw in FALLBACK_PATHS {
        let candidate = PathBuf::from(raw);
        if is_valid_install(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Read the Steam install path from the Windows registry.
///
/// Reads `HKLM\SOFTWARE\WOW6432Node\Valve\Steam -> InstallPath`. Returns
/// `None` on non-Windows platforms or if the key is missing.
#[cfg(target_os = "windows")]
fn read_steam_install_path() -> Option<PathBuf> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags(r"SOFTWARE\WOW6432Node\Valve\Steam", KEY_READ)
        .ok()?;
    let path: String = key.get_value("InstallPath").ok()?;
    Some(PathBuf::from(path))
}

#[cfg(not(target_os = "windows"))]
fn read_steam_install_path() -> Option<PathBuf> {
    None
}

/// Parse `steamapps/libraryfolders.vdf` to get all Steam library paths.
///
/// VDF is a simple key/value format. We just scan for lines containing a
/// `"path"` key followed by a quoted value and pull out every match. The Steam
/// install itself is always included (its own steamapps folder is implicit).
fn read_library_folders(steam_path: &Path) -> Vec<PathBuf> {
    let mut libraries = Vec::new();

    // The Steam install path is itself a library.
    libraries.push(steam_path.to_path_buf());

    let vdf_path = steam_path.join("steamapps").join("libraryfolders.vdf");
    let text = match std::fs::read_to_string(&vdf_path) {
        Ok(t) => t,
        Err(_) => return libraries,
    };

    // Match lines like:  `\t\t"path"\t\t"C:\\SteamLibrary"`
    // We don't have the regex crate available, so do a simple manual scan:
    // for each line, trim, check it starts with `"path"`, then take the second
    // quoted string on the line.
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("\"path\"") {
            continue;
        }
        // Find the second pair of quotes (the first is the "path" key).
        let after_key = &trimmed["\"path\"".len()..];
        let Some(open) = after_key.find('"') else {
            continue;
        };
        let rest = &after_key[open + 1..];
        let Some(close) = rest.find('"') else {
            continue;
        };
        let raw = &rest[..close];
        // VDF escapes backslashes as `\\` — un-escape them for filesystem use.
        let unescaped = raw.replace("\\\\", "\\");
        let path = PathBuf::from(unescaped);
        if !libraries.contains(&path) {
            libraries.push(path);
        }
    }

    libraries
}

/// Check if a Steam library contains a valid Crimson Desert install.
fn check_library(library_path: &Path) -> Option<PathBuf> {
    let candidate = library_path
        .join("steamapps")
        .join("common")
        .join("Crimson Desert");
    if is_valid_install(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// A path is a Crimson Desert install only if `path/meta/0.papgt` exists.
fn is_valid_install(path: &Path) -> bool {
    path.join("meta").join("0.papgt").exists()
}
