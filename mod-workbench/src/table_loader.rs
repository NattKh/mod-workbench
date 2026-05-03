use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::pamt::PackMeta;
use dmm_parser_rust_only::binary::paz;

use crate::state::TableMeta;

const GAME_DATA_DIR: &str = "gamedata/binary__/client/bin";

/// Load a table's entries from the game's PAZ archives.
///
/// Reads the pabgb (and optionally pabgh) from PAZ group 0008, then parses
/// via dmm_parser_rust_only's dispatch layer.
pub fn load_table(
    game_dir: &Path,
    meta: &TableMeta,
) -> io::Result<Vec<serde_json::Value>> {
    let group_dir = game_dir.join("0008");
    let pamt_path = group_dir.join("0.pamt");

    let pamt_data = std::fs::read(&pamt_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("Cannot read PAMT at {}: {}", pamt_path.display(), e),
        )
    })?;
    let pamt = PackMeta::parse(&pamt_data, None)?;

    // Find the directory entry for game data binaries
    let dir = pamt
        .directories
        .iter()
        .find(|d| d.path == GAME_DATA_DIR)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory '{}' not found in 0008/0.pamt", GAME_DATA_DIR),
            )
        })?;

    // Extract pabgb
    let pabgb_file = dir
        .files
        .iter()
        .find(|f| f.name == meta.pabgb_filename)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "File '{}' not found in {}",
                    meta.pabgb_filename, GAME_DATA_DIR
                ),
            )
        })?;

    let pabgb_bytes = paz::extract_file(
        &group_dir,
        pabgb_file,
        GAME_DATA_DIR,
        &pamt.header.encrypt_info.encrypt_info,
    )?;

    // Extract pabgh if the table has one
    let pabgh_bytes = if let Some(ref pabgh_name) = meta.pabgh_filename {
        dir.files
            .iter()
            .find(|f| f.name == *pabgh_name)
            .map(|pabgh_file| {
                paz::extract_file(
                    &group_dir,
                    pabgh_file,
                    GAME_DATA_DIR,
                    &pamt.header.encrypt_info.encrypt_info,
                )
            })
            .transpose()?
    } else {
        None
    };

    dmm_parser_rust_only::parse_table_to_json(
        &meta.dispatch_name,
        &pabgb_bytes,
        pabgh_bytes.as_deref(),
    )
}
