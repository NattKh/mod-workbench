use std::io;
use std::path::Path;

use dmm_parser_rust_only::binary::pamt::{Compression, CryptoType, PackMeta};
use dmm_parser_rust_only::binary::papgt::{LanguageType, PackGroupTreeMeta};
use dmm_parser_rust_only::binary::paz::PackGroupBuilder;

use crate::backup;
use crate::state::TableMeta;

const GAME_DATA_DIR: &str = "gamedata/binary__/client/bin";

/// How many snapshots we keep around after a successful deploy. Older
/// snapshots beyond this count are pruned automatically so the backups dir
/// can't grow without bound.
const SNAPSHOT_RETAIN_COUNT: usize = 20;

/// Deploy a modified table into the game as a PAZ overlay.
///
/// Steps:
/// 0. Auto-snapshot the current `meta/0.papgt` and overlay group to the
///    user data backups directory. Snapshot failures are logged but do
///    not abort the deploy — losing one backup is less bad than losing
///    the user's actual edit.
/// 1. Serialize entries back to pabgb bytes via dmm_parser_rust_only
/// 2. Build a PAZ overlay in the specified overlay group directory
/// 3. Update the PAPGT to include the new overlay group
/// 4. Prune old snapshots beyond [`SNAPSHOT_RETAIN_COUNT`].
pub fn deploy(
    game_dir: &Path,
    table_name: &str,
    meta: &TableMeta,
    entries: &[serde_json::Value],
    overlay_group: &str,
) -> io::Result<()> {
    // Step 0 — pre-deploy snapshot (best effort; non-fatal on failure).
    let label = format!("Pre-deploy: {}", table_name);
    let _snapshot = backup::create_snapshot(game_dir, overlay_group, &label)
        .map_err(|e| eprintln!("backup: pre-deploy snapshot failed: {}", e))
        .ok();

    // Serialize entries to pabgb bytes. iteminfo lives outside the generic
    // dispatch (see `table_loader::load_iteminfo`) so we route it through
    // its dedicated serializer here as well.
    let pabgb_bytes = if table_name == "item_info" {
        dmm_parser_rust_only::item_info::serialize_iteminfo_from_json(entries)?
    } else {
        dmm_parser_rust_only::serialize_table_from_json(table_name, entries)?
    };

    // Build the overlay directory
    let overlay_dir = game_dir.join(overlay_group);
    std::fs::create_dir_all(&overlay_dir)?;

    // Read the original PAMT from group 0008 to get encrypt_info
    let orig_pamt_data = std::fs::read(game_dir.join("0008/0.pamt"))?;
    let orig_pamt = PackMeta::parse(&orig_pamt_data, None)?;
    let encrypt_info = orig_pamt.header.encrypt_info.encrypt_info;

    // Build PAZ overlay using PackGroupBuilder with NO compression
    // (pabgh files must not be LZ4-compressed -- they inflate and the game rejects them)
    let mut builder = PackGroupBuilder::new(
        &overlay_dir,
        Compression::None,
        CryptoType::ChaCha20,
        encrypt_info,
        256 * 1024 * 1024, // 256MB max chunk
    );

    // Add the pabgb file
    builder.add_file(GAME_DATA_DIR, &meta.pabgb_filename, &pabgb_bytes)?;

    // If the table has a pabgh, we need to rebuild it from the serialized body.
    // For now, extract the original pabgh and add it unchanged -- the entry offsets
    // only change if entries are added/removed, which the workbench doesn't do yet.
    if let Some(ref pabgh_name) = meta.pabgh_filename {
        if let Ok(pabgh_bytes) = extract_original_pabgh(game_dir, pabgh_name, &encrypt_info) {
            // pabgh MUST use Compression::None to avoid LZ4 inflation
            builder.add_file_with_compression(
                GAME_DATA_DIR,
                pabgh_name,
                &pabgh_bytes,
                Compression::None,
            )?;
        }
    }

    // Finish building -- writes .paz and 0.pamt to overlay_dir
    let pamt_bytes = builder.finish()?;

    // Compute the PAMT checksum for the PAPGT entry
    // The checksum covers post-header data (everything after the 10-byte header)
    let pamt = PackMeta::parse(&pamt_bytes, None)?;
    let pamt_checksum = pamt.header.checksum;

    // Backup and update PAPGT
    let papgt_path = game_dir.join("meta/0.papgt");
    let papgt_backup = game_dir.join("meta/0.papgt.workbench_backup");
    if !papgt_backup.exists() {
        std::fs::copy(&papgt_path, &papgt_backup)?;
    }

    let papgt_data = std::fs::read(&papgt_path)?;
    let mut papgt = PackGroupTreeMeta::parse(&papgt_data)?;

    // Add overlay entry at front (takes priority over vanilla)
    papgt.add_entry(
        overlay_group,
        pamt_checksum,
        1, // is_optional = 1 (mod overlay)
        LanguageType::ALL,
    );

    let papgt_bytes = papgt.to_bytes()?;
    std::fs::write(&papgt_path, &papgt_bytes)?;

    // Step 4 — prune old snapshots. Errors here are non-fatal: the deploy
    // itself succeeded, and the backups directory just having one extra
    // snapshot is harmless.
    if let Err(e) = backup::cleanup_old_snapshots(SNAPSHOT_RETAIN_COUNT) {
        eprintln!("backup: snapshot cleanup failed: {}", e);
    }

    Ok(())
}

/// Extract the original pabgh file from group 0008.
fn extract_original_pabgh(
    game_dir: &Path,
    pabgh_name: &str,
    encrypt_info: &[u8; 3],
) -> io::Result<Vec<u8>> {
    use dmm_parser_rust_only::binary::paz;

    let group_dir = game_dir.join("0008");
    let pamt_data = std::fs::read(group_dir.join("0.pamt"))?;
    let pamt = PackMeta::parse(&pamt_data, None)?;

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

    let file = dir
        .files
        .iter()
        .find(|f| f.name == pabgh_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("File '{}' not found in {}", pabgh_name, GAME_DATA_DIR),
            )
        })?;

    paz::extract_file(&group_dir, file, GAME_DATA_DIR, encrypt_info)
}
