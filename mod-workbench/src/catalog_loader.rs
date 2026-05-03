//! Thin wrapper around [`crate::catalog::Catalog::load`] so the rest of the
//! app has a single place to update when we move catalog loading off the UI
//! thread (see ROADMAP 1.3 / 1.9).
//!
//! Today this is purely synchronous; in a later sprint this module is the
//! intended seam for spawning a background worker, deserializing a cached
//! `bincode` blob, etc.

use std::path::Path;

use crate::catalog::Catalog;

/// Load the catalog from a JSON path. Errors propagate from the underlying
/// file IO + JSON parse.
pub fn try_load(path: &Path) -> std::io::Result<Catalog> {
    Catalog::load(path)
}
