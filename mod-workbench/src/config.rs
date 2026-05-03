use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_RECENT_MODS: usize = 5;

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
    pub game_dir: Option<PathBuf>,
    pub catalog_path: Option<PathBuf>,
    pub window_size: Option<(f32, f32)>,
    pub left_panel_width: Option<f32>,
    pub right_panel_width: Option<f32>,
    pub theme: Option<String>, // "dark" | "light" | "crimson"
    pub last_table: Option<String>,
    #[serde(default)]
    pub recent_mods: Vec<PathBuf>, // most recent 5
    /// How many deploy snapshots to retain. `None` falls back to the
    /// hard-coded default in `deploy.rs`. Configurable via the Settings
    /// panel so power users can crank it up.
    #[serde(default)]
    pub snapshot_retention: Option<usize>,
}

impl Config {
    /// Load config from disk, returning a default Config on any error
    /// (missing file, parse failure, no home dir, etc).
    pub fn load() -> Self {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Self::default(),
        };

        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("config: read {} failed: {}", path.display(), e);
                }
                return Self::default();
            }
        };

        match toml::from_str(&data) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("config: parse {} failed: {}", path.display(), e);
                Self::default()
            }
        }
    }

    /// Persist config to disk. Silent on errors (logged via eprintln!) so a
    /// failure here never breaks the app.
    pub fn save(&self) -> std::io::Result<()> {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Ok(()),
        };

        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("config: mkdir {} failed: {}", parent.display(), e);
                return Err(e);
            }
        }

        let serialized = match toml::to_string(self) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("config: serialize failed: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        };

        if let Err(e) = std::fs::write(&path, serialized) {
            eprintln!("config: write {} failed: {}", path.display(), e);
            return Err(e);
        }

        Ok(())
    }

    /// Resolved config file path under
    /// `%APPDATA%\Crimson\ModWorkbench\config.toml` on Windows
    /// (or the platform-equivalent dir). Returns `None` if no home dir
    /// exists, in which case `load`/`save` become no-ops.
    pub fn config_path() -> Option<PathBuf> {
        let dirs = ProjectDirs::from("com", "Crimson", "ModWorkbench")?;
        Some(dirs.config_dir().join("config.toml"))
    }

    /// Insert `path` at the front of recent_mods, dedup, capped at 5 entries.
    pub fn add_recent_mod(&mut self, path: PathBuf) {
        self.recent_mods.retain(|p| p != &path);
        self.recent_mods.insert(0, path);
        if self.recent_mods.len() > MAX_RECENT_MODS {
            self.recent_mods.truncate(MAX_RECENT_MODS);
        }
    }
}
