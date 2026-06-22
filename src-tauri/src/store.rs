// Persistent storage layout under the user's config dir or portable folder:
//   <PORTABLE_DIR>/
//     profiles/                   ← fingerprint profile JSON files
//     proxies.json                ← saved proxy list
//     user-data/<profile-id>/     ← per-profile user-data-dir for ShardX
//     settings.json               ← global app settings

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn config_root() -> Result<PathBuf> {
    // 1. Check if there is a portable mode configuration next to the launcher EXE.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let config_marker = exe_dir.join("portable_config.txt");
            if config_marker.exists() {
                if let Ok(saved_path) = std::fs::read_to_string(&config_marker) {
                    let trimmed = saved_path.trim();
                    if !trimmed.is_empty() {
                        let portable_root = PathBuf::from(trimmed);
                        // If the folder is not on the disk/flash drive, create it
                        if !portable_root.exists() {
                            std::fs::create_dir_all(&portable_root)?;
                        }
                        return Ok(portable_root); // All data will now be saved here!
                    }
                }
            }
        }
    }

    // 2. If there is no configuration file, we use the standard mode via system Roaming.
    let base = dirs::config_dir().context("OS config dir unavailable")?;
    let root = base.join("shardx-launcher");
    if !root.exists() {
        std::fs::create_dir_all(&root)?;
    }
    Ok(root)
}

pub fn profiles_dir() -> Result<PathBuf> {
    let p = config_root()?.join("profiles");
    if !p.exists() {
        std::fs::create_dir_all(&p)?;
    }
    Ok(p)
}

pub fn fingerprints_dir() -> Result<PathBuf> {
    let p = config_root()?.join("fingerprints");
    if !p.exists() {
        std::fs::create_dir_all(&p)?;
    }
    Ok(p)
}

/// Cached Widevine CDM, seeded from a host Chrome install
pub fn widevine_cache_dir() -> Result<PathBuf> {
    let p = config_root()?.join("widevine-cdm");
    if !p.exists() {
        std::fs::create_dir_all(&p)?;
    }
    Ok(p)
}

pub fn user_data_root() -> Result<PathBuf> {
    let p = config_root()?.join("user-data");
    if !p.exists() {
        std::fs::create_dir_all(&p)?;
    }
    Ok(p)
}

pub fn proxies_path() -> Result<PathBuf> {
    Ok(config_root()?.join("proxies.json"))
}

pub fn settings_path() -> Result<PathBuf> {
    Ok(config_root()?.join("settings.json"))
}

pub fn psapi_path() -> Result<PathBuf> {
    Ok(config_root()?.join("psapi.json"))
}

#[allow(dead_code)]
pub fn logs_dir() -> Result<PathBuf> {
    let p = config_root()?.join("logs");
    if !p.exists() {
        std::fs::create_dir_all(&p)?;
    }
    Ok(p)
}
