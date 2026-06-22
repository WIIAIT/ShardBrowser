// Persistent storage layout under the user's config dir or portable folder:
//   <PORTABLE_DIR>/
//     profiles/
//     proxies.json
//     user-data/<profile-id>/
//     settings.json
//     runtime/
//     widevine-cdm/
//     webview_cache/

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Returns portable root if `portable_config.txt` exists next to the executable.
/// Supports both absolute and relative paths.
pub(crate) fn portable_root() -> Result<Option<PathBuf>> {
    let exe_path = std::env::current_exe().context("failed to get current exe path")?;

    let exe_dir = exe_path.parent().context("failed to get exe directory")?;

    let marker = exe_dir.join("portable_config.txt");
    if !marker.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&marker).context("failed to read portable_config.txt")?;

    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // Support relative and absolute paths
    let root = if trimmed.starts_with(['/', '\\'])
        || trimmed.starts_with("\\\\")
        || (trimmed.len() > 2
            && trimmed.chars().nth(1) == Some(':')
            && trimmed.chars().nth(2) == Some('\\'))
    {
        PathBuf::from(trimmed)
    } else {
        exe_dir.join(trimmed)
    };

    if !root.exists() {
        std::fs::create_dir_all(&root).context("failed to create portable root directory")?;
    }

    Ok(Some(root))
}

/// Returns the root directory for all launcher data (portable or standard).
pub fn config_root() -> Result<PathBuf> {
    if let Some(portable) = portable_root()? {
        return Ok(portable);
    }

    // Standard mode
    let base = dirs::config_dir().context("OS config directory unavailable")?;

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

pub fn is_portable() -> bool {
    portable_root().unwrap_or(None).is_some()
}
