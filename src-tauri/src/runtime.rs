//! Self-bootstrapping runtime: download ShardX browser + Widevine from R2.
//! Emits `runtime:progress` and `runtime:done` events to the Tauri frontend.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tauri::{Emitter, Window};
//use tokio::io::AsyncWriteExt;

const PUB_BASE: &str = "https://pub-e57a7c60f6934eb09a6600bf2fc59cdc.r2.dev";
/// Version manifest (GitHub raw) — one tiny GET yields every archive's current
/// etag, so install/status checks never poll R2/S3 per-archive.
const MANIFEST_URL: &str =
    "https://raw.githubusercontent.com/ProxyShard/ShardBrowser/main/runtime.json";
const LAUNCHER_RELEASE_REPO: &str = "ProxyShard/ShardBrowser";
/// Chromium version baked into the current bundle (used for Mac Framework path).
const CHROMIUM_VERSION: &str = "149.0.7827.103";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArchiveSpec {
    pub key: String,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlatformSpec {
    pub browser: ArchiveSpec,
    pub widevine: Option<ArchiveSpec>,
}

/// Archives required for this host; None on unsupported platforms.
pub fn host_spec() -> Option<PlatformSpec> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Mac-arm64.zip".into(),
            label: "ShardX browser (macOS arm64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Mac-arm64.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Windows.zip".into(),
            label: "ShardX browser (Windows x64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Win.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some(PlatformSpec {
        browser: ArchiveSpec {
            key: "ShardX-Linux.zip".into(),
            label: "ShardX browser (Linux x64)".into(),
        },
        widevine: Some(ArchiveSpec {
            key: "ShardX-Widevine-Linux.zip".into(),
            label: "Widevine CDM".into(),
        }),
    });
    #[allow(unreachable_code)]
    None
}

/// Runtime dir under the platform data dir; kept outside the launcher bundle.
pub fn runtime_dir() -> Result<PathBuf> {
    // 1. Check if there is a portable mode configuration next to the EXE.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let config_marker = exe_dir.join("portable_config.txt");
            if config_marker.exists() {
                if let Ok(saved_path) = std::fs::read_to_string(&config_marker) {
                    let trimmed = saved_path.trim();
                    if !trimmed.is_empty() {
                        let portable_runtime = PathBuf::from(trimmed).join("runtime");
                        // If the folder is not created, create it
                        if !portable_runtime.exists() {
                            std::fs::create_dir_all(&portable_runtime)?;
                        }
                        return Ok(portable_runtime);
                    }
                }
            }
        }
    }

    // 2. If there is no configuration file, we use the standard mode via system Roaming.
    let base = dirs::data_dir()
        .context("platform data dir not available")?;

    let runtime_path = base.join("shardx-launcher").join("runtime");
    if !runtime_path.exists() {
        std::fs::create_dir_all(&runtime_path)?;
    }

    Ok(runtime_path)
}

/// Path to the chrome binary inside the extracted runtime.
pub fn binary_path() -> Result<PathBuf> {
    let base = runtime_dir()?;
    #[cfg(target_os = "macos")]
    return Ok(base
        .join("ShardX-Mac-arm64")
        .join("ShardX.app")
        .join("Contents")
        .join("MacOS")
        .join("ShardX"));
    #[cfg(target_os = "windows")]
    return Ok(base.join("ShardX-Windows").join("chrome.exe"));
    #[cfg(target_os = "linux")]
    return Ok(base.join("ShardX-Linux").join("chrome"));
}

fn manifest_path() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("manifest.json"))
}

/// Top-level dir (under runtime_dir) the engine archive extracts into. Wiped
/// before a re-extract so stale files from the previous version can't linger.
fn engine_root_dir() -> &'static str {
    #[cfg(target_os = "macos")]
    return "ShardX-Mac-arm64";
    #[cfg(target_os = "windows")]
    return "ShardX-Windows";
    #[cfg(target_os = "linux")]
    return "ShardX-Linux";
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return "ShardX-Engine";
}

// Bundled fingerprint library (cross-platform); seeds fingerprints dir on first run.
const FINGERPRINTS_ARCHIVE_KEY: &str = "ShardX-Fingerprints.zip";
const FINGERPRINTS_TOP_DIR: &str = "shardx-fingerprints";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Manifest {
    browser_etag: Option<String>,
    widevine_etag: Option<String>,
    fingerprints_etag: Option<String>,
    /// Chromium version the *already-created* profiles were last migrated to.
    /// Lets us bump saved profiles' UA + client_hints when the engine updates,
    /// independent of the fingerprint-library seed.
    #[serde(default)]
    applied_chromium_version: Option<String>,
    /// Signature (`<version>|<grease_brand>|<grease_version>`) of the engine
    /// descriptor the profiles/fingerprints were last migrated against. Migration
    /// re-runs whenever this changes — so adding grease (or any future field) to
    /// the manifest auto-triggers a re-migration even for users already on the
    /// current `applied_chromium_version`. No bump-the-constant ceremony.
    #[serde(default)]
    applied_signature: Option<String>,
    /// Chromium version of the engine binary currently extracted on disk.
    /// The engine update is detected by comparing THIS to the manifest's
    /// `chromium_version` — robust where the etag check failed (e.g. a user who
    /// updated the app but whose stored etag already matched).
    #[serde(default)]
    installed_chromium_version: Option<String>,
}

/// Chromium version of the engine actually on disk (ground truth), read from
/// the bundle layout: the macOS Framework `Versions/<ver>/` dir, the Windows
/// `<ver>.manifest` file. Returns `None` on Linux (no on-disk marker) — callers
/// fall back to the stored `installed_chromium_version`.
fn installed_engine_version() -> Option<String> {
    let base = runtime_dir().ok()?;
    #[cfg(target_os = "macos")]
    {
        let versions = base
            .join("ShardX-Mac-arm64")
            .join("ShardX.app")
            .join("Contents")
            .join("Frameworks")
            .join("ShardX Framework.framework")
            .join("Versions");
        for ent in fs::read_dir(&versions).ok()?.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name != "Current" && name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some(name);
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        let dir = base.join("ShardX-Windows");
        // Marker is the `<version>.manifest` sidecar next to chrome.exe. Require
        // the stem to parse as a dotted version so a stray/leftover file can't
        // feed a bogus version into the update check.
        let looks_like_version =
            |s: &str| s.split('.').count() >= 2 && s.starts_with(|c: char| c.is_ascii_digit());
        for ent in fs::read_dir(&dir).ok()?.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    if looks_like_version(stem) {
                        return Some(stem.to_string());
                    }
                }
            }
        }
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = base;
        None
    }
}

/// Effective installed engine version. Trusts the version recorded at install
/// time (authoritative — written only after a successful download+extract) over
/// re-reading it off disk, whose layout varies per-OS and can carry stale files
/// from a previous version (a leftover `<old>.manifest` made Windows re-download
/// forever). On-disk detection is the fallback for legacy installs that predate
/// `installed_chromium_version`.
fn effective_installed_version(local: &Manifest) -> Option<String> {
    local
        .installed_chromium_version
        .clone()
        .or_else(installed_engine_version)
}

fn load_manifest() -> Manifest {
    let Ok(p) = manifest_path() else { return Manifest::default() };
    fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_manifest(m: &Manifest) -> Result<()> {
    let p = manifest_path()?;
    fs::create_dir_all(p.parent().unwrap())?;
    fs::write(p, serde_json::to_string_pretty(m)?)?;
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
pub struct RuntimeStatus {
    pub installed: bool,
    pub binary_path: Option<PathBuf>,
    pub installed_browser_etag: Option<String>,
    pub remote_browser_etag: Option<String>,
    pub update_available: bool,
    pub spec: Option<PlatformSpec>,
    /// True once the fingerprint library bundle has been extracted.
    pub fingerprints_installed: bool,
}

#[derive(Default)]
struct RemoteManifest {
    archives: std::collections::HashMap<String, String>,
    chromium_version: Option<String>,
    /// GREASE brand/version the engine emits in `sec-ch-ua`. Not derivable from
    /// the version number (it rotates per major release), so it travels in the
    /// manifest as data — migration writes it into every profile/fingerprint.
    grease_brand: Option<String>,
    grease_version: Option<String>,
}

/// Fetch the version manifest (GitHub raw) — one request yielding every
/// archive's current etag + the chromium version, so install/status never poll
/// R2/S3 per-archive. Empty/None when unreachable.
async fn fetch_manifest() -> RemoteManifest {
    async fn inner() -> Option<RemoteManifest> {
        let resp = reqwest::Client::new().get(MANIFEST_URL).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let archives = v
            .get("archives")
            .and_then(|a| a.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let str_field = |k: &str| v.get(k).and_then(|s| s.as_str()).map(String::from);
        Some(RemoteManifest {
            archives,
            chromium_version: str_field("chromium_version"),
            grease_brand: str_field("grease_brand"),
            grease_version: str_field("grease_version"),
        })
    }
    inner().await.unwrap_or_default()
}

/// Migrate every `*.json` in `dir` to a new engine descriptor: bump
/// `navigator.user_agent` (Chrome/<major>.0.0.0) and the version fields in
/// `client_hints` — `brand_version` / `brand_full_version` / `chrome_build` /
/// `chrome_version`. Modifies profiles in-place.
async fn migrate_profiles(dir: &Path, chromium_version: &str, brand_version: &str, brand_full_version: &str, chrome_build: &str) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let major = chromium_version.split('.').next().unwrap_or("130");
    let target_ua = format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36");

    for ent in fs::read_dir(dir)?.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(body) = fs::read_to_string(&p) else { continue; };
        let Ok(mut val): std::result::Result<serde_json::Value, _> = serde_json::from_str(&body) else { continue; };

        if let Some(nav) = val.get_mut("navigator") {
            if let Some(ua) = nav.get_mut("user_agent") {
                *ua = serde_json::Value::String(target_ua.clone());
            }
        }
        if let Some(ch) = val.get_mut("client_hints") {
            if let Some(bv) = ch.get_mut("brand_version") {
                *bv = serde_json::Value::String(brand_version.to_string());
            }
            if let Some(bfv) = ch.get_mut("brand_full_version") {
                *bfv = serde_json::Value::String(brand_full_version.to_string());
            }
            if let Some(cb) = ch.get_mut("chrome_build") {
                *cb = serde_json::Value::String(chrome_build.to_string());
            }
            if let Some(cv) = ch.get_mut("chrome_version") {
                *cv = serde_json::Value::String(chromium_version.to_string());
            }
        }
        if let Ok(out) = serde_json::to_string_pretty(&val) {
            let _ = fs::write(&p, out);
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn runtime_status() -> Result<RuntimeStatus, String> {
    let spec = host_spec();
    let local = load_manifest();

    // We safely get the path to the binary. If a path error has occurred, we pass it as a string.
    let r_dir = runtime_dir().map_err(|e| format!("Runtime directory error: {}", e))?;

    #[cfg(target_os = "macos")]
    let b_path_expected = r_dir.join("ShardX-Mac-arm64").join("ShardX.app").join("Contents").join("MacOS").join("ShardX");
    #[cfg(target_os = "windows")]
    let b_path_expected = r_dir.join("ShardX-Windows").join("chrome.exe");
    #[cfg(target_os = "linux")]
    let b_path_expected = r_dir.join("ShardX-Linux").join("chrome");

    let installed = b_path_expected.exists();
    let b_path = if installed { Some(b_path_expected) } else { None };

    // Check fingerprints dir status
    let fingerprints_installed = crate::store::fingerprints_dir()
        .map(|d| d.join("starter-desktop-windows-nvidia.json").exists())
        .unwrap_or(false);

    if !installed {
        return Ok(RuntimeStatus {
            installed: false,
            binary_path: None,
            installed_browser_etag: None,
            remote_browser_etag: None,
            update_available: false,
            spec,
            fingerprints_installed,
        });
    }

    let remote = fetch_manifest().await;
    let mut update_available = false;
    let mut remote_etag = None;

    if let Some(ref s) = spec {
        if let Some(r_etag) = remote.archives.get(&s.browser.key) {
            remote_etag = Some(r_etag.clone());
            if local.browser_etag.as_ref() != Some(r_etag) {
                update_available = true;
            }
        }
    }

    // Secondary check: if remote manifest tells us a newer chromium version than
    // what we recorded during the last extract, an update is available.
    if let Some(ref rem_ver) = remote.chromium_version {
        if let Some(inst_ver) = effective_installed_version(&local) {
            if inst_ver != *rem_ver {
                update_available = true;
            }
        }
    }

    Ok(RuntimeStatus {
        installed,
        binary_path: b_path,
        installed_browser_etag: local.browser_etag,
        remote_browser_etag: remote_etag,
        update_available,
        spec,
        fingerprints_installed,
    })
}

// Internal helper for decompressing ZIP with full normalization of paths under Windows
fn extract_zip(bytes: &[u8], target: &Path) -> Result<()> {
    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| anyhow::anyhow!("Failed to open zip archive: {}", e))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| anyhow::anyhow!("Failed to read file inside zip: {}", e))?;

        // We get a clean inner path without dangerous relative transitions
        let enclosed = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };

        // Collecting the absolute path on the disk
        let outpath = target.join(enclosed);

        // Normalize the path: remove unnecessary dots, duplicate slashes, and end separators.
        if file.name().ends_with('/') || file.name().ends_with('\\') {
            if !outpath.exists() {
                fs::create_dir_all(&outpath)
                    .map_err(|e| anyhow::anyhow!("Failed to create directory {:?}: {}", outpath, e))?;
            }
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)
                        .map_err(|e| anyhow::anyhow!("Failed to create parent directory {:?}: {}", p, e))?;
                }
            }
            let mut outfile = fs::File::create(&outpath)
                .map_err(|e| anyhow::anyhow!("Failed to create file {:?}: {}", outpath, e))?;
            std::io::copy(&mut file, &mut outfile)
                .map_err(|e| anyhow::anyhow!("Failed to write data to {:?}: {}", outpath, e))?;
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn runtime_install(window: Window) -> Result<(), String> {
    let spec = host_spec().ok_or_else(|| "Unsupported platform".to_string())?;
    let r_dir = runtime_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&r_dir).map_err(|e| e.to_string())?;

    let remote = fetch_manifest().await;
    let remote_browser_etag = remote
        .archives
        .get(&spec.browser.key)
        .ok_or_else(|| "Browser archive not found in remote manifest".to_string())?;
    let remote_widevine_etag = spec
        .widevine
        .as_ref()
        .and_then(|w| remote.archives.get(&w.key));
    let remote_fingerprints_etag = remote.archives.get(FINGERPRINTS_ARCHIVE_KEY);

    let mut local = load_manifest();

    // 1. Download & Extract Browser if missing or stale
    let current_inst_ver = effective_installed_version(&local);
    let browser_stale = local.browser_etag.as_ref() != Some(remote_browser_etag)
        || current_inst_ver.is_none()
        || remote.chromium_version.as_ref() != current_inst_ver.as_ref();

    if browser_stale {
        let _ = window.emit("runtime:progress", "Downloading ShardX browser core...");
        let url = format!("{PUB_BASE}/{}", spec.browser.key);
        let bytes = reqwest::get(&url)
            .await
            .map_err(|e| e.to_string())?
            .bytes()
            .await
            .map_err(|e| e.to_string())?;

        let _ = window.emit("runtime:progress", "Extracting ShardX browser...");
        let target_root = r_dir.join(engine_root_dir());
        if target_root.exists() {
            let _ = fs::remove_dir_all(&target_root);
        }

        extract_zip(&bytes, &r_dir).map_err(|e| e.to_string())?;

        local.browser_etag = Some(remote_browser_etag.clone());
        local.installed_chromium_version = remote.chromium_version.clone();
        save_manifest(&local).map_err(|e| e.to_string())?;
    }

    // 2. Download & Extract Widevine if applicable
    if let Some(ref w_spec) = spec.widevine {
        if let Some(r_wv_etag) = remote_widevine_etag {
            let wv_cache = crate::store::widevine_cache_dir().map_err(|e| e.to_string())?;
            let wv_stale = local.widevine_etag.as_ref() != Some(r_wv_etag) || !wv_cache.exists();

            if wv_stale {
                let _ = window.emit("runtime:progress", "Downloading Widevine CDM module...");
                let url = format!("{PUB_BASE}/{}", w_spec.key);
                let bytes = reqwest::get(&url)
                    .await
                    .map_err(|e| e.to_string())?
                    .bytes()
                    .await
                    .map_err(|e| e.to_string())?;

                let _ = window.emit("runtime:progress", "Extracting Widevine CDM...");
                if wv_cache.exists() {
                    let _ = fs::remove_dir_all(&wv_cache);
                }
                std::fs::create_dir_all(&wv_cache).map_err(|e| e.to_string())?;

                extract_zip(&bytes, &wv_cache).map_err(|e| e.to_string())?;

                local.widevine_etag = Some(r_wv_etag.clone());
                save_manifest(&local).map_err(|e| e.to_string())?;
            }
        }
    }

    // 3. Download & Seed Fingerprints library if missing or stale
    if let Some(r_fp_etag) = remote_fingerprints_etag {
        let fp_dir = crate::store::fingerprints_dir().map_err(|e| e.to_string())?;
        let marker = fp_dir.join("starter-desktop-windows-nvidia.json");
        let fp_stale = local.fingerprints_etag.as_ref() != Some(r_fp_etag) || !marker.exists();

        if fp_stale {
            let _ = window.emit("runtime:progress", "Downloading global fingerprint assets...");
            let url = format!("{PUB_BASE}/{FINGERPRINTS_ARCHIVE_KEY}");
            let bytes = reqwest::get(&url)
                .await
                .map_err(|e| e.to_string())?
                .bytes()
                .await
                .map_err(|e| e.to_string())?;

            let _ = window.emit("runtime:progress", "Seeding fingerprint templates...");
            let tmp_extract = r_dir.join("tmp_fingerprints");
            if tmp_extract.exists() {
                let _ = fs::remove_dir_all(&tmp_extract);
            }

            extract_zip(&bytes, &tmp_extract).map_err(|e| e.to_string())?;

            let src_dir = tmp_extract.join(FINGERPRINTS_TOP_DIR);
            if src_dir.exists() {
                for ent in fs::read_dir(&src_dir).map_err(|e| e.to_string())?.flatten() {
                    let from = ent.path();
                    if let Some(fname) = from.file_name() {
                        let to = fp_dir.join(fname);
                        let _ = fs::copy(&from, &to);
                    }
                }
            }
            let _ = fs::remove_dir_all(&tmp_extract);

            local.fingerprints_etag = Some(r_fp_etag.clone());
            save_manifest(&local).map_err(|e| e.to_string())?;
        }
    }

    // 4. Run version migration on existing profiles if engine version changed
    if let Some(ref cv) = remote.chromium_version {
        let sig = format!(
            "{}|{}|{}",
            cv,
            remote.grease_brand.as_deref().unwrap_or(""),
            remote.grease_version.as_deref().unwrap_or("")
        );
        let ver_changed = local.applied_chromium_version.as_ref() != Some(cv)
            || local.applied_signature.as_ref() != Some(&sig);

        if ver_changed {
            let _ = window.emit("runtime:progress", "Migrating fingerprint schemas...");
            if let Ok(p_dir) = crate::store::profiles_dir() {
                let bv = remote.grease_brand.as_deref().unwrap_or("Not A;Brand");
                let bfv = remote.grease_version.as_deref().unwrap_or("99");
                let build = cv.split('.').nth(2).unwrap_or("0");
                let _ = migrate_profiles(&p_dir, cv, bv, bfv, build).await;
            }
            local.applied_chromium_version = Some(cv.clone());
            local.applied_signature = Some(sig);
            save_manifest(&local).map_err(|e| e.to_string())?;
        }
    }

    let _ = window.emit("runtime:done", ());
    Ok(())
}

pub async fn ensure_profiles_migrated() {
    let remote = fetch_manifest().await;
    let cv = match remote.chromium_version {
        Some(ref v) if !v.is_empty() => v,
        _ => CHROMIUM_VERSION,
    };
    let sig = format!(
        "{}|{}|{}",
        cv,
        remote.grease_brand.as_deref().unwrap_or(""),
        remote.grease_version.as_deref().unwrap_or("")
    );

    let mut local = load_manifest();
    if local.applied_chromium_version.as_ref() != Some(&cv.to_string())
        || local.applied_signature.as_ref() != Some(&sig)
    {
        if let Ok(p_dir) = crate::store::profiles_dir() {
            let bv = remote.grease_brand.as_deref().unwrap_or("Not A;Brand");
            let bfv = remote.grease_version.as_deref().unwrap_or("99");
            let build = cv.split('.').nth(2).unwrap_or("0");
            let _ = migrate_profiles(&p_dir, cv, bv, bfv, build).await;
        }
        local.applied_chromium_version = Some(cv.to_string());
        local.applied_signature = Some(sig);
        let _ = save_manifest(&local);
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct LauncherVersionInfo {
    pub current: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
}

#[tauri::command]
pub async fn launcher_update_check() -> Result<LauncherVersionInfo, String> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let url = format!("https://api.github.com/repos/{LAUNCHER_RELEASE_REPO}/releases/latest");

    let client = match reqwest::Client::builder()
        .user_agent(format!("shardx-launcher/{current}"))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Err(e.to_string()),
    };

    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(6))
        .send()
        .await;

    let Ok(resp) = resp else {
        return Ok(LauncherVersionInfo {
            current, latest: None, update_available: false, release_url: None,
        });
    };

    if !resp.status().is_success() {
        return Ok(LauncherVersionInfo {
            current, latest: None, update_available: false, release_url: None,
        });
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Ok(LauncherVersionInfo {
            current, latest: None, update_available: false, release_url: None,
        }),
    };

    let latest = body.get("tag_name").and_then(|v| v.as_str()).map(String::from);
    let release_url = body.get("html_url").and_then(|v| v.as_str()).map(String::from);

    let mut update_available = false;
    if let Some(ref lat) = latest {
        let clean_lat = lat.trim_start_matches('v');
        let clean_cur = current.trim_start_matches('v');
        if clean_lat != clean_cur {
            update_available = true;
        }
    }

    Ok(LauncherVersionInfo {
        current,
        latest,
        update_available,
        release_url,
    })
}
