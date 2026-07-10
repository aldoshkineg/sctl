//! Configuration loading (TOML) with environment overrides.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

/// Raw TOML shape.
#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    settings: RawSettings,
    #[serde(default)]
    secrets: BTreeMap<String, RawSecret>,
}

#[derive(Debug, Default, Deserialize)]
struct RawSettings {
    default_idle: Option<String>,
    enc_root: Option<String>,
    keyfile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSecret {
    path: String,
    idle: Option<String>,
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default)]
    gpg: bool,
    /// Preset secret-key passphrases into gpg-agent after mounting.
    #[serde(default)]
    gpg_preset: bool,
    /// Passphrase file for gpg_preset (default: `<mountpoint>/.gpg-passphrase`).
    gpg_passphrase_file: Option<String>,
    /// Process names (comm) that may be killed silently on a busy unmount.
    #[serde(default)]
    auto_kill: Vec<String>,
    #[serde(default)]
    pre_mount: Vec<String>,
    #[serde(default)]
    post_mount: Vec<String>,
    #[serde(default)]
    pre_unmount: Vec<String>,
    #[serde(default)]
    post_unmount: Vec<String>,
}

/// A single secret container definition (resolved).
#[derive(Debug, Clone)]
pub struct Secret {
    pub name: String,
    /// Path relative to `$HOME` where the cleartext is mounted.
    pub rel_path: String,
    /// Per-secret idle override (raw string, e.g. "30m").
    pub idle: Option<String>,
    pub depends: Vec<String>,
    pub gpg: bool,
    /// Preset secret-key passphrases into gpg-agent after mounting.
    pub gpg_preset: bool,
    /// Passphrase file for gpg_preset (default: `<mountpoint>/.gpg-passphrase`).
    pub gpg_passphrase_file: Option<String>,
    /// Process names (comm) that may be killed silently on a busy unmount.
    pub auto_kill: Vec<String>,
    pub pre_mount: Vec<String>,
    pub post_mount: Vec<String>,
    pub pre_unmount: Vec<String>,
    pub post_unmount: Vec<String>,
}

impl Secret {
    /// Filesystem-safe token derived from the name (`/` -> `_`).
    pub fn safe(&self) -> String {
        self.name.replace('/', "_")
    }

    /// Cleartext mountpoint: `$HOME/<rel_path>`.
    pub fn mountpoint(&self, home: &Path) -> PathBuf {
        home.join(self.rel_path.trim_start_matches("./"))
    }

    /// Encrypted backend directory: `<enc_root>/<safe>`.
    pub fn enc_dir(&self, enc_root: &Path) -> PathBuf {
        enc_root.join(self.safe())
    }
}

/// Fully resolved configuration + paths.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub stray_dir: PathBuf,
    pub enc_root: PathBuf,
    pub keyfile: PathBuf,
    pub default_idle: Option<String>,
    pub secrets: BTreeMap<String, Secret>,
}

/// Expand a leading `~` / `~/` to the given home directory.
pub fn expand_tilde(p: &str, home: &Path) -> PathBuf {
    if p == "~" {
        home.to_path_buf()
    } else if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(p)
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var_os(key).map(PathBuf::from)
}

impl Config {
    /// Resolve config-dir/file/state paths (respecting env overrides) without
    /// reading the config file. Used before load to report the config path.
    pub fn locate() -> Result<(PathBuf, PathBuf, PathBuf)> {
        let home = home_dir()?;
        let config_dir = env_path("SCTL_CONFIG_DIR").unwrap_or_else(|| home.join(".config/sctl"));
        let config_file = env_path("SCTL_CONFIG").unwrap_or_else(|| config_dir.join("config.toml"));
        let state_dir = env_path("SCTL_STATE_DIR").unwrap_or_else(|| config_dir.join("state"));
        Ok((config_dir, config_file, state_dir))
    }

    /// Load and fully resolve configuration.
    pub fn load() -> Result<Config> {
        let home = home_dir()?;
        let (config_dir, config_file, state_dir) = Self::locate()?;

        if !config_file.exists() {
            bail!("config not found: {}", config_file.display());
        }
        let text = std::fs::read_to_string(&config_file)
            .with_context(|| format!("reading {}", config_file.display()))?;
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", config_file.display()))?;

        // enc_root: env > config > default (~/.encrypted)
        let enc_root = env::var("SCTL_ENC_ROOT")
            .ok()
            .or(raw.settings.enc_root)
            .unwrap_or_else(|| "~/.encrypted".to_string());
        let enc_root = expand_tilde(&enc_root, &home);

        // keyfile: env > config > default (<config_dir>/key)
        let keyfile = env::var("SCTL_KEYFILE")
            .ok()
            .or(raw.settings.keyfile)
            .map(|k| expand_tilde(&k, &home))
            .unwrap_or_else(|| config_dir.join("key"));

        // default_idle: env > config
        let default_idle = env::var("SCTL_DEFAULT_IDLE")
            .ok()
            .or(raw.settings.default_idle)
            .filter(|s| !s.is_empty());

        let stray_dir =
            env_path("SCTL_STRAY_DIR").unwrap_or_else(|| home.join(".local/share/sctl/stray"));

        let mut secrets = BTreeMap::new();
        for (name, r) in raw.secrets {
            secrets.insert(
                name.clone(),
                Secret {
                    name,
                    rel_path: r.path,
                    idle: r.idle,
                    depends: r.depends,
                    gpg: r.gpg,
                    gpg_preset: r.gpg_preset,
                    gpg_passphrase_file: r.gpg_passphrase_file,
                    auto_kill: r.auto_kill,
                    pre_mount: r.pre_mount,
                    post_mount: r.post_mount,
                    pre_unmount: r.pre_unmount,
                    post_unmount: r.post_unmount,
                },
            );
        }

        let cfg = Config {
            home,
            state_dir,
            stray_dir,
            enc_root,
            keyfile,
            default_idle,
            secrets,
        };
        cfg.validate_depends()?;
        Ok(cfg)
    }

    /// Ensure every `depends` entry references a known secret.
    fn validate_depends(&self) -> Result<()> {
        for s in self.secrets.values() {
            for d in &s.depends {
                if !self.secrets.contains_key(d) {
                    bail!("secret '{}' depends on unknown secret '{}'", s.name, d);
                }
            }
        }
        Ok(())
    }

    /// Look up a secret by name or error.
    pub fn get(&self, name: &str) -> Result<&Secret> {
        self.secrets
            .get(name)
            .with_context(|| format!("unknown secret: {name}"))
    }

    /// All secret names, sorted (BTreeMap order).
    pub fn all_names(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }
}

/// Resolve the user's home directory (env `HOME` first for test isolation).
pub fn home_dir() -> Result<PathBuf> {
    if let Some(h) = env::var_os("HOME")
        && !h.is_empty()
    {
        return Ok(PathBuf::from(h));
    }
    #[allow(deprecated)]
    std::env::home_dir().context("could not determine home directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands() {
        let home = Path::new("/home/x");
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/x"));
        assert_eq!(expand_tilde("~/.ssh", home), PathBuf::from("/home/x/.ssh"));
        assert_eq!(expand_tilde("/abs", home), PathBuf::from("/abs"));
        assert_eq!(expand_tilde("rel", home), PathBuf::from("rel"));
    }

    #[test]
    fn secret_paths() {
        let s = Secret {
            name: "a/b".into(),
            rel_path: "./.ssh".into(),
            idle: None,
            depends: vec![],
            gpg: false,
            gpg_preset: false,
            gpg_passphrase_file: None,
            auto_kill: vec![],
            pre_mount: vec![],
            post_mount: vec![],
            pre_unmount: vec![],
            post_unmount: vec![],
        };
        assert_eq!(s.safe(), "a_b");
        assert_eq!(s.mountpoint(Path::new("/h")), PathBuf::from("/h/.ssh"));
        assert_eq!(s.enc_dir(Path::new("/e")), PathBuf::from("/e/a_b"));
    }
}
