//! Unified secret resolution: the single entry point that maps a `(kind, id)`
//! pair to its raw bytes, sourcing them from the configured backend (TPM or
//! escrow). Used by `mount` (gocryptfs key) and `gpg` (key passphrases).

use crate::config::{Config, SecretBackend};
use crate::escrow;
use crate::tpm;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

pub use crate::escrow::SecretMap;

/// Cached decrypted maps for the process session, keyed by their on-disk path
/// (escrow file / TPM map file). Keying by path keeps distinct backends (and
/// concurrent tests) from colliding on a single global cache.
static MAP_CACHE: OnceLock<Mutex<HashMap<PathBuf, SecretMap>>> = OnceLock::new();
/// Cached master passphrase (prompted/read once).
static MASTER_CACHE: OnceLock<Zeroizing<String>> = OnceLock::new();

/// Clone the cached map for `path`, if present.
fn cached_map(path: &PathBuf) -> Option<SecretMap> {
    MAP_CACHE
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|g| g.get(path).cloned())
}

/// Store `map` in the cache under `path` and return a clone.
fn store_map(path: PathBuf, map: SecretMap) -> SecretMap {
    if let Ok(mut g) = MAP_CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        g.insert(path, map.clone());
    }
    map
}

/// Composite map/TPM key for a `(kind, id)` pair: `{kind}:{id}`. This is the
/// single source of truth for key composition so `install`, `gpg` and `check`
/// can never drift (the key namespace is defined here and reused everywhere).
pub fn composite_key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

/// Tail of a gpg secret-key id: `{name}:{fpr}`. Compose with `kind = "gpg"`
/// via [`composite_key`] to obtain the full map key.
pub fn gpg_id_tail(name: &str, fpr: &str) -> String {
    format!("{name}:{fpr}")
}

/// Whether the backend has not been enrolled yet (so `mount`/`init` may prompt
/// for the gocryptfs password during the pre-`install` migration window). Real
/// unseal failures on an *enrolled* backend still propagate through
/// [`resolve_secret`].
pub fn backend_missing(cfg: &Config) -> bool {
    match cfg.secret_backend {
        SecretBackend::Tpm => !tpm::dek_exists(cfg) || !cfg.tpm_map_file().exists(),
        SecretBackend::Escrow => !cfg.escrow_file.exists(),
    }
}

/// Resolve the whole secret map from the configured backend, cached for the
/// process session.
///
/// Both backends share one on-disk format (an age container of the serialized
/// map); they differ only in how the map is unwrapped:
/// - **TPM**: a single `tpm2_unseal` recovers the random DEK, which decrypts
///   `tpm_map_file`. One TPM round-trip yields every secret.
/// - **Escrow**: the master passphrase decrypts `escrow_file`.
pub fn resolve_all(cfg: &Config) -> Result<SecretMap> {
    match cfg.secret_backend {
        SecretBackend::Tpm => tpm_map(cfg),
        SecretBackend::Escrow => escrow_map(cfg),
    }
}

/// Resolve the composite key and return the secret bytes.
///
/// `kind` is one of `gocryptfs`, `gpg`, `ssh`; `id` is the backend-specific
/// tail (`__shared__`, `<home_id>:<fpr>`, `<abspath>`). The full map key is
/// `composite_key(kind, id)`.
pub fn resolve_secret(cfg: &Config, kind: &str, id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = composite_key(kind, id);
    let map = resolve_all(cfg)?;
    map.get(&key)
        .cloned()
        .with_context(|| format!("secret '{key}' not found in backend"))
}

/// Lazily unwrap the TPM map: unseal the DEK, decrypt `tpm_map_file` with it.
fn tpm_map(cfg: &Config) -> Result<SecretMap> {
    let path = cfg.tpm_map_file();
    if let Some(m) = cached_map(&path) {
        return Ok(m);
    }
    let dek = tpm::unseal_dek(cfg).context("unsealing DEK from TPM")?;
    let id = tpm::dek_identity(&dek);
    let blob =
        std::fs::read(&path).with_context(|| format!("reading TPM map {}", path.display()))?;
    let map = escrow::open_identity(&blob, &id).context("decrypting TPM map with DEK")?;
    Ok(store_map(path, map))
}

/// Resolve the master passphrase. Source order: env `SCTL_MASTER_PASS` >
/// `master_passphrase_file` > (if `allow_prompt`) interactive prompt. When
/// `allow_prompt` is false and no non-interactive source is available, errors
/// (used by `check` so it never blocks on input).
fn get_master_passphrase(cfg: &Config, allow_prompt: bool) -> Result<Zeroizing<String>> {
    if let Some(s) = std::env::var_os("SCTL_MASTER_PASS") {
        return Ok(Zeroizing::new(s.to_string_lossy().into_owned()));
    }
    if let Some(path) = &cfg.master_passphrase_file
        && path.is_file()
    {
        let data = Zeroizing::new(
            std::fs::read(path)
                .with_context(|| format!("reading master passphrase file {}", path.display()))?,
        );
        return Ok(Zeroizing::new(
            String::from_utf8_lossy(&data).trim().to_string(),
        ));
    }
    if allow_prompt {
        let pw = rpassword::prompt_password("Master passphrase: ")
            .context("reading master passphrase")?;
        return Ok(Zeroizing::new(pw));
    }
    bail!(
        "master passphrase not available non-interactively \
         (set SCTL_MASTER_PASS or master_passphrase_file)"
    )
}

/// Lazily decrypt the escrow file (cached for the session) and return the map.
fn escrow_map(cfg: &Config) -> Result<SecretMap> {
    let path = cfg.escrow_file.clone();
    if let Some(m) = cached_map(&path) {
        return Ok(m);
    }
    let blob =
        std::fs::read(&path).with_context(|| format!("reading escrow file {}", path.display()))?;
    let master = read_master_passphrase(cfg)?;
    let map = escrow::open(&blob, &master)?;
    Ok(store_map(path, map))
}

/// Master passphrase: env `SCTL_MASTER_PASS` > `master_passphrase_file` >
/// (if `allow_prompt`) interactive prompt. Cached for the process session.
fn master_passphrase_inner(cfg: &Config, allow_prompt: bool) -> Result<Zeroizing<String>> {
    if let Some(p) = MASTER_CACHE.get() {
        return Ok(p.clone());
    }
    let p = get_master_passphrase(cfg, allow_prompt)?;
    Ok(MASTER_CACHE.get_or_init(|| p).clone())
}

/// Public, owned accessor for the master passphrase (cached per session).
/// Prompts when no non-interactive source is available. Used by `install` and
/// `recovery` to seal/open the escrow container, and by `mount` to decrypt.
pub fn read_master_passphrase(cfg: &Config) -> Result<Zeroizing<String>> {
    master_passphrase_inner(cfg, true)
}

/// Like [`read_master_passphrase`], but never prompts. Errors if the master
/// passphrase is not available non-interactively (`SCTL_MASTER_PASS` env or
/// `master_passphrase_file`). Used by `check` so it never blocks on input.
pub fn read_master_passphrase_noninteractive(cfg: &Config) -> Result<Zeroizing<String>> {
    master_passphrase_inner(cfg, false)
}

/// Resolve the master passphrase for the `install` write path. Non-interactive
/// sources (`SCTL_MASTER_PASS` env, `master_passphrase_file`) are returned
/// unchanged without a second prompt; otherwise the passphrase is prompted
/// twice and the two entries must match — a typo'd master passphrase would lock
/// the entire backend irrecoverably until a re-install.
fn get_master_passphrase_confirm(cfg: &Config) -> Result<Zeroizing<String>> {
    if let Some(s) = std::env::var_os("SCTL_MASTER_PASS") {
        return Ok(Zeroizing::new(s.to_string_lossy().into_owned()));
    }
    if let Some(path) = &cfg.master_passphrase_file
        && path.is_file()
    {
        let data = Zeroizing::new(
            std::fs::read(path)
                .with_context(|| format!("reading master passphrase file {}", path.display()))?,
        );
        return Ok(Zeroizing::new(
            String::from_utf8_lossy(&data).trim().to_string(),
        ));
    }
    let pw1 =
        rpassword::prompt_password("Master passphrase: ").context("reading master passphrase")?;
    let pw2 = rpassword::prompt_password("Confirm master passphrase: ")
        .context("reading master passphrase confirmation")?;
    if pw1 != pw2 {
        bail!("master passphrases do not match");
    }
    Ok(Zeroizing::new(pw1))
}

/// Like [`read_master_passphrase`], but on the interactive path prompts twice
/// and requires the two entries to match. Intended for the `install`/`finalize`
/// write path, where a typo'd master passphrase would lock the whole backend
/// irrecoverably. Non-interactive sources bypass the second prompt (a mismatch
/// there is the operator's responsibility). Cached for the session.
pub fn read_master_passphrase_confirm(cfg: &Config) -> Result<Zeroizing<String>> {
    if let Some(p) = MASTER_CACHE.get() {
        return Ok(p.clone());
    }
    let p = get_master_passphrase_confirm(cfg)?;
    Ok(MASTER_CACHE.get_or_init(|| p).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretBackend;
    use rand::Rng;
    use rand::rng;
    use std::path::PathBuf;

    fn cfg_with(backend: SecretBackend, state_dir: PathBuf, escrow_file: PathBuf) -> Config {
        Config {
            home: PathBuf::from("/h"),
            state_dir,
            enc_root: PathBuf::from("/e"),
            default_idle: None,
            secret_backend: backend,
            escrow_file,
            master_passphrase_file: None,
            tpm_pcr: false,
            secrets: Default::default(),
        }
    }

    fn rand_bytes(n: usize) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![0u8; n]);
        rng().fill_bytes(&mut b);
        b
    }

    #[test]
    fn escrow_resolve() {
        unsafe {
            std::env::set_var("SCTL_MASTER_PASS", "test-master-pass");
        }
        let dir = std::env::temp_dir().join("sctl-secret-escrow-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let escrow_file = dir.join("escrow.age");

        let mut map = SecretMap::new();
        let g = rand_bytes(32);
        map.insert("gocryptfs:__shared__".into(), g.clone());
        let master = Zeroizing::new("test-master-pass".to_string());
        let blob = escrow::seal(&map, &master).unwrap();
        std::fs::write(&escrow_file, blob).unwrap();

        let cfg = cfg_with(SecretBackend::Escrow, dir.clone(), escrow_file);
        let got = resolve_secret(&cfg, "gocryptfs", "__shared__").unwrap();
        assert_eq!(got.as_slice(), g.as_slice());
        assert!(resolve_secret(&cfg, "gocryptfs", "missing").is_err());
    }

    #[test]
    fn id_format_is_stable() {
        assert_eq!(
            composite_key("gocryptfs", "__shared__"),
            "gocryptfs:__shared__"
        );
        assert_eq!(gpg_id_tail("mail", "ABCDEF"), "mail:ABCDEF");
        assert_eq!(
            composite_key("gpg", &gpg_id_tail("mail", "ABCDEF")),
            "gpg:mail:ABCDEF"
        );
    }

    #[test]
    fn tpm_resolve() {
        let dir = std::env::temp_dir().join("sctl-secret-tpm-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = cfg_with(SecretBackend::Tpm, dir.clone(), dir.join("escrow.age"));

        // Enroll the DEK + DEK-wrapped map exactly as `install::finalize` does.
        let mut map = SecretMap::new();
        let g = rand_bytes(24);
        map.insert("gocryptfs:__shared__".into(), g.clone());
        let mut dek = Zeroizing::new(vec![0u8; 32]);
        rand::rng().fill_bytes(dek.as_mut_slice());
        tpm::seal_dek(&dek, &cfg).unwrap();
        let blob = tpm::seal_map(&map, &dek).unwrap();
        std::fs::write(cfg.tpm_map_file(), blob).unwrap();

        let got = resolve_secret(&cfg, "gocryptfs", "__shared__").unwrap();
        assert_eq!(got.as_slice(), g.as_slice());
    }
}
