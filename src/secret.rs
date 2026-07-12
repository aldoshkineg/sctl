//! Unified secret resolution: the single entry point that maps a `(kind, id)`
//! pair to its raw bytes, sourcing them from the configured backend (TPM or
//! escrow). Used by `mount` (gocryptfs key) and `gpg` (key passphrases).

use crate::config::{Config, SecretBackend};
use crate::escrow;
use crate::tpm;
use anyhow::{Context, Result, bail};
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub use crate::escrow::SecretMap;

/// Cached decrypted escrow map for the process session.
static ESCROW_CACHE: OnceLock<SecretMap> = OnceLock::new();
/// Cached master passphrase (prompted/read once).
static MASTER_CACHE: OnceLock<Zeroizing<String>> = OnceLock::new();

/// Composite map/TPM key for a `(kind, id)` pair: `{kind}:{id}`. This is the
/// single source of truth for key composition so `install`, `gpg` and `check`
/// can never drift (see docs/SECRETS.md §2 key namespace).
pub fn composite_key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

/// Tail of a gpg secret-key id: `{name}:{fpr}`. Compose with `kind = "gpg"`
/// via [`composite_key`] to obtain the full map key.
pub fn gpg_id_tail(name: &str, fpr: &str) -> String {
    format!("{name}:{fpr}")
}

/// Resolve the composite key and return the secret bytes.
///
/// `kind` is one of `gocryptfs`, `gpg`, `ssh`; `id` is the backend-specific
/// tail (`__shared__`, `<home_id>:<fpr>`, `<abspath>`). The full map key is
/// `composite_key(kind, id)`.
pub fn resolve_secret(cfg: &Config, kind: &str, id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = composite_key(kind, id);
    match cfg.secret_backend {
        Some(SecretBackend::Tpm) => tpm::unseal(&key, cfg),
        Some(SecretBackend::Escrow) => {
            let map = escrow_map(cfg)?;
            map.get(&key)
                .cloned()
                .with_context(|| format!("secret '{key}' not found in escrow"))
        }
        None => bail!("resolve_secret called in legacy mode (no secret_backend configured)"),
    }
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
fn escrow_map(cfg: &Config) -> Result<&'static SecretMap> {
    if let Some(m) = ESCROW_CACHE.get() {
        return Ok(m);
    }
    let blob = std::fs::read(&cfg.escrow_file)
        .with_context(|| format!("reading escrow file {}", cfg.escrow_file.display()))?;
    let master = read_master_passphrase(cfg)?;
    let map = escrow::open(&blob, &master)?;
    Ok(ESCROW_CACHE.get_or_init(|| map))
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
            stray_dir: PathBuf::from("/c/stray"),
            enc_root: PathBuf::from("/e"),
            keyfile: PathBuf::from("/c/key"),
            default_idle: None,
            secret_backend: Some(backend),
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
        let secret = rand_bytes(24);
        tpm::seal(&secret, "gocryptfs:__shared__", &cfg).unwrap();
        let got = resolve_secret(&cfg, "gocryptfs", "__shared__").unwrap();
        assert_eq!(got.as_slice(), secret.as_slice());
    }
}
