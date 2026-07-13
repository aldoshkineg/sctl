//! `sctl install`: enroll every managed secret into the configured backend.
//!
//! This is the single writer. It:
//!   1. prompts for the shared gocryptfs password `G` (or reads `CRYPT_PASS`),
//!   2. collects each `gpg_preset` gpg home's primary-key passphrase,
//!   3. seals every entry into the chosen backend:
//!      - `tpm`: a random DEK into the TPM, the map wrapped by the DEK (X25519,
//!        no scrypt); no master passphrase required,
//!      - `escrow`: the map wrapped by the master passphrase (scrypt) into the
//!        escrow file.
//!
//! NOTE on gpg passphrase rotation (docs/SECRETS.md §11.6): gpg 2.5.x cannot
//! non-interactively change a key's passphrase to a *different* value via the
//! loopback pinentry (it reuses the same passphrase for the old and new
//! prompts), and offers no `--quick-passwd`. Until that is solved (e.g. a custom
//! pinentry wrapper), `install` stores the *existing* passphrase so sctl can
//! preset it into gpg-agent. The secret is still sealed/unlocked by the backend;
//! only the "random rotation" hardening is deferred.

use crate::config::{Config, Secret, SecretBackend};
use crate::escrow;
use crate::gpg;
use crate::secret;
use crate::tpm;
use anyhow::{Context, Result, bail};
use rand::{Rng, rng};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

/// Options for the install command.
pub struct InstallOpts {
    /// Restrict enrollment to these secret names (empty = all managed).
    pub names: Vec<String>,
}

/// Source of an existing gpg key passphrase. Abstracted so tests can supply a
/// known value without an interactive prompt. `home` is the mounted gpg home
/// (used to verify the passphrase); `uid` is the key's `Name <email>` for a
/// human-readable prompt; `grips` are the key's keygrips (used to verify).
///
/// Returns `None` to *skip* this key (exclude it from backend enrollment).
pub trait GpgPassProvider {
    fn get(
        &self,
        secret: &Secret,
        home: &Path,
        fpr: &str,
        uid: &str,
        grips: &[String],
    ) -> Result<Option<Zeroizing<String>>>;
}

/// Real provider: prompt on the terminal, verifying the passphrase against the
/// key via gpg-agent so a typo is caught immediately (rather than only at the
/// next `mount`). An empty entry (just Enter) *skips* the key.
pub struct PromptProvider;

impl GpgPassProvider for PromptProvider {
    fn get(
        &self,
        secret: &Secret,
        home: &Path,
        fpr: &str,
        uid: &str,
        grips: &[String],
    ) -> Result<Option<Zeroizing<String>>> {
        let shown = &fpr[..fpr.len().min(16)];
        let label = format!(
            "Passphrase for gpg key {} ({}) [secret '{}'] (empty = skip this key): ",
            shown, uid, secret.name
        );
        loop {
            let pass = Zeroizing::new(
                rpassword::prompt_password(&label).context("reading gpg passphrase")?,
            );
            if pass.is_empty() {
                eprintln!("skipping gpg key {shown}");
                return Ok(None);
            }
            if let Some(g) = grips.first() {
                match gpg::verify_passphrase(home, fpr, g, pass.as_bytes()) {
                    Ok(()) => return Ok(Some(pass)),
                    Err(e) => {
                        eprintln!("passphrase verification failed ({e:#}); try again");
                        continue;
                    }
                }
            }
            return Ok(Some(pass));
        }
    }
}

/// Known-value provider for tests.
pub struct ConstProvider<'a> {
    pub pass: &'a str,
}

impl GpgPassProvider for ConstProvider<'_> {
    fn get(
        &self,
        _secret: &Secret,
        _home: &Path,
        _fpr: &str,
        _uid: &str,
        _grips: &[String],
    ) -> Result<Option<Zeroizing<String>>> {
        Ok(Some(Zeroizing::new(self.pass.to_string())))
    }
}

/// Source of the shared gocryptfs password `G`. Abstracted so tests can supply a
/// known value without an interactive prompt.
pub trait GocryptfsKeyProvider {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>>;
}

/// Real provider: prompt on the terminal (confirmed), or read `CRYPT_PASS`.
pub struct PromptKey;

impl GocryptfsKeyProvider for PromptKey {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>> {
        let g = crate::passfile::read_password("gocryptfs container", true)?;
        if g.is_empty() {
            bail!("gocryptfs password is empty");
        }
        Ok(g)
    }
}

/// Known-value provider for tests.
pub struct ConstKey<'a> {
    pub key: &'a [u8],
}

impl GocryptfsKeyProvider for ConstKey<'_> {
    fn get(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.key.to_vec()))
    }
}

/// Build the secret map to enroll.
///
/// `names` restricts which `gpg_preset` gpg homes are enrolled (empty = all). The
/// shared gocryptfs key is always enrolled (from `g_provider`).
pub fn build_map(
    cfg: &Config,
    g_provider: &dyn GocryptfsKeyProvider,
    provider: &dyn GpgPassProvider,
    names: &[String],
) -> Result<escrow::SecretMap> {
    let mut map = escrow::SecretMap::new();

    // Shared gocryptfs key G: prompt for it (or read CRYPT_PASS).
    let g = g_provider.get()?;
    if g.is_empty() {
        bail!("gocryptfs password is empty");
    }
    map.insert(secret::composite_key("gocryptfs", "__shared__"), g);

    for secret in cfg.secrets.values() {
        if !secret.gpg_preset {
            continue;
        }
        if !names.is_empty() && !names.contains(&secret.name) {
            continue;
        }
        let home = secret.mountpoint(&cfg.home);
        if !home.exists() {
            bail!(
                "gpg home for secret '{}' does not exist at {}",
                secret.name,
                home.display()
            );
        }
        let keys = gpg::keys_with_keygrips(&home)
            .with_context(|| format!("listing gpg keys for '{}'", secret.name))?;
        if keys.is_empty() {
            bail!("no gpg secret keys found for secret '{}'", secret.name);
        }
        for (fpr, uid, grips) in keys {
            let Some(pass) = provider.get(secret, &home, &fpr, &uid, &grips)? else {
                continue; // key skipped by the user (empty passphrase entry)
            };
            let pass_bytes = Zeroizing::new(pass.as_bytes().to_vec());
            map.insert(
                secret::composite_key("gpg", &secret::gpg_id_tail(&secret.name, &fpr)),
                pass_bytes,
            );
        }
    }
    Ok(map)
}

/// Persist the secret map into the configured backend.
///
/// - **TPM**: generate a random 32-byte DEK, seal it into the TPM, and write the
///   map wrapped by the DEK (X25519, no scrypt) to `tpm_map_file`. A single
///   `tpm2_unseal` of the DEK then decrypts the whole map at mount time. In
///   addition, an `escrow_file` (master-passphrase, scrypt) backup copy is
///   written so the secrets remain recoverable if the TPM ever breaks — it is
///   only read by `sctl recovery`, never on the daily TPM mount path.
/// - **Escrow**: wrap the map with the master passphrase (scrypt) into
///   `escrow_file`.
///
/// All files are written atomically (tmp + rename) with `0600` perms. `finalize`
/// is the sole writer (see docs §6).
pub fn finalize(cfg: &Config, map: &escrow::SecretMap) -> Result<()> {
    match cfg.secret_backend {
        SecretBackend::Tpm => {
            let mut dek = Zeroizing::new(vec![0u8; 32]);
            rng().fill_bytes(dek.as_mut_slice());
            tpm::seal_dek(&dek, cfg).context("sealing DEK into TPM")?;
            let blob = tpm::seal_map(map, &dek).context("sealing TPM map with DEK")?;
            std::fs::create_dir_all(cfg.tpm_dir())
                .with_context(|| format!("creating {}", cfg.tpm_dir().display()))?;
            write_atomic(&cfg.tpm_map_file(), &blob)?;

            // Recovery backup: master-passphrase copy, read only by `sctl recovery`.
            let master = secret::read_master_passphrase(cfg)?;
            let escrow_blob = escrow::seal(map, &master).context("sealing escrow backup")?;
            write_atomic(&cfg.escrow_file, &escrow_blob)?;
            Ok(())
        }
        SecretBackend::Escrow => {
            let master = secret::read_master_passphrase(cfg)?;
            let blob = escrow::seal(map, &master).context("sealing escrow container")?;
            write_atomic(&cfg.escrow_file, &blob)?;
            Ok(())
        }
    }
}

/// Write `data` to `path` atomically (tmp + rename) with `0600` permissions,
/// regardless of umask (the contents hold every secret).
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// CLI entry: enroll the configured secrets.
pub fn run(cfg: &Config, opts: &InstallOpts) -> Result<()> {
    if !opts.names.is_empty() {
        for n in &opts.names {
            cfg.get(n)?;
        }
    }
    let map = build_map(cfg, &PromptKey, &PromptProvider, &opts.names)?;
    finalize(cfg, &map)?;
    eprintln!("installed {} secret(s) into the backend", map.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretBackend;
    use crate::recovery;
    use rand::Rng;
    use rand::rng;
    use std::path::PathBuf;

    fn rand_bytes(n: usize) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![0u8; n]);
        rng().fill_bytes(&mut b);
        b
    }

    fn base_cfg(backend: SecretBackend) -> Config {
        let dir = std::env::temp_dir().join(format!("sctl-install-{backend:?}"));
        Config {
            home: PathBuf::from("/h"),
            state_dir: dir.clone(),
            enc_root: PathBuf::from("/e"),
            default_idle: None,
            secret_backend: backend,
            escrow_file: dir.join("escrow.age"),
            master_passphrase_file: None,
            tpm_pcr: false,
            secrets: Default::default(),
        }
    }

    const MASTER: &str = "test-master-pass";

    #[test]
    fn finalize_then_recovery_roundtrip_escrow() {
        let cfg = base_cfg(SecretBackend::Escrow);
        let _ = std::fs::remove_dir_all(&cfg.state_dir);
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        unsafe {
            std::env::set_var("SCTL_MASTER_PASS", MASTER);
        }

        let mut map = escrow::SecretMap::new();
        map.insert("gocryptfs:__shared__".into(), rand_bytes(32));
        map.insert("gpg:mail:ABCDEF".into(), rand_bytes(16));
        finalize(&cfg, &map).unwrap();

        let recovered = recovery::read_map(&cfg).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(
            recovered.get("gocryptfs:__shared__").unwrap().as_slice(),
            map.get("gocryptfs:__shared__").unwrap().as_slice()
        );
        assert_eq!(
            recovered.get("gpg:mail:ABCDEF").unwrap().as_slice(),
            map.get("gpg:mail:ABCDEF").unwrap().as_slice()
        );
    }

    #[test]
    fn finalize_then_resolve_tpm() {
        let cfg = base_cfg(SecretBackend::Tpm);
        let _ = std::fs::remove_dir_all(&cfg.state_dir);
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        unsafe {
            std::env::set_var("SCTL_MASTER_PASS", MASTER);
        }

        let mut map = escrow::SecretMap::new();
        map.insert("gocryptfs:__shared__".into(), rand_bytes(24));
        finalize(&cfg, &map).unwrap();

        // TPM backend does not write an escrow recovery file; verify via the TPM
        // resolution path instead.
        let recovered = secret::resolve_secret(&cfg, "gocryptfs", "__shared__").unwrap();
        assert_eq!(
            recovered.as_slice(),
            map.get("gocryptfs:__shared__").unwrap().as_slice()
        );
    }
}
