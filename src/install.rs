//! `sctl install`: enroll every managed secret into the configured backend.
//!
//! This is the single writer. It:
//!   1. adopts the shared gocryptfs key `G` from the existing keyfile,
//!   2. collects each `gpg_preset` gpg home's primary-key passphrase,
//!   3. seals every entry into the TPM (when `secret_backend = "tpm"`), and
//!   4. writes the age/scrypt escrow container atomically.
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
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::{Rng, rng};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use zeroize::Zeroizing;

/// Options for the install command.
pub struct InstallOpts {
    /// Restrict enrollment to these secret names (empty = all managed).
    pub names: Vec<String>,
    /// Interactive mode (key selection picker; deferred, see docs §11.4).
    #[allow(dead_code)]
    pub interactive: bool,
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
#[allow(dead_code)]
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

/// Build the secret map to enroll.
///
/// `names` restricts which `gpg_preset` gpg homes are enrolled (empty = all). The
/// shared gocryptfs key is always enrolled.
pub fn build_map(
    cfg: &Config,
    provider: &dyn GpgPassProvider,
    names: &[String],
) -> Result<escrow::SecretMap> {
    let mut map = escrow::SecretMap::new();

    // Shared gocryptfs key G: adopt the existing keyfile bytes.
    let g = Zeroizing::new(
        std::fs::read(&cfg.keyfile)
            .with_context(|| format!("reading keyfile {}", cfg.keyfile.display()))?,
    );
    if g.is_empty() {
        bail!(
            "keyfile {} is empty; run `sctl init` for at least one secret first",
            cfg.keyfile.display()
        );
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

/// Persist the secret map into the configured backend(s).
///
/// Always writes the escrow container (age/scrypt, master passphrase) as the
/// portable recovery copy. In TPM mode additionally: generate a random 32-byte
/// DEK, seal it into the TPM, and write the *same* map wrapped by that DEK to
/// `tpm_map_file` (identical age format, DEK instead of the master passphrase).
/// A single `tpm2_unseal` of the DEK then decrypts the whole map at mount time.
///
/// All files are written atomically (tmp + rename) with `0600` perms. `finalize`
/// is the sole writer, so the two copies stay consistent (see docs §6).
pub fn finalize(cfg: &Config, map: &escrow::SecretMap) -> Result<()> {
    // Recovery copy: escrow wrapped by the master passphrase.
    let master = secret::read_master_passphrase(cfg)?;
    let escrow_blob = escrow::seal(map, &master).context("sealing escrow container")?;
    write_atomic(&cfg.escrow_file, &escrow_blob)?;

    // Fast path: TPM-sealed DEK + DEK-wrapped map (same format as escrow).
    if let Some(SecretBackend::Tpm) = cfg.secret_backend {
        let mut dek = Zeroizing::new(vec![0u8; 32]);
        rng().fill_bytes(dek.as_mut_slice());
        tpm::seal_dek(&dek, cfg).context("sealing DEK into TPM")?;

        let dek_pass = Zeroizing::new(B64.encode(dek.as_slice()));
        let tpm_blob = escrow::seal(map, &dek_pass).context("sealing TPM map with DEK")?;
        std::fs::create_dir_all(cfg.tpm_dir())
            .with_context(|| format!("creating {}", cfg.tpm_dir().display()))?;
        write_atomic(&cfg.tpm_map_file(), &tpm_blob)?;
    }
    Ok(())
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
    if cfg.secret_backend.is_none() {
        bail!(
            "secret_backend is not set; add `secret_backend = \"tpm\"` or \
             `secret_backend = \"escrow\"` to [settings] in the config"
        );
    }
    if !opts.names.is_empty() {
        for n in &opts.names {
            cfg.get(n)?;
        }
    }
    let map = build_map(cfg, &PromptProvider, &opts.names)?;
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
            stray_dir: PathBuf::from("/c/stray"),
            enc_root: PathBuf::from("/e"),
            keyfile: PathBuf::from("/c/key"),
            default_idle: None,
            secret_backend: Some(backend),
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
    fn finalize_then_recovery_roundtrip_tpm() {
        let cfg = base_cfg(SecretBackend::Tpm);
        let _ = std::fs::remove_dir_all(&cfg.state_dir);
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        unsafe {
            std::env::set_var("SCTL_MASTER_PASS", MASTER);
        }

        let mut map = escrow::SecretMap::new();
        map.insert("gocryptfs:__shared__".into(), rand_bytes(24));
        finalize(&cfg, &map).unwrap();

        let recovered = recovery::read_map(&cfg).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered.get("gocryptfs:__shared__").unwrap().as_slice(),
            map.get("gocryptfs:__shared__").unwrap().as_slice()
        );
    }
}
