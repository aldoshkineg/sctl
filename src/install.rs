//! `sctl install`: enroll every managed secret into the configured backend.
//!
//! This is the single writer. It:
//!   1. adopts the shared gocryptfs key `G` from the existing keyfile,
//!   2. collects each `tpm_gpg` gpg home's primary-key passphrase,
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
/// known value without an interactive prompt.
pub trait GpgPassProvider {
    fn get(&self, secret: &Secret, fpr: &str) -> Result<Zeroizing<String>>;
}

/// Real provider: prompt on the terminal.
pub struct PromptProvider;

impl GpgPassProvider for PromptProvider {
    fn get(&self, secret: &Secret, fpr: &str) -> Result<Zeroizing<String>> {
        let shown = &fpr[..fpr.len().min(16)];
        let p = rpassword::prompt_password(format!(
            "Existing passphrase for gpg key {} (secret '{}'): ",
            shown, secret.name
        ))
        .context("reading gpg passphrase")?;
        Ok(Zeroizing::new(p))
    }
}

/// Known-value provider for tests.
#[allow(dead_code)]
pub struct ConstProvider<'a> {
    pub pass: &'a str,
}

impl GpgPassProvider for ConstProvider<'_> {
    fn get(&self, _secret: &Secret, _fpr: &str) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(self.pass.to_string()))
    }
}

/// Build the secret map to enroll.
///
/// `names` restricts which `tpm_gpg` gpg homes are enrolled (empty = all). The
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
        if !secret.tpm_gpg {
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
        let fprs = gpg::list_primary_fprs(&home)
            .with_context(|| format!("listing gpg keys for '{}'", secret.name))?;
        if fprs.is_empty() {
            bail!("no gpg secret keys found for secret '{}'", secret.name);
        }
        for fpr in fprs {
            let pass = provider.get(secret, &fpr)?;
            let pass_bytes = Zeroizing::new(pass.as_bytes().to_vec());
            map.insert(
                secret::composite_key("gpg", &secret::gpg_id_tail(&secret.name, &fpr)),
                pass_bytes,
            );
        }
    }
    Ok(map)
}

/// Seal every entry into the TPM (if TPM backend) and write the escrow file.
///
/// The escrow file is written atomically (tmp + rename). TPM blob writes are
/// consistent because `finalize` runs as the sole writer (see docs §6).
pub fn finalize(cfg: &Config, map: &escrow::SecretMap) -> Result<()> {
    if let Some(SecretBackend::Tpm) = cfg.secret_backend {
        for (id, secret) in map {
            tpm::seal(secret, id, cfg).with_context(|| format!("sealing '{id}' into TPM"))?;
        }
    }

    let master = secret::read_master_passphrase(cfg)?;
    let blob = escrow::seal(map, &master).context("sealing escrow container")?;

    let tmp = cfg.escrow_file.with_extension("age.tmp");
    std::fs::write(&tmp, &blob).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &cfg.escrow_file)
        .with_context(|| format!("installing {}", cfg.escrow_file.display()))?;
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
