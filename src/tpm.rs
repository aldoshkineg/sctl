//! TPM seal/unseal via the system `tpm2-tools` package (dependency, see
//! docs/SECRETS.md §12).
//!
//! The interface is intentionally narrow (`seal`/`unseal`) so the underlying
//! implementation can later be swapped for the `tss-esapi` Rust binding
//! without touching callers (`secret.rs`, `install.rs`).
//!
//! Seal flow (verified on the target machine, fTPM 2.0):
//! ```text
//! tpm2_createprimary -C o -c prim.ctx
//! echo -n "$SECRET" | tpm2_create -C prim.ctx -i- -u <id>.pub -r <id>.priv
//! ```
//! Unseal recreates the primary (no NV persistence) and loads+unseals.

use crate::config::Config;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

/// Process-wide cache of unsealed secrets, keyed by composite id. Avoids
/// repeated TPM round-trips (createprimary + load + unseal) for the same id
/// within a single `sctl` invocation. Safe because secrets are never mutated
/// on disk during one run.
static UNSEAL_CACHE: OnceLock<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>> = OnceLock::new();

/// Directory under `state_dir` holding the per-id TPM blobs.
fn tpm_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tpm")
}

/// Resolve the `(priv, pub)` blob paths for a composite secret id. The id may
/// contain `:` and `/` (e.g. `ssh:/home/u/.ssh/id_ed25519`), so it is
/// sanitized into a filename.
fn blob_paths(state_dir: &Path, id: &str) -> Result<(PathBuf, PathBuf)> {
    let dir = tpm_dir(state_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let safe = id.replace(['/', ':'], "_");
    Ok((
        dir.join(format!("{safe}.priv")),
        dir.join(format!("{safe}.pub")),
    ))
}

fn run(args: &[&str]) -> Result<()> {
    let (program, rest) = args.split_first().context("empty command")?;
    let out = Command::new(program)
        .args(rest)
        .output()
        .with_context(|| format!("spawning {program}"))?;
    if !out.status.success() {
        bail!(
            "{} failed ({}):\n{}",
            program,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn run_stdin(bytes: &[u8], args: &[&str]) -> Result<()> {
    let (program, rest) = args.split_first().context("empty command")?;
    let mut child = Command::new(program)
        .args(rest)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().context("stdin")?;
        stdin.write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{} failed ({}):\n{}",
            program,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn run_capture(args: &[&str], out_buf: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    let (program, rest) = args.split_first().context("empty command")?;
    let out = Command::new(program)
        .args(rest)
        .output()
        .with_context(|| format!("spawning {program}"))?;
    if !out.status.success() {
        bail!(
            "{} failed ({}):\n{}",
            program,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out_buf.extend_from_slice(&out.stdout);
    Ok(())
}

/// Seal `secret` for composite id `id`, writing `<id>.priv`/`<id>.pub` into
/// `state_dir/tpm/`. PCR-bound seals are not yet implemented (see docs §5);
/// `cfg.tpm_pcr` currently triggers an explicit error rather than silent skip.
pub fn seal(secret: &[u8], id: &str, cfg: &Config) -> Result<()> {
    if cfg.tpm_pcr {
        bail!("PCR-bound TPM seals (tpm_pcr=true) are not yet implemented");
    }
    let (priv_path, pub_path) = blob_paths(&cfg.state_dir, id)?;
    let prim = tempfile::tempdir().context("tpm tempdir")?;
    let prim_ctx = prim.path().join("prim.ctx");
    let prim_s = prim_ctx.to_str().context("prim.ctx path")?;
    let pub_s = pub_path.to_str().context("pub path")?;
    let priv_s = priv_path.to_str().context("priv path")?;

    run(&["tpm2_createprimary", "-C", "o", "-c", prim_s])?;
    run_stdin(
        secret,
        &[
            "tpm2_create",
            "-C",
            prim_s,
            "-i",
            "-",
            "-u",
            pub_s,
            "-r",
            priv_s,
        ],
    )?;
    Ok(())
}

/// Whether a sealed TPM blob exists for composite id `id`.
pub fn exists(id: &str, cfg: &Config) -> bool {
    let safe = id.replace(['/', ':'], "_");
    cfg.state_dir
        .join("tpm")
        .join(format!("{safe}.priv"))
        .is_file()
}

/// Unseal the TPM blob for composite id `id`, returning the secret.
pub fn unseal(id: &str, cfg: &Config) -> Result<Zeroizing<Vec<u8>>> {
    if cfg.tpm_pcr {
        bail!("PCR-bound TPM seals (tpm_pcr=true) are not yet implemented");
    }
    // Serve from cache if we already unsealed this id this process.
    if let Some(cache) = UNSEAL_CACHE.get()
        && let Ok(g) = cache.lock()
        && let Some(v) = g.get(id)
    {
        return Ok(v.clone());
    }
    let (priv_path, pub_path) = blob_paths(&cfg.state_dir, id)?;
    if !priv_path.is_file() {
        bail!("TPM blob missing for '{id}' at {}", priv_path.display());
    }
    let prim = tempfile::tempdir().context("tpm tempdir")?;
    let prim_ctx = prim.path().join("prim.ctx");
    let loaded = prim.path().join("loaded.ctx");
    let prim_s = prim_ctx.to_str().context("prim.ctx path")?;
    let pub_s = pub_path.to_str().context("pub path")?;
    let priv_s = priv_path.to_str().context("priv path")?;
    let loaded_s = loaded.to_str().context("loaded.ctx path")?;

    run(&["tpm2_createprimary", "-C", "o", "-c", prim_s])?;
    run(&[
        "tpm2_load",
        "-C",
        prim_s,
        "-u",
        pub_s,
        "-r",
        priv_s,
        "-c",
        loaded_s,
    ])?;
    let mut out = Zeroizing::new(Vec::new());
    run_capture(&["tpm2_unseal", "-c", loaded_s], &mut out)?;

    if let Ok(mut g) = UNSEAL_CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        g.insert(id.to_string(), out.clone());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretBackend;

    fn test_cfg() -> Config {
        Config {
            home: PathBuf::from("/h"),
            state_dir: std::env::temp_dir().join("sctl-tpm-test"),
            stray_dir: PathBuf::from("/c/stray"),
            enc_root: PathBuf::from("/e"),
            keyfile: PathBuf::from("/c/key"),
            default_idle: None,
            secret_backend: Some(SecretBackend::Tpm),
            escrow_file: PathBuf::from("/c/sctl-escrow.age"),
            master_passphrase_file: None,
            tpm_pcr: false,
            secrets: Default::default(),
        }
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let cfg = test_cfg();
        let secret = b"super-secret-gocryptfs-key-material";
        let id = "gocryptfs:__shared__";
        seal(secret, id, &cfg).expect("seal");
        let got = unseal(id, &cfg).expect("unseal");
        assert_eq!(got.as_slice(), secret);
    }
}
