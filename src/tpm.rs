//! TPM seal/unseal via the system `tpm2-tools` package (a runtime dependency).
//!
//! The interface is intentionally narrow (`seal_dek`/`unseal_dek`) so the
//! underlying implementation can later be swapped for the `tss-esapi` Rust
//! binding without touching callers (`secret.rs`, `install.rs`).
//!
//! Design (v0.8.5): the TPM does **not** seal each secret individually. Instead
//! `install` generates a random 32-byte data-encryption key (DEK), seals only
//! the DEK into the TPM (a small blob well under the ~128-byte TPM seal limit),
//! and encrypts the whole secret map with that DEK into `tpm_map_file` — the
//! exact same age-container format as the escrow file, just wrapped by the DEK
//! instead of the master passphrase. Daily use therefore needs a *single* TPM
//! unseal (of the DEK) to decrypt the entire map, and nothing about individual
//! keys (names, fingerprints) ever touches the filesystem.
//!
//! Seal/unseal flow (verified on the target machine, fTPM 2.0):
//! ```text
//! tpm2_createprimary -C o -c prim.ctx           # cached across mounts
//! echo -n "$DEK" | tpm2_create -C prim.ctx -i- -u dek.pub -r dek.priv
//! tpm2_load -C prim.ctx -u dek.pub -r dek.priv -c dek.ctx && tpm2_unseal -c dek.ctx
//! ```

use crate::config::Config;
use crate::escrow::SecretMap;
use age::x25519::{Identity, Recipient};
use anyhow::{Context, Result, bail};
use bech32::{ToBase32, Variant};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

/// Process-wide cache of unsealed DEKs, keyed by the sealed `dek.priv` path.
/// Avoids repeated TPM round-trips (load + unseal) within a single `sctl`
/// invocation. Keying by path keeps distinct state dirs (and concurrent tests)
/// from colliding. Safe because the DEK is never mutated on disk during a run.
static DEK_CACHE: OnceLock<Mutex<HashMap<PathBuf, Zeroizing<Vec<u8>>>>> = OnceLock::new();

/// Directory under `state_dir` holding the TPM blobs and the persisted primary
/// context (`prim.ctx`).
fn tpm_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("tpm")
}

/// The `(priv, pub)` paths of the sealed DEK. Fixed opaque names: nothing about
/// individual secrets is derivable from the filesystem.
fn dek_paths(state_dir: &Path) -> (PathBuf, PathBuf) {
    let dir = tpm_dir(state_dir);
    (dir.join("dek.priv"), dir.join("dek.pub"))
}

/// Ensure a primary-key context exists on disk, returning its path. The context
/// lives in a per-boot runtime dir (`cfg.primary_ctx_file`), not `state_dir`:
/// persisting it avoids the slow `tpm2_createprimary` (~2s) within a boot
/// session, but a TPM saved context is only valid until the next TPM reset, so
/// it is regenerated after each reboot anyway. It is not secret material.
///
/// Invariant (from the user's design): if the `.ctx` file is **present but
/// invalid** (e.g. the TPM owner was cleared / reset since it was written), the
/// later `tpm2_load` of the DEK fails clearly and the operator re-runs
/// `sctl install` — we do NOT silently recreate it here. The file is only
/// created when it is **absent**.
fn ensure_primary(cfg: &Config) -> Result<PathBuf> {
    let p = cfg.primary_ctx_file();
    if p.is_file() {
        return Ok(p);
    }
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let ps = p.to_str().context("prim.ctx path")?;
    run(&["tpm2_createprimary", "-C", "o", "-c", ps])
        .with_context(|| format!("creating TPM primary key at {ps}"))?;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok();
    Ok(p)
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

/// Whether the sealed DEK exists (i.e. the TPM backend has been enrolled via
/// `sctl install`). Used by `mount` to decide whether to prompt for the
/// gocryptfs password before enrollment (migration window) and by `check` for
/// presence reporting.
pub fn dek_exists(cfg: &Config) -> bool {
    let (priv_path, _) = dek_paths(&cfg.state_dir);
    priv_path.is_file()
}

/// Seal the data-encryption key `dek` into the TPM, writing `dek.priv`/`dek.pub`
/// into `state_dir/tpm/`. PCR-bound seals are not yet implemented (docs §5);
/// `cfg.tpm_pcr` triggers an explicit error rather than a silent skip.
pub fn seal_dek(dek: &[u8], cfg: &Config) -> Result<()> {
    if cfg.tpm_pcr {
        bail!("PCR-bound TPM seals (tpm_pcr=true) are not yet implemented");
    }
    std::fs::create_dir_all(tpm_dir(&cfg.state_dir))
        .with_context(|| format!("creating {}", tpm_dir(&cfg.state_dir).display()))?;
    let (priv_path, pub_path) = dek_paths(&cfg.state_dir);

    let prim_ctx = ensure_primary(cfg)?;
    let prim_s = prim_ctx.to_str().context("prim.ctx path")?;
    let pub_s = pub_path.to_str().context("pub path")?;
    let priv_s = priv_path.to_str().context("priv path")?;

    run_stdin(
        dek,
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
    )
    .context("sealing DEK into TPM (primary context established by ensure_primary)")?;

    // Restrictive perms regardless of umask: the `.priv` blob is the sealed DEK.
    std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600)).ok();
    std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o600)).ok();
    Ok(())
}

/// Derive the X25519 identity used to wrap the secret map from the raw DEK.
/// The DEK is a random 32-byte value, used directly as the X25519 scalar; the
/// matching recipient is `to_public()`. This lets the map be sealed/opened via
/// a fast X25519 key agreement (no scrypt KDF), unlike the escrow backend which
/// wraps the map with the master passphrase.
///
/// `age::x25519::Identity` has no `From<[u8; 32]>` constructor, so we round-trip
/// the DEK through age's own secret-key string encoding (base32 + bech32 with
/// the `age-secret-key-` HRP), which is deterministic and reverses `to_string`.
pub fn dek_identity(dek: &[u8]) -> Identity {
    let sk_base32 = dek.to_base32();
    let encoded = bech32::encode("age-secret-key-", sk_base32, Variant::Bech32)
        .expect("HRP is valid")
        .to_uppercase();
    age::x25519::Identity::from_str(&encoded).expect("DEK is a valid X25519 scalar")
}

/// Seal the secret map under the DEK via X25519 (no scrypt), returning the
/// age-encrypted bytes written to `tpm_map_file`.
pub fn seal_map(map: &SecretMap, dek: &[u8]) -> Result<Vec<u8>> {
    let recipient: Recipient = dek_identity(dek).to_public();
    crate::escrow::seal_recipient(map, &recipient)
}

/// Unseal the DEK from the TPM (cached for the process session).
pub fn unseal_dek(cfg: &Config) -> Result<Zeroizing<Vec<u8>>> {
    if cfg.tpm_pcr {
        bail!("PCR-bound TPM seals (tpm_pcr=true) are not yet implemented");
    }
    let (priv_path, pub_path) = dek_paths(&cfg.state_dir);
    if let Some(cache) = DEK_CACHE.get()
        && let Ok(g) = cache.lock()
        && let Some(v) = g.get(&priv_path)
    {
        return Ok(v.clone());
    }

    if !priv_path.is_file() {
        bail!(
            "TPM DEK missing at {} (run `sctl install`)",
            priv_path.display()
        );
    }
    let prim_ctx = ensure_primary(cfg)?;
    let prim_s = prim_ctx.to_str().context("prim.ctx path")?;
    let pub_s = pub_path.to_str().context("pub path")?;
    let priv_s = priv_path.to_str().context("priv path")?;

    let tmp = tempfile::tempdir().context("tpm tempdir")?;
    let loaded = tmp.path().join("dek.ctx");
    let loaded_s = loaded.to_str().context("dek.ctx path")?;

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
    ])
    .context("loading sealed DEK (primary context validated by ensure_primary)")?;

    let mut out = Zeroizing::new(Vec::new());
    run_capture(&["tpm2_unseal", "-c", loaded_s], &mut out)?;

    if let Ok(mut g) = DEK_CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        g.insert(priv_path, out.clone());
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
            enc_root: PathBuf::from("/e"),
            default_idle: None,
            secret_backend: SecretBackend::Tpm,
            escrow_file: PathBuf::from("/c/sctl-escrow.age"),
            master_passphrase_file: None,
            tpm_pcr: false,
            secrets: Default::default(),
        }
    }

    #[test]
    fn dek_seal_unseal_roundtrip() {
        let cfg = test_cfg();
        let _ = std::fs::remove_dir_all(tpm_dir(&cfg.state_dir));
        let dek = b"0123456789abcdef0123456789abcdef";
        seal_dek(dek, &cfg).expect("seal_dek");
        // Fresh cache: no prior process state to clear, read straight back from
        let got = unseal_dek(&cfg).expect("unseal_dek");
        assert_eq!(got.as_slice(), dek);
    }
}
