//! Password resolution into a temporary 0600 passfile (never exposed via `ps`).

use anyhow::{Context, Result, bail};
use std::env;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// A temporary passfile that is deleted on drop.
pub struct Passfile {
    inner: NamedTempFile,
}

impl Passfile {
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

fn new_tmp() -> Result<NamedTempFile> {
    let tmp = NamedTempFile::new().context("creating temp passfile")?;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    Ok(tmp)
}

/// Write already-resolved secret bytes to a fresh 0600 temp passfile. Used by
/// the secret-backend path (`secret::resolve_secret` -> gocryptfs passfile) and
/// by the interactive prompt fallbacks below.
pub fn from_bytes(data: &[u8]) -> Result<Passfile> {
    let mut tmp = new_tmp()?;
    tmp.write_all(data)?;
    tmp.flush()?;
    Ok(Passfile { inner: tmp })
}

/// The `CRYPT_PASS` env override (automation / tests): a non-interactive source
/// for the gocryptfs password so unattended runs and the test suite do not need
/// a tty. It is not persisted anywhere.
fn crypt_pass_env() -> Option<Zeroizing<Vec<u8>>> {
    env::var_os("CRYPT_PASS").map(|v| Zeroizing::new(v.as_encoded_bytes().to_vec()))
}

/// Resolve the gocryptfs password for `name`: the `CRYPT_PASS` env override if
/// set, otherwise an interactive prompt. When `confirm` is true the prompt is
/// asked twice and must match (used by `init`, which *creates* a container and
/// so must not silently record a typo'd password).
pub fn read_password(name: &str, confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(pw) = crypt_pass_env() {
        return Ok(pw);
    }
    let pw1 = Zeroizing::new(
        rpassword::prompt_password(format!("Password for '{name}': "))
            .context("reading password")?,
    );
    if confirm {
        let pw2 =
            Zeroizing::new(rpassword::prompt_password("Confirm: ").context("reading password")?);
        if *pw1 != *pw2 {
            bail!("passwords do not match");
        }
    }
    Ok(Zeroizing::new(pw1.as_bytes().to_vec()))
}

/// Resolve the gocryptfs password (see [`read_password`]) and write it to a
/// fresh 0600 temp passfile.
pub fn prompt(name: &str, confirm: bool) -> Result<Passfile> {
    let pw = read_password(name, confirm)?;
    from_bytes(&pw)
}
