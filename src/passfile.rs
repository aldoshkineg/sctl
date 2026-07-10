//! Password resolution into a temporary 0600 passfile (never exposed via `ps`).

use anyhow::{Context, Result, bail};
use std::env;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::NamedTempFile;

/// A temporary passfile that is deleted on drop.
pub struct Passfile {
    inner: NamedTempFile,
}

impl Passfile {
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

/// Resolve a password for `name` and write it to a fresh 0600 temp file.
///
/// Source order: `CRYPT_PASS` env, `SCTL_KEY` file, configured `keyfile`, then
/// an interactive prompt (with confirmation).
pub fn resolve(name: &str, keyfile: &Path) -> Result<Passfile> {
    let mut tmp = NamedTempFile::new().context("creating temp passfile")?;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;

    if let Some(pass) = env::var_os("CRYPT_PASS") {
        tmp.write_all(pass.as_encoded_bytes())?;
    } else if let Some(keyenv) = env::var_os("SCTL_KEY").filter(|k| !k.is_empty()) {
        let p = Path::new(&keyenv);
        if p.is_file() {
            let data = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            tmp.write_all(&data)?;
        } else {
            copy_or_prompt(&mut tmp, keyfile, name)?;
        }
    } else {
        copy_or_prompt(&mut tmp, keyfile, name)?;
    }

    tmp.flush()?;
    Ok(Passfile { inner: tmp })
}

fn copy_or_prompt(tmp: &mut NamedTempFile, keyfile: &Path, name: &str) -> Result<()> {
    if keyfile.is_file() {
        let data =
            std::fs::read(keyfile).with_context(|| format!("reading {}", keyfile.display()))?;
        tmp.write_all(&data)?;
        return Ok(());
    }
    let pw1 = rpassword::prompt_password(format!("Password for '{name}': "))
        .context("reading password")?;
    let pw2 = rpassword::prompt_password("Confirm: ").context("reading password")?;
    if pw1 != pw2 {
        bail!("passwords do not match");
    }
    tmp.write_all(pw1.as_bytes())?;
    Ok(())
}
