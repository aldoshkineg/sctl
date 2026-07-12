//! `sctl recovery`: read the escrow container and print the secret map.
//!
//! The master passphrase is taken from `SCTL_MASTER_PASS`, the
//! `master_passphrase_file`, or an interactive prompt (see
//! `secret::read_master_passphrase`). Output is base64-encoded per entry so it
//! round-trips back into the binary format used everywhere else.

use crate::config::Config;
use crate::escrow::SecretMap;
use crate::secret;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// Read the full secret map from the escrow container.
pub fn read_map(cfg: &Config) -> Result<SecretMap> {
    let blob = std::fs::read(&cfg.escrow_file)
        .with_context(|| format!("reading escrow file {}", cfg.escrow_file.display()))?;
    let master = secret::read_master_passphrase(cfg)?;
    crate::escrow::open(&blob, &master)
}

/// CLI entry: print the secret map (optionally filtered by key prefix).
pub fn run(cfg: &Config, filter: Option<&str>) -> Result<()> {
    eprintln!("WARNING: printing secrets to stdout");
    let map = read_map(cfg)?;
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys {
        if let Some(f) = filter
            && !k.starts_with(f)
        {
            continue;
        }
        let v = map.get(k).unwrap();
        println!("{} = {}", k, B64.encode(v));
    }
    Ok(())
}
