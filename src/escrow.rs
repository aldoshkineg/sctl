//! Escrow container: the full secret map encrypted under a master passphrase
//! via age (scrypt recipient), with the plaintext serialized as TOML.

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// The named secret map. Key = composite id (e.g. `gocryptfs:__shared__`,
/// `gpg:<home_id>:<fpr>`, `ssh:<abspath>`). Value = raw secret bytes, zeroized
/// on drop.
pub type SecretMap = BTreeMap<String, Zeroizing<Vec<u8>>>;

#[derive(Serialize, Deserialize)]
struct EscrowFile {
    secrets: BTreeMap<String, String>, // base64-encoded raw bytes
}

/// Seal the secret map under `master`, returning the age-encrypted bytes.
pub fn seal(map: &SecretMap, master: &Zeroizing<String>) -> Result<Vec<u8>> {
    let mut plain = EscrowFile {
        secrets: BTreeMap::new(),
    };
    for (k, v) in map {
        plain.secrets.insert(k.clone(), B64.encode(v));
    }
    let toml = toml::to_string(&plain).context("serializing escrow map")?;

    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(master.to_string()));
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .context("starting age encryption")?;
    writer
        .write_all(toml.as_bytes())
        .context("writing escrow plaintext")?;
    writer.finish().context("finalizing age encryption")?;
    Ok(encrypted)
}

/// Open an age-encrypted escrow blob with `master`, returning the secret map.
pub fn open(blob: &[u8], master: &Zeroizing<String>) -> Result<SecretMap> {
    let decryptor = age::Decryptor::new(blob).context("parsing age header")?;
    if !decryptor.is_scrypt() {
        bail!("escrow blob is not passphrase-protected");
    }
    let identity = age::scrypt::Identity::new(SecretString::from(master.to_string()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("decrypting escrow (wrong master passphrase?)")?;
    let mut toml_text = Zeroizing::new(String::new());
    reader
        .read_to_string(&mut toml_text)
        .context("reading escrow plaintext")?;

    let plain: EscrowFile = toml::from_str(&toml_text).context("parsing escrow TOML")?;
    let mut map = SecretMap::new();
    for (k, v) in plain.secrets {
        let bytes = B64
            .decode(&v)
            .with_context(|| format!("decoding secret '{k}'"))?;
        map.insert(k, Zeroizing::new(bytes));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand::rng;

    fn rand_bytes(n: usize) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![0u8; n]);
        rng().fill_bytes(&mut b);
        b
    }

    #[test]
    fn roundtrip_preserves_all_entries() {
        let mut map = SecretMap::new();
        let g = rand_bytes(32);
        let p = rand_bytes(16);
        map.insert("gocryptfs:__shared__".into(), g.clone());
        map.insert("gpg:home:abc123".into(), p.clone());

        let master = Zeroizing::new("correct horse battery staple".to_string());
        let blob = seal(&map, &master).expect("seal");
        assert!(!blob.is_empty());

        let opened = open(&blob, &master).expect("open");
        assert_eq!(opened.len(), 2);
        assert_eq!(
            opened.get("gocryptfs:__shared__").unwrap().as_slice(),
            g.as_slice()
        );
        assert_eq!(
            opened.get("gpg:home:abc123").unwrap().as_slice(),
            p.as_slice()
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let mut map = SecretMap::new();
        map.insert("k".into(), Zeroizing::new(vec![1, 2, 3]));
        let blob = seal(&map, &Zeroizing::new("right".to_string())).expect("seal");
        assert!(open(&blob, &Zeroizing::new("wrong".to_string())).is_err());
    }
}
