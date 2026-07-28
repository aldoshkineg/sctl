# Security properties

- **Only ciphertext on disk.** TPM blobs and the age-encrypted escrow blob are the only files written to disk. There is no plaintext keyfile in the config directory.
- **Stolen-disk useless.** TPM blobs won't open off the chip; the escrow blob requires the master passphrase.
- **Passphrases ≠ keys.** `gpg`/`ssh` keys keep their fingerprint/keygrip; `sctl` only caches the existing passphrase and never changes the actual key.
- **Atomic writes.** Both backends are derived from one in-memory map and written atomically (tmp + rename, `0600`), so the TPM and escrow views cannot diverge through normal operation.
- **Zeroized memory.** All secret bytes use `Zeroizing` and are cleared on drop.
- **Advisory file locking.** Each secret is guarded by an advisory lock, so concurrent `sctl` invocations touching the same secret fail fast instead of racing.

## DEK model

`sctl` keeps one in-memory **secret map** — the gocryptfs shared password `G` plus per-gpg-key passphrases. That map is serialized once (TOML, base64 secrets) and wrapped two ways:

| File | Wrapper | Purpose |
|------|---------|---------|
| `escrow_file` (`sctl-escrow.age`) | master passphrase (age/scrypt) | recovery, portable to any machine |
| `state_dir/tpm/map.age` | **DEK** (age X25519, password = base64(DEK)) | daily fast path on this machine |
| `state_dir/tpm/dek.priv`+`dek.pub` | sealed in TPM | holds the DEK (32 random bytes) |
| `$XDG_RUNTIME_DIR/sctl/prim-<hash>.ctx` | — (non-secret, per-boot tmpfs) | cached primary-key context |

A TPM can only seal ≈128 bytes, so the map (larger) is encrypted with a random **DEK** that is what actually gets sealed. On mount, `sctl` does one `tpm2_unseal` to get the DEK, then decrypts the whole `map.age` into a process-local `Zeroizing` cache. The escrow file is the identical container, merely wrapped with the master passphrase instead of the DEK.

## Known limitations

- **gpg passphrase is not rotated.** gpg 2.5.x won't apply a different passphrase non-interactively, so `install` stores the existing passphrase and presets it; keys are still auto-unlocked, just not randomized.
- **PCR binding is not implemented.** `tpm_pcr = true` is rejected; seals are not bound to secure-boot PCRs.
- **SSH key passphrases are not yet managed.** Only gocryptfs + gpg are enrolled; standalone ssh keys (future `tpm_ssh`) are not. A `ssh` secret here is just a gocryptfs volume (`~/.ssh`); the key passphrases inside are untouched.