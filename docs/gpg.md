# GPG integration

`sctl` manages gpg passphrases by integrating with `gpg-agent` in two ways:

1. Restarting `gpg-agent` on mount/unmount when `gpg = true` on the secret.
2. Preloading key passphrases into `gpg-agent` via `gpg-preset-passphrase` when `gpg_preset = true`.

## Managed mode (recommended)

Set `gpg_preset = true` on the `.gnupg` secret. `sctl` will resolve passphrases from the backend (TPM or escrow, per `secret_backend`) and preload them automatically — no manual entry, no seed file.

Setup:

1. Enable presetting in the volume's `~/.gnupg/gpg-agent.conf`:
   ```
   allow-preset-passphrase
   max-cache-ttl 86400
   ```
2. Configure the secret:
   ```toml
   [secrets.gpg]
   path = ".gnupg"
   gpg = true
   gpg_preset = true
   ```
3. Run `sctl install` once to enroll the keys.

Preset failures are warnings and never abort the mount.

## Manual mode

Leave `gpg_preset` unset. `gpg-agent` is restarted on mount and you type the passphrase once. There is no automatic preloading.

## gpg-agent restart behavior

When `gpg = true` is set on a secret, `sctl` runs `gpgconf --kill all` before mounting. After mounting, gpg-agent is fresh and has no cached passphrases. With `gpg_preset = true` these are immediately populated from the backend. Without it, you will be prompted for each key passphrase after mount.