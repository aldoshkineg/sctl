# Recovery

## Escrow blob

The escrow blob (`sctl-escrow.age`) is an encrypted copy of the entire secret map, wrapped with the master passphrase using age/scrypt encryption. It is written by `sctl install` and is the sole backend when `secret_backend = "escrow"`.

When `secret_backend = "tpm"`, the escrow is updated on every `install` as well — it serves as a portable backup that can be used on any machine without a TPM.

## Cross-machine recovery

If the hardware is lost or the TPM is unavailable, use the escrow blob to recover:

```sh
SCTL_MASTER_PASS=... sctl recovery
```

This decrypts the escrow blob with the master passphrase and prints the entire secret map to stdout (base64).

Optional prefix filter:

```sh
SCTL_MASTER_PASS=... sctl recovery gpg:
```

This prints only entries whose key starts with `gpg:` — useful for recovering just the gpg passphrases without exposing the full map.

## Recovering an existing machine

When setting up a new machine, copy the escrow blob to it and:

```sh
export SCTL_MASTER_PASS='...recovery password...'
export SCTL_CONFIG=...
sctl install
```

`install` will adopt `G` from `CRYPT_PASS` or the prompt, rewrite both backends from the in-memory map, and you'll be back to full functionality — zeroing the gpg-agent and preset passphrase cache on the new machine.

## Master passphrase

The master passphrase (`SCTL_MASTER_PASS`) is a *new* recovery password — it is not the gocryptfs or gpg password. It controls access to the escrow blob.

You can also provide it via:
- A dedicated file: `master_passphrase_file = "~/.config/sctl/master.pass"` (permissions `0600`)
- An interactive prompt if neither env nor file is set