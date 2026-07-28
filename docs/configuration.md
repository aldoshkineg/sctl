# Configuration

Config lives at `~/.config/sctl/config.toml` (see [`config.example.toml`](../config.example.toml)).

## Settings

```toml
[settings]
default_idle = "15m"
enc_root = "~/.encrypted"
secret_backend = "tpm"        # required: "tpm" | "escrow"

[secrets.gpg]
path = ".gnupg"
gpg = true
auto_kill = ["gpg-agent", "keyboxd", "scdaemon"]

[secrets.mail]
path = ".local/share/mail"
depends = ["gpg", "pass"]
idle = "30m"
auto_kill = ["lf", "nnn"]
```

### `settings`

| Field | Description |
|-------|-------------|
| `default_idle` | Global auto-unmount timeout (e.g. `"15m"`) |
| `enc_root` | Directory holding encrypted backends (one subdir per secret) |
| `secret_backend` | **Required.** `"tpm"` or `"escrow"` |
| `escrow_file` | Path to the age-encrypted escrow blob |
| `master_passphrase_file` | Emergency-only file for the master passphrase |
| `tpm_pcr` | Bind TPM seals to PCR 7 (secure-boot). Not implemented. |

### `secrets.NAME`

| Field | Description |
|-------|-------------|
| `path` | Cleartext mountpoint relative to `$HOME` |
| `depends` | Secrets that must be mounted first |
| `idle` | Per-secret idle timeout (overrides `default_idle`) |
| `auto_kill` | Processes killed silently on busy unmount |
| `kill_busy` | Enable the watch daemon for this secret |
| `kill_busy_after` | Busy threshold before force-unmount (default `"10m"`) |
| `gpg` | Restart all gpg daemons around mount/unmount |
| `gpg_preset` | Preload gpg key passphrases from the backend |
| `pre_mount` | Shell commands to run before mounting |
| `post_mount` | Shell commands to run after mounting |
| `pre_unmount` | Shell commands to run before unmounting |
| `post_unmount` | Shell commands to run after unmounting |

## Secret backend (TPM + escrow)

`secret_backend` is **required**. It controls where the shared gocryptfs password `G` and per-gpg-key passphrases are stored.

- **`tpm`** — secrets are sealed into the machine's TPM (zero input on mount) and mirrored into an encrypted *escrow* blob for recovery.
- **`escrow`** — no TPM; secrets are decrypted from the escrow blob using a master passphrase (`SCTL_MASTER_PASS`, `master_passphrase_file`, or a prompt).

`G` is entered once at `sctl install` and stored only in the backend — there is no plaintext keyfile on disk. Before the first `install`, `mount`/`init` prompt for the gocryptfs password so you can mount a volume to enroll it.

```toml
[settings]
secret_backend = "tpm"
escrow_file    = "~/.config/sctl/sctl-escrow.age"
# master_passphrase_file = "~/.config/sctl/master.pass"   # emergency only
# tpm_pcr        = false                    # bind seals to PCR 7 (secure-boot)

[secrets.gpg]
path   = ".gnupg"
gpg    = true
gpg_preset = true                            # manage this home's keys via the backend
```

## DEK model

`sctl` keeps one in-memory **secret map** — `gocryptfs:__shared__` → `G` plus `gpg:<home>:<fpr>` → passphrase for each enrolled key. That single map is serialized once (TOML, base64 secrets) and wrapped two ways:

| File | Wrapper | Purpose |
|------|---------|---------|
| `escrow_file` (`sctl-escrow.age`) | master passphrase (age/scrypt) | recovery, portable to any machine |
| `state_dir/tpm/map.age` | **DEK** (age X25519, "password" = base64(DEK)) | daily fast path on this machine |
| `state_dir/tpm/dek.priv`+`dek.pub` | sealed in TPM | holds the DEK (32 random bytes) |
| `$XDG_RUNTIME_DIR/sctl/prim-<hash>.ctx` | — (non-secret, per-boot tmpfs) | cached primary-key context |

A TPM can only seal ≈128 bytes, so the whole map (larger) is encrypted with a random **DEK** that is what actually gets sealed. On mount, `sctl` does **one** `tpm2_unseal` to get the DEK, then decrypts the whole `map.age` into a process-local `Zeroizing` cache — every subsequent `resolve_secret` hits the cache. The primary-key context is created once (`tpm2_createprimary`, ~2s) and cached in tmpfs; later mounts only `load`+`unseal` (~1s). The escrow file is the identical container, merely wrapped with the master passphrase instead of the DEK.

All secret bytes in memory are `Zeroizing` (zeroized on drop).

## `sctl install` — the single writer

Enrolls every managed secret into the backend in one atomic, in-memory pass: prompts for the shared gocryptfs password `G` (or reads `CRYPT_PASS`), then asks once **`Use encryption for gpg keys? [y/N]`**. Answering `y` collects each `gpg_preset` gpg home's key passphrase and seals every entry into the TPM (tpm backend) **and** writes the age/scrypt escrow blob atomically. Answering `n` enrolls only `G` — any previously enrolled gpg keys are dropped from the live backend (see backup below). Run it once on each machine:

```sh
SCTL_MASTER_PASS=... sctl install
```

`install` rewrites the **entire** backend every time (a fresh DEK, a fresh map, a fresh escrow blob). Before overwriting, if a previous `tpm`/`escrow` configuration exists, it is copied verbatim to a timestamped directory under `$TMPDIR` (`sctl-backup-<pid>-<nanos>`) and an informational line is printed, so the prior configuration can always be recovered by hand.

## First run / migrating an existing machine

Your volumes already exist and their gocryptfs password is known — the goal is to bring up the backend **without** re-keying the volumes.

> The gpg home is itself an encrypted volume and must be mounted *before* `install`, otherwise enrolment can't find the keys. Because `secret_backend` is required, `mount`/`init` prompt for the gocryptfs password (or read `CRYPT_PASS`) until the first `install` populates the backend.

```sh
# 0. mount the gpg volume so ~/.gnupg appears. Backend is empty -> sctl asks
#    for the gocryptfs password (the one that already encrypts your volumes).
sctl mount gpg

# 1. master passphrase for this install session (encrypts the escrow blob).
#    This is a NEW recovery password, not the gocryptfs/gpg password.
export SCTL_MASTER_PASS='...recovery password...'

# 2. enroll: prompt for the gocryptfs password -> G (sealed into TPM); for each
#    gpg_preset key, enter its CURRENT passphrase (kept as-is, see below).
sctl install

# 3. verify.
sctl check
sctl recovery          # base64 gocryptfs:__shared__ — compare if needed

# 4. switch to backend mounting (gpg passphrase is now preset from TPM).
sctl umount gpg && sctl mount gpg

# 5. (optional) harden: drop a master_passphrase_file (0600) for emergency recovery.
```

`install` does **not** regenerate the volume key — it adopts the password you type as `G`. If you ever kept a plaintext key (older builds), remove it after enrolment: `rm ~/.config/sctl/key` and drop any `keyfile = …` line from `config.toml`.

## gpg passphrase preloading

Re-entering your gpg key passphrase after every mount is tedious (the agent is restarted on mount, so its cache is empty). Set `gpg_preset = true` on the `.gnupg` secret and sctl will, right after mounting, preset the secret-key passphrases into gpg-agent via `gpg-preset-passphrase`.

Two modes:

- **Managed** (`gpg_preset = true` on the secret): the passphrases are resolved from the backend (TPM or escrow, per `secret_backend`) and preloaded automatically — no manual entry, no seed file. Run `sctl install` once to enroll the keys.
- **Manual** (`gpg_preset` unset): gpg-agent is restarted on mount and you type the passphrase once. There is no automatic preloading.

Setup for backend mode:

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

Preset failures are warnings and never abort the mount.

## zsh environment secrets (`zshenv`)

A secret can hold a zsh env file that your shell sources. The file lives *inside* the encrypted volume, so while the volume is unmounted it does not exist and `.zshrc` simply skips it — secrets never leak into a shell while the volume is locked. Once mounted, new shells pick them up automatically.

1. Declare the secret (any mount point you like):
   ```toml
   [secrets.zshenv]
   path = ".zsh-sec"      # mounts ~/.zsh-sec from ~/.encrypted/.zsh_sec
   depends = ["gpg"]      # optional: also bring up the gpg agent
   ```
   ```sh
   sctl init zshenv
   sctl mount zshenv
   ```

2. Put your exports *inside* the mounted volume (e.g. `~/.zsh-sec/env.zsh`):
   ```zsh
   export API_TOKEN=...
   export DB_PASSWORD=...
   ```

3. Source it conditionally from `~/.zshrc`:
   ```zsh
   # sctl-managed zsh env secrets
   ZSH_SEC=~/.zsh-sec/env.zsh
   [[ -f $ZSH_SEC ]] && source "$ZSH_SEC"

   # mount the volume (pulls gpg) and load secrets into the current shell
   zsec() { sctl mount zshenv && [[ -f $ZSH_SEC ]] && source "$ZSH_SEC"; }
   ```
   With the volume unmounted, `ZSH_SEC` is absent and the `[[ -f ]]` guard no-ops. After `zsec` (or opening a new terminal) the variables are exported into the environment. Remount/`idle`-unmount does not retroactively clear variables already exported into running shells — only new shells start clean.
