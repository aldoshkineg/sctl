# sctl

A config-driven [gocryptfs](https://github.com/rfjakob/gocryptfs) secret mount
manager. Keep sensitive directories (`~/.ssh`, `~/.gnupg`, a password store, a
mail spool, …) encrypted at rest and mount them on demand with:

- **Dependencies** — mounting `mail` can auto-mount `gpg` and `pass` first.
- **Smart-cascade unmount** — unmounting `mail` also unmounts dependencies that
  nothing else still needs; refuses to unmount a dependency another mount needs.
- **Idle auto-unmount** — per-secret or global idle timeout (via `gocryptfs -idle`).
- **Busy handling** — configurable `auto_kill` list per secret; otherwise it
  lists the holding processes and requires `--force`.
- **Colored status** — aligned table, mounted secrets highlighted.
- **No secrets in `ps`** — passwords are passed via a temporary `0600` passfile.

## Install

```sh
cargo install --path .
# or
cargo build --release && install -m755 target/release/sctl ~/.local/bin/sctl
```

Requires `gocryptfs` and `fusermount3` at runtime; `fuser` (busy detection) and
`notify-send` (`--notify`) are optional.

## Configuration

Config lives at `~/.config/sctl/config.toml` (see [`config.example.toml`](config.example.toml)):

```toml
[settings]
default_idle = "15m"
enc_root = "~/.encrypted"
secret_backend = "tpm"        # required: "tpm" | "escrow" (see below)

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

## Secret backend (TPM + escrow)

`sctl` manages its secrets (the shared gocryptfs password `G` and per-gpg-key
passphrases) through a hardware/escrow backend. `secret_backend` is **required**:

- **`tpm`** — secrets are sealed into the machine's TPM (zero input on mount)
  and mirrored into an encrypted *escrow* blob for recovery.
- **`escrow`** — no TPM; secrets are decrypted from the escrow blob using a
  master passphrase (env `SCTL_MASTER_PASS`, `master_passphrase_file`, or a
  prompt).

`G` is entered once at `sctl install` (prompt, or env `CRYPT_PASS` for
automation) and stored only in the backend — there is no plaintext keyfile on
disk. Before the first `install`, `mount`/`init` prompt for the gocryptfs
password so you can mount a volume to enroll it.

```toml
[settings]
secret_backend = "tpm"                       # required: "tpm" | "escrow"
escrow_file    = "~/.config/sctl/sctl-escrow.age"
# master_passphrase_file = "~/.config/sctl/master.pass"   # emergency only
# tpm_pcr        = false                    # bind seals to PCR 7 (secure-boot)

[secrets.gpg]
path   = ".gnupg"
gpg    = true
gpg_preset = true                            # manage this home's keys via the backend
```

### `sctl install` — the single writer

Enrolls every managed secret into the backend in one atomic, in-memory pass:
prompts for the shared gocryptfs password `G` (or reads `CRYPT_PASS`), then asks
once **`Use encryption for gpg keys? [y/N]`**. Answering `y` collects each
`gpg_preset` gpg home's key passphrase and seals every entry into the TPM (tpm
backend) **and** writes the age/scrypt escrow blob atomically. Answering `n`
enrolls only `G` — any previously enrolled gpg keys are dropped from the live
backend (see backup below). Run it once on each machine:

```sh
SCTL_MASTER_PASS=... sctl install
```

`install` rewrites the **entire** backend every time (a fresh DEK, a fresh map,
a fresh escrow blob). Before overwriting, if a previous `tpm`/`escrow`
configuration exists, it is copied verbatim to a timestamped directory under
`$TMPDIR` (`sctl-backup-<pid>-<nanos>`) and an informational line is printed, so
the prior configuration can always be recovered by hand.

### `sctl recovery`

Decrypts the escrow blob with the master passphrase and prints the **entire**
secret map to stdout (base64). Works on any machine, no TPM required — this is
how you recover access if the hardware is lost. Optional prefix filter
(e.g. `sctl recovery gpg:`):

```sh
SCTL_MASTER_PASS=... sctl recovery
```

### `sctl check`

Validates the backend: for `tpm` it checks `tpm2-tools`, `/dev/tpmrm0`, the
`tss` group, and per-secret TPM blobs; for `escrow` it checks the file and runs
a decrypt self-test. It also runs the **desync detector** — if both TPM blobs
and the escrow blob exist, it unseals both and compares them, failing loudly if
they agree (re-run `sctl install` to rewrite both from the single in-memory
map if they ever differ).

### How it works (DEK model)

`sctl` keeps one in-memory **secret map** — `gocryptfs:__shared__` → `G` plus
`gpg:<home>:<fpr>` → passphrase for each enrolled key. That single map is
serialized once (TOML, base64 secrets) and wrapped two ways:

| File | Wrapper | Purpose |
|------|---------|---------|
| `escrow_file` (`sctl-escrow.age`) | master passphrase (age/scrypt) | recovery, portable to any machine |
| `state_dir/tpm/map.age` | **DEK** (age X25519, "password" = base64(DEK)) | daily fast path on this machine |
| `state_dir/tpm/dek.priv`+`dek.pub` | sealed in TPM | holds the DEK (32 random bytes) |
| `$XDG_RUNTIME_DIR/sctl/prim-<hash>.ctx` | — (non-secret, per-boot tmpfs) | cached primary-key context |

A TPM can only seal ≈128 bytes, so the whole map (larger) is encrypted with a
random **DEK** that is what actually gets sealed. On mount, `sctl` does **one**
`tpm2_unseal` to get the DEK, then decrypts the whole `map.age` into a
process-local `Zeroizing` cache — every subsequent `resolve_secret` hits the
cache. The primary-key context is created once (`tpm2_createprimary`, ~2s) and
cached in tmpfs; later mounts only `load`+`unseal` (~1s). The escrow file is the
identical container, merely wrapped with the master passphrase instead of the
DEK.

All secret bytes in memory are `Zeroizing` (zeroized on drop).

### First run / migrating an existing machine

Your volumes already exist and their gocryptfs password is known — the goal is
to bring up the backend **without** re-keying the volumes.

> The gpg home is itself an encrypted volume and must be mounted *before*
> `install`, otherwise enrolment can't find the keys. Because `secret_backend`
> is required, `mount`/`init` prompt for the gocryptfs password (or read
> `CRYPT_PASS`) until the first `install` populates the backend.

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

`install` does **not** regenerate the volume key — it adopts the password you
type as `G`. If you ever kept a plaintext key (older builds), remove it after
enrolment: `rm ~/.config/sctl/key` and drop any `keyfile = …` line from
`config.toml`.

### Security properties

- Only ciphertext on disk: TPM blobs + the escrow blob under the master
  passphrase. No plaintext keyfile in the config dir.
- A stolen disk is useless: TPM blobs won't open off the chip, escrow needs the
  master passphrase.
- Changing a passphrase ≠ changing the key: `gpg`/`ssh` keys keep their
  fingerprint/keygrip; `sctl` only caches the existing passphrase.
- `install` is the single writer: both backends are derived from one in-memory
  map and written atomically (tmp + rename, `0600`), so the TPM and escrow
  views cannot diverge through normal operation.

### Known limitations

- **gpg passphrase is not rotated.** gpg 2.5.x won't apply a *different*
  passphrase non-interactively, so `install` stores the existing passphrase and
  presets it; keys are still auto-unlocked, just not randomized.
- **PCR binding is not implemented.** `tpm_pcr = true` is rejected; seals are
  not bound to secure-boot PCRs.
- **SSH key passphrases are not yet managed.** Only gocryptfs + gpg are enrolled;
  standalone ssh keys (future `tpm_ssh`) are not. A `ssh` secret here is just a
  gocryptfs volume (`~/.ssh`); the key passphrases inside are untouched.

## Usage

```sh
sctl init mail              # create container(s), migrate existing data
sctl mount mail             # mounts gpg, pass, then mail
sctl mount ssh gpg          # multiple at once
sctl mount all --no-idle    # everything, no idle auto-unmount
sctl mount mail --dry-run   # preview dependency resolution, do nothing
sctl status                 # colored, aligned table
sctl toggle mail            # mount if down, unmount if up (great for hotkeys)
sctl umount mail            # smart cascade
sctl umount all
sctl umount mail --force    # kill any process holding it busy
sctl umount mail --dry-run  # preview the cascade
sctl check                  # validate config, backends, perms, dependencies
sctl watch --once           # one pass: force-unmount secrets busy past threshold
sctl watch                  # resident loop (also auto-forked on `mount`)
sctl completions zsh        # shell completions (bash|zsh|fish|...)
```

Concurrent invocations are safe: each secret is guarded by an advisory lock, so
a second `sctl` touching the same secret fails fast instead of racing.

### `status` — `UNMOUNT IN` column

| Value  | Meaning                                              |
|--------|------------------------------------------------------|
| `-`    | not mounted                                          |
| `never`| mounted with idle disabled (`--no-idle`)            |
| `?`    | mounted, but not by sctl (no state file)            |
| `12m`  | estimated time until idle auto-unmount              |
| `busy` | idle estimate elapsed but still mounted (activity resets the timer) |

### Busy unmount policy

When a mount is busy on `umount`:

1. If **every** holding process is in the secret's `auto_kill` list → killed
   silently (SIGTERM, then SIGKILL), then unmounted.
2. If **any other** process holds it → nothing is killed; the processes are
   listed and `--force` is required.
3. `--force` kills all holders regardless. It also bypasses the dependency
   guard: a requested secret is unmounted even if other mounted secrets still
   depend on it (those dependents are left mounted, now broken). `--lazy`
   detaches immediately.

### Busy watcher (`kill_busy`)

A mounted secret can get stuck `busy` (e.g. gpg-agent keeps `~/.gnupg`
open, or a shell's cwd is inside it) so a normal idle/unmount can never
succeed. Mark a secret with `kill_busy` and the background **watcher**
force-unmounts it once it has been busy longer than `kill_busy_after`:

```toml
[secrets.gpg]
path = ".gnupg"
gpg = true
gpg_preset = true
kill_busy = true
kill_busy_after = "10m"   # optional; defaults to 10m
```

The `sctl mount` command forks a **single resident `sctl watch` daemon**
(singleton, guarded by a lock) whenever any secret enables `kill_busy`. The
watcher polls every 60s: for each mounted `kill_busy` secret it records when
it first became busy, and when that exceeds `kill_busy_after` it performs a
forced unmount (`gpg_kill` for gpg secrets, then kills the holders and
`fusermount`). It self-exits when nothing is left to watch and is respawned
by the next `mount`.

Run it manually / from cron as a single pass instead of the resident loop:

```sh
sctl watch --once        # one pass, then exit
sctl watch               # resident loop (same as the forked daemon)
```

Mounting a secret with `--no-idle` (or `SCTL_NO_IDLE`) opts it out of the
watcher entirely: `sctl mount` will not fork the daemon, and `sctl watch`
skips such volumes (their status column already shows `never`).

Note: because gpg-agent normally keeps `~/.gnupg` open, a `gpg` secret
counts as busy for its entire mounted lifetime — so `kill_busy` effectively
force-unmounts it `kill_busy_after` after mount. Set the threshold longer
than a typical session if you only want it reclaimed when truly stuck.

### gpg passphrase preloading

Re-entering your gpg key passphrase after every mount is tedious (the agent is
restarted on mount, so its cache is empty). Set `gpg_preset = true` on the
`.gnupg` secret and sctl will, right after mounting, preset the secret-key
passphrases into gpg-agent via `gpg-preset-passphrase`.

Two modes:

- **Managed** (`gpg_preset = true` on the secret): the passphrases are resolved
  from the backend (TPM or escrow, per `secret_backend`) and preloaded
  automatically — no manual entry, no seed file. Run `sctl install` once to
  enroll the keys.
- **Manual** (`gpg_preset` unset): gpg-agent is restarted on mount and you type
  the passphrase once. There is no automatic preloading.

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

### zsh environment secrets (`zshenv`)

A secret can hold a zsh env file that your shell sources. The file lives
*inside* the encrypted volume, so while the volume is unmounted it does not
exist and `.zshrc` simply skips it — secrets never leak into a shell while the
volume is locked. Once mounted, new shells pick them up automatically.

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
   With the volume unmounted, `ZSH_SEC` is absent and the `[[ -f ]]` guard
   no-ops. After `zsec` (or opening a new terminal) the variables are exported
   into the environment. Remount/`idle`-unmount does not retroactively clear
   variables already exported into running shells — only new shells start clean.

## Environment overrides

`SCTL_CONFIG_DIR`, `SCTL_CONFIG`, `SCTL_STATE_DIR`, `SCTL_ENC_ROOT`,
`SCTL_DEFAULT_IDLE`, `SCTL_IDLE`, `SCTL_NO_IDLE`, `SCTL_MASTER_PASS`,
`CRYPT_PASS` (non-interactive gocryptfs password), `SCTL_STRAY_DIR`,
`SCTL_COLOR` (`always`/`never`), `NO_COLOR`.

## License

Licensed under either of MIT or Apache-2.0 at your option.
