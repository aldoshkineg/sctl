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
keyfile = "~/.config/sctl/key"

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

`sctl` can manage its secrets (the shared gocryptfs key `G` and per-gpg-key
passphrases) through a hardware/escrow backend instead of a plaintext keyfile.
This is governed by the global `secret_backend` setting:

- **`tpm`** — secrets are sealed into the machine's TPM (zero input on mount)
  and mirrored into an encrypted *escrow* blob for recovery.
- **`escrow`** — no TPM; secrets are decrypted from the escrow blob using a
  master passphrase (env `SCTL_MASTER_PASS`, `master_passphrase_file`, or a
  prompt).
- **unset (legacy)** — gocryptfs uses the plaintext `keyfile`; gpg is entered
  manually.

```toml
[settings]
secret_backend = "tpm"                       # "tpm" | "escrow" | (unset = legacy)
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
adopts the shared gocryptfs key `G` from the existing `keyfile`, collects each
`gpg_preset` gpg home's key passphrase, seals every entry into the TPM (tpm
backend) **and** writes the age/scrypt escrow blob atomically. Run it once on
each machine:

```sh
SCTL_MASTER_PASS=... sctl install
```

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
they disagree (re-run `sctl install` to resync).

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
3. `--force` kills all holders regardless. `--lazy` detaches immediately.

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

- **Backend mode** (`secret_backend` set + `gpg_preset = true` on the secret):
  the passphrases are resolved from the backend (TPM or escrow, per
  `secret_backend`) and preloaded automatically — no manual entry, no seed file.
  Run `sctl install` once to enroll the keys.
- **Legacy / manual mode** (no `secret_backend`): gpg-agent is restarted on
  mount and you type the passphrase once. There is no automatic preloading.

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
`SCTL_KEYFILE`, `SCTL_DEFAULT_IDLE`, `SCTL_IDLE`, `SCTL_NO_IDLE`, `SCTL_KEY`,
`CRYPT_PASS`, `SCTL_STRAY_DIR`, `SCTL_COLOR` (`always`/`never`), `NO_COLOR`.

## License

Licensed under either of MIT or Apache-2.0 at your option.
