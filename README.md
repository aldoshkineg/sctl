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

### gpg passphrase preloading

Re-entering your gpg key passphrase after every mount is tedious (the agent is
restarted on mount, so its cache is empty). Set `gpg_preset = true` on the
`.gnupg` secret and sctl will, right after mounting, read the secret-key
keygrips and preset their passphrase into gpg-agent via `gpg-preset-passphrase`.

Setup:

1. Enable presetting in the volume's `~/.gnupg/gpg-agent.conf`:
   ```
   allow-preset-passphrase
   max-cache-ttl 86400
   ```
2. Put the key passphrase in a file **inside the encrypted volume** (so it only
   exists while mounted), default `~/.gnupg/.gpg-passphrase` (mode `0600`).
   Override the path with `gpg_passphrase_file`.
3. Configure the secret:
   ```toml
   [secrets.gpg]
   path = ".gnupg"
   gpg = true
   gpg_preset = true
   # gpg_passphrase_file = ".gpg-passphrase"
   ```

The passphrase buffer is zeroed in memory after use. Preset failures are
warnings and never abort the mount.

## Environment overrides

`SCTL_CONFIG_DIR`, `SCTL_CONFIG`, `SCTL_STATE_DIR`, `SCTL_ENC_ROOT`,
`SCTL_KEYFILE`, `SCTL_DEFAULT_IDLE`, `SCTL_IDLE`, `SCTL_NO_IDLE`, `SCTL_KEY`,
`CRYPT_PASS`, `SCTL_STRAY_DIR`, `SCTL_COLOR` (`always`/`never`), `NO_COLOR`.

## License

Licensed under either of MIT or Apache-2.0 at your option.
