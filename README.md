<p align="center">
  <img src="docs/assets/logo.png" alt="sctl logo" width="120" />
</p>

# sctl

[![CI](https://github.com/aldoshkineg/sctl/actions/workflows/ci.yml/badge.svg)](https://github.com/aldoshkineg/sctl/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/aldoshkineg/sctl)
[![rust](https://img.shields.io/badge/rust-1.89%2B-orange)](https://www.rust-lang.org)

[![sctl status](docs/assets/main.png)](https://github.com/aldoshkineg/sctl)

Keep sensitive directories encrypted at rest and mount them on demand — without thinking about it. `sctl` manages the complexity: it resolves dependency chains, caches credentials securely behind TPM or an encrypted escrow, presets gpg passphrases into `gpg-agent`, and auto-unmounts idle volumes. One configuration file. One command. Done.

## Table of Contents

- [Why sctl?](#why-sctl)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Security](#security)
- [Documentation](#documentation)
- [Environment Variables](#environment-variables)
- [License](#license)

## Why sctl?

Managing multiple encrypted directories means mounting them by hand,
remembering passwords, ordering dependencies correctly, and cleaning
everything up when you're done. `sctl` eliminates that burden entirely.

| | Without sctl | With sctl |
|---|---|---|
| Mount volumes | Manually, in order | `sctl mount mail` — deps resolve automatically |
| Passwords | Remember each one | Stored once in TPM or escrow |
| Dependency order | Figure it out yourself | Declared in config, enforced at runtime |
| Unmount | Manual, fragile | Smart cascade — removes only what's unused |
| Idle cleanup | None | Auto-unmount after configurable timeout |
| gpg-agent integration | Restart and re-enter passphrase | Preloaded from backend automatically |
| Plaintext keyfiles on disk | Common | None — secrets are zeroized in memory |
| Recovery if hardware fails | Manual backups | Encrypted escrow blob, any machine |

## Features

### Mount lifecycle

- **Dependency-aware mounting** — mount a secret and all its dependencies come up in the right order.
- **Smart-cascade unmount** — unused dependencies are removed automatically; mounted dependents are protected from accidental removal.
- **Idle auto-unmount** — per-secret or global timeout triggers automatic cleanup.
- **Busy handling** — configurable `auto_kill` list silently terminates known processes; `--force` handles the rest.
- **Watch daemon** — background process force-unmounts secrets stuck busy past a configurable threshold.

### Security

- **TPM + escrow backend** — secrets sealed to hardware or an encrypted portable blob.
- **No plaintext keyfiles** — passwords are passed via a temporary `0600` passfile, never visible in `ps`.
- **Zeroized memory** — all secret bytes are zeroized on drop.
- **Atomic writes** — backends are rewritten atomically (tmp + rename, `0600`), so TPM and escrow can never diverge.
- **Single writer** — `sctl install` is the sole source of truth for the backend.

### User experience

- **One configuration file** — TOML, human-readable.
- **Colored status table** — aligned output with mounted secrets highlighted.
- **Shell completions** — `sctl completions zsh|bash|fish|powershell`.
- **Dry-run mode** — preview mount/unmount plans without doing anything.
- **Toggle command** — mount if down, unmount if up — perfect for keybindings.

## Architecture

```mermaid
graph TB
    User["User"] -->|"sctl mount mail"| Cli["sctl CLI"]

    Cli -->|"load config"| Cfg["config.toml"]
    Cli -->|"resolve deps"| Deps["dependency graph"]
    Deps -->|"ordered mount"| Gocryptfs["gocryptfs"]

    Cli -->|"read secrets"| Backend["secret backend"]
    Backend -->|"sealed blobs"| TPM[(TPM)]
    Backend -->|"age-encrypted"| Escrow[(escrow blob)]

    Cli -->|"cache in memory"| Cache["Zeroizing cache"]
    Cli -->|"watch & kill"| Watcher["watch daemon"]
```

`sctl` keeps a single in-memory **secret map** (gocryptfs password `G` + per-gpg-key passphrases). That map is serialized once, wrapped with a Data Encryption Key (DEK), and sealed into both the TPM and an encrypted escrow blob. On mount, `sctl` retrieves the DEK from the TPM, decrypts the map, and uses it — all in memory, zeroized when done.

## Quick Start

1. **Copy the example config** and edit your secrets:

   ```sh
   cp config.example.toml ~/.config/sctl/config.toml
   # edit ~/.config/sctl/config.toml
   ```

2. **Create encrypted containers** and migrate existing data:

   ```sh
   sctl init gpg ssh mail
   ```

3. **Enroll secrets** into the backend (one time per machine):

   ```sh
   sctl install
   ```

4. **Mount everything** — dependencies resolved automatically:

   ```sh
   sctl mount all
   ```

5. **Verify** the backend is healthy:

   ```sh
   sctl check
   ```

6. **View status** — mounted secrets are highlighted, idle timers visible:

   ```sh
   sctl status
   ```

## Commands

| Command | Description |
|---------|-------------|
| `sctl init <name>…` | Create encrypted container(s), migrate existing data |
| `sctl mount <name>…` | Mount secret(s); dependencies resolved first |
| `sctl umount <name>…` | Unmount with smart dependency cascade |
| `sctl toggle <name>…` | Mount if down, unmount if up |
| `sctl status` | Colored table of mount states and idle timers |
| `sctl check` | Validate config, backends, permissions, dependencies |
| `sctl install` | Enroll all secrets into the backend |
| `sctl recovery [filter]` | Decrypt the escrow blob (no TPM needed) |
| `sctl watch [--once]` | Force-unmount secrets stuck busy past threshold |
| `sctl completions <shell>` | Generate shell completions |
| `sctl version` | Print version |

## Configuration

Config lives at `~/.config/sctl/config.toml`. See [`config.example.toml`](config.example.toml) for the full reference.

Minimal example:

```toml
[settings]
default_idle = "15m"
secret_backend = "tpm"

[secrets.gpg]
path = ".gnupg"
gpg = true
gpg_preset = true

[secrets.mail]
path = ".local/share/mail"
depends = ["gpg", "pass"]
idle = "30m"
auto_kill = ["lf", "nnn"]
```

For the full configuration reference — secret backend details, DEK model, first-run walkthrough, gpg preloading, and `zshenv` — see [docs/configuration.md](docs/configuration.md).

## Security

- ✅ Only ciphertext on disk — TPM blobs + the age-encrypted escrow blob
- ✅ No plaintext keyfiles in the config directory
- ✅ Stolen-disk useless — TPM blobs won't open off the chip; escrow requires the master passphrase
- ✅ TPM + escrow derive from one in-memory map — atomic writes prevent divergence
- ✅ Passphrases ≠ keys — `gpg`/`ssh` keys keep their fingerprint/keygrip; only the passphrase is cached
- ✅ Zeroized memory — all secret bytes cleared on drop
- ✅ Advisory file locking — concurrent invocations are safe, second `sctl` touching the same secret fails fast

For a deeper dive into the encryption model, threat analysis, and known limitations, see [docs/security.md](docs/security.md).

## Documentation

| Topic | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Full config reference, DEK model, first-run guide, gpg preloading |
| [Security](docs/security.md) | Encryption architecture, threat model, backend design |
| [GPG integration](docs/gpg.md) | Passphrase preloading, gpg-agent integration, preset modes |
| [Recovery](docs/recovery.md) | Escrow decryption, cross-machine recovery, prefix filtering |
| [Busy handling](docs/busy.md) | auto_kill policy, kill_busy watcher, mount/unmount behavior |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SCTL_CONFIG_DIR` | Config directory (default: `~/.config/sctl`) |
| `SCTL_CONFIG` | Override config path |
| `SCTL_STATE_DIR` | State directory for TPM blobs |
| `SCTL_ENC_ROOT` | Encryption root directory |
| `SCTL_DEFAULT_IDLE` | Global default idle timeout |
| `SCTL_IDLE` | Per-invocation idle timeout |
| `SCTL_NO_IDLE` | Disable idle auto-unmount |
| `SCTL_MASTER_PASS` | Master passphrase for escrow (non-interactive) |
| `CRYPT_PASS` | Non-interactive gocryptfs password |
| `SCTL_STRAY_DIR` | Stray directory for orphaned mounts |
| `SCTL_COLOR` | Color output: `always` or `never` |
| `NO_COLOR` | Disable colored output |

## License

Licensed under either of MIT or Apache-2.0 at your option.