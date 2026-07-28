# Busy handling

When a mount is busy (a process holds an open file or a shell has its cwd inside the mountpoint), a normal `umount` will fail. `sctl` offers several policies for handling this.

## auto_kill

If every holding process is in the secret's `auto_kill` list, they are terminated silently (SIGTERM, then SIGKILL) and the volume is unmounted.

```toml
[secrets.mail]
path = ".local/share/mail"
auto_kill = ["lf", "nnn"]
```

## kill_busy + watch daemon

A mounted secret can get stuck `busy` (e.g. gpg-agent keeps `~/.gnupg` open, or a shell's cwd is inside it) so a normal idle/unmount can never succeed. Mark a secret with `kill_busy`:

```toml
[secrets.gpg]
path = ".gnupg"
gpg = true
gpg_preset = true
kill_busy = true
kill_busy_after = "10m"   # optional; defaults to 10m
```

The `sctl mount` command forks a **single resident `sctl watch` daemon** (singleton, guarded by a lock) whenever any secret enables `kill_busy`. The watcher polls every 60 s: for each mounted `kill_busy` secret it records when it first became busy, and when that exceeds `kill_busy_after` it performs a forced unmount (`gpg_kill` for gpg secrets, then kills the holders and `fusermount`). It self-exits when nothing is left to watch and is respawned by the next `mount`.

Run it manually / from cron as a single pass instead of the resident loop:

```sh
sctl watch --once        # one pass, then exit
sctl watch               # resident loop (same as the forked daemon)
```

Mounting a secret with `--no-idle` (or `SCTL_NO_IDLE`) opts it out of the watcher entirely: `sctl mount` will not fork the daemon, and `sctl watch` skips such volumes (their status column already shows `never`).

> Note: because gpg-agent normally keeps `~/.gnupg` open, a `gpg` secret counts as busy for its entire mounted lifetime — so `kill_busy` effectively force-unmounts it `kill_busy_after` after mount. Set the threshold longer than a typical session if you only want it reclaimed when truly stuck.

## --force and --lazy

When a mount is busy on `umount` and no matching `auto_kill` entry exists:

- Nothing is killed; the processes are listed and `--force` is required.
- `--force` kills all holders regardless. It also bypasses the dependency guard: a requested secret is unmounted even if other mounted secrets still depend on it (those dependents are left mounted, now broken).
- `--lazy` detaches immediately.