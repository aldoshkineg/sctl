# AGENTS

Project conventions and workflow rules for `sctl` (Rust / clap CLI).

## Deploying a new build to the system

**Always bump the version in `Cargo.toml` before building/installing the binary.**
A "deploy" = building and copying the binary into the system (e.g. installing
`target/release/sctl` to `~/.local/bin/sctl`). Every such deploy must bump
`version` (and the user expects it to increase monotonically). Do not install a
new build at the same version as what is already in the system.

Deploy checklist:
1. Bump `version` in `Cargo.toml`.
2. `cargo fmt` + `cargo clippy --all-targets -- -D warnings` + `cargo test`
   (all must be clean).
3. `cargo build --release`.
4. Copy `target/release/sctl` to the install location; `chmod 755`.
5. Regenerate shell completions: `sctl completions zsh > ~/.zsh/completions/_sctl`
   (and `chmod 644`). The user relies on completions — never forget this step.
6. Verify with `sctl version`.

## Code style

- **No `#![allow(dead_code)]`** anywhere. Resolve dead code by splitting
  fixtures, underscore-prefixed `_`-fields for owned-but-unused handles, and
  guard-style control flow (`let ... else` + `continue`).
- **let-chains (`if ... && let ...`)** are allowed: they are stable in Rust
  1.89 / edition 2024, and both rustfmt and clippy accept them (used in
  `mount.rs`, `tpm.rs`, `procfs.rs`). Prefer them over nested `if let` where they
  read clearly; `let ... else` + guard `continue` remains fine too.
