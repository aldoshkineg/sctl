# Add non-interactive `install` gpg passphrase + e2e coverage

Baseline: version 0.9.7, commit 703e823.

## Plan
- [ ] `src/install.rs`: `InstallOpts { names, gpg_pass: Vec<String>, yes: bool }`;
      add `MapGpgProvider` (NAME=PASSWORD, verifies via gpg-agent, falls back to
      `PromptProvider`) and use `ConstConfirm(true)` when `yes`.
- [ ] `src/cli.rs`: `--gpg-pass <NAME=PASSWORD>` (repeatable) + `-y/--yes` on `Install`.
- [ ] `src/main.rs`: pass `gpg_pass`/`yes` into `InstallOpts`.
- [ ] `tests/common/mod.rs`: `gen_gpg_home_at(path, n, pass)` (reuse key layout).
- [ ] `tests/e2e.rs`: re-add `mod common;`; test `gpg_preset_install_enrolls_all_keys`
      generates 5 primary keys (+ subkeys) at `$HOME/.gnupg`, installs via
      `install --yes --gpg-pass vault=$PW`, asserts `recovery` lists 5 `gpg:vault:`
      entries + `gocryptfs:__shared__`.
- [ ] `make lint` clean; run the new e2e test (gated on `have_gpg()`).
- [ ] Bump version, `make build`, commit.
