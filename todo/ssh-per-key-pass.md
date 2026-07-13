# `--ssh-pass` per-key (mirrors gpg `NAME=PASSWORD`)

Baseline: version `0.9.10`, commit `0100aee` (whole-home `--ssh-pass vault=PASS`).

ssh keys can have different passphrases and there can be several `ssh_preset`
secrets, so address keys with `NAME:KEY=PASSWORD` (NAME = secret, KEY = key
filename/comment), mirroring gpg's `NAME=PASSWORD`. The interactive path
(PromptSshProvider) already iterates keys one by one, verifies immediately and
allows skipping — that already matches the gpg mechanism.

## Plan
- [ ] **install.rs** `MapSshProvider`: parse `NAME=PASSWORD` (whole-home) and
      `NAME:KEY=PASSWORD` (per-key); at `get`, try per-key match
      (basename/comment), then whole-home, then interactive fallback.
- [ ] **cli.rs**: document both `--ssh-pass` forms.
- [ ] **tests/common/mod.rs**: `gen_ssh_home_at_multi(dir, &[&str])` — N keys
      each with its own passphrase.
- [ ] **tests/e2e.rs**: `ssh_preset_install_per_key_passwords` — 3 keys, 3
      `--ssh-pass vault:id_ed25519_i=...`, assert recovery shows 3 entries.
      Keep existing whole-home test.
- [ ] Bump version, `make check`, `make deploy`, commit (drop this todo file).
