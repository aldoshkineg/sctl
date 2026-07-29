# TODO

Open / future work for `sctl`. Implementation history lives in git; older
design TODOs (`TODO_legacy.md`, `TODO_watch_tpm.md`) are closed.

## Future features

- **SSH key passphrase management (`tpm_ssh`).** Enroll ssh key passphrases into
  the backend at `install` and preset them into `ssh-agent` at `mount`, the same
  way gpg works today. Blocked on `ssh-add` having no stdin/arg passphrase API —
  needs an `SSH_ASKPASS` wrapper or `sshpass`. gocryptfs + gpg are the only
  enrolled kinds for now.

## Possible improvements

- **Rotate gpg passphrase to a random secret.** gpg 2.5.x won't apply a
  different passphrase non-interactively (`--change-passphrase` reuses the same
  value under loopback pinentry), so `install` stores the existing passphrase. A
  custom `pinentry` wrapper (returns distinct old/new) would enable randomization.

## Low priority

- **Replace `tpm2-tools` shell-out with the `tss-esapi` Rust crate.** Links the
  system `tpm2-tss` (already installed). Benefit is modest (self-contained binary,
  typed errors) vs. real cost (C build dep, breaks musl-static, lockout risk on
  existing enrollment, untestable in CI). Current fallback CLI works; swap is
  optional and not worth the risk for now.

## Testing

- **Full e2e needs a local machine with TPM + FUSE, not CI.** `make test` runs
   `cargo test --all`; TPM/mount/`status`/`toggle`/`umount` tests gate on
   `/dev/tpmrm0` (+ `tss` group) and `gocryptfs`/`fusermount3`, so they skip on the
   shared CI runner (ubuntu-latest, no TPM/FUSE) and run only locally. CI covers the
   non-FUSE/non-TPM subset (escrow `install`/`check`/`recovery`, `backend.rs`).
   Containerized/swtpm CI for TPM+FUSE is deliberately avoided: FUSE needs privileged
   runners (flaky/unsafe), TPM needs swtpm + gating changes — not worth it. A
   self-hosted runner with a real TPM would give full CI coverage later.

- **Fix `gpg_preset_install_enrolls_all_keys` in CI without touching `src/`.**
  Root cause: `keys_with_keygrips` uses `gpg --list-secret-keys --homedir <temp>`
  which consults the gpg-agent; the GitHub runner ships a pre-started (default)
  agent that refuses to serve a custom (temp) homedir, so it returns no secret keys
  and `sctl install` fails with "no gpg secret keys found". On a normal machine with
  no pre-started agent this works fine. `src/gpg.rs` must stay as-is (reverting it to
  "fix" the test was wrong and broke the real passphrase-preset feature). Fix in
  test/CI environment only:

  - **Option 1 (preferred): neutralize the runner's pre-started agent in `ci.yml`.**
    Before `cargo test`, kill the system gpg-agent and point `XDG_RUNTIME_DIR`/
    `GNUPGHOME` at a fresh temp dir so gpg spawns its own per-home agent — mirroring
    the local environment where the test already passes. Zero changes to test code.

  - **Option 2: set `GNUPGHOME` to the temp gpg home from inside the test.**
    In `gpg_preset_install_enrolls_all_keys`, export `GNUPGHOME=<temp gpg home>` (the
    binary inherits it) and launch that home's agent via `gpgconf --launch`, so
    `--list-secret-keys` talks to the right agent. Test-only env change; no `src/`
    edits.

  - (Fallback) skip the test on CI (`if std::env::var("CI").is_ok() { return; }`) —
    safe but loses gpg-preset coverage.
