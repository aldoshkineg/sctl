# TODO

Open / future work for `sctl`. Implementation history lives in git; older
design TODOs (`TODO_legacy.md`, `TODO_watch_tpm.md`) are closed.

## Implemented

- **SSH key passphrase management (`ssh_preset`).** ssh private-key passphrases
  are enrolled into the backend at `install` (`--ssh-pass NAME=PASSWORD`,
  `--yes` to confirm) and preset into `ssh-agent` at `mount` (via `ssh-add` +
  `SSH_ASKPASS`, best-effort — skipped with a warning when `SSH_AUTH_SOCK` is
  unset). Map keys are `ssh:<secret>:<SHA256:fingerprint>`, mirroring gpg.
  Verified end-to-end through the binary by `tests/e2e.rs`
  (`ssh_preset_install_enrolls_all_keys`).

## Future features

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
