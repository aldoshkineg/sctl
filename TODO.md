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
