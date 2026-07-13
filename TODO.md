# TODO

Open / future work for `sctl`. Implementation history lives in git; older
design TODOs (`TODO_legacy.md`, `TODO_watch_tpm.md`) are closed.

## Future features

- **SSH key passphrase management (`tpm_ssh`).** Enroll ssh key passphrases into
  the backend at `install` and preset them into `ssh-agent` at `mount`, the same
  way gpg works today. Blocked on `ssh-add` having no stdin/arg passphrase API —
  needs an `SSH_ASKPASS` wrapper or `sshpass`. gocryptfs + gpg are the only
  enrolled kinds for now.
- **PCR binding.** `tpm_pcr = true` currently `bail!`. Bind the TPM seal to
  secure-boot PCR 7 (breaks on firmware updates).

## Possible improvements

- **Rotate gpg passphrase to a random secret.** gpg 2.5.x won't apply a
  different passphrase non-interactively (`--change-passphrase` reuses the same
  value under loopback pinentry), so `install` stores the existing passphrase. A
  custom `pinentry` wrapper (returns distinct old/new) would enable randomization.
- **Replace `tpm2-tools` shell-out with the `tss-esapi` Rust crate** (links the
  system `tpm2-tss`, already installed). Fallback CLI works; swap is optional.
- **Automate live-machine migration.** Today the first-run/`install` flow is
  manual (mount gpg → install → umount/remount → `rm` old plaintext key). Could
  be a guided `sctl install --migrate` step.

## Housekeeping

- Regenerate shell completions after any CLI change.
