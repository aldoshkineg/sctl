# AGENTS

Project conventions and workflow rules for `sctl` (Rust / clap CLI).

## Commands (all via the Makefile)

Never run `cargo` / `install` by hand — every build/verify/install step goes
through the `Makefile`.

- `make lint` — iteration lint: `cargo fmt` + `cargo clippy --all-targets -- -D warnings`.
- `make test` — `cargo test` only.
- `make check` — verification gate: `make lint` + `cargo test`. Must be clean before a commit/deploy.
- `make build` — `cargo build --release`.
- `make install` — install `target/release/sctl` to `~/.local/bin/sctl` (0755) and regenerate zsh completions to `~/.zsh/completions/_sctl` (0644).
- `make deploy` — `make check` + `make build` + `make install`, then prints `sctl version`.

## Task workflow

For each non-trivial task, follow this loop:

1. **Plan + TODO.** Write a short `todo/<slug>.md` capturing the plan and a
   check-list. Record the starting point in its header — current `version` from
   `Cargo.toml` and the short `git` commit hash — so the later review knows the
   baseline. Keep items as `- [ ]` and tick them as the work progresses.
2. **Implement + verify iteratively.** Make the code/doc changes, then run
   `make lint` continuously. **Run tests only once you believe the task is
   solved** — via `make test` (or the full `make check` gate) — don't churn
   them on every edit. Do not leave the tree red.

   Never invoke `cargo` / `install` directly — use the Makefile targets above.

3. **Review.** Do a quick self-review: `git status` / `git diff` to confirm
   only intended files changed (no stray debug, no leftover temp files, no
   `oldString_unused`-style artifacts). Verify every TODO item is done.
   - If corrections are needed, go back to step 2.
   - If the review is clean, proceed.
4. **Bump version + build.** Bump `version` in `Cargo.toml` (it must increase
   monotonically — the user expects a fresh version on every deploy, never
   install a build at the same version already in the system). Then `make build`
   (or `make deploy` for the full install + completions + `sctl version` step).
   On a **successful build**, commit with a concise message following the repo
   style.
5. **Commit.** Commit once the build passes. Do **not** `push` or open a PR
   unless explicitly asked. Then fold any durable items from `todo/<slug>.md`
   into the root `TODO.md` (future work) and delete the task-specific file.

## Code style

- **No `.unwrap()` or `.expect()` in production code.** Runtime panics are treated as critical bugs. Always propagate errors using the `?` operator, or handle them safely with defaults (`unwrap_or_else`).
- **Keep control flow flat.** Avoid deeply nested ladders of `if let` or `match`. Use guard clauses (early `return`, `break`, or `continue`) to keep the primary happy path at the lowest indentation level.
- **Leverage let-chains and `let-else`.** Use `let Some(x) = opt else { ... }` for early exits. Use let-chains (`if cond && let Some(x) = opt`) to flatten sequential conditional checks (stable since Rust 1.89 / Edition 2024).
- **Pass borrowed slices, not containers.** Prefer `&str` over `&String`, `&[T]` over `&Vec<T>`, and `&Path` over `&PathBuf` to avoid redundant allocations in function signatures.
- **Avoid careless `.clone()`.** Cloning must be intentional. If you are cloning just to satisfy the borrow checker, reconsider the ownership structure or lifetimes first.
- **Zero tolerance for `#[allow(...)]`.** Code must compile with zero warnings from both the compiler and Clippy. Fix the underlying root cause instead of suppressing warnings with macros (e.g., do not hide `dead_code` or `unused`).
