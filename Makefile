BIN := sctl
PREFIX := $(HOME)/.local
BINDIR := $(PREFIX)/bin
COMPLETIONS := $(HOME)/.zsh/completions
BINPATH := $(BINDIR)/$(BIN)
COMPLETIONPATH := $(COMPLETIONS)/_$(BIN)
RELEASE := target/release/$(BIN)

.PHONY: build test install fmt clippy lint check deploy

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

# Iteration lint: format + clippy.
lint: fmt clippy

test:
	cargo test

# Verification gate: must be clean before a deploy.
check: lint test

build:
	cargo build --release

# Install the release binary (0755) and zsh completions (0644).
install: build
	install -d $(BINDIR) $(COMPLETIONS)
	install -m755 $(RELEASE) $(BINPATH)
	$(RELEASE) completions zsh > $(COMPLETIONPATH)
	chmod 644 $(COMPLETIONPATH)

# Full deploy: verify, build, install, then confirm the version.
deploy: check build install
	$(BINPATH) version
