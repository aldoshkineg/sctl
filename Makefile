BIN := sctl
PREFIX := $(HOME)/.local
BINDIR := $(PREFIX)/bin
COMPLETIONS := $(HOME)/.zsh/completions

.PHONY: build test install completions fmt clippy

build:
	cargo build --release

test:
	cargo test

completions: build
	$(BIN) completions zsh > $(COMPLETIONS)/_$(BIN)

install: build completions
	install -d $(BINDIR) $(COMPLETIONS)
	cp target/release/$(BIN) $(BINDIR)/$(BIN)
	$(BIN) completions zsh > $(COMPLETIONS)/_$(BIN)

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings
