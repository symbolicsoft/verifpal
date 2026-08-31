# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

build:
	@/bin/echo "[Verifpal] Building Verifpal..."
	@cargo build --release 

lint:
	@/bin/echo "[Verifpal] Running clippy..."
	@cargo fmt --check
	@cargo clippy --all-targets -- -D warnings
	@cargo clippy --lib --no-default-features --features wasm -- -D warnings

test:
	@/bin/echo "[Verifpal] Running test battery..."
	@cargo test --release

test-tex:
	@/bin/echo "[Verifpal] Compiling generated LaTeX reports with tectonic..."
	@VERIFPAL_TECTONIC=1 cargo test --release tex:: -- --test-threads=1

test-exhaustive:
	@/bin/echo "[Verifpal] Running exhaustive metamorphic sweeps..."
	@cargo test --release -- --ignored --test-threads=1

dist-assets:
	@/bin/echo "[Verifpal] Generating shell completions and manual pages..."
	@cargo build --quiet
	@$(RM) -r target/dist-assets
	@mkdir -p target/dist-assets/completions target/dist-assets/man
	@./target/debug/verifpal completion bash > target/dist-assets/completions/verifpal.bash
	@./target/debug/verifpal completion zsh  > target/dist-assets/completions/_verifpal
	@./target/debug/verifpal completion fish > target/dist-assets/completions/verifpal.fish
	@./target/debug/verifpal man --output target/dist-assets/man

release-dry:
	@/bin/echo "[Verifpal] Rehearsing a release without touching git or the network..."
	@./scripts/release.sh --dry-run

wasm:
	@/bin/echo "[Verifpal] Building Verifpal WASM..."
	@wasm-pack build --target web --no-default-features --features wasm
	@mkdir -p ../verifpal-website/res/wasm
	@cp pkg/verifpal_bg.wasm ../verifpal-website/res/wasm/
	@cp pkg/verifpal.js ../verifpal-website/res/wasm/

clean:
	@/bin/echo "[Verifpal] Cleaning up..."
	@cargo clean
	@$(RM) -r dist

.PHONY: build lint test test-tex test-exhaustive dist-assets release-dry wasm clean assets examples HomebrewFormula scripts src target
