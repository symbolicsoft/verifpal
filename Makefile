# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

build:
	@/bin/echo -n "[Verifpal] Building Verifpal..."
	@cargo build --release 
	@/bin/echo " OK"

lint:
	@/bin/echo "[Verifpal] Running clippy..."
	@cargo clippy -- -D warnings

test:
	@/bin/echo "[Verifpal] Running test battery..."
	@cargo test --release

wasm:
	@/bin/echo -n "[Verifpal] Building Verifpal WASM..."
	@wasm-pack build --target web --no-default-features --features wasm
	@mkdir -p ../verifpal-website/res/wasm
	@cp pkg/verifpal_bg.wasm ../verifpal-website/res/wasm/
	@cp pkg/verifpal.js ../verifpal-website/res/wasm/
	@/bin/echo " OK"

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@cargo clean
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all build lint test wasm clean assets examples HomebrewFormula scripts src tools
