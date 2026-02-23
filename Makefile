# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

build:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@cargo build --release 
	@/bin/echo " OK"

lint:
	@/bin/echo "[Verifpal] Running clippy..."
	@cargo clippy -- -D warnings

test:
	@/bin/echo "[Verifpal] Running test battery..."
	@cargo test --release

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@cargo clean
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all build lint test clean assets examples HomebrewFormula scripts src tools
