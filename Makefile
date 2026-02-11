# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s windows
	@make -s linux
	@make -s macos
	@make -s freebsd

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@cargo build --release --target x86_64-pc-windows-gnu
	@mkdir -p build/windows
	@cp target/x86_64-pc-windows-gnu/release/verifpal.exe build/windows/
	@/bin/echo " OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@cargo build --release --target x86_64-unknown-linux-gnu
	@mkdir -p build/linux
	@cp target/x86_64-unknown-linux-gnu/release/verifpal build/linux/
	@/bin/echo "   OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@cargo build --release --target aarch64-apple-darwin
	@mkdir -p build/macos
	@cp target/aarch64-apple-darwin/release/verifpal build/macos/
	@/bin/echo "   OK"

freebsd:
	@/bin/echo -n "[Verifpal] Building Verifpal for FreeBSD..."
	@cargo build --release --target x86_64-unknown-freebsd
	@mkdir -p build/freebsd
	@cp target/x86_64-unknown-freebsd/release/verifpal build/freebsd/
	@/bin/echo " OK"

lint:
	@/bin/echo "[Verifpal] Running clippy..."
	@cargo clippy -- -D warnings

test:
	@/bin/echo "[Verifpal] Running test battery..."
	@cargo test --release

release:
	@bash scripts/release.sh
	@bash scripts/email.sh

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@cargo clean
	@$(RM) -r build
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all windows linux macos freebsd lint test release clean HomebrewFormula assets build cmd dist examples internal scripts tools
