# SPDX-License-Identifier: GPL-3.0
# Copyright © 2019-2020 Nadim Kobeissi, Symbolic Software <nadim@symbolic.software>.
# All Rights Reserved.

all:
	@make -s parser
	@make -s windows
	@make -s linux
	@make -s macos

parser:
	@/bin/echo -n "[Verifpal] Generating parser..."
	@rm -f internal/app/verifpal/parser.go
	@pigeon -optimize-basic-latin -optimize-parser -o internal/app/verifpal/parser.go api/grammar/verifpal.peg
	@/bin/echo "             OK"

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows... "
	@GOOS="windows" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/windows/verifpal.exe internal/app/verifpal/*.go
	@/bin/echo "OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux... "
	@GOOS="linux" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/linux/verifpal internal/app/verifpal/*.go
	@/bin/echo "  OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS... "
	@GOOS="darwin" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/macos/verifpal internal/app/verifpal/*.go
	@/bin/echo "  OK"

upx:
	@/bin/echo -n "[Verifpal] Packing with UPX"
	@/bin/echo -n "."
	@upx -9 -qqq build/bin/windows/verifpal.exe
	@/bin/echo -n "."
	@upx -9 -qqq build/bin/linux/verifpal
	@/bin/echo -n "."
	@upx -9 -qqq build/bin/macos/verifpal
	@/bin/echo "              OK"

dependencies:
	@/bin/echo -n "[Verifpal] Installing dependencies."
	@go get -u github.com/mna/pigeon
	@/bin/echo -n "."
	@go get -u github.com/logrusorgru/aurora
	@/bin/echo -n "."
	@/bin/echo "       OK"

release:
	@make -s all
	@make -s upx
	@/bin/echo -n "[Verifpal] Creating release archives"
	@/bin/echo -n "."
	@cp build/bin/windows/verifpal.exe verifpal.exe
	@zip -q -r9 build/release/verifpal_windows verifpal.exe LICENSE.md README.md CHANGELOG.md examples
	@rm verifpal.exe
	@/bin/echo -n "."
	@cp build/bin/linux/verifpal verifpal
	@zip -q -r9 build/release/verifpal_linux verifpal LICENSE.md README.md CHANGELOG.md examples
	@rm verifpal
	@/bin/echo -n "."
	@cp build/bin/macos/verifpal verifpal
	@zip -q -r9 build/release/verifpal_macos verifpal LICENSE.md README.md CHANGELOG.md examples
	@rm verifpal
	@/bin/echo "     OK"

clean:
	@/bin/echo -n "[Verifpal] Cleaning up... "
	@rm -f internal/app/verifpal/parser.go
	@rm -f build/release/*.zip
	@rm -f build/bin/windows/verifpal.exe
	@rm -f build/bin/linux/verifpal
	@rm -f build/bin/macos/verifpal
	@/bin/echo "                  OK"

.PHONY: all parser windows linux macos upx dependencies release clean api build examples internal tools
