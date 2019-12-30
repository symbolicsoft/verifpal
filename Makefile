# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s parser
	@make -s windows
	@make -s linux
	@make -s macos

parser:
	@/bin/echo -n "[Verifpal] Generating parser..."
	@rm -f internal/verifpal/parser.go
	@pigeon -o internal/verifpal/parser.go api/grammar/verifpal.peg
	@/bin/echo "             OK"

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@cp assets/windows/versioninfo.json cmd/verifpal/versioninfo.json
	@cd cmd/verifpal; GOOS="windows" GOARCH="amd64" go generate
	@GOOS="windows" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/windows verifpal.com/...
	@rm cmd/verifpal/versioninfo.json cmd/verifpal/resource.syso
	@/bin/echo " OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@GOOS="linux" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/linux verifpal.com/...
	@/bin/echo "   OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@GOOS="darwin" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/bin/macos verifpal.com/...
	@/bin/echo "   OK"

upx:
	@/bin/echo -n "[Verifpal] Packing with UPX"
	@/bin/echo -n "."
	@upx -9 --ultra-brute -qqq build/bin/windows/verifpal.exe
	@/bin/echo -n "."
	@upx -9 --ultra-brute -qqq build/bin/linux/verifpal
	@/bin/echo -n "."
	@upx -9 --ultra-brute -qqq build/bin/macos/verifpal
	@/bin/echo "              OK"

dependencies:
	@/bin/echo -n "[Verifpal] Installing dependencies"
	@go get -u github.com/mna/pigeon
	@/bin/echo -n "."
	@go get -u github.com/logrusorgru/aurora
	@/bin/echo -n "."
	@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
	@/bin/echo -n "."
	@/bin/echo "       OK"

release:
	@vim cmd/verifpal/main.go assets/windows/versioninfo.json CHANGELOG.md
	@make -s all
	@make -s upx
	@/bin/echo -n "[Verifpal] Creating release archives"
	@/bin/echo -n "."
	@cp build/bin/windows/verifpal.exe verifpal.exe
	@zip -q -r9 build/release/verifpal_windows verifpal.exe LICENSES README.md CHANGELOG.md examples
	@rm verifpal.exe
	@/bin/echo -n "."
	@cp build/bin/linux/verifpal verifpal
	@zip -q -r9 build/release/verifpal_linux verifpal LICENSES README.md CHANGELOG.md examples
	@rm verifpal
	@/bin/echo -n "."
	@cp build/bin/macos/verifpal verifpal
	@zip -q -r9 build/release/verifpal_macos verifpal LICENSES README.md CHANGELOG.md examples
	@rm verifpal
	@/bin/echo "     OK"

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@rm -f build/release/*.zip
	@rm -f build/bin/windows/verifpal.exe
	@rm -f build/bin/linux/verifpal
	@rm -f build/bin/macos/verifpal
	@/bin/echo "                   OK"

.PHONY: all parser windows linux macos upx dependencies release clean api build examples internal tools
