# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s parser
	@make -s windows
	@make -s linux
	@make -s macos
	@make -s freebsd

parser:
	@/bin/echo -n "[Verifpal] Generating parser..."
	@$(RM) internal/verifpal/parser.go
	@pigeon -o internal/verifpal/parser.go api/grammar/verifpal.peg
	@gofmt -s -w internal/verifpal/parser.go
	@/bin/echo "             OK"

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@GOOS="windows" GOARCH="amd64" go generate ./...
	@GOOS="windows" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/windows verifpal.com/...
	@/bin/echo " OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@GOOS="linux" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/linux verifpal.com/...
	@/bin/echo "   OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@GOOS="darwin" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/macos verifpal.com/...
	@/bin/echo "   OK"

freebsd:
	@/bin/echo -n "[Verifpal] Building Verifpal for FreeBSD..."
	@GOOS="freebsd" GOARCH="amd64" go build -gcflags="-e" -ldflags="-s -w" -o build/freebsd verifpal.com/...
	@/bin/echo " OK"

wasm:
	@/bin/echo -n "[Verifpal] Building Verifpal for WebAssembly..."
	@GOOS="js" GOARCH="wasm" go build -gcflags="-e" -ldflags="-s -w" -o build/wasm verifpal.com/...
	@mv build/wasm/verifpal build/wasm/verifpal.wasm
	@/bin/echo " OK"

dependencies:
	@/bin/echo -n "[Verifpal] Installing dependencies."
	@go get -u github.com/mna/pigeon
	@/bin/echo -n "."
	@go get -u github.com/logrusorgru/aurora
	@/bin/echo -n "."
	@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
	@/bin/echo "       OK"

lint:
	@golangci-lint run

test:
	@make -s dependencies
	@make -s parser
	@go get ./...
	@/bin/echo "[Verifpal] Running test battery..."
	@go test verifpal.com/cmd/verifpal

tag:
	@make -s lint
	@make -s clean
	@bash scripts/tag.sh

release:
	@curl -sL https://git.io/goreleaser | bash
	@git checkout go.sum go.mod internal/verifpal/parser.go
	@make -s clean
	@bash scripts/packages.sh

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@$(RM) cmd/verifpal/resource.syso
	@$(RM) build/windows/verifpal.exe
	@$(RM) build/linux/verifpal
	@$(RM) build/macos/verifpal
	@$(RM) build/freebsd/verifpal
	@$(RM) build/wasm/verifpal.wasm
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all parser windows linux macos freebsd wasm dependencies lint test tag release clean HomebrewFormula LICENSES api assets build cmd dist examples internal tools scripts
