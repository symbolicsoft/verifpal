# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s dependencies
	@make -s windows
	@make -s linux
	@make -s macos
	@make -s freebsd

lib:
	@$(RM) internal/verifpal/libpeg.go
	@pigeon -o internal/verifpal/libpeg.go internal/libpeg/libpeg.peg
	@gofmt -s -w internal/verifpal/libpeg.go
	@$(RM) internal/verifpal/libcoq.go
	@cd internal/libcoq; go run libcoqgen.go
	@gofmt -s -w internal/verifpal/libcoq.go

windows:
	@make -s lib
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@GOOS="windows" go generate ./...
	@GOOS="windows" go build -gcflags="-e" -ldflags="-s -w" -o build/windows verifpal.com/cmd/verifpal
	@/bin/echo " OK"

linux:
	@make -s lib
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@GOOS="linux" go build -gcflags="-e" -ldflags="-s -w" -o build/linux verifpal.com/cmd/verifpal
	@/bin/echo "   OK"

macos:
	@make -s lib
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@GOOS="darwin" go build -gcflags="-e" -ldflags="-s -w" -o build/macos verifpal.com/cmd/verifpal
	@/bin/echo "   OK"

freebsd:
	@make -s lib
	@/bin/echo -n "[Verifpal] Building Verifpal for FreeBSD..."
	@GOOS="freebsd" go build -gcflags="-e" -ldflags="-s -w" -o build/freebsd verifpal.com/cmd/verifpal
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
	@make -s lib
	@/bin/echo "[Verifpal] Running golangci-lint..."
	@golangci-lint run

test:
	@make -s lib
	@go get ./...
	@/bin/echo "[Verifpal] Running test battery..."
	@go clean -testcache
	@go test verifpal.com/cmd/verifpal

tag:
	@make -s lib
	@bash scripts/tag.sh

release:
	@make -s dependencies
	@make -s lib
	@curl -sL https://git.io/goreleaser | bash
	@bash scripts/email.sh

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@$(RM) cmd/verifpal/resource.syso
	@$(RM) build/windows/verifpal.exe
	@$(RM) build/linux/verifpal
	@$(RM) build/macos/verifpal
	@$(RM) build/freebsd/verifpal
	@$(RM) internal/verifpal/libpeg.go
	@$(RM) internal/verifpal/libcoq.go
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all lib windows linux macos freebsd dependencies lint test tag release clean HomebrewFormula api assets build cmd dist examples internal tools scripts
