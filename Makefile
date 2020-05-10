# SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s dep
	@make -s windows
	@make -s linux
	@make -s macos
	@make -s freebsd

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@GOOS="" go generate verifpal.com/cmd/verifpal
	@GOOS="windows" go build -gcflags="-e" -ldflags="-s -w" -o build/windows verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo " OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@GOOS="" go generate verifpal.com/cmd/verifpal
	@GOOS="linux" go build -gcflags="-e" -ldflags="-s -w" -o build/linux verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo "   OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@GOOS="" go generate verifpal.com/cmd/verifpal
	@GOOS="darwin" go build -gcflags="-e" -ldflags="-s -w" -o build/macos verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo "   OK"

freebsd:
	@/bin/echo -n "[Verifpal] Building Verifpal for FreeBSD..."
	@GOOS="" go generate verifpal.com/cmd/verifpal
	@GOOS="freebsd" go build -gcflags="-e" -ldflags="-s -w" -o build/freebsd verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo " OK"

dep:
	@/bin/echo -n "[Verifpal] Installing dependencies"
	@go get -u github.com/logrusorgru/aurora
	@/bin/echo -n "."
	@go get -u github.com/mna/pigeon
	@/bin/echo -n "."
	@go get -u github.com/spf13/cobra
	@/bin/echo -n "."
	@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
	@/bin/echo "       OK"

lint:
	@/bin/echo "[Verifpal] Running golangci-lint..."
	@golangci-lint run

test:
	@go get ./...
	@/bin/echo "[Verifpal] Running test battery..."
	@go clean -testcache
	@go test verifpal.com/cmd/verifpal

tag:
	@bash scripts/tag.sh

release:
	@make -s dep
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

.PHONY: all lib windows linux macos freebsd dep lint test tag release clean HomebrewFormula assets build cmd dist examples internal scripts tools
