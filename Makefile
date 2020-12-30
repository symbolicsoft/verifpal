# SPDX-FileCopyrightText: © 2019-2021 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: GPL-3.0-only

all:
	@make -s dep
	@make -s windows
	@make -s linux
	@make -s macos
	@make -s freebsd

windows:
	@/bin/echo -n "[Verifpal] Building Verifpal for Windows..."
	@go generate verifpal.com/cmd/verifpal
	@GOOS="windows" GOARCH="amd64" go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build/windows verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo " OK"

linux:
	@/bin/echo -n "[Verifpal] Building Verifpal for Linux..."
	@go generate verifpal.com/cmd/verifpal
	@GOOS="linux" GOARCH="amd64" go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build/linux verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo "   OK"

macos:
	@/bin/echo -n "[Verifpal] Building Verifpal for macOS..."
	@go generate verifpal.com/cmd/verifpal
	@GOOS="darwin" GOARCH="arm64" go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build/macos verifpal.com/cmd/verifpal
	@mv build/macos/verifpal build/macos/verifpal_applesilicon
	@GOOS="darwin" GOARCH="amd64" go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build/macos verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo "   OK"

freebsd:
	@/bin/echo -n "[Verifpal] Building Verifpal for FreeBSD..."
	@go generate verifpal.com/cmd/verifpal
	@GOOS="freebsd" GOARCH="amd64" go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build/freebsd verifpal.com/cmd/verifpal
	@$(RM) cmd/verifpal/resource.syso
	@/bin/echo " OK"

dep:
	@/bin/echo -n "[Verifpal] Installing dependencies"
	@go get -d -u github.com/logrusorgru/aurora
	@/bin/echo -n "."
	@go get -d -u github.com/mna/pigeon
	@/bin/echo -n "."
	@go get -d -u github.com/spf13/cobra
	@/bin/echo -n "."
	@go get -d -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
	@/bin/echo "       OK"

lint:
	@/bin/echo "[Verifpal] Running golangci-lint..."
	@golangci-lint run

test:
	@go clean -testcache
	@/bin/echo "[Verifpal] Running test battery..."
	@go test verifpal.com/cmd/verifpal

release:
	@bash scripts/release.sh
	@bash scripts/email.sh

clean:
	@/bin/echo -n "[Verifpal] Cleaning up..."
	@$(RM) cmd/vplogic/resource.syso
	@$(RM) build/windows/verifpal.exe
	@$(RM) build/linux/verifpal
	@$(RM) build/macos/verifpal
	@$(RM) build/macos/verifpal_applesilicon
	@$(RM) build/freebsd/verifpal
	@$(RM) cmd/vplogic/libpeg.go
	@$(RM) cmd/vplogic/libcoq.go
	@$(RM) -r dist
	@/bin/echo "                   OK"

.PHONY: all lib windows linux macos freebsd dep lint test release clean HomebrewFormula assets build cmd dist examples internal tools
