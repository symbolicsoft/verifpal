@REM SPDX-FileCopyrightText: © 2019-2022 Nadim Kobeissi <nadim@symbolic.software>
@REM SPDX-License-Identifier: GPL-3.0-only

@echo off

@echo|set /p="[Verifpal] Installing dependencies"
@go mod download github.com/logrusorgru/aurora
@echo|set /p="."
@go install github.com/mna/pigeon@latest
@go mod download github.com/mna/pigeon
@echo|set /p="."
@go mod download github.com/spf13/cobra
@echo|set /p="."
@echo        OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@go generate verifpal.com/cmd/verifpal
@set GOOS=windows
@set GOARCH=amd64
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\windows verifpal.com/cmd/verifpal
@del cmd\verifpal\resource.syso 2>nul
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@go generate verifpal.com/cmd/verifpal
@set GOOS=linux
@set GOARCH=amd64
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\linux verifpal.com/cmd/verifpal
@del cmd\verifpal\resource.syso 2>nul
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@go generate verifpal.com/cmd/verifpal
@set GOOS=darwin
@set GOARCH=amd64
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\macos verifpal.com/cmd/verifpal
@del cmd\verifpal\resource.syso 2>nul
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for FreeBSD..."
@go generate verifpal.com/cmd/verifpal
@set GOOS=freebsd
@set GOARCH=amd64
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\freebsd verifpal.com/cmd/verifpal
@del cmd\verifpal\resource.syso 2>nul
@echo  OK

@echo|set /p="[Verifpal] Cleaning up..."
@set GOOS=
@set GOARCH=
@echo                    OK

@exit /b
