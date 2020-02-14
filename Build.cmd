@REM SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
@REM SPDX-License-Identifier: GPL-3.0-only

@echo off
@setx GOOS "windows" >nul

@echo|set /p="[Verifpal] Installing dependencies..."
@go get -u github.com/mna/pigeon
@go get -u github.com/logrusorgru/aurora
@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
@echo        OK

@echo|set /p="[Verifpal] Generating parser..."
@del internal\verifpal\parser.go
@pigeon -o internal\verifpal\parser.go api\grammar\verifpal.peg
@gofmt -s -w internal\verifpal\parser.go
@echo              OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@go generate ./...
@go build -gcflags="-e" -ldflags="-s -w" -o build\windows verifpal.com/...
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@setx GOOS "linux" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o build\linux verifpal.com/...
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@setx GOOS "darwin" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o build\macos verifpal.com/...
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for FreeBSD..."
@setx GOOS "freebsd" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o build\freebsd verifpal.com/...
@echo  OK

@echo|set /p="[Verifpal] Cleaning up..."
@del cmd\verifpal\resource.syso
@setx GOOS "windows" >nul
@echo                    OK

@exit /b
