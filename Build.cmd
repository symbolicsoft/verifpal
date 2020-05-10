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
@pigeon -o internal\verifpal\libpeg.go internal\libpeg\libpeg.peg
@gofmt -s -w internal\verifpal\libpeg.go
@cd internal\libcoq
@go run libcoqgen.go
@cd ..\..
@gofmt -s -w internal\verifpal\libcoq.go
@echo              OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@setx GOOS "windows" >nul
@go generate verifpal.com/cmd/verifpal
@go build -gcflags="-e" -ldflags="-s -w" -o build\windows verifpal.com/cmd/verifpal
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@setx GOOS "linux" >nul
@go generate verifpal.com/cmd/verifpal
@go build -gcflags="-e" -ldflags="-s -w" -o build\linux verifpal.com/cmd/verifpal
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@setx GOOS "darwin" >nul
@go generate verifpal.com/cmd/verifpal
@go build -gcflags="-e" -ldflags="-s -w" -o build\macos verifpal.com/cmd/verifpal
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for FreeBSD..."
@setx GOOS "freebsd" >nul
@go generate verifpal.com/cmd/verifpal
@go build -gcflags="-e" -ldflags="-s -w" -o build\freebsd verifpal.com/cmd/verifpal
@echo  OK

@echo|set /p="[Verifpal] Cleaning up..."
@del cmd\verifpal\resource.syso
@setx GOOS "windows" >nul
@echo                    OK

@exit /b
