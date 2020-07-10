@REM SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
@REM SPDX-License-Identifier: GPL-3.0-only

@echo off

@echo|set /p="[Verifpal] Installing dependencies..."
@go get -u github.com/mna/pigeon
@go get -u github.com/logrusorgru/aurora
@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
@echo        OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@setx GOOS "" >nul
@go generate verifpal.com/cmd/verifpal
@setx GOOS "windows" >nul
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\windows verifpal.com/cmd/verifpal
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@setx GOOS "" >nul
@go generate verifpal.com/cmd/verifpal
@setx GOOS "linux" >nul
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\linux verifpal.com/cmd/verifpal
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@setx GOOS "" >nul
@go generate verifpal.com/cmd/verifpal
@setx GOOS "darwin" >nul
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\macos verifpal.com/cmd/verifpal
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for FreeBSD..."
@setx GOOS "" >nul
@go generate verifpal.com/cmd/verifpal
@setx GOOS "freebsd" >nul
@go build -trimpath -gcflags="-e" -ldflags="-s -w" -o build\freebsd verifpal.com/cmd/verifpal
@echo  OK

@echo|set /p="[Verifpal] Cleaning up..."
@setx GOOS "" >nul
@del cmd\verifpal\resource.syso
@echo                    OK

@exit /b
