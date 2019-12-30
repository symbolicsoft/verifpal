@REM SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
@REM SPDX-License-Identifier: GPL-3.0-only

@echo off
@setx GOOS "windows" >nul
@setx GOARCH "amd64" >nul

@echo|set /p="[Verifpal] Installing dependencies..."
@go get -u github.com/mna/pigeon
@go get -u github.com/logrusorgru/aurora
@go get -u github.com/josephspurrier/goversioninfo/cmd/goversioninfo
@echo        OK

@echo|set /p="[Verifpal] Generating parser..."
@del internal\verifpal\parser.go
@pigeon -o internal\verifpal\parser.go api\grammar\verifpal.peg
@echo              OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@copy assets\windows\versioninfo.json cmd\verifpal\versioninfo.json >nul
@cd cmd\verifpal
@go generate
@cd ..\..
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\windows verifpal.com/...
@del cmd\verifpal\versioninfo.json cmd\verifpal\resource.syso
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@setx GOOS "linux" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\linux verifpal.com/...
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@setx GOOS "darwin" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\macos verifpal.com/...
@echo    OK

@echo|set /p="[Verifpal] Cleaning up..."
@setx GOOS "windows" >nul
@echo                    OK

@exit /b
