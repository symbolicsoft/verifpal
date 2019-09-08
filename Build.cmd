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
@pigeon -optimize-basic-latin -optimize-parser -o internal/app/verifpal/parser.go api/grammar/verifpal.peg
@echo              OK

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@copy assets\windows\versioninfo.json internal\app\verifpal\versioninfo.json >nul
@cd internal\app\verifpal
@go generate
@go build -gcflags="-e" -ldflags="-s -w" -o ..\..\..\build\bin\windows\verifpal.exe
@del versioninfo.json resource.syso
@echo  OK

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@setx GOOS "linux" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o ..\..\..\build\bin\linux\verifpal
@echo    OK

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@setx GOOS "darwin" >nul
@go build -gcflags="-e" -ldflags="-s -w" -o ..\..\..\build\bin\macos\verifpal
@echo    OK

@echo|set /p="[Verifpal] Cleaning up..."
@setx GOOS "windows" >nul
@cd ..\..\..
@del internal\app\verifpal\parser.go
@echo                    OK

@exit /b
