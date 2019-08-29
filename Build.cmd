@echo off

@echo|set /p="[Verifpal] Installing dependencies..."
@go get -u github.com/mna/pigeon
@go get -u github.com/logrusorgru/aurora
@echo "       OK"

@echo|set /p="[Verifpal] Generating parser..."
@pigeon -optimize-basic-latin -optimize-parser -o internal/app/verifpal/parser.go api/grammar/verifpal.peg
@echo "             OK"

@echo|set /p="[Verifpal] Building Verifpal for Windows..."
@set GOOS="windows"
@set GOARCH="amd64"
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\windows\verifpal.exe internal\app\verifpal\*.go
@echo " OK"

@echo|set /p="[Verifpal] Building Verifpal for Linux..."
@set GOOS="linux"
@set GOARCH="amd64"
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\linux\verifpal internal\app\verifpal\*.go
@echo "   OK"

@echo|set /p="[Verifpal] Building Verifpal for macOS..."
@set GOOS="darwin"
@set GOARCH="amd64"
@go build -gcflags="-e" -ldflags="-s -w" -o build\bin\macos\verifpal internal\app\verifpal\*.go
@echo "   OK"

@echo|set /p="[Verifpal] Cleaning up..."
@set GOOS="windows"
@del internal\app\verifpal\parser.go
@echo "                   OK"