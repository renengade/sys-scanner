# sys-scanner Makefile — cross-compile for Windows, macOS, Linux
# Usage: make [target]
#   make all            — build all platforms and architectures
#   make windows        — build Windows amd64
#   make macos-amd64    — build macOS Intel
#   make macos-arm64    — build macOS Apple Silicon
#   make macos          — build both macOS targets
#   make linux-amd64    — build Linux amd64
#   make linux-arm64    — build Linux ARM64
#   make linux          — build both Linux targets
#   make clean          — remove dist/

MODULE   := sys-scanner
VERSION  ?= 1.2.1
DIST     := dist
LDFLAGS  := -s -w -X main.version=$(VERSION)
GOFLAGS  := -trimpath
SOURCES  := $(shell find . -path ./.git -prune -o -path ./dist -prune -o -type f \( -name '*.go' -o -name '*.html' -o -name 'go.mod' -o -name 'go.sum' \) -print)

.PHONY: all windows macos-amd64 macos-arm64 macos linux-amd64 linux-arm64 linux clean test vet

all: windows macos linux

# ── Windows ──────────────────────────────────────────────────────────────
windows: $(DIST)/$(MODULE)-windows-amd64.exe

$(DIST)/$(MODULE)-windows-amd64.exe: $(SOURCES)
	@mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $@ .
	@echo "Built: $@"
	@file $@

# ── macOS ────────────────────────────────────────────────────────────────
macos: macos-amd64 macos-arm64

macos-amd64: $(DIST)/$(MODULE)-darwin-amd64

$(DIST)/$(MODULE)-darwin-amd64: $(SOURCES)
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $@ .
	@echo "Built: $@"
	@file $@

macos-arm64: $(DIST)/$(MODULE)-darwin-arm64

$(DIST)/$(MODULE)-darwin-arm64: $(SOURCES)
	@mkdir -p $(DIST)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $@ .
	@echo "Built: $@"
	@file $@

# ── Linux ────────────────────────────────────────────────────────────────
linux: linux-amd64 linux-arm64

linux-amd64: $(DIST)/$(MODULE)-linux-amd64

$(DIST)/$(MODULE)-linux-amd64: $(SOURCES)
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $@ .
	@echo "Built: $@"
	@file $@

linux-arm64: $(DIST)/$(MODULE)-linux-arm64

$(DIST)/$(MODULE)-linux-arm64: $(SOURCES)
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $@ .
	@echo "Built: $@"
	@file $@

# ── Clean ────────────────────────────────────────────────────────────────
clean:
	rm -rf $(DIST)
	@echo "Cleaned $(DIST)/"

# ── Checks ───────────────────────────────────────────────────────────────
test:
	go test ./...

vet:
	go vet ./...
