# Release Notes — sys-scanner

## 1.3.0

### Features

- HTML report now includes the full install location for every program.
- Version and publisher enrichment:
  - Windows reads the PE version resource (`FileVersion`, `ProductName`,
    `CompanyName`) of the program executable when registry/App Paths/PATH
    data is missing.
  - Linux `.desktop` entries are enriched from the owning package
    (dpkg/rpm/pacman) for version and maintainer/vendor.
- XLSX summary diff now distinguishes updates: `+N added, -N removed,
  ~N updated`; version bumps count as updates.
- Unchanged runs no longer rewrite the XLSX summary (mtime and the stored
  `scan_time` are preserved, so it marks the last content change).
- Note for maintainers: `VerQueryValue` reports string-block lengths in
  characters, not bytes; the version enrichment walks to the NUL terminator
  instead of slicing by `length/2` (which truncated publisher names).

## 1.2.2

### Code audit

- `merge.Deduplicate` output is now fully deterministic (publisher/source
  tiebreakers) even when sources are scanned concurrently or shuffled.
- Windows Store scan forces UTF-8 console output so non-ASCII publisher names
  (e.g. Chinese OEMs) survive `ConvertTo-Json`; a UTF-8 BOM in redirected
  output is stripped before parsing.
- App Paths now scans the 32-bit WOW64 registry view in addition to the
  64-bit and HKCU views.
- The XLSX summary falls back to the user temp directory when the folder next
  to the executable is read-only.
- Classifier binary-name comparison is case-insensitive on Windows.
- Dead code removed; `staticcheck` is clean on Linux, Windows and Darwin
  targets; `errcheck` is clean.

## 1.2.1

### Security

- Upgraded `github.com/xuri/excelize/v2` to v2.11.1, fixing 11 upstream
  vulnerabilities reported by `govulncheck` (panics, out-of-bounds/OOM in
  spreadsheet parsing).
- Upgraded `golang.org/x/{crypto,net,sys,text}`.
- Windows subprocess hardening: `powershell.exe`, `wsl.exe`, `rundll32.exe`
  and `tasklist.exe` are launched from `%SystemRoot%\System32` by absolute
  path so they cannot be substituted from the current directory or a
  user-writable PATH entry.
- Tightened output directory permissions to `0700` (files remain `0600`).
- Added `SECURITY.md`, a security audit document and CI jobs for `gosec`
  (Linux/Darwin and Windows build tags) and `govulncheck`.
- HTML report data model now uses plain strings; `html/template` performs the
  contextual escaping (removing `gosec`-style "unsafe HTML" findings and
  keeping the same XSS guarantees).
- The summary workbook treats every value as a string cell; Excelize removes
  formulas, so names starting with `=` cannot become formulas.

### Build

- Requires Go 1.26 or later (`github.com/xuri/excelize/v2` v2.11.1 needs it).

## 1.2.0

## Binaries

| File | Platform |
|------|----------|
| `sys-scanner-windows-amd64.exe` | Windows 10/11, x64 |
| `sys-scanner-linux-amd64` | Linux x86_64 (including WSL) |
| `sys-scanner-linux-arm64` | Linux ARM64 |
| `sys-scanner-darwin-amd64` | macOS Intel |
| `sys-scanner-darwin-arm64` | macOS Apple Silicon |

## What is new in 1.2.0

- Summary workbook is a real `.xlsx` written next to the HTML report:
  `<output dir>/sys-scanner-summary.xlsx`.
- Summary times are human-readable local time, e.g.
  `2026-11-15 18:00:00 CST`.
- Re-running on the same machine replaces that machine's rows and reports
  `+N added / -N removed`; software version changes are updates, not
  add/remove.
- Windows built-in/runtime filtering; Store inbox apps, System32 tools, and
  App Paths inbox helpers are excluded by default.
- Start Menu `.lnk` resolution is off by default.
- Windows sources run concurrently; warm scans are about 1.3–1.5 s.
- Host information in the report and JSON: hostname, IP, MAC (virtual
  interfaces filtered).
- Linux package coverage includes pacman and apk.
- All five platform binaries are built by `make all`.

## Fixes and hardening

- Windows report opening no longer produces `C:\\Users\\...` paths; it uses
  `rundll32 url.dll,FileProtocolHandler`.
- WSL probing works when the Windows binary is launched from inside WSL.
- AI detection no longer reports LocalAI from an unrelated service listening
  on port 8080; port-only signals cannot synthesize an installed tool.
- Process matching is line-anchored instead of substring-based.
- The process list and VS Code extension directories are read once per scan.
- Scans honour the overall deadline and return partial results.
- Reports, inventories, and summaries are written atomically with `0600`
  permissions where supported.

## Known issues

- The macOS binaries are not signed or notarized. macOS Gatekeeper may block
  them on first launch. Right-click the binary and choose **Open** to run it.
- Windows Store app detection depends on PowerShell being available.
- Start Menu `.lnk` scanning is opt-in and slower.
- There is no 32-bit support. Only 64-bit and ARM64 binaries are provided.
- WSL host tools are not fully inventoried from Windows; run the Linux binary
  inside WSL for a full Linux inventory.
- Docker container applications are not detected.

## Unsupported platforms

- Windows 7 and earlier
- macOS versions earlier than 11 (Big Sur)
- 32-bit operating systems

## How to use

Download the binary for your platform, make it executable if necessary, and
run it. See [README.md](./README.md) for full instructions and
[docs/INVENTORY.md](./docs/INVENTORY.md) for the JSON schema.
