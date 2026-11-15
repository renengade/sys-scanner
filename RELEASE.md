# Release Notes — sys-scanner 1.2.0

## Version

1.2.0

## Binaries

| File | Platform |
|------|----------|
| `sys-scanner-windows-amd64.exe` | Windows 10/11, x64 |
| `sys-scanner-linux-amd64` | Linux x86_64 (including WSL) |
| `sys-scanner-linux-arm64` | Linux ARM64 |
| `sys-scanner-darwin-amd64` | macOS Intel |
| `sys-scanner-darwin-arm64` | macOS Apple Silicon |

## What is new in 1.2.0

- Removed script/automation scanning. Reports, JSON, CSV, and the summary
  workbook now contain software entries only.
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
