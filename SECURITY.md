# Security Policy

## Supported versions

Only the latest release (`v1.2.x`) receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for security problems.

- Preferred: use GitHub's **Report a vulnerability** flow on this repository
  (Security → Advisories). This creates a private thread.
- Alternatively, contact the maintainer through the GitHub account
  [@renengade](https://github.com/renengade).

Please include:

- affected version and platform,
- reproduction steps,
- expected vs. actual behavior,
- any relevant log output (redact hostnames/IPs/MAC addresses).

## What this tool does and does not do

- It **never** opens network connections.
- It performs read-only scans of software registration sources.
- It writes HTML/XLSX/JSON/CSV files that contain hostnames, IP/MAC addresses,
  paths, and software names — treat generated files as confidential.

## Automated checks

Every commit is scanned with:

- `go vet` on Linux, Windows and macOS,
- `gosec` static analysis (Linux/Darwin and Windows build tags),
- `govulncheck` against the Go vulnerability database.

Results are summarized in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
