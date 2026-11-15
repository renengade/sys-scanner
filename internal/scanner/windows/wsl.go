//go:build windows

package windows

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

const (
	wslListTimeout  = 15 * time.Second
	wslProbeTimeout = 30 * time.Second
)

// scanWSLTools probes all installed WSL distros for AI tool signatures. A
// distro that fails to probe (offline, missing wsl.exe, timeout) is logged and
// skipped without aborting the rest of the scan.
func scanWSLTools() ([]types.Program, error) {
	tools := signatures.All()

	distros, err := listWSLDistros()
	if err != nil {
		slog.Debug("WSL distro listing unavailable", "error", err)
		return nil, nil
	}
	if len(distros) == 0 {
		return nil, nil
	}

	var all []types.Program
	for _, distro := range distros {
		progs, err := probeDistro(distro, tools)
		if err != nil {
			slog.Warn("WSL distro probe failed", "distro", distro, "error", err)
			continue
		}
		all = append(all, progs...)
	}
	return all, nil
}

// listWSLDistros runs `wsl.exe -l -q` and returns the installed distro names.
// It returns (nil, nil) when wsl.exe is unavailable so callers degrade
// gracefully.
func listWSLDistros() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wslListTimeout)
	defer cancel()

	// #nosec G204 -- absolute path under %SystemRoot%; arguments are fixed.
	cmd := exec.CommandContext(ctx, windowsSystemToolPath("wsl.exe"), "-l", "-q")
	// When sys-scanner is launched from inside WSL via interop, the current
	// directory is a \\wsl.localhost\... UNC path. wsl.exe cannot translate
	// that path into another distro, so run it from the Windows directory.
	cmd.Dir = windowsSystemDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, nil
	}

	raw := decodeUTF16LEIfNeeded(stdout.Bytes())
	var distros []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Windows Subsystem") || strings.HasPrefix(line, "适用于") {
			continue
		}
		distros = append(distros, line)
	}
	return distros, nil
}

// probeDistro runs the WSL probe script inside a single distro and returns the
// AI tools it detects.
func probeDistro(distro string, tools []types.ToolSignature) ([]types.Program, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wslProbeTimeout)
	defer cancel()

	// #nosec G204 -- distro names come from wsl.exe -l -q on the local
	// machine, and the probe script is generated from a static signature DB.
	cmd := exec.CommandContext(ctx,
		windowsSystemToolPath("wsl.exe"), "-d", distro, "--", "bash", "-lc", buildWSLProbeScript(tools),
	)
	cmd.Dir = windowsSystemDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("wsl -d %s probe: %w: %s", distro, err, stderr.String())
	}
	return parseWSLOutput(stdout.String(), tools), nil
}

// windowsSystemDir returns a Windows-local working directory for wsl.exe.
// This avoids UNC current-directory translation failures when sys-scanner is
// itself running through WSL interop.
func windowsSystemDir() string {
	return windowsRootDir()
}

// decodeUTF16LEIfNeeded decodes wsl.exe output when it is UTF-16LE (detected
// via a BOM of FF FE or NUL bytes at odd indices) and otherwise returns the
// input as UTF-8.
func decodeUTF16LEIfNeeded(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		return decodeUTF16LE(b[2:])
	}
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			return decodeUTF16LE(b)
		}
	}
	return string(b)
}

// decodeUTF16LE decodes little-endian UTF-16 bytes to a string.
func decodeUTF16LE(b []byte) string {
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		r := uint16(b[i]) | uint16(b[i+1])<<8
		runes = append(runes, rune(r))
	}
	return string(runes)
}
