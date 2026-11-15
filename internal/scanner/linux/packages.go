package linux

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"sys-scanner/internal/types"
)

const pkgTimeout = 30 * time.Second

// lookPath is a function variable for checking binary existence.
// Tests replace this with a mock to avoid requiring real Linux binaries.
var lookPath = exec.LookPath

// execCommand is a function variable for running external commands.
// Tests replace this with a mock to avoid requiring real Linux binaries.
var execCommand = defaultExecCommand

func defaultExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- name is one of a fixed set of package-manager commands;
	// it is never user-controlled.
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

// scanPackages runs all available package manager scanners and returns
// the combined results. Each scanner runs independently; failure of one
// does not affect others.
func scanPackages() []types.Program {
	var programs []types.Program

	programs = append(programs, scanDpkg()...)
	programs = append(programs, scanRpm()...)
	programs = append(programs, scanPacman()...)
	programs = append(programs, scanApk()...)
	programs = append(programs, scanSnap()...)
	programs = append(programs, scanFlatpak()...)

	return programs
}

// scanPacman queries the pacman database (Arch Linux).
// Command: pacman -Q
func scanPacman() []types.Program {
	if _, err := lookPath("pacman"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "pacman", "-Q")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		programs = append(programs, types.Program{
			Name:    fields[0],
			Version: fields[1],
			Source:  "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "pacman",
			},
		})
	}
	return programs
}

// scanApk queries installed Alpine packages.
// Command: apk info
func scanApk() []types.Program {
	if _, err := lookPath("apk"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "apk", "info")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		name := strings.TrimSpace(strings.ToValidUTF8(scanner.Text(), ""))
		if name == "" || strings.HasPrefix(name, "WARNING:") {
			continue
		}
		programs = append(programs, types.Program{
			Name:   name,
			Source: "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "apk",
			},
		})
	}
	return programs
}

// scanDpkg queries the dpkg package database (Debian/Ubuntu).
// Command: dpkg-query -W -f '${Package}\t${Version}\t${Maintainer}\n'
func scanDpkg() []types.Program {
	if _, err := lookPath("dpkg-query"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\n")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 2 {
			continue
		}

		p := types.Program{
			Name:    fields[0],
			Version: fields[1],
			Source:  "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "dpkg",
			},
		}
		if len(fields) == 3 {
			p.Publisher = fields[2]
		}
		programs = append(programs, p)
	}

	return programs
}

// scanRpm queries the RPM package database (RHEL/Fedora/SUSE).
// Command: rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{VENDOR}\n'
func scanRpm() []types.Program {
	if _, err := lookPath("rpm"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 2 {
			continue
		}

		p := types.Program{
			Name:    fields[0],
			Version: fields[1],
			Source:  "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "rpm",
			},
		}
		if len(fields) == 3 {
			p.Publisher = fields[2]
		}
		programs = append(programs, p)
	}

	return programs
}

// scanSnap queries installed snap packages.
// Command: snap list
// Output is a table with header: Name  Version  Publisher  ...
func scanSnap() []types.Program {
	if _, err := lookPath("snap"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "snap", "list")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	// Skip header line.
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		p := types.Program{
			Name:    fields[0],
			Version: fields[1],
			Source:  "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "snap",
			},
		}
		if len(fields) >= 5 {
			p.Publisher = fields[4]
		}
		programs = append(programs, p)
	}

	return programs
}

// scanFlatpak queries installed flatpak applications.
// Command: flatpak list --columns=name,version,origin
func scanFlatpak() []types.Program {
	if _, err := lookPath("flatpak"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), pkgTimeout)
	defer cancel()

	out, err := execCommand(ctx, "flatpak", "list", "--columns=name,version,origin")
	if err != nil {
		return nil
	}

	var programs []types.Program
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) < 2 {
			continue
		}

		p := types.Program{
			Name:    fields[0],
			Version: fields[1],
			Source:  "package_manager",
			RawMetadata: map[string]string{
				"package_manager": "flatpak",
			},
		}
		if len(fields) == 3 {
			p.Publisher = fields[2]
		}
		programs = append(programs, p)
	}

	return programs
}
