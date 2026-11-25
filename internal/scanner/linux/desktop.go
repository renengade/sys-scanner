// Package linux implements Linux-specific program detection.
package linux

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"sys-scanner/internal/types"
)

// desktopDirs lists directories scanned for .desktop files.
// Order: system-wide first, then user-local, then snap/flatpak.
var desktopDirs = func() []string {
	home, _ := os.UserHomeDir()
	if h := os.Getenv("HOME"); h != "" {
		home = h
	}

	dirs := []string{
		"/usr/share/applications",
		"/usr/local/share/applications",
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "applications"))
	}
	dirs = append(dirs,
		"/var/lib/snapd/desktop/applications",
		"/var/lib/flatpak/exports/share/applications",
	)
	if home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".local", "share", "flatpak", "exports", "share", "applications"),
		)
	}
	return dirs
}

// desktopEntry holds parsed fields from a [Desktop Entry] section.
type desktopEntry struct {
	name    string
	comment string
	exec    string
}

// parseDesktopFile parses a single .desktop file and returns the entry.
// Returns (entry, true) on success, (zero, false) if the file should be skipped.
//
// The read is scoped through os.Root: the file is opened by bare filename
// inside its own directory, so no path component outside that directory can
// ever be traversed, regardless of where the caller obtained the path.
func parseDesktopFile(path string) (desktopEntry, bool) {
	dir, name := filepath.Split(path)
	if dir == "" || name == "" {
		return desktopEntry{}, false
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return desktopEntry{}, false
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(name)
	if err != nil {
		return desktopEntry{}, false
	}
	defer func() { _ = f.Close() }()

	var entry desktopEntry
	inDesktopSection := false
	noDisplay := false
	hidden := false
	isApplication := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToValidUTF8(scanner.Text(), "")
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") {
			if line == "[Desktop Entry]" {
				inDesktopSection = true
			} else {
				// Once we leave [Desktop Entry], stop parsing.
				if inDesktopSection {
					break
				}
			}
			continue
		}

		if !inDesktopSection {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Type":
			if value == "Application" {
				isApplication = true
			}
		case "Name":
			if entry.name == "" {
				entry.name = value
			}
		case "Comment":
			if entry.comment == "" {
				entry.comment = value
			}
		case "Exec":
			if entry.exec == "" {
				entry.exec = value
			}
		case "NoDisplay":
			noDisplay = strings.EqualFold(value, "true")
		case "Hidden":
			hidden = strings.EqualFold(value, "true")
		}
	}

	if !isApplication || noDisplay || hidden || entry.name == "" {
		return desktopEntry{}, false
	}

	return entry, true
}

// execBinary extracts the first token from the Exec value, stripping
// field codes (%f, %F, %u, %U, etc.) per the Desktop Entry Specification.
func execBinary(exec string) string {
	exec = strings.TrimSpace(exec)
	if exec == "" {
		return ""
	}

	// A quoted Exec value may contain spaces inside the quotes, so the
	// binary must be taken up to the matching closing quote.
	for _, q := range []string{`"`, `'`} {
		if strings.HasPrefix(exec, q) {
			if end := strings.Index(exec[1:], q); end >= 0 {
				return filepath.Base(exec[1 : 1+end])
			}
		}
	}

	// Otherwise take the first space-delimited token.
	parts := strings.Fields(exec)
	if len(parts) == 0 {
		return ""
	}

	bin := strings.Trim(parts[0], `"'`)
	return filepath.Base(bin)
}

// scanDesktopFiles walks all known .desktop directories and returns programs.
func scanDesktopFiles() []types.Program {
	var programs []types.Program

	for _, dir := range desktopDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}

			filePath := filepath.Join(dir, entry.Name())
			parsed, ok := parseDesktopFile(filePath)
			if !ok {
				continue
			}

			binary := execBinary(parsed.exec)
			installLoc := ""
			if binary != "" {
				installLoc = binary
			}

			p := types.Program{
				Name:            strings.ToValidUTF8(parsed.name, ""),
				InstallLocation: installLoc,
				Source:          ".desktop",
				RawMetadata: map[string]string{
					"comment":  strings.ToValidUTF8(parsed.comment, ""),
					"exec":     strings.ToValidUTF8(parsed.exec, ""),
					"file_dir": dir,
				},
			}

			programs = append(programs, p)
		}
	}

	return programs
}
