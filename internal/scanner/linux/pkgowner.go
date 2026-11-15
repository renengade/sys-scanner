package linux

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"sys-scanner/internal/types"
)

const pkgOwnerTimeout = 10 * time.Second

// enrichDesktopPrograms completes .desktop entries with the version and
// maintainer/vendor of the package that owns their executable. .desktop files
// themselves do not carry this metadata, so the owning package is the best
// available source.
//
// Best-effort: entries whose executable cannot be resolved or whose package
// manager is unknown are left untouched.
func enrichDesktopPrograms(programs []types.Program) []types.Program {
	for i := range programs {
		p := &programs[i]
		if p.Source != ".desktop" {
			continue
		}
		if strings.TrimSpace(p.Version) != "" && strings.TrimSpace(p.Publisher) != "" {
			continue
		}
		exe := desktopExecPath(*p)
		if exe == "" {
			continue
		}
		pkg, version, publisher, ok := packageOwner(exe)
		if !ok {
			continue
		}
		changed := false
		if strings.TrimSpace(p.Version) == "" && version != "" {
			p.Version = version
			changed = true
		}
		if strings.TrimSpace(p.Publisher) == "" && publisher != "" {
			p.Publisher = publisher
			changed = true
		}
		if changed {
			if p.RawMetadata == nil {
				p.RawMetadata = make(map[string]string)
			}
			p.RawMetadata["Package"] = pkg
		}
	}
	return programs
}

// desktopExecPath resolves the executable a .desktop entry launches. It
// prefers the raw Exec token (which may be an absolute path), falling back to
// PATH lookup for bare command names.
func desktopExecPath(p types.Program) string {
	token := ""
	if p.RawMetadata != nil {
		token = firstExecToken(p.RawMetadata["exec"])
	}
	if token == "" && p.InstallLocation != "" {
		token = p.InstallLocation
	}
	if token == "" {
		return ""
	}
	if filepath.IsAbs(token) {
		return token
	}
	if resolved, err := lookPath(token); err == nil {
		return resolved
	}
	return ""
}

// firstExecToken extracts the executable token from an Exec= value, honouring
// quotes and skipping `env` wrappers.
func firstExecToken(exec string) string {
	exec = strings.TrimSpace(exec)
	if exec == "" {
		return ""
	}

	token := ""
	rest := ""
	for _, q := range []string{`"`, `'`} {
		if strings.HasPrefix(exec, q) {
			if end := strings.Index(exec[1:], q); end >= 0 {
				token = exec[1 : 1+end]
				rest = exec[1+end+1:]
				break
			}
		}
	}
	if token == "" {
		fields := strings.Fields(exec)
		if len(fields) == 0 {
			return ""
		}
		token, rest = fields[0], strings.Join(fields[1:], " ")
	}
	token = strings.Trim(token, `"'`)

	// `env VAR=1 python3 %f` — the interesting binary is the one after env.
	fields := strings.Fields(rest)
	if strings.EqualFold(filepath.Base(token), "env") && len(fields) > 0 {
		// Skip over `VAR=value` assignments that `env` may carry.
		i := 0
		for i < len(fields) && strings.Contains(fields[i], "=") {
			i++
		}
		if i < len(fields) {
			token = fields[i]
		}
	}
	return token
}

// packageOwner looks up which installed package provides path and returns its
// name, version, and publisher/maintainer.
func packageOwner(path string) (pkg, version, publisher string, ok bool) {
	if path == "" {
		return "", "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), pkgOwnerTimeout)
	defer cancel()

	if _, err := lookPath("dpkg-query"); err == nil {
		if out, err := execCommand(ctx, "dpkg-query", "-S", path); err == nil {
			if pkg := dpkgOwnerPackage(string(out)); pkg != "" {
				if out2, err := execCommand(ctx, "dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\n", pkg); err == nil {
					if fields := strings.SplitN(strings.ToValidUTF8(firstLine(string(out2)), ""), "\t", 3); len(fields) >= 2 {
						return pkg, strings.TrimSpace(fields[1]), strings.TrimSpace(fields[2]), true
					}
				}
				return pkg, "", "", true
			}
		}
	}

	if _, err := lookPath("rpm"); err == nil {
		if out, err := execCommand(ctx, "rpm", "-qf", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n", path); err == nil {
			if fields := strings.SplitN(strings.ToValidUTF8(firstLine(string(out)), ""), "\t", 3); len(fields) >= 2 && fields[0] != "" {
				publisher := ""
				if len(fields) == 3 {
					publisher = strings.TrimSpace(fields[2])
				}
				return strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1]), publisher, true
			}
		}
	}

	if _, err := lookPath("pacman"); err == nil {
		if out, err := execCommand(ctx, "pacman", "-Qo", path); err == nil {
			if pkg, version := pacmanOwner(string(out)); pkg != "" {
				return pkg, version, "", true
			}
		}
	}

	return "", "", "", false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// dpkgOwnerPackage parses `dpkg-query -S` output; the first line looks like
// "coreutils: /usr/bin/ls".
func dpkgOwnerPackage(out string) string {
	line := firstLine(out)
	if line == "" {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
}

// pacmanOwner parses `pacman -Qo` output:
// "/usr/bin/foo is owned by foo 1.2-3".
func pacmanOwner(out string) (pkg, version string) {
	line := strings.ToValidUTF8(firstLine(out), "")
	idx := strings.Index(line, " is owned by ")
	if idx < 0 {
		return "", ""
	}
	fields := strings.Fields(line[idx+len(" is owned by "):])
	if len(fields) < 2 {
		return "", ""
	}
	return fields[0], fields[1]
}
