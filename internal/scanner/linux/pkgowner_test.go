package linux

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sys-scanner/internal/types"
)

// stubPackageTools replaces lookPath/execCommand for package-owner tests.
func stubPackageTools(t *testing.T, paths map[string]string, run func(name string, args []string) ([]byte, error)) func() {
	t.Helper()
	origLookPath := lookPath
	origExec := execCommand
	lookPath = func(name string) (string, error) {
		if p, ok := paths[name]; ok {
			return p, nil
		}
		return "", os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return run(name, args)
	}
	return func() { lookPath = origLookPath; execCommand = origExec }
}

func TestEnrichDesktopPrograms_Dpkg(t *testing.T) {
	defer stubPackageTools(t,
		map[string]string{"dpkg-query": "/usr/bin/dpkg-query"},
		func(name string, args []string) ([]byte, error) {
			switch {
			case name == "dpkg-query" && len(args) > 0 && args[0] == "-S":
				return []byte("coreutils: /usr/bin/ls\n"), nil
			case name == "dpkg-query" && len(args) > 0 && args[0] == "-W":
				return []byte("coreutils\t8.32-4.1\tUbuntu Developers <ubuntu-devel@lists.ubuntu.com>\n"), nil
			}
			return nil, os.ErrNotExist
		})()

	programs := []types.Program{{
		Name:            "GNU Coreutils",
		Source:          ".desktop",
		InstallLocation: "ls",
		RawMetadata:     map[string]string{"exec": "/usr/bin/ls %u"},
	}}
	out := enrichDesktopPrograms(programs)
	if out[0].Version != "8.32-4.1" {
		t.Errorf("Version = %q, want 8.32-4.1", out[0].Version)
	}
	if !containsStr(out[0].Publisher, "Ubuntu Developers") {
		t.Errorf("Publisher = %q, want maintainer", out[0].Publisher)
	}
	if out[0].RawMetadata["Package"] != "coreutils" {
		t.Errorf("Package = %q", out[0].RawMetadata["Package"])
	}
	if out[0].Source != ".desktop" {
		t.Errorf("Source changed: %q", out[0].Source)
	}
}

func TestEnrichDesktopPrograms_Pacman(t *testing.T) {
	defer stubPackageTools(t,
		map[string]string{"pacman": "/usr/bin/pacman", "firefox": "/usr/bin/firefox"},
		func(name string, args []string) ([]byte, error) {
			if name == "pacman" && len(args) > 1 && args[0] == "-Qo" {
				return []byte("/usr/bin/firefox is owned by firefox 133.0-1\n"), nil
			}
			return nil, os.ErrNotExist
		})()

	programs := []types.Program{{
		Name:            "Firefox",
		Source:          ".desktop",
		InstallLocation: "firefox",
		RawMetadata:     map[string]string{"exec": "firefox %u"},
	}}
	out := enrichDesktopPrograms(programs)
	if out[0].Version != "133.0-1" {
		t.Errorf("Version = %q, want 133.0-1", out[0].Version)
	}
	if out[0].RawMetadata["Package"] != "firefox" {
		t.Errorf("Package = %q", out[0].RawMetadata["Package"])
	}
}

func TestEnrichDesktopPrograms_UnresolvedStaysUntouched(t *testing.T) {
	defer stubPackageTools(t,
		map[string]string{"dpkg-query": "/usr/bin/dpkg-query"},
		func(name string, args []string) ([]byte, error) {
			if name == "dpkg-query" && len(args) > 0 && args[0] == "-S" {
				return []byte("dpkg-query: no path found matching /no/such/exe\n"), nil
			}
			return nil, os.ErrNotExist
		})()

	programs := []types.Program{{
		Name:        "Mystery App",
		Source:      ".desktop",
		RawMetadata: map[string]string{"exec": "/no/such/exe"},
	}}
	out := enrichDesktopPrograms(programs)
	if out[0].Version != "" || out[0].Publisher != "" {
		t.Errorf("unresolved entry should stay untouched: %+v", out[0])
	}
}

func TestFirstExecToken(t *testing.T) {
	tests := []struct {
		exec string
		want string
	}{
		{"/usr/bin/firefox %u", "/usr/bin/firefox"},
		{`"C:\Program Files\App\app.exe" --flag`, `C:\Program Files\App\app.exe`},
		{"/usr/bin/env python3 %f", "python3"},
		{"env PYTHONUNBUFFERED=1 tool", "tool"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstExecToken(tt.exec); got != tt.want {
			t.Errorf("firstExecToken(%q) = %q, want %q", tt.exec, got, tt.want)
		}
	}
}

func TestDesktopExecPath_PrefersRawExecThenPATH(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux path semantics")
	}
	defer stubPackageTools(t,
		map[string]string{"mytool": "/opt/tools/mytool"},
		func(string, []string) ([]byte, error) { return nil, os.ErrNotExist })()

	p := types.Program{
		Source:          ".desktop",
		InstallLocation: "mytool",
		RawMetadata:     map[string]string{"exec": "mytool %u"},
	}
	if got := desktopExecPath(p); got != filepath.Join("/opt/tools", "mytool") {
		t.Errorf("desktopExecPath = %q, want /opt/tools/mytool", got)
	}
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
