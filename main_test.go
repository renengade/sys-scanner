package main

import (
	"path/filepath"
	"testing"

	"sys-scanner/internal/types"
)

func TestDefaultFilename(t *testing.T) {
	if defaultFilename("html") != "sys-scanner-report.html" {
		t.Errorf("html default = %q", defaultFilename("html"))
	}
	if defaultFilename("json") != "sys-scanner-inventory.json" {
		t.Errorf("json default = %q", defaultFilename("json"))
	}
	if defaultFilename("csv") != "sys-scanner-inventory.csv" {
		t.Errorf("csv default = %q", defaultFilename("csv"))
	}
}

func TestResolveOutputPath(t *testing.T) {
	if got := resolveOutputPath("json", "-"); got != "-" {
		t.Errorf("stdout path = %q", got)
	}
	dir := t.TempDir()
	if got := resolveOutputPath("csv", dir); got != filepath.Join(dir, "sys-scanner-inventory.csv") {
		t.Errorf("directory path = %q", got)
	}
	explicit := filepath.Join(t.TempDir(), "custom.json")
	if got := resolveOutputPath("json", explicit); got != explicit {
		t.Errorf("explicit path = %q", got)
	}
	if got := resolveOutputPath("html", ""); filepath.Dir(got) != defaultOutputDir() {
		t.Errorf("default path = %q, want in %q", got, defaultOutputDir())
	}
	if filepath.Base(defaultOutputDir()) != "sys-scanner" {
		t.Errorf("default output dir = %q, want a sys-scanner folder", defaultOutputDir())
	}
}

func TestCountSources(t *testing.T) {
	programs := []types.Program{
		{Source: "registry"},
		{Source: "registry"},
		{Source: "PATH"},
		{Source: ""},
	}
	if got := countSources(programs); got != 2 {
		t.Errorf("countSources = %d, want 2", got)
	}
}

func TestRun_VersionAndInvalidFormat(t *testing.T) {
	if code := run([]string{"-version"}); code != 0 {
		t.Errorf("-version exit code = %d", code)
	}
	if code := run([]string{"-format", "xml"}); code != 2 {
		t.Errorf("invalid format exit code = %d, want 2", code)
	}
	if code := run([]string{"-timeout", "0s"}); code != 2 {
		t.Errorf("invalid timeout exit code = %d, want 2", code)
	}
}
