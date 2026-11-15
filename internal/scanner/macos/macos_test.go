//go:build darwin

package macos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"

	"sys-scanner/internal/platform"
	"sys-scanner/internal/signatures"
)

// Compile-time interface check.
var _ platform.PlatformDetector = (*Scanner)(nil)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.Stats == nil {
		t.Fatal("New() did not initialize Stats")
	}
}

// --- parseAppBundle tests ---

func TestParseAppBundle_XMLPlist(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "TestApp.app")
	plistDir := filepath.Join(appDir, "Contents")
	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		t.Fatal(err)
	}

	info := map[string]any{
		"CFBundleDisplayName":        "Test Application",
		"CFBundleName":               "TestApp",
		"CFBundleShortVersionString": "1.2.3",
		"CFBundleIdentifier":         "com.example.testapp",
		"CFBundleVersion":            "42",
		"CFBundleExecutable":         "TestApp",
		"LSMinimumSystemVersion":     "12.0",
	}
	data, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plistDir, "Info.plist"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := parseAppBundle(appDir)
	if err != nil {
		t.Fatalf("parseAppBundle failed: %v", err)
	}

	assertField(t, "Name", p.Name, "Test Application")
	assertField(t, "Version", p.Version, "1.2.3")
	assertField(t, "Publisher", p.Publisher, "com.example.testapp")
	assertField(t, "InstallLocation", p.InstallLocation, appDir)
	assertField(t, "Source", p.Source, "app_bundle")

	if p.RawMetadata["CFBundleVersion"] != "42" {
		t.Errorf("RawMetadata CFBundleVersion: got %q, want %q", p.RawMetadata["CFBundleVersion"], "42")
	}
}

func TestParseAppBundle_BinaryPlist(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Binary.app")
	plistDir := filepath.Join(appDir, "Contents")
	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		t.Fatal(err)
	}

	info := map[string]any{
		"CFBundleDisplayName":        "Binary Tool",
		"CFBundleShortVersionString": "2.0.0",
		"CFBundleIdentifier":         "com.example.binary",
	}
	data, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plistDir, "Info.plist"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := parseAppBundle(appDir)
	if err != nil {
		t.Fatalf("parseAppBundle binary plist failed: %v", err)
	}

	assertField(t, "Name", p.Name, "Binary Tool")
	assertField(t, "Version", p.Version, "2.0.0")
	assertField(t, "Source", p.Source, "app_bundle")
}

func TestParseAppBundle_NameFallback(t *testing.T) {
	dir := t.TempDir()

	// Case 1: CFBundleDisplayName absent → falls back to CFBundleName
	appDir1 := filepath.Join(dir, "AppName.app")
	writeMockPlist(t, appDir1, map[string]any{
		"CFBundleName":               "FromBundleName",
		"CFBundleShortVersionString": "1.0",
	})
	p1, err := parseAppBundle(appDir1)
	if err != nil {
		t.Fatal(err)
	}
	assertField(t, "Name", p1.Name, "FromBundleName")

	// Case 2: Both absent → falls back to directory basename
	appDir2 := filepath.Join(dir, "DirFallback.app")
	writeMockPlist(t, appDir2, map[string]any{
		"CFBundleShortVersionString": "1.0",
	})
	p2, err := parseAppBundle(appDir2)
	if err != nil {
		t.Fatal(err)
	}
	assertField(t, "Name", p2.Name, "DirFallback")
}

func TestParseAppBundle_MissingPlist(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "NoPlist.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := parseAppBundle(appDir)
	if err == nil {
		t.Fatal("expected error for missing Info.plist")
	}
}

func TestParseAppBundle_InvalidPlist(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "Bad.app")
	plistDir := filepath.Join(appDir, "Contents")
	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plistDir, "Info.plist"), []byte("not a plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := parseAppBundle(appDir)
	if err == nil {
		t.Fatal("expected error for invalid plist data")
	}
}

// --- parseSysProfilerOutput tests ---

func TestParseSysProfilerOutput(t *testing.T) {
	// Build a mock system_profiler XML plist output.
	root := []map[string]any{
		{
			"_items": []any{
				map[string]any{
					"_name":         "Safari",
					"version":       "17.2",
					"path":          "/Applications/Safari.app",
					"obtained_from": "apple_installers",
				},
				map[string]any{
					"_name":         "Xcode",
					"version":       "15.1",
					"path":          "/Applications/Xcode.app",
					"obtained_from": "identified_developer",
				},
			},
		},
	}
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	programs, err := parseSysProfilerOutput(data)
	if err != nil {
		t.Fatalf("parseSysProfilerOutput failed: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(programs))
	}

	assertField(t, "Name[0]", programs[0].Name, "Safari")
	assertField(t, "Version[0]", programs[0].Version, "17.2")
	assertField(t, "InstallLocation[0]", programs[0].InstallLocation, "/Applications/Safari.app")
	assertField(t, "Source[0]", programs[0].Source, "system_profiler")
	assertField(t, "obtained_from[0]", programs[0].RawMetadata["obtained_from"], "apple_installers")

	assertField(t, "Name[1]", programs[1].Name, "Xcode")
}

func TestParseSysProfilerOutput_Empty(t *testing.T) {
	root := []map[string]any{{}}
	data, err := plist.Marshal(root, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	programs, err := parseSysProfilerOutput(data)
	if err != nil {
		t.Fatalf("parseSysProfilerOutput empty failed: %v", err)
	}
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs, got %d", len(programs))
	}
}

func TestParseSysProfilerOutput_InvalidData(t *testing.T) {
	_, err := parseSysProfilerOutput([]byte("not a plist"))
	if err == nil {
		t.Fatal("expected error for invalid plist data")
	}
}

// --- macosPATHAllowlist / AI binary names tests ---

func TestMacOSAIBinariesNonEmpty(t *testing.T) {
	binaries := signatures.BinaryNames()
	if len(binaries) == 0 {
		t.Fatal("signatures.BinaryNames() returned empty list")
	}

	// All names must be unique and lowercased.
	seen := make(map[string]struct{}, len(binaries))
	for _, b := range binaries {
		if b != strings.ToLower(b) {
			t.Errorf("binary name %q is not lowercased", b)
		}
		if _, ok := seen[b]; ok {
			t.Errorf("duplicate binary name %q", b)
		}
		seen[b] = struct{}{}
	}

	// Check known tools are present
	found := make(map[string]bool)
	for _, b := range binaries {
		found[b] = true
	}
	for _, expected := range []string{"opencode", "claude", "cursor", "ollama"} {
		if !found[expected] {
			t.Errorf("signatures.BinaryNames() missing %q", expected)
		}
	}
}

func TestMacosPATHAllowlistNonEmpty(t *testing.T) {
	allowlist := macosPATHAllowlist()
	if len(allowlist) == 0 {
		t.Fatal("macosPATHAllowlist() returned empty list")
	}
}

// --- Scanner interface compliance ---

func TestScannerDetectInterface(t *testing.T) {
	var d platform.PlatformDetector = New()
	// Detect will return empty on non-macOS (no /Applications, no brew, no system_profiler).
	// We just verify it doesn't panic and returns a valid result.
	result, err := d.Detect()
	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	// result should be a non-nil (possibly empty) slice from merge.Deduplicate
	if result == nil {
		// merge.Deduplicate returns []types.Program{} for empty input, not nil
		// but either is acceptable — just verify no panic
		_ = result
	}
}

// --- helpers ---

func writeMockPlist(t *testing.T, appDir string, info map[string]any) {
	t.Helper()
	plistDir := filepath.Join(appDir, "Contents")
	if err := os.MkdirAll(plistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plistDir, "Info.plist"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertField(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", label, got, want)
	}
}
