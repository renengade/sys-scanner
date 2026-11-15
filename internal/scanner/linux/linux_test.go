package linux

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sys-scanner/internal/types"
)

// --- .desktop file parser tests ---

func TestParseDesktopFile_Valid(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=Firefox Web Browser
Comment=Browse the World Wide Web
Exec=/usr/lib/firefox/firefox %u
Icon=firefox
Terminal=false
Categories=Network;WebBrowser;
`
	path := filepath.Join(dir, "firefox.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, ok := parseDesktopFile(path)
	if !ok {
		t.Fatal("expected parseDesktopFile to return true for valid .desktop file")
	}
	if entry.name != "Firefox Web Browser" {
		t.Errorf("Name = %q, want %q", entry.name, "Firefox Web Browser")
	}
	if entry.comment != "Browse the World Wide Web" {
		t.Errorf("Comment = %q, want %q", entry.comment, "Browse the World Wide Web")
	}
	if !strings.Contains(entry.exec, "/usr/lib/firefox/firefox") {
		t.Errorf("Exec = %q, want to contain %q", entry.exec, "/usr/lib/firefox/firefox")
	}
}

func TestParseDesktopFile_NoDisplay(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=Hidden App
Exec=/usr/bin/hidden
NoDisplay=true
`
	path := filepath.Join(dir, "hidden.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok := parseDesktopFile(path)
	if ok {
		t.Error("expected NoDisplay=true to skip this entry")
	}
}

func TestParseDesktopFile_Hidden(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=Also Hidden
Exec=/usr/bin/also-hidden
Hidden=true
`
	path := filepath.Join(dir, "also-hidden.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok := parseDesktopFile(path)
	if ok {
		t.Error("expected Hidden=true to skip this entry")
	}
}

func TestParseDesktopFile_NotApplication(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Link
Name=A Link
URL=https://example.com
`
	path := filepath.Join(dir, "link.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok := parseDesktopFile(path)
	if ok {
		t.Error("expected Type=Link to skip this entry (only Application accepted)")
	}
}

func TestParseDesktopFile_MissingType(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Name=No Type App
Exec=/usr/bin/notype
`
	path := filepath.Join(dir, "notype.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok := parseDesktopFile(path)
	if ok {
		t.Error("expected missing Type to skip this entry")
	}
}

func TestParseDesktopFile_OnlyDesktopEntrySection(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=Good App
Exec=/usr/bin/good

[Desktop Action NewWindow]
Name=New Window
`
	path := filepath.Join(dir, "good.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, ok := parseDesktopFile(path)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if entry.name != "Good App" {
		t.Errorf("Name = %q, want %q", entry.name, "Good App")
	}
}

func TestParseDesktopFile_UTF8Handling(t *testing.T) {
	dir := t.TempDir()
	content := "[Desktop Entry]\nType=Application\nName=App with \xff\xfe invalid bytes\nExec=/usr/bin/app\n"
	path := filepath.Join(dir, "utf8.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, ok := parseDesktopFile(path)
	if !ok {
		t.Fatal("expected parse to succeed even with invalid UTF-8 bytes")
	}
	// Name should have invalid bytes stripped (ToValidUTF8).
	if entry.name == "" {
		t.Error("Name should not be empty after stripping invalid UTF-8")
	}
}

func TestParseDesktopFile_DuplicateName(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=First Name
Name=Second Name
Exec=/usr/bin/app
`
	path := filepath.Join(dir, "dup.desktop")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	entry, ok := parseDesktopFile(path)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if entry.name != "First Name" {
		t.Errorf("Name = %q, want first occurrence %q", entry.name, "First Name")
	}
}

// --- scanDesktopFiles integration with mock dirs ---

func TestScanDesktopFiles_MockDirs(t *testing.T) {
	dir := t.TempDir()
	content := `[Desktop Entry]
Type=Application
Name=Test App
Comment=A test application
Exec=/usr/bin/testapp %u
`
	if err := os.WriteFile(filepath.Join(dir, "testapp.desktop"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	origDirs := desktopDirs
	defer func() { desktopDirs = origDirs }()
	desktopDirs = func() []string { return []string{dir} }

	programs := scanDesktopFiles()
	if len(programs) != 1 {
		t.Fatalf("scanDesktopFiles() returned %d programs, want 1", len(programs))
	}

	p := programs[0]
	if p.Name != "Test App" {
		t.Errorf("Name = %q, want %q", p.Name, "Test App")
	}
	if p.Source != ".desktop" {
		t.Errorf("Source = %q, want %q", p.Source, ".desktop")
	}
	if p.InstallLocation != "testapp" {
		t.Errorf("InstallLocation = %q, want %q", p.InstallLocation, "testapp")
	}
	if p.RawMetadata["comment"] != "A test application" {
		t.Errorf("RawMetadata[comment] = %q, want %q", p.RawMetadata["comment"], "A test application")
	}
}

// --- Exec binary extraction tests ---

func TestExecBinary(t *testing.T) {
	tests := []struct {
		exec string
		want string
	}{
		{"/usr/bin/firefox", "firefox"},
		{"/usr/lib/firefox/firefox %u", "firefox"},
		{`"/opt/My App/bin/app" --flag`, "app"},
		{"java -jar /opt/app.jar", "java"},
		{"", ""},
		{"/usr/bin/env python3 %f", "env"},
	}

	for _, tt := range tests {
		got := execBinary(tt.exec)
		if got != tt.want {
			t.Errorf("execBinary(%q) = %q, want %q", tt.exec, got, tt.want)
		}
	}
}

// --- Package manager tests (with mock execCommand) ---

func TestScanDpkg(t *testing.T) {
	mockOutput := "bash\t5.1-6\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\ncoreutils\t8.32-4.1ubuntu1\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n"

	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte(mockOutput), nil
		}
		return nil, nil
	}

	programs := scanDpkg()
	if len(programs) != 2 {
		t.Fatalf("scanDpkg() returned %d programs, want 2", len(programs))
	}

	if programs[0].Name != "bash" {
		t.Errorf("programs[0].Name = %q, want %q", programs[0].Name, "bash")
	}
	if programs[0].Version != "5.1-6" {
		t.Errorf("programs[0].Version = %q, want %q", programs[0].Version, "5.1-6")
	}
	if programs[0].Source != "package_manager" {
		t.Errorf("programs[0].Source = %q, want %q", programs[0].Source, "package_manager")
	}
	if !strings.Contains(programs[0].Publisher, "Ubuntu") {
		t.Errorf("programs[0].Publisher = %q, want to contain %q", programs[0].Publisher, "Ubuntu")
	}
}

func TestScanRpm(t *testing.T) {
	mockOutput := "kernel\t5.14.0\tRed Hat, Inc.\nglibc\t2.34\tRed Hat, Inc.\n"

	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "rpm" {
			return []byte(mockOutput), nil
		}
		return nil, nil
	}

	programs := scanRpm()
	if len(programs) != 2 {
		t.Fatalf("scanRpm() returned %d programs, want 2", len(programs))
	}

	if programs[0].Name != "kernel" {
		t.Errorf("programs[0].Name = %q, want %q", programs[0].Name, "kernel")
	}
	if programs[0].Publisher != "Red Hat, Inc." {
		t.Errorf("programs[0].Publisher = %q, want %q", programs[0].Publisher, "Red Hat, Inc.")
	}
}

func TestScanSnap(t *testing.T) {
	mockOutput := `Name    Version   Rev    Tracking     Publisher   Notes
core20  20231123  2105   latest/stable  canonical✓    base
snapd   2.61.1    20671  latest/stable  canonical✓    snapd
`

	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "snap" {
			return []byte(mockOutput), nil
		}
		return nil, nil
	}

	programs := scanSnap()
	if len(programs) != 2 {
		t.Fatalf("scanSnap() returned %d programs, want 2", len(programs))
	}

	if programs[0].Name != "core20" {
		t.Errorf("programs[0].Name = %q, want %q", programs[0].Name, "core20")
	}
	if programs[0].Version != "20231123" {
		t.Errorf("programs[0].Version = %q, want %q", programs[0].Version, "20231123")
	}
	if programs[0].Publisher != "canonical✓" {
		t.Errorf("programs[0].Publisher = %q, want %q", programs[0].Publisher, "canonical✓")
	}
}

func TestScanFlatpak(t *testing.T) {
	mockOutput := "Firefox\t121.0\tflathub\nVLC\t3.0.20\tflathub\n"

	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "flatpak" {
			return []byte(mockOutput), nil
		}
		return nil, nil
	}

	programs := scanFlatpak()
	if len(programs) != 2 {
		t.Fatalf("scanFlatpak() returned %d programs, want 2", len(programs))
	}

	if programs[0].Name != "Firefox" {
		t.Errorf("programs[0].Name = %q, want %q", programs[0].Name, "Firefox")
	}
	if programs[0].Publisher != "flathub" {
		t.Errorf("programs[0].Publisher = %q, want %q", programs[0].Publisher, "flathub")
	}
}

// --- /opt/ scanner tests ---

func TestScanOptDir(t *testing.T) {
	root := t.TempDir()

	// Create subdirectories (programs).
	subdirs := []string{"google", "vscode", "zoom"}
	for _, name := range subdirs {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Create a file at root level (should be skipped).
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a hidden directory (should be skipped).
	if err := os.MkdirAll(filepath.Join(root, ".hidden"), 0o755); err != nil {
		t.Fatal(err)
	}

	programs := scanOptDir(root)

	if len(programs) != 3 {
		t.Fatalf("scanOptDir() returned %d programs, want 3", len(programs))
	}

	names := make(map[string]bool)
	for _, p := range programs {
		names[p.Name] = true
		if p.Source != "opt" {
			t.Errorf("Source = %q, want %q for program %q", p.Source, "opt", p.Name)
		}
		if p.InstallLocation == "" {
			t.Errorf("InstallLocation should not be empty for %q", p.Name)
		}
	}

	for _, want := range subdirs {
		if !names[want] {
			t.Errorf("missing expected program %q", want)
		}
	}
}

func TestScanOptDir_Empty(t *testing.T) {
	root := t.TempDir()
	programs := scanOptDir(root)
	if len(programs) != 0 {
		t.Errorf("scanOptDir() on empty dir returned %d programs, want 0", len(programs))
	}
}

func TestScanOptDir_NonExistent(t *testing.T) {
	programs := scanOptDir("/nonexistent/path/that/does/not/exist")
	if len(programs) != 0 {
		t.Errorf("scanOptDir() on non-existent dir returned %d programs, want 0", len(programs))
	}
}

// --- PATH scanner allowlist tests ---

func TestScanPATHDirs_AllowlistFiltersNonPrograms(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tests the Linux executable-bit behavior")
	}
	dir := t.TempDir()
	for _, name := range []string{
		"git",         // in allowlist
		"mysterytool", // NOT in allowlist -> must be filtered out
		"ollama",      // AI binary -> always passes regardless of allowlist
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", dir)

	scanner := NewLinuxScanner()
	programs := scanner.scanPATHDirs()

	got := make(map[string]bool)
	for _, p := range programs {
		got[p.Name] = true
		if p.Source != "PATH" {
			t.Errorf("Source = %q, want %q", p.Source, "PATH")
		}
	}

	if !got["git"] {
		t.Error("expected git in results (in allowlist)")
	}
	if !got["ollama"] {
		t.Error("expected ollama in results (AI binary bypass)")
	}
	if got["mysterytool"] {
		t.Error("mysterytool should be filtered out (not in allowlist)")
	}
}

func TestLinuxPATHAllowlist_NotEmpty(t *testing.T) {
	if len(linuxPATHAllowlist()) == 0 {
		t.Error("linuxPATHAllowlist() should not be empty")
	}
}

// --- Integration test: LinuxScanner ---

func TestLinuxScanner_Detect(t *testing.T) {
	origOptRoot := optRoot
	defer func() { optRoot = origOptRoot }()

	optDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(optDir, "testapp"), 0o755); err != nil {
		t.Fatal(err)
	}
	optRoot = optDir

	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) {
		if name == "dpkg-query" {
			return "/usr/bin/dpkg-query", nil
		}
		return "", os.ErrNotExist
	}
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "dpkg-query" {
			return []byte("testpkg\t1.0.0\tTestPublisher\n"), nil
		}
		return nil, nil
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer func() {
		if origPath != "" {
			os.Setenv("PATH", origPath)
		}
	}()

	scanner := NewLinuxScanner()
	programs, err := scanner.Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Should have at least: 1 from dpkg + 1 from /opt.
	if len(programs) < 2 {
		t.Fatalf("Detect() returned %d programs, want >= 2", len(programs))
	}

	// Check that programs from different sources are present.
	sources := make(map[string]bool)
	for _, p := range programs {
		sources[p.Source] = true
	}

	if !sources["package_manager"] {
		t.Error("expected package_manager source in results")
	}
	if !sources["opt"] {
		t.Error("expected opt source in results")
	}

	// Verify stats were updated.
	if scanner.Stats.CountBySource["opt"] != 1 {
		t.Errorf("CountBySource[opt] = %d, want 1", scanner.Stats.CountBySource["opt"])
	}
	if scanner.Stats.CountBySource["package_manager"] != 1 {
		t.Errorf("CountBySource[package_manager] = %d, want 1", scanner.Stats.CountBySource["package_manager"])
	}
	// ScanDuration may legitimately be 0 on Windows due to timer resolution;
	// only guard against a negative value.
	if scanner.Stats.ScanDuration < 0 {
		t.Errorf("ScanDuration = %v, want >= 0", scanner.Stats.ScanDuration)
	}
}

// --- Verify PlatformDetector interface compliance ---

func TestLinuxScanner_ImplementsPlatformDetector(t *testing.T) {
	// This is a compile-time check.
	var _ interface {
		Detect() ([]types.Program, error)
	} = NewLinuxScanner()
}

func TestScanPacman(t *testing.T) {
	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "pacman" {
			return []byte("bash 5.2.037-1\npython 3.13.1-1\n"), nil
		}
		return nil, nil
	}

	programs := scanPacman()
	if len(programs) != 2 {
		t.Fatalf("scanPacman() returned %d programs, want 2", len(programs))
	}
	if programs[0].Name != "bash" || programs[0].Version != "5.2.037-1" {
		t.Errorf("programs[0] = %+v", programs[0])
	}
	if programs[0].RawMetadata["package_manager"] != "pacman" {
		t.Errorf("package_manager = %q", programs[0].RawMetadata["package_manager"])
	}
}

func TestScanApk(t *testing.T) {
	origExec := execCommand
	origLookPath := lookPath
	defer func() { execCommand = origExec; lookPath = origLookPath }()

	lookPath = func(name string) (string, error) { return "/sbin/" + name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "apk" {
			return []byte("musl\nbusybox\n"), nil
		}
		return nil, nil
	}

	programs := scanApk()
	if len(programs) != 2 {
		t.Fatalf("scanApk() returned %d programs, want 2", len(programs))
	}
	if programs[1].Name != "busybox" {
		t.Errorf("programs[1].Name = %q", programs[1].Name)
	}
	if programs[1].RawMetadata["package_manager"] != "apk" {
		t.Errorf("package_manager = %q", programs[1].RawMetadata["package_manager"])
	}
}
