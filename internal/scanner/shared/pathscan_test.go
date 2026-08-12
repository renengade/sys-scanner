package shared

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestScanPATH_EmptyDirs(t *testing.T) {
	programs, err := ScanPATH(context.Background(), nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs, got %d", len(programs))
	}

	programs, err = ScanPATH(context.Background(), []string{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs, got %d", len(programs))
	}
}

func TestScanPATH_NonExistentDir(t *testing.T) {
	programs, err := ScanPATH(context.Background(), []string{"/nonexistent/path/12345"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs from nonexistent dir, got %d", len(programs))
	}
}

func TestScanPATH_EmptyDirNoExecutables(t *testing.T) {
	dir := t.TempDir()

	programs, err := ScanPATH(context.Background(), []string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 0 {
		t.Fatalf("expected 0 programs from empty dir, got %d", len(programs))
	}
}

func TestScanPATH_DetectsExecutables(t *testing.T) {
	dir := t.TempDir()
	createExecutable(t, dir, "mytool")
	createExecutable(t, dir, "othertool")
	createRegularFile(t, dir, "readme.txt")

	programs, err := ScanPATH(context.Background(), []string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(programs))
	}

	names := make(map[string]bool)
	for _, p := range programs {
		names[p.Name] = true
		if p.Source != "PATH" {
			t.Errorf("expected Source=PATH, got %q", p.Source)
		}
		if p.InstallLocation != dir {
			t.Errorf("expected InstallLocation=%q, got %q", dir, p.InstallLocation)
		}
	}
	if !names["mytool"] || !names["othertool"] {
		t.Errorf("expected mytool and othertool, got %v", names)
	}
}

func TestScanPATH_AllowlistFiltering(t *testing.T) {
	dir := t.TempDir()
	createExecutable(t, dir, "allowed")
	createExecutable(t, dir, "blocked")
	createExecutable(t, dir, "also-allowed")

	programs, err := ScanPATH(context.Background(), []string{dir}, []string{"allowed", "also-allowed"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs (allowlist), got %d", len(programs))
	}

	names := make(map[string]bool)
	for _, p := range programs {
		names[p.Name] = true
	}
	if !names["allowed"] || !names["also-allowed"] {
		t.Errorf("expected allowed and also-allowed, got %v", names)
	}
	if names["blocked"] {
		t.Error("blocked should not be in results")
	}
}

func TestScanPATH_AIBinaryBypass(t *testing.T) {
	dir := t.TempDir()
	createExecutable(t, dir, "cursor")
	createExecutable(t, dir, "random-tool")

	// Allowlist does NOT include "cursor", but aiBinaries does.
	programs, err := ScanPATH(context.Background(), []string{dir}, []string{"random-tool"}, []string{"cursor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(programs))
	}

	for _, p := range programs {
		if p.Name == "cursor" {
			if p.IsAITool != "true" {
				t.Errorf("expected cursor IsAITool=true, got %q", p.IsAITool)
			}
			if p.AIToolName != "cursor" {
				t.Errorf("expected AIToolName=cursor, got %q", p.AIToolName)
			}
		}
		if p.Name == "random-tool" {
			if p.IsAITool != "" {
				t.Errorf("expected random-tool IsAITool empty, got %q", p.IsAITool)
			}
		}
	}
}

func TestScanPATH_AIBinaryBypassWithEmptyAllowlist(t *testing.T) {
	dir := t.TempDir()
	createExecutable(t, dir, "claude")
	createExecutable(t, dir, "some-other")

	// Empty allowlist + aiBinaries: AI binary still passes.
	programs, err := ScanPATH(context.Background(), []string{dir}, nil, []string{"claude"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range programs {
		if p.Name == "claude" {
			found = true
			if p.IsAITool != "true" {
				t.Errorf("expected claude IsAITool=true, got %q", p.IsAITool)
			}
		}
	}
	if !found {
		t.Error("expected claude in results (AI bypass)")
	}
}

func TestScanPATH_Timeout(t *testing.T) {
	dir := t.TempDir()

	// Create a context that's already cancelled to simulate timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond) // ensure context expires

	createExecutable(t, dir, "tool1")

	programs, err := ScanPATH(ctx, []string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With an expired context, the scan should return 0 or very few results.
	// We just verify it doesn't hang or panic.
	_ = programs
}

func TestScanPATH_MaxEntriesPerDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	dir := t.TempDir()
	// Create more than maxEntriesPerDir executables.
	for i := 0; i < maxEntriesPerDir+50; i++ {
		name := filepath.Join(dir, "tool"+itoa(i))
		if err := os.WriteFile(name, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	programs, err := ScanPATH(context.Background(), []string{dir}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) > maxEntriesPerDir {
		t.Errorf("expected at most %d programs, got %d", maxEntriesPerDir, len(programs))
	}
}

func TestScanPATH_MultipleDirs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	createExecutable(t, dir1, "tool-a")
	createExecutable(t, dir2, "tool-b")

	programs, err := ScanPATH(context.Background(), []string{dir1, dir2}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("expected 2 programs from 2 dirs, got %d", len(programs))
	}
}

func TestScanPATH_SkipsBlankDirs(t *testing.T) {
	dir := t.TempDir()
	createExecutable(t, dir, "tool")

	programs, err := ScanPATH(context.Background(), []string{"", "  ", dir}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(programs) != 1 {
		t.Fatalf("expected 1 program, got %d", len(programs))
	}
}

// --- helpers ---

func createExecutable(t *testing.T, dir, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(path, []byte("MZ"), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func createRegularFile(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
