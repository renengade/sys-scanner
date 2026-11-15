package classifier

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mkdir is a test helper that creates a directory under base and returns the
// full path. It calls t.Helper so failures point to the caller.
func mkdir(t *testing.T, base string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{base}, parts...)...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	return p
}

// writeFile is a test helper that creates parent directories as needed and
// writes a file under base, returning the full path.
func writeFile(t *testing.T, base string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{base}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte("test"), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// createConfigDir creates the first config directory for a tool on the
// current OS and returns its expanded path. Returns "" when the signature has
// no config dir for this OS.
func createConfigDir(t *testing.T, home, toolName string) string {
	t.Helper()
	sig, ok := signatures.Lookup(toolName)
	if !ok {
		t.Fatalf("tool %q not found", toolName)
	}
	dirs, ok := sig.ConfigDirs[runtime.GOOS]
	if !ok || len(dirs) == 0 {
		return ""
	}
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", home)
	}
	expanded := expandUserPath(dirs[0], home)
	if err := os.MkdirAll(expanded, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", expanded, err)
	}
	return expanded
}

// stubLookPath replaces the package-level lookPath function with a stub that
// returns an error, so PATH lookups never accidentally pass tests. Returns a
// restore function the caller should defer.
func stubLookPath() func() {
	orig := lookPath
	lookPath = func(_ string) (string, error) { return "", os.ErrNotExist }
	return func() { lookPath = orig }
}

// stubProcesses replaces the process lister with a stub returning no output,
// so process-signal matches never accidentally pass tests.
func stubProcesses() func() {
	orig := processLister
	processLister = func() (string, error) { return "", nil }
	return func() { processLister = orig }
}

// stubPorts replaces the port prober with a stub that always fails to connect,
// so port-signal matches never accidentally pass tests.
func stubPorts() func() {
	orig := dialPort
	dialPort = func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, os.ErrNotExist
	}
	return func() { dialPort = orig }
}

// findProgram returns the first program in results whose AIToolName equals
// name, or nil when none is present.
func findProgram(results []types.Program, name string) *types.Program {
	for i := range results {
		if results[i].AIToolName == name {
			return &results[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Signal 1 — Binary match
// ---------------------------------------------------------------------------

func TestBinaryMatch_InstallLocation(t *testing.T) {
	// Stub lookPath so PATH lookups never accidentally pass tests.
	origLookPath := lookPath
	lookPath = func(_ string) (string, error) { return "", os.ErrNotExist }
	defer func() { lookPath = origLookPath }()

	tests := []struct {
		name            string
		installLocation string
		wantMatch       bool
	}{
		{"exact unix", "/usr/bin/opencode", true},
		{"deep path", "/opt/OpenCode/bin/opencode", true},
		{"wrong binary", "/usr/bin/codex", false},
		{"substring trap", "/usr/bin/my-opencode-helper", false},
		{"empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := types.Program{InstallLocation: tt.installLocation}
			sig, _ := signatures.Lookup("opencode")
			result := binaryMatches(prog, sig, nil)
			if result != tt.wantMatch {
				t.Errorf("binaryMatches(%q, opencode) = %v, want %v", tt.installLocation, result, tt.wantMatch)
			}
		})
	}
}

func TestBinaryMatch_WindowsCaseInsensitive(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name            string
		installLocation string
		binaryName      string
		wantMatch       bool
	}{
		{"lower vs upper", `C:\Tools\OPENCODE.EXE`, "opencode", true},
		{"upper vs lower", `C:\Tools\opencode.exe`, "OPENCODE", true},
		{"mixed case", `C:\Tools\OpenCode.exe`, "opencode", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := types.Program{InstallLocation: tt.installLocation}
			sig := types.ToolSignature{BinaryNames: []string{tt.binaryName}}
			result := binaryMatches(prog, sig, nil)
			if result != tt.wantMatch {
				t.Errorf("binaryMatches(%q, [%q]) = %v, want %v", tt.installLocation, tt.binaryName, result, tt.wantMatch)
			}
		})
	}
}

func TestBinaryMatch_EmptyBinaryNames(t *testing.T) {
	origLookPath := lookPath
	lookPath = func(_ string) (string, error) { return "", os.ErrNotExist }
	defer func() { lookPath = origLookPath }()

	prog := types.Program{InstallLocation: "/usr/bin/copilot-agent"}
	sig, _ := signatures.Lookup("github-copilot") // has no binary names
	if binaryMatches(prog, sig, nil) {
		t.Error("binaryMatches should return false when BinaryNames is empty")
	}
}

func TestBinaryMatch_PathCacheRequiresNameMatch(t *testing.T) {
	sig, _ := signatures.Lookup("opencode")
	onPath := map[string]bool{"opencode": true}

	// Binary is on PATH but the program's Name is unrelated — must NOT match.
	prog := types.Program{Name: "Google Chrome"}
	if binaryMatches(prog, sig, onPath) {
		t.Error("binary on PATH must NOT match a program whose Name differs")
	}

	// Program Name matches AND binary is on PATH — must match.
	prog = types.Program{Name: "opencode"}
	if !binaryMatches(prog, sig, onPath) {
		t.Error("program Name == binary name and binary on PATH should match")
	}

	// Program Name matches but binary is NOT on PATH — must NOT match.
	prog = types.Program{Name: "opencode"}
	if binaryMatches(prog, sig, nil) {
		t.Error("program Name == binary name but binary absent from PATH should NOT match")
	}
}

// ---------------------------------------------------------------------------
// Signal 2 — Config dir match
// ---------------------------------------------------------------------------

func TestConfigDirMatch_HomeExpansion(t *testing.T) {
	home := t.TempDir()
	if createConfigDir(t, home, "opencode") == "" {
		t.Skip("opencode has no config dir for this OS")
	}

	sig, _ := signatures.Lookup("opencode")
	if !hasConfigDir(sig, home) {
		t.Errorf("hasConfigDir(opencode) = false, want true; home=%s", home)
	}
}

func TestConfigDirMatch_NoMatch(t *testing.T) {
	home := t.TempDir()
	// Do NOT create the config dir.

	sig, _ := signatures.Lookup("opencode")
	if hasConfigDir(sig, home) {
		t.Error("hasConfigDir(opencode) should be false when dir does not exist")
	}
}

func TestConfigDirMatch_EmptyConfigDirs(t *testing.T) {
	home := t.TempDir()
	sig, _ := signatures.Lookup("github-copilot") // no ConfigDirs
	if hasConfigDir(sig, home) {
		t.Error("hasConfigDir should return false when ConfigDirs is empty")
	}
}

func TestConfigDirMatch_MultipleDirs(t *testing.T) {
	home := t.TempDir()
	// Cursor has multiple config dirs on linux: ~/.cursor, ~/.config/Cursor
	// Only create one of them — it should still match.
	mkdir(t, home, ".cursor")

	sig, _ := signatures.Lookup("cursor")
	if !hasConfigDir(sig, home) {
		t.Error("hasConfigDir(cursor) = false, want true; ~/.cursor exists")
	}
}

func TestConfigDirMatch_NestedDirs(t *testing.T) {
	home := t.TempDir()
	// Windsurf has ~/.codeium/windsurf
	mkdir(t, home, ".codeium", "windsurf")

	sig, _ := signatures.Lookup("windsurf")
	if !hasConfigDir(sig, home) {
		t.Error("hasConfigDir(windsurf) = false, want true; ~/.codeium/windsurf exists")
	}
}

func TestConfigDirMatch_WindowsEnvExpansion(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	home := t.TempDir()
	t.Setenv("APPDATA", home)
	mkdir(t, home, "opencode")

	sig, _ := signatures.Lookup("opencode")
	if !hasConfigDir(sig, home) {
		t.Errorf("hasConfigDir(opencode) with APPDATA=%s = false, want true", home)
	}
}

// ---------------------------------------------------------------------------
// Signal 2 — expandUserPath edge cases
// ---------------------------------------------------------------------------

func TestExpandUserPath_Variants(t *testing.T) {
	home := "/home/testuser"
	if runtime.GOOS == "windows" {
		home = `C:\Users\testuser`
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"~", home},
		{"~/.config/opencode", filepath.Join(home, ".config", "opencode")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := expandUserPath(tt.input, home)
			if result != tt.expected {
				t.Errorf("expandUserPath(%q, %q) = %q, want %q", tt.input, home, result, tt.expected)
			}
		})
	}
}

func TestExpandUserPath_PercentVars(t *testing.T) {
	t.Setenv("APPDATA", `C:\Users\testuser\AppData\Roaming`)
	got := expandUserPath(`%APPDATA%\opencode`, `C:\Users\testuser`)
	want := `C:\Users\testuser\AppData\Roaming\opencode`
	if got != want {
		t.Errorf("expandUserPath percent vars = %q, want %q", got, want)
	}
}

func TestExpandUserPath_EmptyHome(t *testing.T) {
	result := expandUserPath("~/.config/opencode", "")
	if result != "~/.config/opencode" {
		t.Errorf("expandUserPath with empty home should leave ~ untouched, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Signal 3 — VS Code extension match
// ---------------------------------------------------------------------------

func TestExtensionMatch_VSCode(t *testing.T) {
	home := t.TempDir()
	// Simulate github.copilot-1.200.0 installed under ~/.vscode/extensions/
	mkdir(t, home, ".vscode", "extensions", "github.copilot-1.200.0")

	sig, _ := signatures.Lookup("github-copilot")
	if !hasExtension(sig, home) {
		t.Error("hasExtension(github-copilot) = false, want true")
	}
}

func TestExtensionMatch_VSCodeOSS(t *testing.T) {
	home := t.TempDir()
	mkdir(t, home, ".vscode-oss", "extensions", "saoudrizwan.claude-dev-3.0.0")

	sig, _ := signatures.Lookup("cline")
	if !hasExtension(sig, home) {
		t.Error("hasExtension(cline) under vscode-oss = false, want true")
	}
}

func TestExtensionMatch_CursorExtensions(t *testing.T) {
	home := t.TempDir()
	mkdir(t, home, ".cursor", "extensions", "continue.continue-1.2.3")

	sig, _ := signatures.Lookup("continue")
	if !hasExtension(sig, home) {
		t.Error("hasExtension(continue) under .cursor/extensions = false, want true")
	}
}

func TestExtensionMatch_MultipleExtensions(t *testing.T) {
	home := t.TempDir()
	// Cline and Roo Code both in Cursor extensions dir
	mkdir(t, home, ".cursor", "extensions", "saoudrizwan.claude-dev-3.0.0")
	mkdir(t, home, ".cursor", "extensions", "rooveterinaryinc.roo-cline-2.0.0")

	t.Run("cline", func(t *testing.T) {
		sig, _ := signatures.Lookup("cline")
		if !hasExtension(sig, home) {
			t.Error("hasExtension(cline) = false, want true")
		}
	})
	t.Run("roo-code", func(t *testing.T) {
		sig, _ := signatures.Lookup("roo-code")
		if !hasExtension(sig, home) {
			t.Error("hasExtension(roo-code) = false, want true")
		}
	})
}

func TestExtensionMatch_NoExtensionDirs(t *testing.T) {
	home := t.TempDir()
	// No .vscode, .vscode-oss, or .cursor dirs exist.

	sig, _ := signatures.Lookup("github-copilot")
	if hasExtension(sig, home) {
		t.Error("hasExtension should be false when no extension dirs exist")
	}
}

func TestExtensionMatch_EmptyExtensionIDs(t *testing.T) {
	home := t.TempDir()
	// opencode has no ExtensionIDs
	sig, _ := signatures.Lookup("opencode")
	if hasExtension(sig, home) {
		t.Error("hasExtension should be false when ExtensionIDs is empty")
	}
}

func TestExtensionMatch_NoHome(t *testing.T) {
	sig, _ := signatures.Lookup("github-copilot")
	if hasExtension(sig, "") {
		t.Error("hasExtension should be false when homeDir is empty")
	}
}

// ---------------------------------------------------------------------------
// Signal 3 — False-positive: similar-looking dirs should NOT match
// ---------------------------------------------------------------------------

func TestExtensionMatch_FalsePositives(t *testing.T) {
	home := t.TempDir()

	// Create dirs that look similar but should NOT match.
	mkdir(t, home, ".vscode", "extensions", "github.copilot-chat-0.20.0")  // different extension
	mkdir(t, home, ".vscode", "extensions", "github-copilot-1.0.0")        // different publisher format (hyphen)
	mkdir(t, home, ".vscode-oss", "extensions", "saoudrizwan.other-1.0.0") // different name
	mkdir(t, home, ".cursor", "extensions", "continue-dev-0.0.1")          // no dot separator

	t.Run("copilot extension not copilot-chat", func(t *testing.T) {
		sig, _ := signatures.Lookup("github-copilot")
		if hasExtension(sig, home) {
			t.Error("github-copilot should NOT match github.copilot-chat extension dir")
		}
	})
	t.Run("cline not other extension", func(t *testing.T) {
		sig, _ := signatures.Lookup("cline")
		if hasExtension(sig, home) {
			t.Error("cline should NOT match saoudrizwan.other extension dir")
		}
	})
	t.Run("continue not continue-dev", func(t *testing.T) {
		sig, _ := signatures.Lookup("continue")
		if hasExtension(sig, home) {
			t.Error("continue should NOT match continue-dev extension dir")
		}
	})
}

// ---------------------------------------------------------------------------
// Signal 5 — Port match
// ---------------------------------------------------------------------------

func TestPortMatch_EmptyPorts(t *testing.T) {
	sig, _ := signatures.Lookup("opencode") // no Ports
	if hasPort(sig) {
		t.Error("hasPort should be false when Ports is empty")
	}
}

func TestPortMatch_NothingListening(t *testing.T) {
	// Use a high port that is extremely unlikely to have a listener.
	sig := types.ToolSignature{Ports: []int{59123}}
	if hasPort(sig) {
		t.Log("unexpected: port 59123 is open (someone is listening)")
	}
	// We don't assert false because there's a tiny chance something listens.
}

// ---------------------------------------------------------------------------
// confidenceLabel
// ---------------------------------------------------------------------------

func TestConfidenceLabel(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{1, "low"},
		{2, "medium"},
		{3, "high"},
		{5, "high"},
		{10, "high"},
	}
	for _, tt := range tests {
		got := confidenceLabel(tt.n)
		if got != tt.want {
			t.Errorf("confidenceLabel(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// classifyOne — full integration tests
// ---------------------------------------------------------------------------

func TestClassifyOne_BinaryOnly(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()
	// No config dirs, no extensions. Only binary match via InstallLocation.
	prog := types.Program{
		Name:            "OpenCode",
		InstallLocation: "/usr/local/bin/opencode",
	}

	result := classifyOne(prog, signatures.All(), systemSignals{
		configMatches:    map[string]bool{},
		extensionMatches: map[string]bool{},
		processMatches:   map[string]bool{},
		portMatches:      map[string]bool{},
	})

	if !result.IsAITool {
		t.Fatal("expected IsAITool=true")
	}
	if result.AIToolName != "opencode" {
		t.Errorf("expected AIToolName=opencode, got %q", result.AIToolName)
	}
	if result.RawMetadata["ai_confidence"] != "low" {
		t.Errorf("expected ai_confidence=low (1 signal), got %q", result.RawMetadata["ai_confidence"])
	}

	_ = home // avoid unused
}

func TestClassifyOne_BinaryAndConfig(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()
	if createConfigDir(t, home, "opencode") == "" {
		t.Skip("opencode has no config dir for this OS")
	}

	prog := types.Program{
		Name:            "OpenCode",
		InstallLocation: "/usr/local/bin/opencode",
	}

	tools := signatures.All()
	sigs := computeSystemSignals(tools, home)

	result := classifyOne(prog, tools, sigs)

	if !result.IsAITool {
		t.Fatal("expected IsAITool=true")
	}
	if result.AIToolName != "opencode" {
		t.Errorf("expected AIToolName=opencode, got %q", result.AIToolName)
	}
	if result.RawMetadata["ai_confidence"] != "medium" {
		t.Errorf("expected ai_confidence=medium (2 signals), got %q", result.RawMetadata["ai_confidence"])
	}
}

func TestClassifyOne_NoMatch(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()
	prog := types.Program{
		Name:            "SomeRandomApp",
		InstallLocation: "/opt/random/bin/randomapp",
	}

	tools := signatures.All()
	sigs := computeSystemSignals(tools, home)

	result := classifyOne(prog, tools, sigs)

	if result.IsAITool {
		t.Errorf("expected IsAITool=false, got true with AIToolName=%q", result.AIToolName)
	}
}

func TestClassifyOne_ConfigOnlyNoBinaryNames(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	// GitHub Copilot has no binary names but has ExtensionIDs.
	home := t.TempDir()
	mkdir(t, home, ".vscode", "extensions", "github.copilot-1.200.0")

	prog := types.Program{
		Name:            "Some Program",
		InstallLocation: "/opt/something",
	}

	tools := signatures.All()
	sigs := computeSystemSignals(tools, home)

	// System signals are global facts, not per-program facts: classifyOne must
	// NOT mark an arbitrary program via an extension match alone.
	if classifyOne(prog, tools, sigs).IsAITool {
		t.Fatal("classifyOne must not mark a program via system signals alone")
	}

	// The synthesis pass must surface the tool as a synthetic entry instead.
	result := classifyWithHome([]types.Program{prog}, home)
	copilot := findProgram(result, "github-copilot")
	if copilot == nil {
		t.Fatal("expected a synthetic github-copilot entry in classifyWithHome result")
	}
	if !copilot.IsAITool {
		t.Error("synthetic github-copilot entry should have IsAITool=true")
	}
	if copilot.Name != "GitHub Copilot" {
		t.Errorf("synthetic entry Name = %q, want %q", copilot.Name, "GitHub Copilot")
	}
	if copilot.Source != "ai-signal" {
		t.Errorf("synthetic entry Source = %q, want %q", copilot.Source, "ai-signal")
	}
}

func TestClassify_BinaryMatchSuppressesSynthetic(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	// opencode has both a binary name and a config dir. The program is
	// binary-matched, so opencode must be reported via the real program and
	// must NOT also appear as a duplicate synthetic entry.
	mkdir(t, home, ".config", "opencode")

	prog := types.Program{
		Name:            "OpenCode",
		InstallLocation: "/usr/local/bin/opencode",
	}

	result := classifyWithHome([]types.Program{prog}, home)

	if len(result) != 1 {
		t.Fatalf("expected exactly 1 result (no synthetic duplicate), got %d", len(result))
	}
	if !result[0].IsAITool || result[0].AIToolName != "opencode" {
		t.Errorf("expected the opencode program to be classified, got %+v", result[0])
	}
}

// ---------------------------------------------------------------------------
// Classify — full slice tests
// ---------------------------------------------------------------------------

func TestClassify_ReturnsNewSlice(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()

	original := []types.Program{
		{Name: "A", InstallLocation: "/usr/bin/opencode"},
		{Name: "B", InstallLocation: "/usr/bin/other"},
	}

	result := classifyWithHome(original, home)

	// Verify it's a different slice.
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}

	// Mutate result — original should be untouched.
	result[0].Name = "MUTATED"
	if original[0].Name == "MUTATED" {
		t.Error("original slice was mutated; classify must return a new slice")
	}
}

func TestClassify_EmptyInput(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	result := classifyWithHome(nil, home)
	if result == nil {
		t.Error("expected non-nil slice for nil input")
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d elements", len(result))
	}

	result = classifyWithHome([]types.Program{}, home)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d elements", len(result))
	}
}

func TestClassify_MultiplePrograms(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	if createConfigDir(t, home, "opencode") == "" {
		t.Skip("opencode has no config dir for this OS")
	}

	programs := []types.Program{
		{Name: "OpenCode Pkg", InstallLocation: "/usr/bin/opencode"},
		{Name: "Random App", InstallLocation: "/usr/bin/random"},
		{Name: "Aider Pkg", InstallLocation: "/usr/bin/aider"},
	}

	result := classifyWithHome(programs, home)

	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}

	// Program 0: opencode — binary + config = medium (dual-pass requires binary match)
	if !result[0].IsAITool || result[0].AIToolName != "opencode" {
		t.Errorf("program[0]: expected opencode, got IsAITool=%v AIToolName=%q", result[0].IsAITool, result[0].AIToolName)
	}
	if result[0].RawMetadata["ai_confidence"] != "medium" {
		t.Errorf("program[0]: expected medium (2 signals), got %q", result[0].RawMetadata["ai_confidence"])
	}

	// Program 1: random binary, no config for any binary-name tool → no match
	if result[1].IsAITool {
		t.Errorf("program[1]: expected no match, got %q", result[1].AIToolName)
	}

	// Program 2: aider — binary only = low
	if !result[2].IsAITool || result[2].AIToolName != "aider" {
		t.Errorf("program[2]: expected aider, got IsAITool=%v AIToolName=%q", result[2].IsAITool, result[2].AIToolName)
	}
	if result[2].RawMetadata["ai_confidence"] != "low" {
		t.Errorf("program[2]: expected low (1 signal), got %q", result[2].RawMetadata["ai_confidence"])
	}
}

func TestClassify_SyntheticEntryForCursorConfigDir(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	// Cursor is installed as a GUI app off PATH, but its config dir exists.
	mkdir(t, home, ".cursor")

	// A single unrelated program — must NOT be falsely marked as an AI tool.
	programs := []types.Program{
		{Name: "Unrelated App", InstallLocation: "/opt/unrelated/bin/app"},
	}

	result := classifyWithHome(programs, home)

	if result[0].IsAITool {
		t.Errorf("unrelated program must not be classified, got AIToolName=%q", result[0].AIToolName)
	}

	cursor := findProgram(result, "cursor")
	if cursor == nil {
		t.Fatal("expected a synthetic cursor entry when ~/.cursor exists but no cursor binary is present")
	}
	if !cursor.IsAITool {
		t.Error("synthetic cursor entry should have IsAITool=true")
	}
	if cursor.Name != "Cursor" {
		t.Errorf("synthetic entry Name = %q, want %q", cursor.Name, "Cursor")
	}
	if cursor.Source != "ai-signal" {
		t.Errorf("synthetic entry Source = %q, want %q", cursor.Source, "ai-signal")
	}
	if cursor.RawMetadata["ai_confidence"] != "low" {
		t.Errorf("synthetic entry confidence = %q, want %q", cursor.RawMetadata["ai_confidence"], "low")
	}
}

// ---------------------------------------------------------------------------
// False-positive suite — config dirs
// ---------------------------------------------------------------------------

func TestConfigDir_FalsePositive(t *testing.T) {
	home := t.TempDir()

	t.Run("cursor-rules is NOT cursor", func(t *testing.T) {
		mkdir(t, home, ".cursor-rules")
		sig, _ := signatures.Lookup("cursor")
		if hasConfigDir(sig, home) {
			t.Error(".cursor-rules should NOT match Cursor's config dir")
		}
	})

	t.Run("claude-desktop is NOT claude-code", func(t *testing.T) {
		mkdir(t, home, ".config", "claude-desktop")
		sig, _ := signatures.Lookup("claude-code")
		if hasConfigDir(sig, home) {
			t.Error("~/.config/claude-desktop should NOT match Claude Code's config dir")
		}
	})

	t.Run("codeium-server is NOT windsurf", func(t *testing.T) {
		mkdir(t, home, ".codeium-server")
		sig, _ := signatures.Lookup("windsurf")
		if hasConfigDir(sig, home) {
			t.Error("~/.codeium-server should NOT match Windsurf's config dir")
		}
	})

	t.Run("partial prefix trap", func(t *testing.T) {
		// ~/.cursor-bak should NOT match Cursor's ~/.cursor
		mkdir(t, home, ".cursor-bak")
		sig, _ := signatures.Lookup("cursor")
		if hasConfigDir(sig, home) {
			t.Error("~/.cursor-bak should NOT match Cursor's config dir ~/.cursor")
		}
	})
}

// ---------------------------------------------------------------------------
// Claude Code — strict config-dir validation
// ---------------------------------------------------------------------------

func TestClaudeCode_StrictConfigDetection(t *testing.T) {
	t.Run("bare .claude with only transcripts is NOT installed", func(t *testing.T) {
		home := t.TempDir()
		mkdir(t, home, ".claude", "transcripts")

		if claudeCodeActuallyInstalled(home) {
			t.Error("bare ~/.claude with only transcripts/ must NOT count as installed")
		}
	})

	t.Run("empty .claude dir is NOT installed", func(t *testing.T) {
		home := t.TempDir()
		mkdir(t, home, ".claude")

		if claudeCodeActuallyInstalled(home) {
			t.Error("empty ~/.claude must NOT count as installed")
		}
	})

	t.Run(".claude.json counts", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, home, ".claude.json")

		if !claudeCodeActuallyInstalled(home) {
			t.Error("~/.claude.json must count as installed")
		}
	})

	t.Run(".claude/settings.json counts", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, home, ".claude", "settings.json")

		if !claudeCodeActuallyInstalled(home) {
			t.Error("~/.claude/settings.json must count as installed")
		}
	})

	t.Run("empty .claude/commands does NOT count", func(t *testing.T) {
		home := t.TempDir()
		mkdir(t, home, ".claude", "commands")

		if claudeCodeActuallyInstalled(home) {
			t.Error("empty ~/.claude/commands must NOT count as installed")
		}
	})

	t.Run("non-empty .claude/commands counts", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, home, ".claude", "commands", "review.md")

		if !claudeCodeActuallyInstalled(home) {
			t.Error("non-empty ~/.claude/commands must count as installed")
		}
	})
}

func TestClassify_ClaudeCodeBareDirNotDetected(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	mkdir(t, home, ".claude", "transcripts")

	result := classifyWithHome(nil, home)
	if findProgram(result, "claude-code") != nil {
		t.Error("claude-code must NOT be detected when ~/.claude contains only transcripts/")
	}
}

func TestClassify_ClaudeCodeWithConfigDetected(t *testing.T) {
	defer stubLookPath()()
	defer stubProcesses()()
	defer stubPorts()()
	home := t.TempDir()
	writeFile(t, home, ".claude.json")

	result := classifyWithHome(nil, home)
	claude := findProgram(result, "claude-code")
	if claude == nil {
		t.Fatal("claude-code must be detected when ~/.claude.json exists")
	}
	if claude.Source != "ai-signal" {
		t.Errorf("claude-code Source = %q, want ai-signal", claude.Source)
	}
}

// ---------------------------------------------------------------------------
// All 22 tools — per-tool binary signature tests
// ---------------------------------------------------------------------------

func TestAllTools_BinaryDetection(t *testing.T) {
	defer stubLookPath()()
	// Each tool that has BinaryNames is tested here.
	tests := []struct {
		toolName   string
		binaryPath string
	}{
		{"opencode", "/usr/bin/opencode"},
		{"codex-cli", "/usr/local/bin/codex"},
		{"claude-code", "/opt/claude/bin/claude"},
		{"cursor", "/opt/cursor/cursor"},
		{"windsurf", "/opt/windsurf/bin/windsurf"},
		{"aider", "/usr/local/bin/aider"},
		{"cody", "/usr/bin/cody"},
		{"tabnine", "/opt/TabNine/TabNine"},
		{"amazon-q", "/usr/bin/q"},
		{"augment-code", "/usr/local/bin/auggie"},
		{"zed-ai", "/usr/bin/zed"},
		{"pearai", "/opt/pearai/pearai"},
		{"trae", "/usr/local/bin/trae"},
		{"ollama", "/usr/bin/ollama"},
		{"gpt4all", "/usr/bin/gpt4all"},
		{"localai", "/usr/bin/local-ai"},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			sig, ok := signatures.Lookup(tt.toolName)
			if !ok {
				t.Fatalf("tool %q not found in signatures", tt.toolName)
			}

			prog := types.Program{
				Name:            sig.DisplayName,
				InstallLocation: tt.binaryPath,
			}

			home := t.TempDir()
			result := classifyOne(prog, signatures.All(), systemSignals{
				configMatches:    map[string]bool{},
				extensionMatches: map[string]bool{},
				processMatches:   map[string]bool{},
				portMatches:      map[string]bool{},
			})

			if !result.IsAITool {
				t.Errorf("%s: expected IsAITool=true for InstallLocation=%q", tt.toolName, tt.binaryPath)
			}
			if result.AIToolName != tt.toolName {
				t.Errorf("%s: expected AIToolName=%q, got %q", tt.toolName, tt.toolName, result.AIToolName)
			}
			_ = home
		})
	}
}

// ---------------------------------------------------------------------------
// All 22 tools — per-tool config dir detection
// ---------------------------------------------------------------------------

func TestAllTools_ConfigDirDetection(t *testing.T) {
	home := t.TempDir()
	toolNames := []string{
		"opencode", "codex-cli", "claude-code", "cursor", "windsurf", "aider",
		"cline", "roo-code", "continue", "tabnine", "amazon-q", "codeium",
		"augment-code", "hermes", "zed-ai", "pearai", "trae", "ollama",
		"lm-studio", "gpt4all", "localai",
	}

	for _, toolName := range toolNames {
		t.Run(toolName, func(t *testing.T) {
			sig, ok := signatures.Lookup(toolName)
			if !ok {
				t.Fatalf("tool %q not found", toolName)
			}
			if toolName == "claude-code" {
				writeFile(t, home, ".claude.json")
				if !claudeCodeActuallyInstalled(home) {
					t.Error("claude-code: claudeCodeActuallyInstalled = false, want true")
				}
				return
			}
			if createConfigDir(t, home, toolName) == "" {
				t.Skipf("%s has no config dir for %s", toolName, runtime.GOOS)
			}
			if !hasConfigDir(sig, home) {
				t.Errorf("%s: hasConfigDir = false, want true", toolName)
			}
		})
	}

	// Tools without config dirs should not match.
	t.Run("github-copilot-no-config", func(t *testing.T) {
		sig, _ := signatures.Lookup("github-copilot")
		if hasConfigDir(sig, home) {
			t.Error("github-copilot has no ConfigDirs; should return false")
		}
	})
}

// ---------------------------------------------------------------------------
// All 22 tools — per-tool extension detection
// ---------------------------------------------------------------------------

func TestAllTools_ExtensionDetection(t *testing.T) {
	home := t.TempDir()

	type extTest struct {
		toolName string
		extID    string
		version  string
	}
	tests := []extTest{
		{"github-copilot", "github.copilot", "1.200.0"},
		{"cline", "saoudrizwan.claude-dev", "3.0.0"},
		{"roo-code", "rooveterinaryinc.roo-cline", "2.1.0"},
		{"continue", "continue.continue", "1.2.3"},
		{"cody", "sourcegraph.cody-ai", "1.0.0"},
		{"tabnine", "TabNine.tabnine-vscode", "4.0.0"},
		{"amazon-q", "AmazonWebServices.amazon-q-vscode", "1.0.0"},
		{"codeium", "Codeium.codeium", "1.20.0"},
		{"augment-code", "augment.vscode-augment", "1.5.0"},
	}

	for _, et := range tests {
		t.Run(et.toolName, func(t *testing.T) {
			extDirName := et.extID + "-" + et.version
			mkdir(t, home, ".vscode", "extensions", extDirName)

			sig, ok := signatures.Lookup(et.toolName)
			if !ok {
				t.Fatalf("tool %q not found", et.toolName)
			}
			if !hasExtension(sig, home) {
				t.Errorf("%s: hasExtension = false, want true; ext dir = %s", et.toolName, extDirName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// All 22 tools — end-to-end: at least one program classified per tool
// ---------------------------------------------------------------------------

func TestAllTools_EndToEnd(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()

	// Create config dirs for every tool that has them.
	configDirs := map[string][]string{
		"opencode":     {".config/opencode"},
		"codex-cli":    {".codex"},
		"claude-code":  {".claude"},
		"cursor":       {".cursor"},
		"windsurf":     {".codeium/windsurf"},
		"aider":        {".aider"},
		"cline":        {".cline"},
		"roo-code":     {".roo"},
		"continue":     {".continue"},
		"tabnine":      {".tabnine"},
		"amazon-q":     {".aws/amazonq"},
		"codeium":      {".codeium"},
		"augment-code": {".augment"},
		"hermes":       {".hermes"},
		"zed-ai":       {".config/zed"},
		"pearai":       {".config/pear"},
		"trae":         {".trae"},
		"ollama":       {".ollama"},
		"lm-studio":    {".lmstudio"},
		"gpt4all":      {".config/nomic.ai"},
		"localai":      {".config/localai"},
	}

	for _, dirs := range configDirs {
		for _, d := range dirs {
			mkdir(t, home, strings.Split(d, "/")...)
		}
	}

	tools := signatures.All()
	binaryToolNames := make(map[string]bool)
	for _, tool := range tools {
		if len(tool.BinaryNames) > 0 {
			binaryToolNames[tool.Name] = false
		}
	}

	var programs []types.Program
	for _, tool := range tools {
		if len(tool.BinaryNames) == 0 {
			continue
		}
		programs = append(programs, types.Program{
			Name:            tool.DisplayName,
			InstallLocation: "/opt/" + tool.Name + "/bin/" + tool.BinaryNames[0],
		})
	}

	result := classifyWithHome(programs, home)

	for _, prog := range result {
		if prog.IsAITool {
			binaryToolNames[prog.AIToolName] = true
		}
	}

	for name, detected := range binaryToolNames {
		if !detected {
			t.Errorf("tool %q was NOT detected", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestClassify_PreservesExistingFields(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()
	prog := types.Program{
		Name:            "MyOpenCode",
		Version:         "1.2.3",
		Publisher:       "OpenCode Inc",
		InstallLocation: "/usr/bin/opencode",
		Source:          "dpkg",
	}

	result := classifyOne(prog, signatures.All(), systemSignals{
		configMatches:    map[string]bool{},
		extensionMatches: map[string]bool{},
		processMatches:   map[string]bool{},
		portMatches:      map[string]bool{},
	})

	if result.Name != "MyOpenCode" {
		t.Errorf("Name was changed from %q to %q", "MyOpenCode", result.Name)
	}
	if result.Version != "1.2.3" {
		t.Errorf("Version was changed")
	}
	if result.Publisher != "OpenCode Inc" {
		t.Errorf("Publisher was changed")
	}
	if result.Source != "dpkg" {
		t.Errorf("Source was changed")
	}
	_ = home
}

func TestClassify_ProgramWithNilRawMetadata(t *testing.T) {
	defer stubLookPath()()
	home := t.TempDir()
	prog := types.Program{
		Name:            "OpenCode",
		InstallLocation: "/usr/bin/opencode",
		RawMetadata:     nil,
	}

	result := classifyOne(prog, signatures.All(), systemSignals{
		configMatches:    map[string]bool{},
		extensionMatches: map[string]bool{},
		processMatches:   map[string]bool{},
		portMatches:      map[string]bool{},
	})

	if result.RawMetadata == nil {
		t.Error("RawMetadata should be initialized after classification")
	}
	if result.RawMetadata["ai_confidence"] != "low" {
		t.Errorf("expected ai_confidence=low, got %q", result.RawMetadata["ai_confidence"])
	}
	_ = home
}

// ---------------------------------------------------------------------------
// pathEndsWith
// ---------------------------------------------------------------------------

func TestPathEndsWith(t *testing.T) {
	tests := []struct {
		path    string
		name    string
		want    bool
		skipMsg string
	}{
		{"/usr/bin/opencode", "opencode", true, ""},
		{"/usr/bin/opencode/", "opencode", true, ""},
		{`C:\Tools\opencode.exe`, "opencode.exe", true, "windows-only backslash path"},
		{"/usr/bin/codex", "opencode", false, ""},
		{"", "opencode", false, ""},
		{"/usr/bin/opencode", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path+"_"+tt.name, func(t *testing.T) {
			if tt.skipMsg != "" {
				t.Skip(tt.skipMsg)
			}
			got := pathEndsWith(tt.path, tt.name)
			if got != tt.want {
				t.Errorf("pathEndsWith(%q, %q) = %v, want %v", tt.path, tt.name, got, tt.want)
			}
		})
	}
}
