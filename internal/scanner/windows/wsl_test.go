// wsl_test.go — cross-platform tests for parseWSLOutput in helpers.go.
// No //go:build tag: these tests compile and run on all platforms.
package windows

import (
	"strings"
	"testing"

	"sys-scanner/internal/types"
)

func wslTestTools() []types.ToolSignature {
	return []types.ToolSignature{
		{
			Name:        "opencode",
			DisplayName: "OpenCode",
			BinaryNames: []string{"opencode"},
			ConfigDirs:  map[string][]string{"linux": {"~/.config/opencode"}},
		},
		{
			Name:        "hermes",
			DisplayName: "Hermes",
			BinaryNames: []string{"hermes"},
			ConfigDirs:  map[string][]string{"linux": {"~/.hermes"}},
		},
		{
			Name:        "cursor",
			DisplayName: "Cursor",
			BinaryNames: []string{"cursor"},
			ConfigDirs:  map[string][]string{"linux": {"~/.cursor", "~/.config/Cursor"}},
		},
	}
}

func TestParseWSLOutput_BinaryFound(t *testing.T) {
	progs := parseWSLOutput("BIN:opencode\nBIN:hermes\n", wslTestTools())
	if len(progs) != 2 {
		t.Fatalf("len = %d, want 2", len(progs))
	}

	want := map[string]string{"opencode": "OpenCode", "hermes": "Hermes"}
	for _, p := range progs {
		if !p.IsAITool {
			t.Errorf("IsAITool = false for %q", p.AIToolName)
		}
		if p.Source != "wsl" {
			t.Errorf("Source = %q, want wsl", p.Source)
		}
		if p.RawMetadata["ai_confidence"] != "high" {
			t.Errorf("ai_confidence = %q, want high", p.RawMetadata["ai_confidence"])
		}
		name, ok := want[p.AIToolName]
		if !ok {
			t.Errorf("unexpected AIToolName %q", p.AIToolName)
			continue
		}
		if p.Name != name {
			t.Errorf("Name = %q, want %q", p.Name, name)
		}
	}
}

func TestParseWSLOutput_ConfigDirFound(t *testing.T) {
	progs := parseWSLOutput("DIR:/home/user/.cursor\n", wslTestTools())
	if len(progs) != 1 {
		t.Fatalf("len = %d, want 1", len(progs))
	}
	p := progs[0]
	if p.Name != "Cursor" {
		t.Errorf("Name = %q, want Cursor", p.Name)
	}
	if p.AIToolName != "cursor" {
		t.Errorf("AIToolName = %q, want cursor", p.AIToolName)
	}
	if !p.IsAITool {
		t.Error("IsAITool = false, want true")
	}
}

func TestParseWSLOutput_UnknownBinaryIgnored(t *testing.T) {
	progs := parseWSLOutput("BIN:nonexistent-tool\n", wslTestTools())
	if len(progs) != 0 {
		t.Errorf("len = %d, want 0", len(progs))
	}
}

func TestParseWSLOutput_Empty(t *testing.T) {
	if got := parseWSLOutput("", wslTestTools()); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestParseWSLOutput_Dedup(t *testing.T) {
	progs := parseWSLOutput("BIN:cursor\nDIR:/home/user/.cursor\n", wslTestTools())
	if len(progs) != 1 {
		t.Fatalf("len = %d, want 1 (deduplicated)", len(progs))
	}
	if progs[0].AIToolName != "cursor" {
		t.Errorf("AIToolName = %q, want cursor", progs[0].AIToolName)
	}
}

func TestBuildWSLProbeScript_AvoidsInteropMangledSyntax(t *testing.T) {
	script := buildWSLProbeScript(wslTestTools())

	// Shell variables and double quotes are mangled when the Windows binary is
	// launched from inside WSL. The probe must use explicit commands instead.
	if strings.ContainsAny(script, `"$`) {
		t.Errorf("probe script must not contain quotes or shell variables: %q", script)
	}
	for _, want := range []string{
		"command -v opencode >/dev/null 2>&1 && echo BIN:opencode",
		"command -v hermes >/dev/null 2>&1 && echo BIN:hermes",
		"[ -e ~/.cursor ] && echo DIR:~/.cursor",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("probe script missing %q: %q", want, script)
		}
	}
	if !strings.HasSuffix(script, "true") {
		t.Error("probe script must end with true so the last failed test does not set exit status 1")
	}
}
