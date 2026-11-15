package signatures

import (
	"strings"
	"testing"
)

func countSignalsFromFields(binaryNames []string, configDirs map[string][]string, extensionIDs []string, processNames []string, ports []int) int {
	n := 0
	if len(binaryNames) > 0 {
		n++
	}
	if len(configDirs) > 0 {
		hasAny := false
		for _, dirs := range configDirs {
			if len(dirs) > 0 {
				hasAny = true
				break
			}
		}
		if hasAny {
			n++
		}
	}
	if len(extensionIDs) > 0 {
		n++
	}
	if len(processNames) > 0 {
		n++
	}
	if len(ports) > 0 {
		n++
	}
	return n
}

func TestAll_Returns23Tools(t *testing.T) {
	all := All()
	if len(all) != 23 {
		t.Fatalf("expected 23 tools, got %d", len(all))
	}
}

func TestNoDuplicateNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, sig := range All() {
		lower := strings.ToLower(sig.Name)
		if seen[lower] {
			t.Errorf("duplicate tool name: %q", sig.Name)
		}
		seen[lower] = true
	}
}

func TestEachToolHasAtLeast2Signals(t *testing.T) {
	for _, sig := range All() {
		n := countSignalsFromFields(sig.BinaryNames, sig.ConfigDirs, sig.ExtensionIDs, sig.ProcessNames, sig.Ports)
		if n < 2 {
			t.Errorf("tool %q has only %d signal(s), need >= 2", sig.Name, n)
		}
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	for _, sig := range All() {
		// Test exact match
		found, ok := Lookup(sig.Name)
		if !ok {
			t.Errorf("Lookup(%q) not found", sig.Name)
			continue
		}
		if found.Name != sig.Name {
			t.Errorf("Lookup(%q) returned %q", sig.Name, found.Name)
		}

		// Test uppercase
		upper := strings.ToUpper(sig.Name)
		found, ok = Lookup(upper)
		if !ok {
			t.Errorf("Lookup(%q) not found (case-insensitive)", upper)
		}
		if found.Name != sig.Name {
			t.Errorf("Lookup(%q) returned %q", upper, found.Name)
		}
	}
}

func TestLookup_NotFound(t *testing.T) {
	_, ok := Lookup("nonexistent-tool-xyz")
	if ok {
		t.Error("expected Lookup to return false for nonexistent tool")
	}
}

func TestAllToolsHaveDisplayName(t *testing.T) {
	for _, sig := range All() {
		if sig.DisplayName == "" {
			t.Errorf("tool %q has empty DisplayName", sig.Name)
		}
	}
}

func TestAllToolsHaveCategory(t *testing.T) {
	for _, sig := range All() {
		if sig.Category == "" {
			t.Errorf("tool %q has empty Category", sig.Name)
		}
	}
}

func TestExpectedToolNames(t *testing.T) {
	expected := []string{
		"opencode", "codex-cli", "claude-code", "github-copilot",
		"cursor", "windsurf", "aider", "cline", "roo-code",
		"continue", "cody", "tabnine", "amazon-q", "codeium",
		"augment-code", "hermes", "zed-ai", "pearai", "trae", "ollama",
		"lm-studio", "gpt4all", "localai",
	}

	for _, name := range expected {
		if _, ok := Lookup(name); !ok {
			t.Errorf("expected tool %q not found in registry", name)
		}
	}
}
