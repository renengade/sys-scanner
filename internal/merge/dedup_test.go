package merge

import (
	"sort"
	"testing"

	"sys-scanner/internal/types"
)

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Firefox", "firefox"},
		{"Firefox v100.0.1", "firefox"},
		{"Node.js 18.12.0", "node.js"},
		{"Python (x64)", "python"},
		{"Python (64-bit)", "python"},
		{"Git version 2.38.1 (x64)", "git"},
		{"MyApp v2.0 beta", "myapp"},
		{"  spaces  ", "spaces"},
		{"NoVersion", "noversion"},
	}
	for _, tt := range tests {
		got := NormalizeName(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDeduplicate_3SourceMerge(t *testing.T) {
	// Same program detected from 3 different sources → should merge into 1
	programs := []types.Program{
		{
			Name:      "Firefox",
			Version:   "100.0",
			Publisher: "Mozilla",
			Source:    "PATH",
		},
		{
			Name:      "Firefox",
			Version:   "100.0.1",
			Publisher: "",
			Source:    "registry",
		},
		{
			Name:            "Firefox",
			Version:         "99.0",
			Publisher:       "Mozilla Foundation",
			Source:          ".desktop",
			InstallLocation: "/usr/bin/firefox",
		},
	}

	result := Deduplicate(programs)
	if len(result) != 1 {
		t.Fatalf("expected 1 program, got %d: %+v", len(result), result)
	}

	p := result[0]
	// Should pick registry entry as base (highest priority), but merge metadata
	if p.Name != "Firefox" {
		t.Errorf("expected Name=Firefox, got %q", p.Name)
	}
	// Version should come from registry (highest priority source)
	if p.Version != "100.0.1" {
		t.Errorf("expected Version=100.0.1, got %q", p.Version)
	}
	// Publisher should be non-empty: registry has empty, so merged from .desktop or PATH
	if p.Publisher == "" {
		t.Error("expected non-empty Publisher after merge")
	}
	// InstallLocation should be merged from .desktop
	if p.InstallLocation != "/usr/bin/firefox" {
		t.Errorf("expected InstallLocation=/usr/bin/firefox, got %q", p.InstallLocation)
	}
}

func TestDeduplicate_EmptyPublisherSplit(t *testing.T) {
	// Same normalized name but different non-empty publishers → split
	programs := []types.Program{
		{Name: "TestApp v1.0", Version: "1.0", Publisher: "Acme Corp", Source: "registry"},
		{Name: "TestApp v2.0", Version: "2.0", Publisher: "Other Inc", Source: ".desktop"},
		{Name: "TestApp v1.5", Version: "1.5", Publisher: "", Source: "PATH"},
	}

	result := Deduplicate(programs)

	// Should produce: one for "Acme Corp", one for "Other Inc", one for empty publisher
	if len(result) != 3 {
		t.Fatalf("expected 3 programs (split by publisher), got %d: %+v", len(result), result)
	}

	publishers := make(map[string]bool)
	for _, p := range result {
		publishers[p.Publisher] = true
	}
	if !publishers["Acme Corp"] {
		t.Error("missing entry for 'Acme Corp'")
	}
	if !publishers["Other Inc"] {
		t.Error("missing entry for 'Other Inc'")
	}
	if _, ok := publishers[""]; !ok {
		t.Error("missing entry for empty publisher")
	}
}

func TestDeduplicate_CaseInsensitiveSort(t *testing.T) {
	programs := []types.Program{
		{Name: "zebra", Version: "1.0"},
		{Name: "Apple", Version: "2.0"},
		{Name: "banana", Version: "1.5"},
		{Name: "apple", Version: "3.0"}, // same name different case/version
	}

	result := Deduplicate(programs)

	// "Apple" and "apple" should merge (same normalized name)
	if len(result) != 3 {
		t.Fatalf("expected 3 programs, got %d", len(result))
	}

	// Check sort order: case-insensitive ascending by name, then version descending
	expectedNames := []string{"apple", "banana", "zebra"}
	if len(result) != len(expectedNames) {
		t.Fatalf("expected %d results, got %d", len(expectedNames), len(result))
	}

	// Apple and apple have same normalized name → merge → 1 entry
	// Actually let me re-check: NormalizeName("Apple") = "apple", NormalizeName("apple") = "apple"
	// So they should merge into 1. Result should be 3: apple, banana, zebra
	if len(result) != 3 {
		t.Fatalf("expected 3 programs (apple merged), got %d", len(result))
	}

	// First should be apple (case-insensitive)
	if NormalizeName(result[0].Name) != "apple" {
		t.Errorf("expected first result to be apple, got %q", result[0].Name)
	}
	if result[0].Version != "3.0" {
		t.Errorf("expected apple version 3.0 (desc sort), got %q", result[0].Version)
	}
	if NormalizeName(result[1].Name) != "banana" {
		t.Errorf("expected second result to be banana, got %q", result[1].Name)
	}
	if NormalizeName(result[2].Name) != "zebra" {
		t.Errorf("expected third result to be zebra, got %q", result[2].Name)
	}
}

func TestSafeString_HTMLEscape(t *testing.T) {
	tests := []struct {
		input    types.SafeString
		expected string
	}{
		{"hello", "hello"},
		{types.SafeString("<script>alert('xss')</script>"), "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{types.SafeString(`say "hello" & goodbye`), "say &#34;hello&#34; &amp; goodbye"},
		{types.SafeString("a < b > c & d \"e\" 'f'"), "a &lt; b &gt; c &amp; d &#34;e&#34; &#39;f&#39;"},
		{"", ""},
	}
	for _, tt := range tests {
		got := tt.input.HTMLEscape()
		if got != tt.expected {
			t.Errorf("SafeString(%q).HTMLEscape() = %q, want %q", string(tt.input), got, tt.expected)
		}
		// Also test String() method
		got2 := tt.input.String()
		if got2 != tt.expected {
			t.Errorf("SafeString(%q).String() = %q, want %q", string(tt.input), got2, tt.expected)
		}
	}
}

func TestDeduplicate_NoPrograms(t *testing.T) {
	result := Deduplicate(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d", len(result))
	}

	result = Deduplicate([]types.Program{})
	if len(result) != 0 {
		t.Errorf("expected empty result for empty input, got %d", len(result))
	}
}

func TestDeduplicate_SortVersionDescending(t *testing.T) {
	programs := []types.Program{
		{Name: "App", Version: "1.0", Publisher: "A"},
		{Name: "App", Version: "3.0", Publisher: "A"},
		{Name: "App", Version: "2.0", Publisher: "A"},
	}

	result := Deduplicate(programs)
	if len(result) != 1 {
		t.Fatalf("expected 1 program (same name+publisher), got %d", len(result))
	}
	// Should pick the longest version or highest priority source
	// Since all same source priority, longer version wins
	if result[0].Version != "3.0" {
		t.Errorf("expected version 3.0 (longest), got %q", result[0].Version)
	}
}

func TestProgramSorter(t *testing.T) {
	programs := []types.Program{
		{Name: "Zebra", Version: "1.0"},
		{Name: "apple", Version: "2.0"},
		{Name: "Banana", Version: "3.0"},
		{Name: "apple", Version: "1.0"},
	}

	sort.Sort(ProgramSorter(programs))

	// Expected order: apple 2.0, apple 1.0, Banana, Zebra (case-insensitive)
	if programs[0].Name != "apple" || programs[0].Version != "2.0" {
		t.Errorf("expected apple 2.0 first, got %s %s", programs[0].Name, programs[0].Version)
	}
	if programs[1].Name != "apple" || programs[1].Version != "1.0" {
		t.Errorf("expected apple 1.0 second, got %s %s", programs[1].Name, programs[1].Version)
	}
	if programs[2].Name != "Banana" {
		t.Errorf("expected Banana third, got %s", programs[2].Name)
	}
	if programs[3].Name != "Zebra" {
		t.Errorf("expected Zebra fourth, got %s", programs[3].Name)
	}
}

func TestDeduplicate_MergePriority(t *testing.T) {
	// Test that registry is preferred over PATH
	programs := []types.Program{
		{Name: "Test", Version: "1.0", Publisher: "PATH Pub", Source: "PATH", InstallLocation: "/path/location"},
		{Name: "Test", Version: "2.0", Publisher: "Registry Pub", Source: "registry", InstallLocation: ""},
	}

	result := Deduplicate(programs)
	if len(result) != 1 {
		t.Fatalf("expected 1 program, got %d", len(result))
	}

	p := result[0]
	// Should use registry entry as base (higher priority)
	if p.Publisher != "Registry Pub" {
		t.Errorf("expected registry publisher, got %q", p.Publisher)
	}
	if p.Version != "2.0" {
		t.Errorf("expected version 2.0 from registry, got %q", p.Version)
	}
	// InstallLocation should be merged from PATH entry
	if p.InstallLocation != "/path/location" {
		t.Errorf("expected InstallLocation merged from PATH, got %q", p.InstallLocation)
	}
}

func TestDeduplicate_RawMetadataMerge(t *testing.T) {
	programs := []types.Program{
		{
			Name:        "App",
			Source:      "registry",
			RawMetadata: map[string]string{"key1": "val1"},
		},
		{
			Name:        "App",
			Source:      "PATH",
			RawMetadata: map[string]string{"key2": "val2", "key1": "override"},
		},
	}

	result := Deduplicate(programs)
	if len(result) != 1 {
		t.Fatalf("expected 1 program, got %d", len(result))
	}

	meta := result[0].RawMetadata
	if meta["key1"] != "val1" {
		t.Errorf("expected key1=val1 (from higher priority), got %q", meta["key1"])
	}
	if meta["key2"] != "val2" {
		t.Errorf("expected key2=val2 (merged from lower priority), got %q", meta["key2"])
	}
}
