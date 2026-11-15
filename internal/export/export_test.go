package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sys-scanner/internal/types"
)

func sampleInventory() types.Inventory {
	return types.Inventory{
		SchemaVersion: types.SchemaVersion,
		GeneratedAt:   time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		Host:          types.HostInfo{Hostname: "ws-01", OS: "linux", Arch: "amd64"},
		Summary:       types.Summary{ProgramCount: 2, AIToolCount: 1},
		AITools:       []string{"opencode"},
		Programs: []types.Program{
			{Name: "OpenCode", Version: "1.0", Publisher: "OpenCode", InstallLocation: "/usr/bin/opencode", Source: "PATH", IsAITool: true, AIToolName: "opencode"},
			{Name: "Firefox", Version: "120", Publisher: "Mozilla", Source: "package_manager"},
		},
		ProgramsBySource: map[string]int{"PATH": 1, "package_manager": 1},
		ScanDurationMS:   1234,
	}
}

func TestJSON_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleInventory()); err != nil {
		t.Fatal(err)
	}

	var decoded types.Inventory
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.SchemaVersion != types.SchemaVersion {
		t.Errorf("schema version = %q", decoded.SchemaVersion)
	}
	if len(decoded.Programs) != 2 {
		t.Errorf("unexpected program count: %d", len(decoded.Programs))
	}
	if decoded.Summary.AIToolCount != 1 {
		t.Errorf("AIToolCount = %d, want 1", decoded.Summary.AIToolCount)
	}
	if strings.Contains(buf.String(), "\\u003c") {
		t.Error("HTML escaping should be disabled so paths stay readable")
	}
}

func TestCSV_HasProgramRows(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, sampleInventory()); err != nil {
		t.Fatal(err)
	}

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want header + 2", len(rows))
	}
	if strings.Join(rows[0], ",") != strings.Join(CSVHeader, ",") {
		t.Errorf("header = %v", rows[0])
	}
	if rows[1][0] != "OpenCode" || rows[1][5] != "true" {
		t.Errorf("first data row = %v", rows[1])
	}
}

func TestCSV_FormulaInjectionIsNeutralized(t *testing.T) {
	inv := sampleInventory()
	inv.Programs[0].Name = "=HYPERLINK(\"http://evil\")"

	var buf bytes.Buffer
	if err := CSV(&buf, inv); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rows[1][0], "'=") {
		t.Errorf("formula value not neutralized: %q", rows[1][0])
	}
}

func TestWriteFile_JSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "nested", "inventory.json")
	got, err := WriteFile("json", path, sampleInventory(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("path = %q, want %q", got, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want 600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !json.Valid(data) {
		t.Error("output is not valid JSON")
	}
}

func TestWriteFile_Stdout(t *testing.T) {
	var buf bytes.Buffer
	path, err := WriteFile("csv", "-", sampleInventory(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if path != "-" {
		t.Errorf("path = %q, want -", path)
	}
	if !strings.Contains(buf.String(), "is_ai_tool") {
		t.Error("stdout should contain CSV header")
	}
}

func TestWriteFile_UnsupportedFormat(t *testing.T) {
	_, err := WriteFile("xml", filepath.Join(t.TempDir(), "x"), sampleInventory(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}
