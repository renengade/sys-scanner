package summary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"

	"sys-scanner/internal/types"
)

func testInventory(hostname, osName, mac string, programs []types.Program) types.Inventory {
	return types.Inventory{
		SchemaVersion:  types.SchemaVersion,
		ScannerVersion: "1.2.0",
		GeneratedAt:    time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		Host: types.HostInfo{
			Hostname:     hostname,
			OS:           osName,
			Arch:         "amd64",
			IPAddresses:  []string{"192.168.1.20"},
			MACAddresses: []string{mac},
		},
		Programs: programs,
	}
}

func readSummary(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rows, err := f.GetRows(sheetName)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestUpdate_CumulativeAndReplaceSameMachine(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)

	first := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{
			{Name: "Chrome", Version: "120", Source: "registry"},
			{Name: "微信", Version: "3.9", Source: "registry"},
		},
	)
	res, err := Update(path, first)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 || res.Added != 2 || res.Removed != 0 {
		t.Fatalf("first update = %+v, want rows=2 added=2 removed=0", res)
	}

	// Re-running the same machine replaces its rows and reports the diff.
	second := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Firefox", Version: "121", Source: "registry"}})
	res, err = Update(path, second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 1 || res.Added != 1 || res.Removed != 2 {
		t.Fatalf("second update = %+v, want rows=1 added=1 removed=2", res)
	}

	// A second machine appends its rows.
	third := testInventory("ws-02", "linux", "11:22:33:44:55:66",
		[]types.Program{
			{Name: "Git", Version: "2.47", Source: "package_manager"},
			{Name: "OpenCode", Version: "1.0", Source: "PATH", IsAITool: true, AIToolName: "opencode"},
		})
	res, err = Update(path, third)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 3 || res.Added != 2 || res.Removed != 0 {
		t.Fatalf("third update = %+v, want rows=3 added=2 removed=0", res)
	}

	rows := readSummary(t, path)
	if len(rows) != 4 {
		t.Fatalf("got %d lines (header+rows), want 4: %v", len(rows), rows)
	}
	if strings.Join(rows[0], ",") != strings.Join(Header, ",") {
		t.Errorf("header = %v", rows[0])
	}

	var names []string
	for _, row := range rows[1:] {
		names = append(names, row[8])
		if row[0] == "" {
			t.Error("machine_id must not be empty")
		}
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "Chrome") {
		t.Error("old rows for ws-01 should have been replaced")
	}
	for _, want := range []string{"Firefox", "Git", "OpenCode"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, names)
		}
	}
}

func TestUpdate_HumanReadableScanTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	inv := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Source: "registry"}})
	if _, err := Update(path, inv); err != nil {
		t.Fatal(err)
	}
	rows := readSummary(t, path)
	got := rows[1][6]
	// 2026-11-15 18:00:00 CST for UTC+8, or another local zone.
	if len(got) < 19 || got[4] != '-' || got[7] != '-' || got[10] != ' ' || got[13] != ':' {
		t.Errorf("scan_time is not human readable: %q", got)
	}
}

func TestUpdate_BacksUpCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	if err := os.WriteFile(path, []byte("not an xlsx file"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Source: "registry"}})
	if _, err := Update(path, inv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("expected corrupt file backup: %v", err)
	}
	rows := readSummary(t, path)
	if len(rows) != 2 {
		t.Errorf("got %d lines, want header+1", len(rows))
	}
}

func TestMachineID_SeparatesOSAndMissingMAC(t *testing.T) {
	windows := MachineID(types.HostInfo{Hostname: "host", OS: "windows"})
	linux := MachineID(types.HostInfo{Hostname: "host", OS: "linux"})
	if windows == linux {
		t.Error("machine IDs must differ across OS")
	}
	if MachineID(types.HostInfo{OS: "windows"}) == "" {
		t.Error("machine ID should never be empty")
	}
}

func TestUpdate_VersionChangeIsNotAddRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	base := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Firefox", Version: "121", Source: "registry"}})
	if _, err := Update(path, base); err != nil {
		t.Fatal(err)
	}
	updated := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Firefox", Version: "122", Source: "registry"}})
	res, err := Update(path, updated)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 || res.Removed != 0 || res.Rows != 1 {
		t.Errorf("version update = %+v, want added=0 removed=0 rows=1", res)
	}
	rows := readSummary(t, path)
	if rows[1][9] != "122" {
		t.Errorf("version = %q, want 122", rows[1][9])
	}
}

func TestUpdate_NoChangeSkipsWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	inv := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Version: "120", Source: "registry"}})
	if _, err := Update(path, inv); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	res, err := Update(path, inv)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Errorf("unchanged rerun should not mark Changed: %+v", res)
	}
	if res.Rows != 1 || res.Added != 0 || res.Removed != 0 || res.Updated != 0 {
		t.Errorf("unchanged rerun result = %+v", res)
	}
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info2.ModTime().Equal(oldTime) {
		t.Errorf("workbook was rewritten on unchanged run: %v -> %v", oldTime, info2.ModTime())
	}
}

func TestUpdate_VersionBumpIsUpdateNotAddRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	first := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Version: "120", Source: "registry"}})
	if _, err := Update(path, first); err != nil {
		t.Fatal(err)
	}
	second := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Version: "121", Source: "registry"}})
	res, err := Update(path, second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.Added != 0 || res.Removed != 0 || res.Updated != 1 {
		t.Errorf("version bump result = %+v, want changed with 1 updated", res)
	}
}

func TestUpdate_NewScanTimeButSameSoftwareIsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFilename)
	first := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Version: "120", Source: "registry"}})
	if _, err := Update(path, first); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// A later run with the same software list must not rewrite the file.
	second := testInventory("ws-01", "windows", "aa:bb:cc:dd:ee:ff",
		[]types.Program{{Name: "Chrome", Version: "120", Source: "registry"}})
	second.GeneratedAt = first.GeneratedAt.Add(time.Hour)
	res, err := Update(path, second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || res.Rows != 1 {
		t.Errorf("same-software rerun = %+v, want unchanged", res)
	}
	info2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info2.ModTime().Equal(oldTime) {
		t.Errorf("workbook rewritten on same-software rerun: %v -> %v", oldTime, info2.ModTime())
	}
}
