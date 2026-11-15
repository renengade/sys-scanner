// Package summary maintains a cumulative Excel workbook that records the
// software inventory of every machine the scanner has run on. Each run
// replaces that machine's previous rows, so repeated runs update the summary
// instead of duplicating it, and reports added/removed items.
package summary

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"sys-scanner/internal/types"
)

// DefaultFilename is the cumulative workbook written next to the HTML report.
const DefaultFilename = "sys-scanner-summary.xlsx"

const sheetName = "Summary"

// Header is the stable column order of the cumulative summary.
var Header = []string{
	"machine_id",
	"hostname",
	"os",
	"arch",
	"ip_addresses",
	"mac_addresses",
	"scan_time",
	"scanner_version",
	"name",
	"version",
	"publisher",
	"location",
	"source",
	"is_ai_tool",
	"ai_tool_name",
}

// Result describes one summary update.
type Result struct {
	Rows    int // total data rows in the workbook
	Added   int // items present now but not in the previous run for this machine
	Removed int // items present in the previous run but not now
}

// MachineID returns the stable key used to replace a machine's rows on the
// next run. OS is included so a Windows host and its WSL environment remain
// separate records even when they share a hostname.
func MachineID(h types.HostInfo) string {
	host := strings.TrimSpace(h.Hostname)
	if host == "" {
		host = "unknown-host"
	}
	mac := ""
	if len(h.MACAddresses) > 0 {
		mac = h.MACAddresses[0]
	}
	return host + "|" + h.OS + "|" + mac
}

// Update merges the given inventory into the XLSX summary at path and returns
// row/diff counts. Existing rows for the same machine_id are replaced.
func Update(path string, inv types.Inventory) (Result, error) {
	rows, err := readExisting(path)
	if err != nil {
		return Result{}, err
	}

	machineID := MachineID(inv.Host)
	var (
		kept    [][]string
		oldKeys = make(map[string]struct{})
	)
	for _, row := range rows {
		if len(row) != len(Header) {
			continue
		}
		if row[0] == machineID {
			oldKeys[rowKey(row)] = struct{}{}
			continue
		}
		kept = append(kept, row)
	}

	newRows := buildRows(machineID, inv)
	newKeys := make(map[string]struct{}, len(newRows))
	for _, row := range newRows {
		newKeys[rowKey(row)] = struct{}{}
	}

	result := Result{
		Rows:    len(kept) + len(newRows),
		Added:   countMissing(newKeys, oldKeys),
		Removed: countMissing(oldKeys, newKeys),
	}

	merged := append(kept, newRows...)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i][0] != merged[j][0] {
			return merged[i][0] < merged[j][0]
		}
		return strings.ToLower(merged[i][8]) < strings.ToLower(merged[j][8])
	})

	if err := writeWorkbook(path, merged); err != nil {
		return Result{}, err
	}
	return result, nil
}

func countMissing(a, b map[string]struct{}) int {
	n := 0
	for key := range a {
		if _, ok := b[key]; !ok {
			n++
		}
	}
	return n
}

func rowKey(row []string) string {
	return strings.Join([]string{row[8], row[11]}, "\x00")
}

func buildRows(machineID string, inv types.Inventory) [][]string {
	scanTime := humanTime(inv.GeneratedAt)
	ips := strings.Join(inv.Host.IPAddresses, "; ")
	macs := strings.Join(inv.Host.MACAddresses, "; ")

	rows := make([][]string, 0, len(inv.Programs))
	for _, p := range inv.Programs {
		rows = append(rows, []string{
			machineID,
			inv.Host.Hostname,
			inv.Host.OS,
			inv.Host.Arch,
			ips,
			macs,
			scanTime,
			inv.ScannerVersion,
			p.Name,
			p.Version,
			p.Publisher,
			p.InstallLocation,
			p.Source,
			strconv.FormatBool(p.IsAITool),
			p.AIToolName,
		})
	}
	return rows
}

func readExisting(path string) ([][]string, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		backupCorrupt(path)
		return nil, nil
	}
	defer f.Close()

	rows, err := f.GetRows(sheetName)
	if err != nil {
		backupCorrupt(path)
		return nil, nil
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if !sameHeader(rows[0]) {
		backupCorrupt(path)
		return nil, nil
	}

	// GetRows trims trailing empty cells. Pad every row back to the full
	// header width; otherwise rows lose their empty columns and would be
	// dropped on the next update.
	data := rows[1:]
	for i := range data {
		if len(data[i]) > len(Header) {
			data[i] = data[i][:len(Header)]
		}
		for len(data[i]) < len(Header) {
			data[i] = append(data[i], "")
		}
	}
	return data, nil
}

func sameHeader(got []string) bool {
	if len(got) != len(Header) {
		return false
	}
	for i := range Header {
		if got[i] != Header[i] {
			return false
		}
	}
	return true
}

// backupCorrupt moves an unreadable or incompatible workbook aside so the next
// run can start with a clean file without losing the original bytes.
func backupCorrupt(path string) {
	backup := path + ".bak"
	_ = os.Remove(backup)
	_ = os.Rename(path, backup)
}

func writeWorkbook(path string, rows [][]string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	f := excelize.NewFile()
	defer f.Close()

	if err := f.SetSheetName("Sheet1", sheetName); err != nil {
		return err
	}

	header := make([]interface{}, len(Header))
	for i, v := range Header {
		header[i] = v
	}
	if err := f.SetSheetRow(sheetName, "A1", &header); err != nil {
		return err
	}

	for i, row := range rows {
		values := make([]interface{}, len(row))
		for j, v := range row {
			values[j] = v
		}
		cell, err := excelize.CoordinatesToCellName(1, i+2)
		if err != nil {
			return err
		}
		if err := f.SetSheetRow(sheetName, cell, &values); err != nil {
			return err
		}
	}

	lastCol, err := excelize.ColumnNumberToName(len(Header))
	if err != nil {
		return err
	}
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"4472C4"}},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	if err != nil {
		return err
	}
	if err := f.SetCellStyle(sheetName, "A1", lastCol+"1", headerStyle); err != nil {
		return err
	}
	_ = f.SetPanes(sheetName, &excelize.Panes{
		Freeze:      true,
		Split:       true,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})
	lastRow := len(rows) + 1
	lastCell, _ := excelize.CoordinatesToCellName(len(Header), lastRow)
	_ = f.AutoFilter(sheetName, "A1:"+lastCell, nil)
	_ = f.SetSheetDimension(sheetName, "A1:"+lastCell)
	_ = f.SetColWidth(sheetName, "A", "A", 42)
	_ = f.SetColWidth(sheetName, "B", "H", 18)
	_ = f.SetColWidth(sheetName, "I", "K", 24)
	_ = f.SetColWidth(sheetName, "L", "O", 18)

	tmp, err := os.CreateTemp(dir, ".sys-scanner-summary-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := f.WriteTo(tmp); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, abs); err != nil {
		// Windows cannot replace an existing file with os.Rename.
		if removeErr := os.Remove(abs); removeErr == nil {
			if retryErr := os.Rename(tmpName, abs); retryErr == nil {
				return nil
			}
		}
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// humanTime renders timestamps in local time for Excel users, e.g.
// "2026-11-15 13:00:00 CST".
func humanTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}
