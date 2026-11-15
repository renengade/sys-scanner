// Package export writes machine-readable inventory formats for central
// collection (JSON and CSV).
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"sys-scanner/internal/types"
)

// JSON writes the inventory as indented JSON.
func JSON(w io.Writer, inv types.Inventory) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(inv)
}

// CSVHeader is the stable column order for software CSV exports.
var CSVHeader = []string{
	"name",
	"version",
	"publisher",
	"location",
	"source",
	"is_ai_tool",
	"ai_tool_name",
}

// CSV writes the software inventory as a single spreadsheet-friendly table.
func CSV(w io.Writer, inv types.Inventory) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}

	for _, p := range inv.Programs {
		row := []string{
			sanitize(p.Name),
			sanitize(p.Version),
			sanitize(p.Publisher),
			sanitize(p.InstallLocation),
			sanitize(p.Source),
			strconv.FormatBool(p.IsAITool),
			sanitize(p.AIToolName),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

// WriteFile writes the inventory to path in the given format ("json" or
// "csv"). The special path "-" writes to stdout. It returns the path written.
func WriteFile(format, path string, inv types.Inventory, stdout io.Writer) (string, error) {
	write := func(w io.Writer) error {
		switch format {
		case "json":
			return JSON(w, inv)
		case "csv":
			return CSV(w, inv)
		default:
			return fmt.Errorf("unsupported export format %q", format)
		}
	}

	if path == "-" {
		if err := write(stdout); err != nil {
			return "", err
		}
		return "-", nil
	}
	return path, writeFile(path, write)
}

// sanitize guards against spreadsheet formula injection when a CSV is opened
// in Excel or LibreOffice. Values starting with =, +, -, @, tab or CR are
// prefixed with a single quote, which spreadsheet apps treat as text.
func sanitize(value string) string {
	if value == "" {
		return ""
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}
	return value
}

// writeFile writes atomically via a temporary file in the destination
// directory. Output files are created with 0600 permissions because an
// endpoint inventory contains host and path information.
func writeFile(path string, write func(io.Writer) error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".sys-scanner-export-*")
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
	if err := write(tmp); err != nil {
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
		// os.Rename cannot replace an existing file on some platforms
		// (notably Windows). Remove the old file and retry once.
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
