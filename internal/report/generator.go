package report

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sys-scanner/internal/types"
)

// DefaultFilename is the file name used when Generate writes to the system
// temp directory.
const DefaultFilename = "sys-scanner-report.html"

// ProgramView is the template-safe representation of a single Program. The
// fields are plain strings; html/template performs contextual auto-escaping
// at render time, so scanner-supplied values (application names, publishers,
// paths) can never inject markup. The IsAITool flag controls the ai-row class
// and AI badge emission at template-render time.
type ProgramView struct {
	Name            string
	Version         string
	Publisher       string
	Source          string
	InstallLocation string
	AIToolName      string
	IsAITool        bool
	// ShowAIToolBadge is true only when the detected tool's signature ID is
	// not already conveyed by the display name (e.g. registry name
	// "Claude Code" vs signature "claude-code"). This avoids repeating the
	// same information in a blue badge.
	ShowAIToolBadge bool
}

// NewProgramView converts a types.Program to a ProgramView, HTML-escaping
// every string field. Bool fields pass through unchanged.
func NewProgramView(p types.Program) ProgramView {
	return ProgramView{
		Name:            p.Name,
		Version:         p.Version,
		Publisher:       p.Publisher,
		Source:          p.Source,
		InstallLocation: p.InstallLocation,
		AIToolName:      p.AIToolName,
		IsAITool:        p.IsAITool,
		ShowAIToolBadge: showAIToolBadge(p.Name, p.AIToolName),
	}
}

// showAIToolBadge decides whether the blue signature-ID badge is rendered:
// it is redundant when the display name already says the same thing after
// case/separator normalization ("Claude Code" ≈ "claude-code").
func showAIToolBadge(name, toolName string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		return strings.NewReplacer("-", " ", "_", " ").Replace(s)
	}
	n := norm(name)
	t := norm(toolName)
	return t != "" && t != n
}

// ReportData is the top-level data model handed to the HTML template.
// All counts are computed at construction time so the template can render
// stats without recomputing them. Programs is always a non-nil slice
// (possibly empty) so {{range .Programs}} never panics.
type ReportData struct {
	Platform     string
	Hostname     string
	IPAddresses  string
	MACAddresses string
	ScanTime     time.Time
	ScanDuration string
	ProgramCount int
	AICount      int
	Programs     []ProgramView
}

// NewReportData builds a ReportData from a slice of types.Program. It counts
// AI tools, converts each Program to a ProgramView, and stamps the current
// time as the scan time. programs may be nil; an empty (non-nil) slice is
// produced so the template can render the empty state cleanly.
func NewReportData(platform string, programs []types.Program) ReportData {
	return NewReportDataWithHost(platform, types.HostInfo{}, programs, 0)
}

// NewReportDataWithHost builds the full report model, including IP and MAC
// addresses collected by the hostinfo package.
func NewReportDataWithHost(platform string, host types.HostInfo, programs []types.Program, duration time.Duration) ReportData {
	views := make([]ProgramView, len(programs))
	aiCount := 0
	for i, p := range programs {
		views[i] = NewProgramView(p)
		if p.IsAITool {
			aiCount++
		}
	}
	scanDuration := ""
	if duration > 0 {
		scanDuration = duration.Round(time.Millisecond).String()
	}
	return ReportData{
		Platform:     platform,
		Hostname:     host.Hostname,
		IPAddresses:  strings.Join(host.IPAddresses, ", "),
		MACAddresses: strings.Join(host.MACAddresses, ", "),
		ScanTime:     time.Now(),
		ScanDuration: scanDuration,
		ProgramCount: len(programs),
		AICount:      aiCount,
		Programs:     views,
	}
}

// WithScanTime returns a copy of the receiver with the scan time overridden.
// Useful for deterministic testing.
func (d ReportData) WithScanTime(t time.Time) ReportData {
	d.ScanTime = t
	return d
}

// FormattedScanTime renders ScanTime in a human-friendly form for the
// report header. The format is constant for a stable look across runs.
func (d ReportData) FormattedScanTime() string {
	return d.ScanTime.Format("2006-01-02 15:04:05 MST")
}

// Generate renders the report to an in-memory buffer and writes it to the
// system temp directory under DefaultFilename. Any existing file at that
// path is overwritten. The absolute path of the generated file is returned.
func Generate(data ReportData) (string, error) {
	path := filepath.Join(os.TempDir(), DefaultFilename)
	return GenerateTo(path, data)
}

// GenerateTo renders the report to the given destination path, creating or
// overwriting the file. The destination's absolute path is returned on
// success.
//
// The file is written atomically through a temporary file in the same
// directory and created with 0600 permissions, because the report contains
// installed-program names and file paths that should not be world-readable on
// multi-user endpoints.
func GenerateTo(path string, data ReportData) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, ".sys-scanner-report-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return "", err
	}
	if err := reportTemplate.Execute(tmp, data); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}

	if err := os.Rename(tmpName, abs); err != nil {
		// Windows cannot replace an existing file with os.Rename.
		if removeErr := os.Remove(abs); removeErr == nil {
			if retryErr := os.Rename(tmpName, abs); retryErr == nil {
				return abs, nil
			}
		}
		_ = os.Remove(tmpName)
		return "", err
	}
	return abs, nil
}

// Render writes the report to the given io.Writer. Useful for tests and for
// callers that want to stream the output rather than write to a file.
func Render(w io.Writer, data ReportData) error {
	return reportTemplate.Execute(w, data)
}

// RenderToBytes is a convenience wrapper that returns the rendered HTML
// as a byte slice. Primarily intended for tests.
func RenderToBytes(data ReportData) ([]byte, error) {
	var buf bytes.Buffer
	if err := Render(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
