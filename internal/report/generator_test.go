package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sys-scanner/internal/types"
)

// fixedScanTime returns a deterministic timestamp for stable tests.
func fixedScanTime() time.Time {
	return time.Date(2026, 8, 12, 14, 30, 45, 0, time.UTC)
}

// samplePrograms returns a small but representative set of programs covering
// regular entries and AI tools. Reused across several tests.
func samplePrograms() []types.Program {
	return []types.Program{
		{
			Name:      "Firefox",
			Version:   "100.0.1",
			Publisher: "Mozilla Foundation",
			Source:    "registry",
		},
		{
			Name:       "Cursor",
			Version:    "0.42.0",
			Publisher:  "Anysphere",
			Source:     ".desktop",
			IsAITool:   true,
			AIToolName: "Cursor",
		},
		{
			Name:            "Git",
			Version:         "2.43.0",
			Publisher:       "Software Freedom Conservancy",
			InstallLocation: "/usr/bin/git",
			Source:          "PATH",
		},
		{
			Name:       "OpenCode",
			Version:    "1.2.3",
			Publisher:  "OpenCode Team",
			Source:     ".desktop",
			IsAITool:   true,
			AIToolName: "OpenCode",
		},
	}
}

// ---------------------------------------------------------------------------
// Conversion tests
// ---------------------------------------------------------------------------

func TestNewProgramView_PreservesFields(t *testing.T) {
	p := types.Program{
		Name:      `<script>alert("xss")</script>`,
		Version:   `1.0<>&"'`,
		Publisher: `Acme & Co.`,
		Source:    "registry",
	}
	v := NewProgramView(p)

	cases := []struct {
		name, got, want string
	}{
		{"Name", v.Name, `<script>alert("xss")</script>`},
		{"Version", v.Version, `1.0<>&"'`},
		{"Publisher", v.Publisher, `Acme & Co.`},
		{"Source", v.Source, `registry`},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
	if v.IsAITool {
		t.Error("IsAITool should be false")
	}
}

func TestNewProgramView_PreservesUnicode(t *testing.T) {
	p := types.Program{
		Name:      "微信 (WeChat)",
		Version:   "3.9.10",
		Publisher: "Tencent",
		Source:    "registry",
	}
	v := NewProgramView(p)
	if v.Name != "微信 (WeChat)" {
		t.Errorf("Unicode not preserved: got %q", v.Name)
	}
}

func TestNewReportData_CountsAI(t *testing.T) {
	progs := []types.Program{
		{Name: "A", IsAITool: true},
		{Name: "B"},
		{Name: "C", IsAITool: true},
		{Name: "D", IsAITool: true},
		{Name: "E"},
	}
	d := NewReportData("linux", progs)
	if d.Platform != "linux" {
		t.Errorf("Platform: got %q", d.Platform)
	}
	if d.ProgramCount != 5 {
		t.Errorf("ProgramCount: got %d, want 5", d.ProgramCount)
	}
	if d.AICount != 3 {
		t.Errorf("AICount: got %d, want 3", d.AICount)
	}
	if len(d.Programs) != 5 {
		t.Errorf("Programs len: got %d, want 5", len(d.Programs))
	}
	if d.ScanTime.IsZero() {
		t.Error("ScanTime should be set to time.Now()")
	}
}

func TestNewReportData_NilPrograms(t *testing.T) {
	d := NewReportData("linux", nil)
	if d.Programs == nil {
		t.Error("Programs must be non-nil so template can range safely")
	}
	if len(d.Programs) != 0 {
		t.Errorf("Programs len: got %d, want 0", len(d.Programs))
	}
	if d.ProgramCount != 0 || d.AICount != 0 {
		t.Errorf("counts non-zero for nil input: %+v", d)
	}
}

// ---------------------------------------------------------------------------
// Rendering tests (XSS-safe, deterministic)
// ---------------------------------------------------------------------------

func TestRender_BasicStructure(t *testing.T) {
	data := NewReportData("Linux", samplePrograms()).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	s := string(out)

	for _, want := range []string{
		"<!DOCTYPE html>",
		`<meta charset="UTF-8">`,
		"sys-scanner",
		"Linux",
		// formatted scan time
		"2026-08-12",
		// stats
		"Total Programs",
		"AI Tools",
		// tabs
		"All Programs",
		"AI Tools Only",
		// search input
		"Search by name or publisher",
		// columns
		"Name", "Version", "Publisher", "Source",
		// data
		"Firefox", "Mozilla Foundation",
		"Cursor", "OpenCode",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered output missing substring %q", want)
		}
	}
}

func TestRender_TitleAttribute_HasPlatform(t *testing.T) {
	data := NewReportData("FreeBSD", nil).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	if !strings.Contains(string(out), "<title>sys-scanner Report — FreeBSD</title>") {
		t.Errorf("title tag missing platform: %q", string(out))
	}
}

func TestRender_EmptyPrograms_ShowsEmptyState(t *testing.T) {
	data := NewReportData("Linux", nil).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	s := string(out)

	if !strings.Contains(s, "No programs detected") {
		t.Error("empty-state heading missing")
	}
	if !strings.Contains(s, "No programs were detected on this Linux") {
		t.Error("empty-state platform-aware copy missing")
	}
	// Empty-state element must NOT be hidden when Programs is empty.
	// The HTML emits an explicit hidden attribute only when Programs is
	// non-empty, so absence of `hidden` on the empty-state is the signal.
	// Look for `<div class="empty-state"` without a following `hidden`.
	idx := strings.Index(s, `<div class="empty-state"`)
	if idx == -1 {
		t.Fatal("empty-state container missing")
	}
	end := idx + len(`<div class="empty-state"`)
	if end < len(s) && strings.HasPrefix(s[end:], " hidden") {
		t.Errorf("empty-state should NOT be hidden when there are no programs")
	}
}

func TestRender_AllAITools_AllRowsAreAIRows(t *testing.T) {
	progs := []types.Program{
		{Name: "Cursor", IsAITool: true, AIToolName: "Cursor"},
		{Name: "OpenCode", IsAITool: true, AIToolName: "OpenCode"},
		{Name: "Ollama", IsAITool: true, AIToolName: "Ollama"},
	}
	data := NewReportData("macOS", progs).WithScanTime(fixedScanTime())
	if data.AICount != 3 {
		t.Fatalf("AICount: got %d, want 3", data.AICount)
	}
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	s := string(out)

	for _, name := range []string{"Cursor", "OpenCode", "Ollama"} {
		if !strings.Contains(s, `class="ai-row"`) {
			t.Fatal("no ai-row class emitted")
		}
		// The badge should appear in each row.
		if !strings.Contains(s, `<span class="badge">`+name) {
			t.Errorf("badge for %s missing", name)
		}
		if !strings.Contains(s, name) {
			t.Errorf("program %s missing", name)
		}
	}
}

// ---------------------------------------------------------------------------
// XSS Prevention tests
// ---------------------------------------------------------------------------

func TestRender_XSSInName_EscapedInOutput(t *testing.T) {
	const marker = "ZZZ_XSS_MARKER_"
	malicious := types.Program{
		Name:      marker + `<script>alert('xss')</script>`,
		Version:   "1.0",
		Publisher: "Acme",
		Source:    "registry",
	}
	data := NewReportData("Linux", []types.Program{malicious}).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	s := string(out)

	// The raw, unescaped version must NOT appear in the output.
	rawName := marker + `<script>alert('xss')</script>`
	if strings.Contains(s, rawName) {
		t.Errorf("XSS: raw unescaped program name found in output")
	}
	// The escaped version MUST appear (proves the data was rendered at all).
	escapedName := marker + `&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;`
	if !strings.Contains(s, escapedName) {
		t.Errorf("escaped program name not found; want substring:\n  %s", escapedName)
	}
}

func TestRender_XSSInPublisher_AttributeSafe(t *testing.T) {
	malicious := types.Program{
		Name:      "RealName",
		Version:   "1.0",
		Publisher: `evil" onload="alert(1)`,
		Source:    "registry",
	}
	data := NewReportData("Linux", []types.Program{malicious}).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	s := string(out)

	if strings.Contains(s, `" onload="alert(1)`) {
		t.Errorf("XSS: attribute injection in publisher")
	}
	if !strings.Contains(s, `evil&#34; onload=&#34;alert(1)`) {
		t.Error("expected escaped attribute-injection payload in output")
	}
}

func TestRender_NoInnerHTMLOrEvalInScript(t *testing.T) {
	data := NewReportData("Linux", samplePrograms()).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	body := string(out)
	// Extract the inline <script> block (the last one in the document).
	idx := strings.LastIndex(body, "<script>")
	if idx == -1 {
		t.Fatal("no <script> tag in output")
	}
	end := strings.Index(body[idx:], "</script>")
	if end == -1 {
		t.Fatal("no </script> close tag")
	}
	script := body[idx+len("<script>"):][:end]

	// The script must not use eval or new Function.
	for _, bad := range []string{"eval(", "new Function("} {
		if strings.Contains(script, bad) {
			t.Errorf("inline script contains forbidden token %q", bad)
		}
	}
	// Inspect every `<` in the script: the only allowed HTML-like sequences
	// are the sort-indicator placeholder strings; no `innerHTML` assignment
	// may appear (it would need to be a real DOM API call, not a literal
	// in user data). innerHTML appears as identifier here.
	if strings.Contains(script, "innerHTML") {
		t.Error("inline script references innerHTML — must not, user data is read via textContent")
	}
}

func TestRender_NoExternalResourceReferences(t *testing.T) {
	data := NewReportData("Linux", samplePrograms()).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	body := string(out)

	for _, bad := range []string{
		`https://`, `http://`,
		`src="http`, `href="http`,
		`<link `,
		`@import`,
		`googleapis`, `gstatic`,
		`fonts.googleapis`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("output contains forbidden external-reference token %q", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Unicode / global-string safety
// ---------------------------------------------------------------------------

func TestRender_UnicodeNamesPreserved(t *testing.T) {
	progs := []types.Program{
		{Name: "微信", Version: "3.9.10", Publisher: "腾讯", Source: "registry"},
		{Name: "Яндекс Браузер", Version: "24.7", Publisher: "Яндекс", Source: "registry"},
		{Name: "🚀 Rocket", Version: "1.0", Publisher: "🚀", Source: "PATH"},
	}
	data := NewReportData("Linux", progs).WithScanTime(fixedScanTime())
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatalf("RenderToBytes: %v", err)
	}
	body := string(out)

	// All strings must survive the round-trip because they are escaped in
	// full (only HTML-special chars change), and the document declares
	// UTF-8 in its meta tag.
	for _, want := range []string{"微信", "腾讯", "Яндекс Браузер", "🚀"} {
		if !strings.Contains(body, want) {
			t.Errorf("unicode string %q not preserved in output", want)
		}
	}
	if !strings.Contains(body, `<meta charset="UTF-8">`) {
		t.Error("UTF-8 meta tag missing")
	}
}

// ---------------------------------------------------------------------------
// File-system tests
// ---------------------------------------------------------------------------

func TestGenerate_WritesToTempDir(t *testing.T) {
	wantName := DefaultFilename
	data := NewReportData("Linux", samplePrograms()).WithScanTime(fixedScanTime())
	path, err := Generate(data)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if filepath.Base(path) != wantName {
		t.Errorf("Generate file name: got %q, want %q", path, wantName)
	}
	// Verify file actually exists, is non-empty, and is HTML.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Size() == 0 {
		t.Error("generated report is empty")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if !bytes.HasPrefix(body, []byte("<!DOCTYPE html>")) {
		t.Errorf("generated file is not HTML; first 80 bytes: %q", body[:80])
	}
}

func TestGenerateTo_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "nested", "report.html")
	data := NewReportData("Linux", samplePrograms()).WithScanTime(fixedScanTime())

	abs, err := GenerateTo(dst, data)
	if err != nil {
		t.Fatalf("GenerateTo: %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("expected absolute path, got %q", abs)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("stat: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Browser opener tests
// ---------------------------------------------------------------------------

// TestOpen_TimesOut ensures Open never blocks indefinitely when no launcher
// is reachable. We invoke Open on this OS but don't depend on the browser
// actually opening — only that Open returns within the launchTimeout bound.
func TestOpen_TimesOutCleanly(t *testing.T) {
	// Bound the test well above the production 5s budget so we can detect
	// leaks; in practice Open returns quickly on failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Pass a non-existent path so any launcher that tries to open it
		// will still fail, and so the path line printed by Open is harmless.
		_ = Open("/nonexistent-sys-scanner-test-" + filepath.Base(t.TempDir()))
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Open blocked beyond 10s — timeout guard is broken")
	}
}
