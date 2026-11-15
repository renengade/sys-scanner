// windows_test.go — cross-platform tests for pure logic in helpers.go.
// No //go:build tag: these tests compile and run on all platforms.
package windows

import (
	"testing"
)

// ---------------------------------------------------------------------------
// shouldFilterEntry
// ---------------------------------------------------------------------------

func TestShouldFilterEntry_SystemComponent(t *testing.T) {
	vals := map[string]string{
		"DisplayName":     "Some Program",
		"SystemComponent": "1",
	}
	if !shouldFilterEntry(vals) {
		t.Error("expected SystemComponent=1 to be filtered")
	}
}

func TestShouldFilterEntry_NoRemove(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "Some Program",
		"NoRemove":    "1",
	}
	if !shouldFilterEntry(vals) {
		t.Error("expected NoRemove=1 to be filtered")
	}
}

func TestShouldFilterEntry_ParentKeyName(t *testing.T) {
	vals := map[string]string{
		"DisplayName":   "Some Program",
		"ParentKeyName": "Parent",
	}
	if !shouldFilterEntry(vals) {
		t.Error("expected non-empty ParentKeyName to be filtered")
	}
}

func TestShouldFilterEntry_ReleaseType(t *testing.T) {
	cases := []string{"Hotfix", "Security Update", "Update Rollup", "Service Pack"}
	for _, rt := range cases {
		vals := map[string]string{
			"DisplayName": "Some Patch",
			"ReleaseType": rt,
		}
		if !shouldFilterEntry(vals) {
			t.Errorf("expected ReleaseType=%q to be filtered", rt)
		}
	}
}

func TestShouldFilterEntry_HideARP(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "Hidden Tool",
		"HideARP":     "1",
	}
	if !shouldFilterEntry(vals) {
		t.Error("expected HideARP=1 to be filtered")
	}
}

func TestShouldFilterEntry_NotFiltered(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "Good Program",
		"Publisher":   "Acme",
	}
	if shouldFilterEntry(vals) {
		t.Error("expected clean entry NOT to be filtered")
	}
}

// ---------------------------------------------------------------------------
// parseRegistryEntry
// ---------------------------------------------------------------------------

func TestParseRegistryEntry_Valid(t *testing.T) {
	vals := map[string]string{
		"DisplayName":     "Firefox",
		"DisplayVersion":  "120.0",
		"Publisher":       "Mozilla",
		"InstallLocation": `C:\Program Files\Mozilla Firefox`,
		"InstallDate":     "20240101",
	}
	prog, ok := parseRegistryEntry(vals, "registry")
	if !ok {
		t.Fatal("expected valid entry to parse")
	}
	if prog.Name != "Firefox" {
		t.Errorf("Name = %q, want Firefox", prog.Name)
	}
	if prog.Version != "120.0" {
		t.Errorf("Version = %q, want 120.0", prog.Version)
	}
	if prog.Publisher != "Mozilla" {
		t.Errorf("Publisher = %q, want Mozilla", prog.Publisher)
	}
	if prog.InstallLocation != `C:\Program Files\Mozilla Firefox` {
		t.Errorf("InstallLocation = %q", prog.InstallLocation)
	}
	if prog.Source != "registry" {
		t.Errorf("Source = %q, want registry", prog.Source)
	}
	if prog.RawMetadata["InstallDate"] != "20240101" {
		t.Errorf("InstallDate metadata = %q, want 20240101", prog.RawMetadata["InstallDate"])
	}
}

func TestParseRegistryEntry_EmptyDisplayName(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "",
	}
	_, ok := parseRegistryEntry(vals, "registry")
	if ok {
		t.Error("expected empty DisplayName to be rejected")
	}
}

func TestParseRegistryEntry_Filtered(t *testing.T) {
	vals := map[string]string{
		"DisplayName":     "System Update",
		"SystemComponent": "1",
	}
	_, ok := parseRegistryEntry(vals, "registry")
	if ok {
		t.Error("expected filtered entry to be rejected")
	}
}

func TestParseRegistryEntry_TrimSpaces(t *testing.T) {
	vals := map[string]string{
		"DisplayName":     "  Trimmed  ",
		"DisplayVersion":  " 1.0 ",
		"Publisher":       "  Pub  ",
		"InstallLocation": " C:\\path ",
	}
	prog, ok := parseRegistryEntry(vals, "registry")
	if !ok {
		t.Fatal("expected entry to parse")
	}
	if prog.Name != "Trimmed" {
		t.Errorf("Name = %q, want Trimmed", prog.Name)
	}
	if prog.Version != "1.0" {
		t.Errorf("Version = %q, want 1.0", prog.Version)
	}
	if prog.Publisher != "Pub" {
		t.Errorf("Publisher = %q, want Pub", prog.Publisher)
	}
}

func TestParseRegistryEntry_NoInstallDate(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "NoDate",
	}
	prog, ok := parseRegistryEntry(vals, "registry")
	if !ok {
		t.Fatal("expected entry to parse")
	}
	if _, exists := prog.RawMetadata["InstallDate"]; exists {
		t.Error("expected no InstallDate key when not present")
	}
}

// ---------------------------------------------------------------------------
// expandEnvVars
// ---------------------------------------------------------------------------

func TestExpandEnvVars_Basic(t *testing.T) {
	env := map[string]string{
		"SystemRoot":   `C:\Windows`,
		"ProgramFiles": `C:\Program Files`,
	}
	got := expandEnvVars(`%SystemRoot%\System32`, env)
	want := `C:\Windows\System32`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpandEnvVars_Multiple(t *testing.T) {
	env := map[string]string{
		"A": "1",
		"B": "2",
	}
	got := expandEnvVars("%A%-%B%", env)
	if got != "1-2" {
		t.Errorf("got %q, want 1-2", got)
	}
}

func TestExpandEnvVars_UnknownVar(t *testing.T) {
	env := map[string]string{}
	got := expandEnvVars("%UNKNOWN%path", env)
	if got != "path" {
		t.Errorf("got %q, want path (empty expansion)", got)
	}
}

func TestExpandEnvVars_NoClosingPercent(t *testing.T) {
	env := map[string]string{"A": "x"}
	got := expandEnvVars("foo%Ab", env)
	// No closing %, so the rest is literal.
	if got != "foo%Ab" {
		t.Errorf("got %q, want foo%%Ab", got)
	}
}

func TestExpandEnvVars_Empty(t *testing.T) {
	env := map[string]string{}
	if got := expandEnvVars("", env); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExpandEnvVars_NoVars(t *testing.T) {
	env := map[string]string{}
	got := expandEnvVars("plain text", env)
	if got != "plain text" {
		t.Errorf("got %q, want plain text", got)
	}
}

// ---------------------------------------------------------------------------
// splitWindowsPATH
// ---------------------------------------------------------------------------

func TestSplitWindowsPATH_Basic(t *testing.T) {
	got := splitWindowsPATH(`C:\Windows;C:\Windows\System32;C:\Tools`)
	want := []string{`C:\Windows`, `C:\Windows\System32`, `C:\Tools`}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitWindowsPATH_Empty(t *testing.T) {
	got := splitWindowsPATH("")
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

func TestSplitWindowsPATH_TrimsSpaces(t *testing.T) {
	got := splitWindowsPATH(`  C:\A ; C:\B ;  ; C:\C  `)
	want := []string{`C:\A`, `C:\B`, `C:\C`}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitWindowsPATH_DropsEmpty(t *testing.T) {
	got := splitWindowsPATH("A;;B;;;C")
	want := []string{"A", "B", "C"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// cleanPublisher (from store.go — pure function, tests cross-platform)
// ---------------------------------------------------------------------------
// Note: cleanPublisher is defined in store.go which has //go:build windows,
// so we duplicate a minimal version here to keep tests portable.

func cleanPublisherPortable(pub string) string {
	for _, part := range splitOnComma(pub) {
		if len(part) > 3 && toUpper3(part[:3]) == "CN=" {
			return part[3:]
		}
	}
	return trimSpace(pub)
}

func splitOnComma(s string) []string {
	var parts []string
	for _, p := range split(s, ',') {
		parts = append(parts, trimSpace(p))
	}
	return parts
}

func split(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

func toUpper3(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func TestCleanPublisherPortable_CN(t *testing.T) {
	pub := "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond"
	got := cleanPublisherPortable(pub)
	want := "Microsoft Corporation"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCleanPublisherPortable_Plain(t *testing.T) {
	got := cleanPublisherPortable("Mozilla")
	if got != "Mozilla" {
		t.Errorf("got %q, want Mozilla", got)
	}
}

func TestCleanPublisherPortable_Empty(t *testing.T) {
	got := cleanPublisherPortable("")
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestIsWindowsBuiltinName(t *testing.T) {
	t.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "")

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"desktop runtime", "Microsoft Windows Desktop Runtime - 8.0.1", true},
		{"windows sdk", "Windows Software Development Kit 10.0", true},
		{"vc redist", "Microsoft Visual C++ 2015-2022 Redistributable (x64)", true},
		{"edge", "Microsoft Edge", true},
		{"wsl", "Windows Subsystem for Linux", true},
		{"dotnet runtime", "Microsoft .NET Runtime - 8.0.1", true},
		{"vscode", "Microsoft Visual Studio Code", false},
		{"m365", "Microsoft 365 Apps for enterprise", false},
		{"office", "Microsoft Office LTSC Professional Plus 2021", false},
		{"third party", "Google Chrome", false},
		{"docker", "Docker Desktop", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWindowsBuiltinName(tt.input); got != tt.want {
				t.Errorf("isWindowsBuiltinName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsBuiltinStorePackage(t *testing.T) {
	t.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "")

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"calculator", "Microsoft.WindowsCalculator", true},
		{"xbox", "Microsoft.XboxGamingOverlay", true},
		{"photos", "Microsoft.Windows.Photos", true},
		{"winget", "Microsoft.DesktopAppInstaller", true},
		{"vscode store", "Microsoft.VisualStudioCode", false},
		{"powertoys", "Microsoft.PowerToys", false},
		{"claude", "Anthropic.Claude", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBuiltinStorePackage(tt.input); got != tt.want {
				t.Errorf("isBuiltinStorePackage(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsWindowsSystemPath(t *testing.T) {
	t.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "")
	t.Setenv("SystemRoot", `C:\Windows`)

	tests := []struct {
		input string
		want  bool
	}{
		{`C:\Windows\System32\notepad.exe`, true},
		{`"C:\Windows\explorer.exe"`, true},
		{`C:\Windows\System32`, true},
		{`C:\Program Files\Google\Chrome\Application\chrome.exe`, false},
		{`D:\Tools\app.exe`, false},
	}
	for _, tt := range tests {
		if got := isWindowsSystemPath(tt.input); got != tt.want {
			t.Errorf("isWindowsSystemPath(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseRegistryEntry_FiltersWindowsBuiltin(t *testing.T) {
	t.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "")

	_, ok := parseRegistryEntry(map[string]string{
		valDisplayName: "Microsoft Windows Desktop Runtime - 8.0.1",
	}, "registry")
	if ok {
		t.Error("Windows runtime should be filtered from the default inventory")
	}

	p, ok := parseRegistryEntry(map[string]string{
		valDisplayName: "Microsoft Visual Studio Code",
	}, "registry")
	if !ok || p.Name != "Microsoft Visual Studio Code" {
		t.Error("user-installed Microsoft applications must not be filtered")
	}
}

func TestIsBuiltinExecutableName(t *testing.T) {
	t.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "")

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"iexplore uppercase", "IEXPLORE.EXE", true},
		{"iediag", "IEDIAGCMD.EXE", true},
		{"media player", "wmplayer.exe", true},
		{"skype server", "SKYPESERVER.EXE", true},
		{"office helper", "msoasb.exe", true},
		{"office app", "WINWORD.EXE", false},
		{"vscode", "code.exe", false},
		{"chrome", "chrome.exe", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBuiltinExecutableName(tt.input); got != tt.want {
				t.Errorf("isBuiltinExecutableName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestStripJSONBOM(t *testing.T) {
	if got := stripJSONBOM("\ufeff[{\"Name\":\"x\"}]"); got != "[{\"Name\":\"x\"}]" {
		t.Errorf("stripJSONBOM = %q", got)
	}
	if got := stripJSONBOM(`{"Name":"x"}`); got != `{"Name":"x"}` {
		t.Errorf("stripJSONBOM changed non-BOM input: %q", got)
	}
}
