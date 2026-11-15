package report

import (
	"reflect"
	"testing"
)

func TestWindowsOpenArgs_DoesNotPreEscapePath(t *testing.T) {
	path := `C:\Users\Derrick\AppData\Local\Temp\sys-scanner-report.html`
	got := windowsOpenArgs(path)
	want := []string{"url.dll,FileProtocolHandler", path}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("windowsOpenArgs = %#v, want %#v", got, want)
	}
	if got[1] != path {
		t.Errorf("path was modified: %q", got[1])
	}
}

func TestWindowsOpenArgs_ShellMetacharactersAreNotInterpreted(t *testing.T) {
	path := `C:\Temp\a&b\report.html`
	got := windowsOpenArgs(path)
	if got[1] != path {
		t.Errorf("path = %q, want %q", got[1], path)
	}
}
