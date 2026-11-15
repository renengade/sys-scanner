package report

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sys-scanner/internal/types"
)

func TestNewReportDataWithHost_IPAndMAC(t *testing.T) {
	host := types.HostInfo{
		Hostname:     "ws-01",
		OS:           "windows",
		Arch:         "amd64",
		IPAddresses:  []string{"192.168.1.10", "fe80::1"},
		MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
	}
	data := NewReportDataWithHost("windows", host, samplePrograms(), 1500*time.Millisecond)
	if data.IPAddresses != "192.168.1.10, fe80::1" {
		t.Errorf("IPAddresses = %q", data.IPAddresses)
	}
	if data.MACAddresses != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MACAddresses = %q", data.MACAddresses)
	}
	if data.Hostname != "ws-01" || data.ProgramCount != len(samplePrograms()) {
		t.Errorf("host/counts = %q/%d", data.Hostname, data.ProgramCount)
	}
	out, err := RenderToBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"192.168.1.10", "aa:bb:cc:dd:ee:ff", ">IP<", ">MAC<"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestGenerateTo_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	path := filepath.Join(t.TempDir(), "report.html")
	data := NewReportData("linux", samplePrograms())
	if _, err := GenerateTo(path, data); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %o, want 600", info.Mode().Perm())
	}
}
