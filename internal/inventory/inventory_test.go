package inventory

import (
	"testing"
	"time"

	"sys-scanner/internal/types"
)

func TestBuild(t *testing.T) {
	programs := []types.Program{
		{Name: "OpenCode", Source: "PATH", IsAITool: true, AIToolName: "opencode"},
		{Name: "OpenCode", Source: "desktop", IsAITool: true, AIToolName: "opencode"},
		{Name: "Firefox", Source: "package_manager"},
	}

	inv := Build(programs, 1500*time.Millisecond)
	if inv.Summary.ProgramCount != 3 || inv.Summary.AIToolCount != 1 {
		t.Errorf("summary = %+v", inv.Summary)
	}
	if len(inv.AITools) != 1 || inv.AITools[0] != "opencode" {
		t.Errorf("AITools = %v, want [opencode]", inv.AITools)
	}
	if inv.ProgramsBySource["PATH"] != 1 || inv.ProgramsBySource["desktop"] != 1 {
		t.Errorf("ProgramsBySource = %v", inv.ProgramsBySource)
	}
	if inv.ScanDurationMS != 1500 {
		t.Errorf("ScanDurationMS = %d", inv.ScanDurationMS)
	}
	if inv.Host.OS == "" || inv.Host.Arch == "" {
		t.Error("host OS/arch should be populated")
	}
	if inv.SchemaVersion != types.SchemaVersion {
		t.Errorf("SchemaVersion = %q", inv.SchemaVersion)
	}
}

func TestBuild_NilProgramsBecomeEmpty(t *testing.T) {
	inv := Build(nil, 0)
	if inv.Programs == nil || inv.AITools == nil {
		t.Error("nil slices must be normalized to empty slices")
	}
	if inv.Summary.ProgramCount != 0 {
		t.Errorf("summary = %+v", inv.Summary)
	}
}

func TestBuildWithVersion(t *testing.T) {
	inv := BuildWithVersion(nil, 0, "1.2.0")
	if inv.ScannerVersion != "1.2.0" {
		t.Errorf("ScannerVersion = %q", inv.ScannerVersion)
	}
	if inv.SchemaVersion != types.SchemaVersion {
		t.Errorf("SchemaVersion = %q", inv.SchemaVersion)
	}
}

func TestBuildWithHost(t *testing.T) {
	host := types.HostInfo{
		Hostname:     "ws-01",
		OS:           "windows",
		Arch:         "amd64",
		IPAddresses:  []string{"10.0.0.5"},
		MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
	}
	inv := BuildWithHost(nil, 0, "1.2.0", host)
	if inv.Host.Hostname != "ws-01" || inv.Host.IPAddresses[0] != "10.0.0.5" {
		t.Errorf("host = %+v", inv.Host)
	}
	if inv.Host.MACAddresses[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac = %v", inv.Host.MACAddresses)
	}
}
