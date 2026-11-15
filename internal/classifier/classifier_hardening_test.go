package classifier

import (
	"net"
	"os"
	"testing"
	"time"

	"sys-scanner/internal/signatures"
)

func TestClassify_PortOnlySignalDoesNotSynthesizeTool(t *testing.T) {
	origLookPath := lookPath
	origProcesses := processLister
	origDial := dialPort
	defer func() {
		lookPath = origLookPath
		processLister = origProcesses
		dialPort = origDial
	}()

	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	processLister = func() (string, error) { return "", nil }
	dialPort = func(_, address string, _ time.Duration) (net.Conn, error) {
		if address == "127.0.0.1:8080" {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		}
		return nil, os.ErrNotExist
	}

	home := t.TempDir()
	result := classifyWithHome(nil, home)
	for _, p := range result {
		if p.AIToolName == "localai" {
			t.Fatalf("LocalAI must not be reported from port 8080 alone: %+v", p)
		}
	}
}

func TestHasProcessIn_LineAnchored(t *testing.T) {
	tool := signatures.SigHermes
	if hasProcessIn(tool, "hermes-agent\n") {
		t.Error("substring-only process match must not count as Hermes")
	}
	if !hasProcessIn(tool, "hermes\n") {
		t.Error("exact process name should match")
	}
	if !hasProcessIn(tool, `"hermes.exe","1234","Console","1","10,000 K"`+"\n") {
		t.Error("tasklist-style quoted image name should match")
	}
}

func TestProcessLineMatches_LMStudio(t *testing.T) {
	line := `"lm studio.exe","4242","Console","1","120,000 K"`
	if !processLineMatches(line, "LM Studio") {
		t.Error("LM Studio should match its tasklist image name")
	}
	if processLineMatches(`"not-lm studio.exe","1"`, "LM Studio") {
		t.Error("different image name must not match")
	}
}

func TestComputeSystemSignals_ProcessListFetchedOnce(t *testing.T) {
	origLookPath := lookPath
	origProcesses := processLister
	origDial := dialPort
	defer func() {
		lookPath = origLookPath
		processLister = origProcesses
		dialPort = origDial
	}()

	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	dialPort = func(_, _ string, _ time.Duration) (net.Conn, error) { return nil, os.ErrNotExist }

	calls := 0
	processLister = func() (string, error) {
		calls++
		return "hermes\n", nil
	}

	sigs := computeSystemSignals(signatures.All(), t.TempDir())
	if calls != 1 {
		t.Errorf("processLister called %d times, want 1", calls)
	}
	if !sigs.processMatches["hermes"] {
		t.Error("hermes process should be detected from the shared process list")
	}
}
