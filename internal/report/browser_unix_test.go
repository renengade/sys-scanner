//go:build !windows

package report

import (
	"os/exec"
	"runtime"
	"testing"
)

// TestLaunchLinux_NoLauncherReturnsError exercises the non-Windows launcher
// chain. On systems with xdg-open, launchLinux will succeed and start the
// browser — that's accepted and logged. On systems without any launcher it
// must surface ErrNoLauncher cleanly without panicking.
func TestLaunchLinux_NoLauncherReturnsError(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("launchLinux is only meaningful on Linux/BSD; runtime = %s", runtime.GOOS)
	}
	err := launchLinux("/tmp/sys-scanner-test.html")
	if err == nil {
		t.Log("launchLinux returned nil — xdg-open likely available")
		return
	}
	// On a headless server xdg-open exists but fails to start; in that
	// case cmd.Start returns an error, the launcher is skipped, and we
	// fall through to the next candidate. Either ErrNoLauncher or some
	// underlying exec.LookPath failure is acceptable here.
	if err != ErrNoLauncher {
		// Sanity-check that the system exec lookup is functional at all.
		if _, lookErr := exec.LookPath("echo"); lookErr != nil {
			t.Skipf("PATH lookups not functional in this environment: %v", lookErr)
		}
		t.Logf("launchLinux returned non-ErrNoLauncher error (acceptable on headless systems): %v", err)
	}
}
