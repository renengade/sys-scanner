//go:build windows

package report

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// windowsRootDir returns the Windows installation directory so system tools
// are launched by absolute path.
func windowsRootDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// launchBrowser dispatches to the Windows launcher.
func launchBrowser(path string) error {
	return launchWindows(path)
}

// launchWindows opens the report with the Windows default file handler via
// rundll32. This avoids cmd.exe quoting/escaping issues that previously made
// Windows report "file not found" for a generated temp path.
func launchWindows(path string) error {
	// #nosec G204 -- absolute path under %SystemRoot%; the only variable is
	// the local report path, passed as a real argument (never a shell line).
	cmd := exec.Command(filepath.Join(windowsRootDir(), "System32", "rundll32.exe"), windowsOpenArgs(path)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
