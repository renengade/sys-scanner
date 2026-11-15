//go:build windows

package report

import (
	"os/exec"
	"syscall"
)

// launchBrowser dispatches to the Windows launcher.
func launchBrowser(path string) error {
	return launchWindows(path)
}

// launchWindows opens the report with the Windows default file handler via
// rundll32. This avoids cmd.exe quoting/escaping issues that previously made
// Windows report "file not found" for a generated temp path.
func launchWindows(path string) error {
	cmd := exec.Command("rundll32", windowsOpenArgs(path)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
