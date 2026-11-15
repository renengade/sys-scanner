//go:build !windows

package report

import (
	"os/exec"
	"runtime"
	"syscall"
)

func launchBrowser(path string) error {
	if runtime.GOOS == "darwin" {
		return launchDetached("open", path)
	}
	return launchLinux(path)
}

// launchDetached starts cmd with the given argv, detaching the child
// process so it can outlive the parent.
func launchDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// launchLinux tries the launchers in order. Each launcher that is found
// in PATH is invoked with the file URL as its argument. The first one
// that starts cleanly (cmd.Start returns nil) wins. If none of the
// candidates can be started, ErrNoLauncher is returned.
func launchLinux(path string) error {
	candidates := []string{
		"xdg-open",
		"x-www-browser",
		"gnome-open",
		"kde-open",
		"wslview",
	}
	for _, bin := range candidates {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		if err := launchDetached(bin, path); err == nil {
			return nil
		}
	}
	return ErrNoLauncher
}
