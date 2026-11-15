package report

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// launchTimeout is the upper bound on how long Open blocks waiting for the
// OS launcher. After this elapses, Open prints the file path so the user
// can open it manually and returns ctx.DeadlineExceeded.
const launchTimeout = 5 * time.Second

// ErrNoLauncher is returned when no platform-appropriate launcher was
// located. It typically means the user's system is missing a browser
// opener (rare on Linux without xdg-open).
var ErrNoLauncher = errors.New("report: no browser launcher found")

// Open launches the user's default browser pointed at path. The browser
// process is detached so it survives the calling program's exit. If no
// launcher is available, or the launcher does not respond within
// launchTimeout, Open prints the file path so the user can open it
// manually and returns a non-nil error.
//
// The current implementation favours xdg-open on Linux, open(1) on macOS,
// and cmd /c start on Windows. WSL users fall back to wslview.
func Open(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), launchTimeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- launchBrowser(path) }()

	select {
	case err := <-errCh:
		if err != nil {
			fmt.Printf("sys-scanner: could not open browser (%v).\n", err)
			fmt.Printf("Open this file manually: %s\n", path)
		}
		return err
	case <-ctx.Done():
		fmt.Printf("sys-scanner: browser launch timed out after %s.\n", launchTimeout)
		fmt.Printf("Open this file manually: %s\n", path)
		return fmt.Errorf("report: browser launch exceeded %s: %w", launchTimeout, ctx.Err())
	}
}
