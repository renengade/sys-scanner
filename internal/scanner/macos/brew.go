//go:build darwin

package macos

import (
	"context"
	"log"
	"os/exec"
	"time"

	"sys-scanner/internal/types"
)

const brewTimeout = 30 * time.Second

// scanHomebrew runs brew list for both formulae and casks and returns detected
// programs. If brew is not found on PATH the scan is silently skipped.
func scanHomebrew() ([]types.Program, error) {
	brewPath, err := exec.LookPath("brew")
	if err != nil {
		return nil, nil // brew not installed — skip
	}

	ctx, cancel := context.WithTimeout(context.Background(), brewTimeout)
	defer cancel()

	var programs []types.Program

	// Formulae
	formulae, err := runBrewList(ctx, brewPath, "--formula")
	if err != nil {
		log.Printf("macos: brew list --formula failed: %v", err)
	} else {
		for _, p := range formulae {
			p.Source = "homebrew"
			programs = append(programs, p)
		}
	}

	// Casks
	casks, err := runBrewList(ctx, brewPath, "--cask")
	if err != nil {
		log.Printf("macos: brew list --cask failed: %v", err)
	} else {
		for _, p := range casks {
			p.Source = "homebrew-cask"
			programs = append(programs, p)
		}
	}

	return programs, nil
}

// runBrewList executes `brew list <kind> --versions` and parses the output
// into programs. Each line has the format "name version" or "name v1 v2 ..."
// (multiple installed versions). We take the last version token.
func runBrewList(ctx context.Context, brewPath, kind string) ([]types.Program, error) {
	// #nosec G204 -- brewPath comes from exec.LookPath("brew") and the
	// arguments are fixed strings.
	cmd := exec.CommandContext(ctx, brewPath, "list", kind, "--versions")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseBrewListOutput(string(out)), nil
}
