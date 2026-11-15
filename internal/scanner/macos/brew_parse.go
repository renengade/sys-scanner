package macos

import (
	"strings"

	"sys-scanner/internal/types"
)

// parseBrewListOutput parses the output of `brew list <kind> --versions` into
// programs. Each line is "name version" (or "name v1 v2 ..." for multiple
// versions; the last version token is used).
func parseBrewListOutput(output string) []types.Program {
	var programs []types.Program
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		// Last field is the most recently installed version.
		version := fields[len(fields)-1]

		programs = append(programs, types.Program{
			Name:    name,
			Version: version,
		})
	}
	return programs
}
