// Package inventory assembles a complete endpoint inventory from scan results.
package inventory

import (
	"sort"
	"time"

	"sys-scanner/internal/hostinfo"
	"sys-scanner/internal/types"
)

// Build creates an Inventory from the classified program list. programs may be
// nil; it is normalized to a non-nil slice so JSON always contains an array.
func Build(programs []types.Program, duration time.Duration) types.Inventory {
	return BuildWithVersion(programs, duration, "")
}

// BuildWithVersion is Build with the scanner version stamped into the output,
// so a central inventory service can tell which collector version produced a
// record.
func BuildWithVersion(programs []types.Program, duration time.Duration, scannerVersion string) types.Inventory {
	return BuildWithHost(programs, duration, scannerVersion, hostinfo.Collect())
}

// BuildWithHost is BuildWithVersion with an explicit host identity, which
// keeps tests deterministic.
func BuildWithHost(programs []types.Program, duration time.Duration, scannerVersion string, host types.HostInfo) types.Inventory {
	if programs == nil {
		programs = []types.Program{}
	}
	now := time.Now()

	inv := types.Inventory{
		SchemaVersion:    types.SchemaVersion,
		ScannerVersion:   scannerVersion,
		GeneratedAt:      now.UTC(),
		GeneratedAtLocal: now.Format("2006-01-02 15:04:05 MST"),
		Host:             host,
		Programs:         programs,
		AITools:          AITools(programs),
		ProgramsBySource: countProgramSources(programs),
		ScanDurationMS:   duration.Milliseconds(),
	}
	inv.Summary = types.Summary{
		ProgramCount: len(programs),
		AIToolCount:  len(inv.AITools),
	}
	return inv
}

// AITools returns the sorted, deduplicated AI tool names present in programs.
func AITools(programs []types.Program) []string {
	seen := make(map[string]struct{})
	var tools []string
	for _, p := range programs {
		if !p.IsAITool || p.AIToolName == "" {
			continue
		}
		if _, ok := seen[p.AIToolName]; ok {
			continue
		}
		seen[p.AIToolName] = struct{}{}
		tools = append(tools, p.AIToolName)
	}
	sort.Strings(tools)
	if tools == nil {
		return []string{}
	}
	return tools
}

func countProgramSources(programs []types.Program) map[string]int {
	counts := make(map[string]int)
	for _, p := range programs {
		if p.Source != "" {
			counts[p.Source]++
		}
	}
	return counts
}
