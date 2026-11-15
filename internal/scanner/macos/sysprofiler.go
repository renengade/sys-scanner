//go:build darwin

package macos

import (
	"context"
	"log"
	"os/exec"
	"time"

	"howett.net/plist"

	"sys-scanner/internal/types"
)

const sysProfilerTimeout = 60 * time.Second

// sysProfilerEntry represents a single application entry from
// system_profiler SPApplicationsDataType -xml output.
type sysProfilerEntry struct {
	Name         string `plist:"_name"`
	Version      string `plist:"version"`
	Path         string `plist:"path"`
	ObtainedFrom string `plist:"obtained_from"`
}

// scanSysProfiler runs system_profiler SPApplicationsDataType -xml and parses
// the XML plist output into programs. Returns nil on timeout or error.
func scanSysProfiler() ([]types.Program, error) {
	spPath, err := exec.LookPath("system_profiler")
	if err != nil {
		return nil, nil // not macOS or tool missing
	}

	ctx, cancel := context.WithTimeout(context.Background(), sysProfilerTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, spPath, "SPApplicationsDataType", "-xml")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("macos: system_profiler failed: %v", err)
		return nil, nil // skip on error (including timeout)
	}

	return parseSysProfilerOutput(out)
}

// parseSysProfilerOutput parses the XML plist from system_profiler into
// programs. The top-level structure is an array containing a single dict
// with a "_items" key holding an array of application entries.
func parseSysProfilerOutput(data []byte) ([]types.Program, error) {
	var root []map[string]any
	if _, err := plist.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	var programs []types.Program
	for _, item := range root {
		items, ok := item["_items"].([]any)
		if !ok {
			continue
		}
		for _, raw := range items {
			entry, ok := raw.(map[any]any)
			if !ok {
				// Try string-keyed map (howett.net/plist decodes dict keys as strings).
				if sm, ok2 := raw.(map[string]any); ok2 {
					p := entryToProgram(sm)
					if p.Name != "" {
						programs = append(programs, p)
					}
				}
				continue
			}
			// Convert map[any]any → map[string]any
			sm := make(map[string]any, len(entry))
			for k, v := range entry {
				if ks, ok := k.(string); ok {
					sm[ks] = v
				}
			}
			p := entryToProgram(sm)
			if p.Name != "" {
				programs = append(programs, p)
			}
		}
	}
	return programs, nil
}

// entryToProgram converts a system_profiler entry dict to a Program.
func entryToProgram(e map[string]any) types.Program {
	name, _ := e["_name"].(string)
	version, _ := e["version"].(string)
	path, _ := e["path"].(string)
	obtained, _ := e["obtained_from"].(string)

	meta := make(map[string]string)
	if obtained != "" {
		meta["obtained_from"] = obtained
	}

	return types.Program{
		Name:            name,
		Version:         version,
		InstallLocation: path,
		Source:          "system_profiler",
		RawMetadata:     meta,
	}
}
