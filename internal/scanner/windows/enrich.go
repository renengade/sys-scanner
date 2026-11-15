//go:build windows

package windows

import "sys-scanner/internal/types"

// enrichWithFileVersion fills in missing Version/Publisher fields by reading
// the PE version resource of the program's executable. Only the Windows build
// does this; the helper logic itself is portable (helpers.go).
func enrichWithFileVersion(programs []types.Program) []types.Program {
	for i := range programs {
		p := &programs[i]
		if !needsVersionInfo(*p) {
			continue
		}
		for _, exe := range exeCandidatePaths(*p) {
			vi, ok := queryVersionStrings(exe)
			if !ok {
				continue
			}
			applyVersionStrings(p, vi)
			break
		}
	}
	return programs
}
