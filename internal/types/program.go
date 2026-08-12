// Package types defines shared data structures for sys-scanner.
package types

// Program represents a single installed program detected on the system.
type Program struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Publisher       string            `json:"publisher"`
	InstallLocation string            `json:"install_location"`
	Source          string            `json:"source"`
	IsAITool        string            `json:"is_ai_tool"`
	AIToolName      string            `json:"ai_tool_name"`
	RawMetadata     map[string]string `json:"raw_metadata,omitempty"`
}
