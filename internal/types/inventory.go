package types

import "time"

// SchemaVersion identifies the machine-readable inventory schema.
const SchemaVersion = "1.1"

// HostInfo identifies the endpoint that produced an inventory.
type HostInfo struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	IPAddresses  []string `json:"ip_addresses"`
	MACAddresses []string `json:"mac_addresses,omitempty"`
}

// Summary holds the headline counts for an inventory.
type Summary struct {
	ProgramCount int `json:"program_count"`
	AIToolCount  int `json:"ai_tool_count"`
}

// Inventory is the complete, machine-readable result of one endpoint scan.
// It is designed to be posted to a central asset/inventory service as-is.
type Inventory struct {
	SchemaVersion    string         `json:"schema_version"`
	ScannerVersion   string         `json:"scanner_version,omitempty"`
	GeneratedAt      time.Time      `json:"generated_at"`
	GeneratedAtLocal string         `json:"generated_at_local"`
	Host             HostInfo       `json:"host"`
	Summary          Summary        `json:"summary"`
	AITools          []string       `json:"ai_tools"`
	Programs         []Program      `json:"programs"`
	ProgramsBySource map[string]int `json:"programs_by_source"`
	ScanDurationMS   int64          `json:"scan_duration_ms"`
}
