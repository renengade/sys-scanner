package types

import "time"

// ScanResult represents the complete result of a system scan, wrapping
// the deduplicated program list with source-level statistics.
type ScanResult struct {
	Programs       []Program      `json:"programs"`
	CountBySource  map[string]int `json:"count_by_source"`
	ErrorsBySource map[string]int `json:"errors_by_source"`
	ScanDuration   time.Duration  `json:"scan_duration"`
}

// NewScanResult creates a ScanResult with initialized maps.
func NewScanResult() *ScanResult {
	return &ScanResult{
		Programs:       []Program{},
		CountBySource:  make(map[string]int),
		ErrorsBySource: make(map[string]int),
	}
}
