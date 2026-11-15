// Package merge provides deduplication and merging of scan results.
package merge

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sys-scanner/internal/types"
)

// DedupKey is the composite key used for two-pass deduplication.
// After Pass 1 (group by name), Pass 2 splits entries that share a
// normalized name but have different non-empty normalized publishers.
type DedupKey struct {
	Name      string
	Publisher string
}

// sourcePriority maps source identifiers to their priority level.
// Higher value = higher priority (preferred over lower).
var sourcePriority = map[string]int{
	"registry":        10,
	"system_profiler": 9,
	"wsl":             9,
	"package_manager": 8,
	"homebrew":        8,
	"homebrew-cask":   8,
	"store":           7,
	"app_bundle":      6,
	"apppaths":        5,
	".desktop":        4,
	"opt":             3,
	".lnk":            2,
	"PATH":            1,
}

var (
	// versionSuffixRe strips trailing version strings like "v1.2.3", "1.2",
	// "v2.0.1 beta", and "version 2.38.1 (x64)". The required dot keeps it
	// from matching bare-digit arch qualifiers such as "(x64)" or "(64-bit)".
	versionSuffixRe = regexp.MustCompile(`\s*(?:version\s+)?v?\d+\.\d+.*$`)
	// qualifierRe strips architecture qualifiers like "(x64)", "(x86)", "(64-bit)"
	qualifierRe = regexp.MustCompile(`\s*\((x\d+|64-bit)\)`)
)

// NormalizeName lowercases the name, strips version suffixes and
// architecture qualifiers, and trims whitespace.
func NormalizeName(name string) string {
	s := strings.ToLower(name)
	s = versionSuffixRe.ReplaceAllString(s, "")
	s = qualifierRe.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// NormalizePublisher lowercases and trims the publisher name.
func NormalizePublisher(publisher string) string {
	return strings.TrimSpace(strings.ToLower(publisher))
}

// getSourcePriority returns the priority for a given source string.
// Unknown sources get priority 0.
func getSourcePriority(source string) int {
	if p, ok := sourcePriority[source]; ok {
		return p
	}
	return 0
}

// parseNumericVersion splits a version string into numeric components.
// It returns ok=false when the version has no leading numeric segment.
func parseNumericVersion(v string) ([]int, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil, false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	var nums []int
	for _, f := range strings.Split(s, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			if len(nums) == 0 {
				return nil, false
			}
			break
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return nil, false
	}
	return nums, true
}

// compareVersions compares two version strings numerically by their
// major.minor.patch components, falling back to string length when either
// side cannot be parsed. Returns -1, 0, or 1 for a < b, a == b, a > b.
func compareVersions(a, b string) int {
	na, okA := parseNumericVersion(a)
	nb, okB := parseNumericVersion(b)
	if okA && okB {
		n := len(na)
		if len(nb) < n {
			n = len(nb)
		}
		for i := 0; i < n; i++ {
			if na[i] != nb[i] {
				if na[i] < nb[i] {
					return -1
				}
				return 1
			}
		}
		if len(na) != len(nb) {
			if len(na) > len(nb) {
				return 1
			}
			return -1
		}
		return 0
	}
	if len(a) != len(b) {
		if len(a) > len(b) {
			return 1
		}
		return -1
	}
	return 0
}

// isPlaceholderPublisher reports whether a publisher carries no real
// organization information: it is either empty or merely echoes its own
// source (e.g. "PATH Pub" for source "PATH").
func isPlaceholderPublisher(publisher, source string) bool {
	np := NormalizePublisher(publisher)
	if np == "" {
		return true
	}
	ns := strings.ToLower(strings.TrimSpace(source))
	if ns == "" {
		return false
	}
	return strings.Contains(np, ns) || strings.Contains(ns, np)
}

// sameOrganization reports whether two normalized publishers refer to the
// same organization (identical, or one is a substring of the other).
func sameOrganization(a, b string) bool {
	if a == b {
		return true
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

// mergeEntry selects the best Program from a slice of candidates.
// Priority: source priority > non-empty publisher > higher version.
// The returned Program is a copy with metadata merged from all candidates:
// empty fields are filled from lower-priority entries.
func mergeEntry(candidates []types.Program) types.Program {
	if len(candidates) == 0 {
		return types.Program{}
	}

	// Sort candidates by priority (desc), then non-empty publisher (desc), then higher version (desc)
	sorted := make([]types.Program, len(candidates))
	copy(sorted, candidates)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, pj := getSourcePriority(sorted[i].Source), getSourcePriority(sorted[j].Source)
		if pi != pj {
			return pi > pj // higher source priority first
		}
		// prefer non-empty publisher
		if (sorted[i].Publisher == "") != (sorted[j].Publisher == "") {
			return sorted[i].Publisher != ""
		}
		// prefer higher version (numeric comparison)
		return compareVersions(sorted[i].Version, sorted[j].Version) > 0
	})

	best := sorted[0]

	// Merge metadata: fill empty fields from lower-priority entries
	for _, c := range sorted[1:] {
		if best.Name == "" && c.Name != "" {
			best.Name = c.Name
		}
		if best.Version == "" && c.Version != "" {
			best.Version = c.Version
		}
		if best.Publisher == "" && c.Publisher != "" {
			best.Publisher = c.Publisher
		}
		if best.InstallLocation == "" && c.InstallLocation != "" {
			best.InstallLocation = c.InstallLocation
		}
		if best.AIToolName == "" && c.AIToolName != "" {
			best.AIToolName = c.AIToolName
		}
		if !best.IsAITool && c.IsAITool {
			best.IsAITool = true
		}
		// Merge RawMetadata: add keys not already present
		if len(c.RawMetadata) > 0 {
			if best.RawMetadata == nil {
				best.RawMetadata = make(map[string]string)
			}
			for k, v := range c.RawMetadata {
				if _, exists := best.RawMetadata[k]; !exists {
					best.RawMetadata[k] = v
				}
			}
		}
	}

	return best
}

// Deduplicate performs two-pass deduplication on a slice of programs:
//
// Pass 1: Group by normalized name. Within each group, select the best
// entry and merge metadata from all candidates.
//
// Pass 2: For groups where candidates have different non-empty normalized
// publishers, split into separate entries per publisher. The final dedup
// key is DedupKey{NormalizedName, NormalizedPublisher}.
//
// The returned slice is sorted by Name ascending (case-insensitive),
// then Version descending.
func Deduplicate(programs []types.Program) []types.Program {
	if len(programs) == 0 {
		return []types.Program{}
	}

	// --- Pass 1: group by normalized name ---
	nameGroups := make(map[string][]types.Program)
	for _, p := range programs {
		key := NormalizeName(p.Name)
		nameGroups[key] = append(nameGroups[key], p)
	}

	var result []types.Program

	for _, group := range nameGroups {
		// Collect the distinct "real" organizations in the group, treating
		// placeholder publishers (empty or source echoes) as no information
		// and collapsing substring-related publishers into one organization.
		orgOf := make(map[string]string)
		var reps []string
		for _, p := range group {
			np := NormalizePublisher(p.Publisher)
			if np == "" || isPlaceholderPublisher(p.Publisher, p.Source) {
				continue
			}
			if _, ok := orgOf[np]; ok {
				continue
			}
			rep := np
			for _, r := range reps {
				if sameOrganization(r, np) {
					rep = r
					break
				}
			}
			orgOf[np] = rep
			if rep == np {
				reps = append(reps, rep)
			}
		}

		if len(reps) <= 1 {
			// Single organization (or none): merge into one entry.
			result = append(result, mergeEntry(group))
		} else {
			// --- Pass 2: split by distinct organizations ---
			// Real publishers group under their organization representative;
			// placeholder/empty publishers form their own group.
			pubGroups := make(map[string][]types.Program)
			for _, p := range group {
				np := NormalizePublisher(p.Publisher)
				key := ""
				if np != "" && !isPlaceholderPublisher(p.Publisher, p.Source) {
					key = orgOf[np]
				}
				pubGroups[key] = append(pubGroups[key], p)
			}
			for _, subGroup := range pubGroups {
				result = append(result, mergeEntry(subGroup))
			}
		}
	}

	// Sort: Name ascending (case-insensitive), then Version descending
	sort.SliceStable(result, func(i, j int) bool {
		ni, nj := strings.ToLower(result[i].Name), strings.ToLower(result[j].Name)
		if ni != nj {
			return ni < nj
		}
		// Version descending (numeric comparison)
		return compareVersions(result[i].Version, result[j].Version) > 0
	})

	return result
}

// ProgramSorter implements sort.Interface for []types.Program.
// Sorts by Name ascending (case-insensitive), then Version descending.
type ProgramSorter []types.Program

func (s ProgramSorter) Len() int      { return len(s) }
func (s ProgramSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s ProgramSorter) Less(i, j int) bool {
	ni, nj := strings.ToLower(s[i].Name), strings.ToLower(s[j].Name)
	if ni != nj {
		return ni < nj
	}
	return compareVersions(s[i].Version, s[j].Version) > 0
}
