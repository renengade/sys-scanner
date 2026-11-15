// Package classifier provides AI tool classification by matching installed
// programs against the 23-tool signature database using 5 signal types.
package classifier

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"sys-scanner/internal/platform"
	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

// systemSignals holds pre-computed signal match results so they are computed
// only once per classify call, not once per program.
type systemSignals struct {
	configMatches    map[string]bool     // tool name -> has a config dir present
	extensionMatches map[string]bool     // tool name -> has a VS Code extension installed
	processMatches   map[string]bool     // tool name -> has a matching running process
	portMatches      map[string]bool     // tool name -> has a matching listening port
	pathCache        map[string]bool     // binary name -> found on PATH (computed once)
	processOutput    string              // process list, fetched once
	extensionDirs    map[string][]string // extension dir -> entry names, read once
}

// Classify enriches a slice of programs with AI tool detection annotations.
//
// A program is classified as an AI tool only when its install location or
// name matches one of a tool's binary names. System-level signals (config
// directories, VS Code extensions, running processes, listening ports) are
// global facts about the machine, not about any single program, so tools
// detected only by those signals are appended as synthetic program entries
// rather than marking arbitrary programs.
//
// The input slice is not mutated; a new slice is returned.
func Classify(programs []types.Program) []types.Program {
	homeDir, err := platform.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	return classifyWithHome(programs, homeDir)
}

// classifyWithHome is the internal implementation that accepts an explicit
// home directory so tests can point it at t.TempDir().
func classifyWithHome(programs []types.Program, homeDir string) []types.Program {
	tools := signatures.All()
	// Sort tools so those with binary names come first (alphabetically within
	// each group). This ensures programs are preferentially matched by their
	// install location rather than by ambient system-level signals.
	sortTools(tools)
	sigs := computeSystemSignals(tools, homeDir)

	result := make([]types.Program, len(programs))
	binaryMatched := make(map[string]bool, len(tools))
	for i := range programs {
		result[i] = classifyOne(programs[i], tools, sigs)
		if result[i].IsAITool {
			binaryMatched[result[i].AIToolName] = true
		}
	}

	// Synthesis pass: config dir, extension, process and port signals are
	// global facts about the system, not about any single program. Tools that
	// are detected only by those signals (for example GUI apps installed off
	// PATH, like Cursor under %LOCALAPPDATA%) would otherwise never appear.
	// Append a synthetic program entry for each such tool so it shows up in
	// the report without falsely marking an arbitrary real program.
	for _, tool := range tools {
		if binaryMatched[tool.Name] {
			continue
		}
		n := systemSignalCount(tool, sigs)
		if n == 0 {
			continue
		}
		// A listening port alone is too weak a signal to claim a tool is
		// installed. Port 8080 in particular is used by countless unrelated
		// local servers, which previously produced false LocalAI findings.
		// Require at least one identity-bearing signal (config dir, extension
		// or process) before synthesizing an entry.
		if n == 1 && sigs.portMatches[tool.Name] {
			continue
		}
		result = append(result, types.Program{
			Name:       tool.DisplayName,
			IsAITool:   true,
			AIToolName: tool.Name,
			Source:     "ai-signal",
			RawMetadata: map[string]string{
				"ai_confidence": confidenceLabel(n),
			},
		})
	}

	return result
}

// sortTools orders tool signatures so tools with binary names precede tools
// without. Within each group, tools are sorted alphabetically by name.
func sortTools(tools []types.ToolSignature) {
	sort.Slice(tools, func(i, j int) bool {
		hasBinI := len(tools[i].BinaryNames) > 0
		hasBinJ := len(tools[j].BinaryNames) > 0
		if hasBinI != hasBinJ {
			return hasBinI // binary-name tools first
		}
		return tools[i].Name < tools[j].Name
	})
}

// computeSystemSignals evaluates the four system-level signal types (config
// directories, VS Code extensions, running processes, listening ports) once
// for all tools and pre-computes a PATH lookup cache for all binary names.
func computeSystemSignals(tools []types.ToolSignature, homeDir string) systemSignals {
	sigs := systemSignals{
		configMatches:    make(map[string]bool, len(tools)),
		extensionMatches: make(map[string]bool, len(tools)),
		processMatches:   make(map[string]bool, len(tools)),
		portMatches:      make(map[string]bool, len(tools)),
		pathCache:        make(map[string]bool),
		extensionDirs:    make(map[string][]string),
	}

	// Fetch the process list once, not once per tool. Enumerating processes
	// is the most expensive signal on Windows (tasklist), so this is the
	// difference between ~20 subprocess launches and one.
	needsProcesses := false
	for _, tool := range tools {
		if len(tool.ProcessNames) > 0 {
			needsProcesses = true
			break
		}
	}
	if needsProcesses {
		if out, err := processLister(); err == nil {
			sigs.processOutput = out
		}
	}

	// Read VS Code-family extension directories once.
	if homeDir != "" {
		for _, rel := range knownExtensionDirs {
			entries, err := os.ReadDir(filepath.Join(homeDir, rel))
			if err != nil {
				continue
			}
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				if entry.IsDir() {
					names = append(names, entry.Name())
				}
			}
			sigs.extensionDirs[rel] = names
		}
	}

	for _, tool := range tools {
		sigs.configMatches[tool.Name] = hasConfigDir(tool, homeDir)
		sigs.extensionMatches[tool.Name] = hasExtensionIn(tool, sigs.extensionDirs)
		sigs.processMatches[tool.Name] = hasProcessIn(tool, sigs.processOutput)
		sigs.portMatches[tool.Name] = hasPort(tool)

		for _, name := range tool.BinaryNames {
			if _, seen := sigs.pathCache[name]; !seen {
				_, err := lookPath(name)
				sigs.pathCache[name] = err == nil
			}
		}
	}

	// Claude Code's ~/.claude config dir is too weak a signal on its own: a
	// bare directory containing only transcripts/ (residue from another tool
	// or a past session) must not count as installed.
	sigs.configMatches["claude-code"] = claudeCodeActuallyInstalled(homeDir)

	return sigs
}

// classifyOne checks a single program against every tool signature using only
// the binary signal, which is the only per-program identity signal. System
// signals (config dir, extension, process, port) only raise confidence; they
// never trigger detection on their own, because they describe the machine as
// a whole rather than the program being classified. The first match wins.
func classifyOne(prog types.Program, tools []types.ToolSignature, sigs systemSignals) types.Program {
	for _, tool := range tools {
		if !binaryMatches(prog, tool, sigs.pathCache) {
			continue
		}
		n := 1 + systemSignalCount(tool, sigs)
		prog.IsAITool = true
		prog.AIToolName = tool.Name
		if prog.RawMetadata == nil {
			prog.RawMetadata = make(map[string]string)
		}
		prog.RawMetadata["ai_confidence"] = confidenceLabel(n)
		return prog
	}
	return prog
}

// systemSignalCount returns how many system-level signals (config directory,
// VS Code extension, running process, listening port) match the given tool.
func systemSignalCount(tool types.ToolSignature, sigs systemSignals) int {
	n := 0
	if sigs.configMatches[tool.Name] {
		n++
	}
	if sigs.extensionMatches[tool.Name] {
		n++
	}
	if sigs.processMatches[tool.Name] {
		n++
	}
	if sigs.portMatches[tool.Name] {
		n++
	}
	return n
}

// confidenceLabel maps a signal count to a human-readable label.
func confidenceLabel(n int) string {
	switch {
	case n >= 3:
		return "high"
	case n >= 2:
		return "medium"
	default:
		return "low"
	}
}

// ---------------------------------------------------------------------------
// Signal 1 — Binary match
// ---------------------------------------------------------------------------

// lookPath is exec.LookPath by default. Tests replace it to control PATH
// lookup behaviour during cache pre-computation.
var lookPath = exec.LookPath

// binaryMatches returns true when prog.InstallLocation ends with one of the
// tool's BinaryNames (case-insensitive on Windows, exact otherwise) or when
// prog.Name equals a binary name that was found on PATH during pre-computation.
func binaryMatches(prog types.Program, tool types.ToolSignature, pathCache map[string]bool) bool {
	if len(tool.BinaryNames) == 0 {
		return false
	}

	if prog.InstallLocation != "" {
		for _, name := range tool.BinaryNames {
			if pathEndsWith(prog.InstallLocation, name) {
				return true
			}
		}
	}

	for _, name := range tool.BinaryNames {
		if prog.Name == name && pathCache[name] {
			return true
		}
	}

	return false
}

// pathEndsWith returns true when the final path component of p equals name.
// On Windows the comparison is case-insensitive; on all other platforms it is
// exact.
func pathEndsWith(p, name string) bool {
	base := filepath.Base(p)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(base, name)
	}
	return base == name
}

// ---------------------------------------------------------------------------
// Signal 2 — Config directory match
// ---------------------------------------------------------------------------

// hasConfigDir returns true when at least one of the tool's ConfigDirs for
// the current OS exists on disk after expanding ~ and %VAR% tokens.
func hasConfigDir(tool types.ToolSignature, homeDir string) bool {
	if len(tool.ConfigDirs) == 0 {
		return false
	}

	osKey := runtime.GOOS
	dirs, ok := tool.ConfigDirs[osKey]
	if !ok {
		return false
	}

	for _, dir := range dirs {
		expanded := expandUserPath(dir, homeDir)
		if _, err := os.Stat(expanded); err == nil {
			return true
		}
	}
	return false
}

// expandUserPath replaces a leading ~ with homeDir and expands %VAR%-style
// environment variable references via os.ExpandEnv.
func expandUserPath(p, homeDir string) string {
	if homeDir != "" {
		if p == "~" {
			return homeDir
		}
		if strings.HasPrefix(p, "~/") {
			p = filepath.Join(homeDir, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

// claudeCodeActuallyInstalled applies stricter validation for Claude Code.
// A bare ~/.claude/ directory (for example one containing only a transcripts/
// subdirectory left behind by another tool or a past session) must not count
// as installed. At least one real installation signal is required:
// ~/.claude.json, ~/.claude/settings.json, or a non-empty ~/.claude/commands/
// directory.
func claudeCodeActuallyInstalled(homeDir string) bool {
	if homeDir == "" {
		return false
	}
	if pathExists(filepath.Join(homeDir, ".claude.json")) {
		return true
	}
	if pathExists(filepath.Join(homeDir, ".claude", "settings.json")) {
		return true
	}
	return dirHasEntries(filepath.Join(homeDir, ".claude", "commands"))
}

// pathExists reports whether path exists on disk (following symlinks).
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirHasEntries reports whether dir exists and contains at least one entry.
func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// ---------------------------------------------------------------------------
// Signal 3 — VS Code extension match
// ---------------------------------------------------------------------------

// knownExtensionDirs lists the VS Code-family extension directories relative
// to the user's home directory.
var knownExtensionDirs = []string{
	".vscode/extensions",
	".vscode-oss/extensions",
	".cursor/extensions",
}

// hasExtension returns true when a directory matching
// "<extensionID>-<version>" exists in any known VS Code-family extensions
// directory. It reads the directories on each call and is kept for tests;
// production callers use hasExtensionIn with pre-read entries.
func hasExtension(tool types.ToolSignature, homeDir string) bool {
	if len(tool.ExtensionIDs) == 0 || homeDir == "" {
		return false
	}
	entriesByDir := make(map[string][]string, len(knownExtensionDirs))
	for _, rel := range knownExtensionDirs {
		entries, err := os.ReadDir(filepath.Join(homeDir, rel))
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				names = append(names, entry.Name())
			}
		}
		entriesByDir[rel] = names
	}
	return hasExtensionIn(tool, entriesByDir)
}

// hasExtensionIn checks pre-read extension directory entries for a match.
func hasExtensionIn(tool types.ToolSignature, entriesByDir map[string][]string) bool {
	if len(tool.ExtensionIDs) == 0 {
		return false
	}

	for _, names := range entriesByDir {
		for _, dirName := range names {
			for _, extID := range tool.ExtensionIDs {
				prefix := extID + "-"
				if !strings.HasPrefix(dirName, prefix) {
					continue
				}
				// The character immediately after the prefix must be a
				// digit (start of a version). This avoids false
				// positives where a different extension shares the
				// same publisher.name prefix (e.g. github.copilot
				// vs github.copilot-chat).
				rest := dirName[len(prefix):]
				if len(rest) > 0 && unicode.IsDigit(rune(rest[0])) {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Signal 4 — Running process match
// ---------------------------------------------------------------------------

// processTimeout is the maximum time to wait for process enumeration.
const processTimeout = 5 * time.Second

// hasProcess returns true when any of the tool's ProcessNames appears in the
// system process list. It enumerates processes on each call and is kept for
// tests; production callers use hasProcessIn with one shared process list.
func hasProcess(tool types.ToolSignature) bool {
	if len(tool.ProcessNames) == 0 {
		return false
	}
	output, err := processLister()
	if err != nil {
		return false
	}
	return hasProcessIn(tool, output)
}

// hasProcessIn checks a tool's ProcessNames against a pre-fetched process
// list. Matching is line-anchored rather than a raw substring search, so a
// process named "not-hermes" no longer matches "hermes".
func hasProcessIn(tool types.ToolSignature, output string) bool {
	if len(tool.ProcessNames) == 0 || output == "" {
		return false
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		for _, name := range tool.ProcessNames {
			if processLineMatches(line, name) {
				return true
			}
		}
	}
	return false
}

// processLineMatches reports whether a process-list line names the given
// process. It handles both `ps -eo comm=` (one bare name per line) and
// `tasklist` (quoted image name followed by PID and session columns).
func processLineMatches(line, name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".exe")
	if n == "" {
		return false
	}
	return line == n ||
		strings.HasPrefix(line, n+" ") ||
		strings.HasPrefix(line, n+".exe") ||
		strings.HasPrefix(line, `"`+n+`"`) ||
		strings.HasPrefix(line, `"`+n+`.exe"`)
}

// enumerateProcesses returns the process list as a single string.
func enumerateProcesses() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tasklist")
	} else {
		cmd = exec.CommandContext(ctx, "ps", "-eo", "comm=")
	}

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// processLister returns the process list as a single string. It is a package
// variable so tests can replace it with a deterministic stub.
var processLister = enumerateProcesses

// ---------------------------------------------------------------------------
// Signal 5 — Listening port match
// ---------------------------------------------------------------------------

// portDialTimeout is the connection timeout for each port probe.
const portDialTimeout = 500 * time.Millisecond

// hasPort returns true when any of the tool's Ports accepts a TCP connection
// on localhost within the dial timeout.
func hasPort(tool types.ToolSignature) bool {
	if len(tool.Ports) == 0 {
		return false
	}

	for _, port := range tool.Ports {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := dialPort("tcp", addr, portDialTimeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// dialPort probes a TCP endpoint. It is a package variable so tests can
// replace it with a deterministic stub.
var dialPort = net.DialTimeout
