package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"sys-scanner/internal/classifier"
	"sys-scanner/internal/export"
	"sys-scanner/internal/hostinfo"
	"sys-scanner/internal/inventory"
	"sys-scanner/internal/report"
	"sys-scanner/internal/scanner"
	"sys-scanner/internal/summary"
	"sys-scanner/internal/types"
)

// version is stamped into the JSON inventory and printed by -version.
// It can be overridden at build time with -ldflags "-X main.version=...".
var version = "1.2.0"

// contextDetector is an optional extension of the platform detector that can
// honour a deadline and return partial results instead of being abandoned.
type contextDetector interface {
	DetectContext(context.Context) ([]types.Program, error)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sys-scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	format := fs.String("format", "html", "output format: html, json, or csv")
	out := fs.String("out", "", "output file path, or - for stdout (default: <exe dir>/sys-scanner)")
	noOpen := fs.Bool("no-open", false, "do not open the HTML report in a browser")
	timeout := fs.Duration("timeout", 120*time.Second, "overall scan timeout")
	includeBuiltin := fs.Bool("include-builtin", false, "include Windows/Microsoft built-in components (Windows)")
	resolveLnk := fs.Bool("lnk", false, "resolve Start Menu .lnk shortcuts (Windows, slower)")
	summaryEnabled := fs.Bool("summary", true, "maintain a cumulative per-machine summary XLSX")
	summaryOut := fs.String("summary-out", "", "summary XLSX path (default: <output dir>/sys-scanner-summary.xlsx)")
	showVersion := fs.Bool("version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "sys-scanner %s — endpoint software inventory\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: sys-scanner [options]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	formatName := strings.ToLower(strings.TrimSpace(*format))
	switch formatName {
	case "html", "json", "csv":
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported -format %q (want html, json, or csv)\n", *format)
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "Error: -timeout must be positive")
		return 2
	}

	// Windows scanner options are passed through process env so the
	// platform-specific package does not need option plumbing for every
	// helper. These flags override the env defaults.
	if *includeBuiltin {
		_ = os.Setenv("SYS_SCANNER_INCLUDE_BUILTIN", "1")
	}
	if *resolveLnk {
		_ = os.Setenv("SYS_SCANNER_SCAN_LNK", "1")
	}

	// SIGINT handling: cancel the program scan.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, os.Interrupt)
	defer stop()

	goos := runtime.GOOS
	fmt.Fprintln(os.Stderr, "Scanning installed programs...")

	scanStart := time.Now()
	scanCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	detector := scanner.NewScanner()
	programs, scanErr := runDetect(scanCtx, detector)
	duration := time.Since(scanStart)

	if scanErr != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "Scan interrupted")
			return 1
		}
		fmt.Fprintf(os.Stderr, "Warning: scanner error: %v\n", scanErr)
	}
	if programs == nil {
		programs = []types.Program{}
	}

	sourceCount := countSources(programs)
	fmt.Fprintf(os.Stderr, "Found %d programs across %d sources (in %s)\n",
		len(programs), sourceCount, duration.Round(time.Millisecond))

	// Classify AI tools. A classifier panic must not prevent the inventory
	// from being produced.
	classified := programs
	var classifyErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				classifyErr = fmt.Errorf("classifier panic: %v", r)
			}
		}()
		classified = classifier.Classify(programs)
	}()
	if classifyErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: classifier error: %v; continuing without AI classification\n", classifyErr)
		classified = programs
	}

	aiTools := inventory.AITools(classified)
	if len(aiTools) > 0 {
		fmt.Fprintf(os.Stderr, "Identified %d AI tools: %s\n", len(aiTools), strings.Join(aiTools, ", "))
	} else {
		fmt.Fprintln(os.Stderr, "Identified 0 AI tools")
	}

	host := hostinfo.Collect()
	dest := resolveOutputPath(formatName, *out)

	// Maintain the cumulative machine/software summary independently of the
	// selected report format. By default it lives beside the HTML report so
	// all generated artifacts stay in one folder.
	if *summaryEnabled {
		updateSummary(*summaryOut, dest, classified, duration, host)
	}
	if dest == "-" {
		return writeToStdout(formatName, goos, host, classified, duration)
	}

	return writeToFile(formatName, dest, goos, host, classified, duration, *noOpen, *out == "")
}

// updateSummary merges this run into the cumulative machine summary. Failures
// are reported but do not block the primary report/inventory output.
func updateSummary(out, primaryDest string, programs []types.Program, duration time.Duration, host types.HostInfo) {
	path := resolveSummaryPath(out, primaryDest)
	inv := inventory.BuildWithHost(programs, duration, version, host)
	res, err := summary.Update(path, inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: summary update failed: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Summary updated: %s (%d rows; +%d added, -%d removed)\n",
		path, res.Rows, res.Added, res.Removed)
}

// resolveSummaryPath places the default summary beside the primary output so
// the HTML report and summary workbook share a folder. An explicit
// -summary-out overrides the location.
func resolveSummaryPath(out, primaryDest string) string {
	if explicit := strings.TrimSpace(out); explicit != "" {
		if info, err := os.Stat(explicit); err == nil && info.IsDir() {
			return filepath.Join(explicit, summary.DefaultFilename)
		}
		return explicit
	}
	dir := defaultOutputDir()
	if primaryDest != "" && primaryDest != "-" {
		dir = filepath.Dir(primaryDest)
	}
	return filepath.Join(dir, summary.DefaultFilename)
}

// writeToStdout renders the requested format to stdout.
func writeToStdout(formatName, goos string, host types.HostInfo, programs []types.Program, duration time.Duration) int {
	switch formatName {
	case "html":
		data := newReportData(goos, host, programs, duration)
		if err := report.Render(os.Stdout, data); err != nil {
			fmt.Fprintf(os.Stderr, "Error: report generation failed: %v\n", err)
			return 1
		}
	case "json", "csv":
		inv := inventory.BuildWithHost(programs, duration, version, host)
		if _, err := export.WriteFile(formatName, "-", inv, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
	}
	return 0
}

// writeToFile writes the inventory to dest and optionally opens the HTML
// report.
func writeToFile(formatName, dest, goos string, host types.HostInfo, programs []types.Program, duration time.Duration, noOpen, allowFallback bool) int {
	switch formatName {
	case "html":
		data := newReportData(goos, host, programs, duration)
		path, err := report.GenerateTo(dest, data)
		if err != nil && allowFallback {
			if fallback, fallbackErr := report.GenerateTo(fallbackOutputPath(formatName), data); fallbackErr == nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write next to executable (%v); saved to %s\n", err, fallback)
				path, err = fallback, nil
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: report generation failed: %v\n", err)
			fmt.Println("Scan results:")
			for _, p := range programs {
				fmt.Printf("  - %s (source: %s)\n", p.Name, p.Source)
			}
			return 1
		}
		fmt.Printf("Report saved to: %s\n", path)
		if !noOpen {
			if err := report.Open(path); err != nil {
				fmt.Fprintf(os.Stderr, "Could not open browser: %v\n", err)
			}
		}
	case "json", "csv":
		inv := inventory.BuildWithHost(programs, duration, version, host)
		path, err := export.WriteFile(formatName, dest, inv, os.Stdout)
		if err != nil && allowFallback {
			if fallback, fallbackErr := export.WriteFile(formatName, fallbackOutputPath(formatName), inv, os.Stdout); fallbackErr == nil {
				fmt.Fprintf(os.Stderr, "Warning: could not write next to executable (%v); saved to %s\n", err, fallback)
				path, err = fallback, nil
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not write %s inventory: %v\n", formatName, err)
			return 1
		}
		fmt.Printf("Inventory saved to: %s\n", path)
	}
	return 0
}

// fallbackOutputPath is used only when the default executable-adjacent
// directory is not writable (for example an installation under Program Files).
func fallbackOutputPath(formatName string) string {
	return filepath.Join(os.TempDir(), "sys-scanner", defaultFilename(formatName))
}

func newReportData(goos string, host types.HostInfo, programs []types.Program, duration time.Duration) report.ReportData {
	return report.NewReportDataWithHost(goos, host, programs, duration)
}

// resolveOutputPath picks the destination file. An explicit directory gets
// the default file name for the chosen format.
func resolveOutputPath(formatName, out string) string {
	if out == "-" {
		return "-"
	}
	if out == "" {
		return filepath.Join(defaultOutputDir(), defaultFilename(formatName))
	}
	if info, err := os.Stat(out); err == nil && info.IsDir() {
		return filepath.Join(out, defaultFilename(formatName))
	}
	if strings.HasSuffix(out, string(os.PathSeparator)) {
		return filepath.Join(out, defaultFilename(formatName))
	}
	return out
}

// defaultOutputDir is the directory next to the executable, under a
// "sys-scanner" folder. This keeps reports with the tool instead of in the
// system temp directory.
func defaultOutputDir() string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		return filepath.Join(filepath.Dir(exe), "sys-scanner")
	}
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Join(cwd, "sys-scanner")
	}
	return filepath.Join(os.TempDir(), "sys-scanner")
}

func defaultFilename(formatName string) string {
	switch formatName {
	case "json":
		return "sys-scanner-inventory.json"
	case "csv":
		return "sys-scanner-inventory.csv"
	default:
		return report.DefaultFilename
	}
}

// runDetect invokes the platform detector, using a context-aware method when
// available so partial results survive a timeout.
func runDetect(ctx context.Context, detector interface {
	Detect() ([]types.Program, error)
}) ([]types.Program, error) {
	if cd, ok := detector.(contextDetector); ok {
		return cd.DetectContext(ctx)
	}

	// Fallback for detectors that do not support context cancellation.
	type result struct {
		programs []types.Program
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		progs, err := detector.Detect()
		ch <- result{progs, err}
	}()

	select {
	case r := <-ch:
		return r.programs, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// countSources returns the number of unique Source values in the program list.
func countSources(programs []types.Program) int {
	sources := make(map[string]struct{})
	for _, p := range programs {
		if p.Source != "" {
			sources[p.Source] = struct{}{}
		}
	}
	return len(sources)
}
