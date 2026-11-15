//go:build windows

package windows

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/registry"

	"sys-scanner/internal/types"
)

const uninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// registryView describes a single registry hive/path/access combination.
type registryView struct {
	root   registry.Key
	path   string
	access uint32
	source string
	label  string // human-readable label for logging
}

// scanRegistry scans the three standard Uninstall registry views:
//
//	HKLM\…\Uninstall  (64-bit view)
//	HKLM\…\Uninstall  (32-bit view via KEY_WOW64_32KEY)
//	HKCU\…\Uninstall
//
// Errors are logged and skipped — the scan continues with remaining views.
func scanRegistry() ([]types.Program, error) {
	views := []registryView{
		{
			root:   registry.LOCAL_MACHINE,
			path:   uninstallKeyPath,
			access: registry.READ | registry.WOW64_64KEY,
			source: "registry",
			label:  "HKLM/Uninstall (64-bit)",
		},
		{
			root:   registry.LOCAL_MACHINE,
			path:   uninstallKeyPath,
			access: registry.READ | registry.WOW64_32KEY,
			source: "registry",
			label:  "HKLM/Uninstall (32-bit)",
		},
		{
			root:   registry.CURRENT_USER,
			path:   uninstallKeyPath,
			access: registry.READ,
			source: "registry",
			label:  "HKCU/Uninstall",
		},
	}

	var all []types.Program
	for _, v := range views {
		progs, err := scanRegistryView(v)
		if err != nil {
			slog.Warn("registry view scan failed", "label", v.label, "error", err)
			continue
		}
		all = append(all, progs...)
	}
	return all, nil
}

// scanRegistryView opens a single registry view, enumerates subkeys, and
// parses each subkey's values into a types.Program.
func scanRegistryView(view registryView) ([]types.Program, error) {
	k, err := registry.OpenKey(view.root, view.path, view.access)
	if err != nil {
		return nil, fmt.Errorf("open key %s: %w", view.path, err)
	}
	defer k.Close()

	subKeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate subkeys of %s: %w", view.path, err)
	}

	programs := make([]types.Program, 0, len(subKeys))
	for _, name := range subKeys {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			slog.Debug("open subkey failed", "key", name, "error", err)
			continue
		}
		vals := readRegistryStringValues(sk)
		_ = sk.Close()

		if prog, ok := parseRegistryEntry(vals, view.source); ok {
			programs = append(programs, prog)
		}
	}
	return programs, nil
}

// readRegistryStringValues reads every named value under k. String (REG_SZ /
// REG_EXPAND_SZ) values are stored verbatim. Integer (REG_DWORD / REG_QWORD)
// values are stored as their decimal string representation. Other types are
// skipped.
func readRegistryStringValues(k registry.Key) map[string]string {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return map[string]string{}
	}

	vals := make(map[string]string, len(names))
	for _, name := range names {
		// Try string first.
		if s, _, err := k.GetStringValue(name); err == nil {
			vals[name] = s
			continue
		}
		// Fall back to integer.
		if n, _, err := k.GetIntegerValue(name); err == nil {
			vals[name] = fmt.Sprintf("%d", n)
		}
	}
	return vals
}
