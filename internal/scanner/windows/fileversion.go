//go:build windows

package windows

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"sys-scanner/internal/types"
)

// versionStrings holds the PE version-resource fields used to fill in missing
// inventory data.
type versionStrings struct {
	FileVersion    string
	ProductVersion string
	ProductName    string
	CompanyName    string
}

// needsVersionInfo reports whether a program is missing version or publisher
// data that a PE version resource could provide.
func needsVersionInfo(p types.Program) bool {
	return strings.TrimSpace(p.Version) == "" || strings.TrimSpace(p.Publisher) == ""
}

// displayIconToExe converts an Uninstall registry DisplayIcon value into an
// executable path. Icons come in forms like `"C:\app\app.exe,0"`, and may
// point at .ico files, in which case "" is returned.
func displayIconToExe(icon string) string {
	icon = strings.TrimSpace(icon)
	icon = strings.Trim(icon, `"`)
	if i := strings.IndexByte(icon, ','); i >= 0 {
		icon = strings.TrimSpace(icon[:i])
	}
	if icon == "" {
		return ""
	}
	ext := strings.ToLower(filepath.Ext(icon))
	switch ext {
	case ".exe", ".com":
		return icon
	case "":
		return icon + ".exe"
	default:
		return ""
	}
}

// exeCandidatePaths returns plausible executable paths for a program, in the
// order they should be probed for a PE version resource.
func exeCandidatePaths(p types.Program) []string {
	var out []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		path = strings.Trim(path, `"`)
		if path == "" {
			return
		}
		if !strings.EqualFold(filepath.Ext(path), ".exe") && filepath.Ext(path) != "" {
			return
		}
		for _, existing := range out {
			if strings.EqualFold(existing, path) {
				return
			}
		}
		out = append(out, path)
	}

	if p.RawMetadata != nil {
		add(p.RawMetadata["FullPath"])
		add(displayIconToExe(p.RawMetadata["DisplayIcon"]))
	}

	loc := strings.TrimSpace(p.InstallLocation)
	if loc != "" {
		if strings.EqualFold(filepath.Ext(loc), ".exe") {
			add(loc)
		} else if base := strings.TrimSpace(p.Name); base != "" {
			add(filepath.Join(loc, base+".exe"))
		}
	}
	return out
}

// applyVersionStrings fills in missing Version/Publisher fields from a PE
// version resource. Existing values are never overwritten. Returns true when
// any field was set.
func applyVersionStrings(p *types.Program, vi versionStrings) bool {
	changed := false
	if strings.TrimSpace(p.Version) == "" {
		v := vi.FileVersion
		if v == "" {
			v = vi.ProductVersion
		}
		if v != "" {
			p.Version = v
			changed = true
		}
	}
	if strings.TrimSpace(p.Publisher) == "" && vi.CompanyName != "" {
		p.Publisher = vi.CompanyName
		changed = true
	}
	if changed {
		if p.RawMetadata == nil {
			p.RawMetadata = make(map[string]string)
		}
		p.RawMetadata["VersionInfoSource"] = "pe"
	}
	return changed
}

// versionCache avoids re-reading the same PE version resource when several
// inventory entries point at one executable.
var versionCache = struct {
	sync.Mutex
	entries map[string]versionStrings
}{entries: make(map[string]versionStrings)}

// queryVersionStrings reads the PE version resource of an executable and
// extracts the fields used to complete the inventory. Returns ok=false when
// the file has no usable version resource.
//
// #nosec G103 -- version.dll returns pointers into a buffer owned by this
// function; all reads are within the size reported by GetFileVersionInfoSize.
func queryVersionStrings(path string) (versionStrings, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return versionStrings{}, false
	}

	versionCache.Lock()
	if vi, ok := versionCache.entries[path]; ok {
		versionCache.Unlock()
		return vi, true
	}
	versionCache.Unlock()

	vi, ok := readVersionResource(path)
	if ok {
		versionCache.Lock()
		versionCache.entries[path] = vi
		versionCache.Unlock()
	}
	return vi, ok
}

func readVersionResource(path string) (versionStrings, bool) {
	var zero windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &zero)
	if err != nil || size == 0 {
		return versionStrings{}, false
	}

	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil { // #nosec G103 -- version.dll returns pointers into this function's own buffer
		return versionStrings{}, false
	}

	lang, codepage, ok := firstTranslation(buf)
	if !ok {
		return versionStrings{}, false
	}

	get := func(key string) string {
		return queryString(buf, lang, codepage, key)
	}

	vi := versionStrings{
		FileVersion:    get("FileVersion"),
		ProductVersion: get("ProductVersion"),
		ProductName:    get("ProductName"),
		CompanyName:    get("CompanyName"),
	}
	if vi.FileVersion == "" && vi.ProductVersion == "" && vi.CompanyName == "" {
		return versionStrings{}, false
	}
	return vi, true
}

// firstTranslation reads \VarFileInfo\Translation to obtain the language and
// code page of the StringFileInfo block.
func firstTranslation(buf []byte) (uint16, uint16, bool) {
	var ptr unsafe.Pointer // #nosec G103 -- version.dll returns pointers into this function's own buffer
	var length uint32
	sub := `\VarFileInfo\Translation`
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&ptr), &length); err != nil || ptr == nil || length < 4 { // #nosec G103 -- version.dll returns pointers into this function's own buffer
		return 0, 0, false
	}
	words := (*[2]uint16)(unsafe.Pointer(ptr)) // #nosec G103 -- version.dll returns pointers into this function's own buffer
	return words[0], words[1], true
}

// queryString reads one string from \StringFileInfo\<lang><codepage>\<key>.
func queryString(buf []byte, lang, codepage uint16, key string) string {
	sub := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lang, codepage, key)
	var ptr unsafe.Pointer // #nosec G103 -- version.dll returns pointers into this function's own buffer
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), sub, unsafe.Pointer(&ptr), &length); err != nil || ptr == nil || length == 0 { // #nosec G103 -- version.dll returns pointers into this function's own buffer
		return ""
	}
	// VerQueryValue reports the length in characters for string blocks
	// (including the NUL); walk to the terminator instead of trusting either
	// interpretation of `length`.
	out := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr))) // #nosec G103 -- pointer into this function's own buffer
	return strings.TrimSpace(out)
}
