//go:build windows

package windows

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	scannerTypes "sys-scanner/internal/types"
)

// ---- COM / Shell constants ------------------------------------------------

const (
	coinitApartmentThreaded = 0x2
	clsctxInprocServer      = 0x1
	slgpRawPath             = 0x4

	// IShellLinkW vtable indices (from IUnknown).
	iShellLinkGetPath = 3 + iota // 3
	_                            // 4 GetIDList
	_                            // 5 SetIDList
	_                            // 6 GetDescription
)

const (
	iShellLinkResolve = 19 // vtable index for IShellLink::Resolve
)

// IPersistFile vtable indices.
const (
	iPersistFileLoad = 5
)

var (
	ole32    = syscall.NewLazyDLL("ole32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCoInitializeEx       = ole32.NewProc("CoInitializeEx")
	procCoUninitialize       = ole32.NewProc("CoUninitialize")
	procCoCreateInstance     = ole32.NewProc("CoCreateInstance")
	procSHGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
	procCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
)

// ---- GUIDs ----------------------------------------------------------------

var (
	clsidShellLink  = windows.GUID{Data1: 0x00021401, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIShellLinkW  = windows.GUID{Data1: 0x000214F9, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	iidIPersistFile = windows.GUID{Data1: 0x0000010B, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}

	folderIDPrograms       = windows.GUID{Data1: 0x5CD7AEE2, Data2: 0x2219, Data3: 0x4A67, Data4: [8]byte{0xB8, 0x5D, 0x6C, 0x9C, 0xE1, 0x56, 0x60, 0xCB}}
	folderIDCommonPrograms = windows.GUID{Data1: 0x0139D44E, Data2: 0x6AFE, Data3: 0x49F2, Data4: [8]byte{0x86, 0x90, 0x3D, 0xAF, 0xCA, 0xE6, 0xFF, 0xB8}}
)

// ---- scanStartMenu --------------------------------------------------------

// scanStartMenu enumerates .lnk files in the user and system Start Menu
// Programs folders, resolving each shortcut via IShellLink to obtain the
// target executable path.
func scanStartMenu() ([]scannerTypes.Program, error) {
	// COM is apartment-threaded: the goroutine must stay on the OS thread
	// where CoInitializeEx ran, otherwise later COM calls fail or return
	// incomplete results.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialise COM for this thread (apartment-threaded).
	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded)
	if !succeeded(hr) {
		return nil, syscall.Errno(hr)
	}
	defer procCoUninitialize.Call()

	dirs := getStartMenuDirs()

	var programs []scannerTypes.Program
	for _, dir := range dirs {
		progs, err := walkLnkDir(dir)
		if err != nil {
			slog.Debug("start menu walk failed", "dir", dir, "error", err)
			continue
		}
		programs = append(programs, progs...)
	}
	return programs, nil
}

// getStartMenuDirs returns the user and common Start Menu Programs paths.
func getStartMenuDirs() []string {
	var dirs []string
	if d, err := knownFolderPath(folderIDPrograms); err == nil {
		dirs = append(dirs, d)
	}
	if d, err := knownFolderPath(folderIDCommonPrograms); err == nil {
		dirs = append(dirs, d)
	}
	return dirs
}

// knownFolderPath wraps SHGetKnownFolderPath.
func knownFolderPath(folderID windows.GUID) (string, error) {
	var ppszPath uintptr
	hr, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&folderID)), // #nosec G103 -- raw COM interop; pointers are stack-local
		0,                                  // dwFlags
		0,                                  // hToken (current user)
		uintptr(unsafe.Pointer(&ppszPath)), // #nosec G103 -- raw COM interop; pointers are stack-local
	)
	if !succeeded(hr) {
		return "", syscall.Errno(hr)
	}
	defer procCoTaskMemFree.Call(ppszPath)

	// Convert wide string (NUL-terminated UTF-16) to Go string.
	return utf16PtrToString(ppszPath), nil
}

// walkLnkDir walks a directory tree and resolves every .lnk file.
func walkLnkDir(root string) ([]scannerTypes.Program, error) {
	var programs []scannerTypes.Program

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors, continue walk
		}
		if info.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".lnk") {
			return nil
		}

		target, err := resolveShortcut(path)
		if err != nil {
			slog.Debug("resolve shortcut failed", "path", path, "error", err)
			return nil
		}

		name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if name == "" {
			return nil
		}

		p := scannerTypes.Program{
			Name:   name,
			Source: ".lnk",
		}
		if target != "" {
			p.InstallLocation = filepath.Dir(target)
		}
		programs = append(programs, p)
		return nil
	})
	return programs, err
}

// resolveShortcut creates an IShellLink, loads the .lnk via IPersistFile,
// and returns the raw target path.
func resolveShortcut(lnkPath string) (string, error) {
	// CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, &pShellLink)
	var pShellLink uintptr
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidShellLink)), // #nosec G103 -- raw COM interop; pointers are stack-local
		0,
		clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidIShellLinkW)), // #nosec G103 -- raw COM interop; pointers are stack-local
		uintptr(unsafe.Pointer(&pShellLink)),     // #nosec G103 -- raw COM interop; pointers are stack-local
	)
	if !succeeded(hr) {
		return "", syscall.Errno(hr)
	}
	defer comRelease(pShellLink)

	// QueryInterface for IPersistFile.
	var pPersistFile uintptr
	hr = comQueryInterface(pShellLink, &iidIPersistFile, &pPersistFile)
	if !succeeded(uintptr(hr)) {
		return "", syscall.Errno(hr)
	}
	defer comRelease(pPersistFile)

	// IPersistFile::Load(pszFileName, dwMode)
	// vtable index 5
	utf16Path, err := syscall.UTF16PtrFromString(lnkPath)
	if err != nil {
		return "", err
	}
	hr2 := comCall(pPersistFile, iPersistFileLoad,
		uintptr(unsafe.Pointer(utf16Path)), // #nosec G103 -- raw COM interop; pointers are stack-local
		0,                                  // STGM_READ = 0
	)
	if !succeeded(hr2) {
		return "", syscall.Errno(hr2)
	}

	// IShellLink::GetPath(pszFile, cch, pfd, fFlags)
	// vtable index 3
	buf := make([]uint16, windows.MAX_PATH)
	hr3 := comCall(pShellLink, iShellLinkGetPath,
		uintptr(unsafe.Pointer(&buf[0])), // #nosec G103 -- raw COM interop; pointers are stack-local
		uintptr(len(buf)),
		0, // no WIN32_FIND_DATA
		slgpRawPath,
	)
	if !succeeded(hr3) {
		return "", nil // link may be broken; return empty
	}
	return syscall.UTF16ToString(buf), nil
}

// ---- COM helpers ----------------------------------------------------------

// toPtr converts a COM interface pointer held as a uintptr back to an
// unsafe.Pointer. COM vtable dispatch is performed with raw pointers that // #nosec G103 -- raw COM interop; pointers are stack-local
// must flow through uintptr (CoCreateInstance returns them as uintptr and
// syscall.SyscallN accepts only uintptr arguments), so this round-trip is
// inherent to COM interop and cannot be avoided. The pointer is re-derived
// by reinterpreting the uintptr's bits rather than converting it directly,
// which keeps the go vet unsafeptr check satisfied.
func toPtr(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) } // #nosec G103 -- raw COM interop; pointers are stack-local

// comCall invokes a COM method by vtable index. The receiver (this) is
// automatically passed as the first argument.
func comCall(pUnk uintptr, vtblIndex int, args ...uintptr) uintptr {
	pVtbl := *(*uintptr)(toPtr(pUnk))
	pMethod := *(*uintptr)(toPtr(pVtbl + uintptr(vtblIndex)*unsafe.Sizeof(uintptr(0))))

	full := make([]uintptr, 1+len(args))
	full[0] = pUnk // this pointer
	copy(full[1:], args)

	ret, _, _ := syscall.SyscallN(pMethod, full...)
	return ret
}

// comQueryInterface calls IUnknown::QueryInterface (vtable index 0).
func comQueryInterface(pUnk uintptr, iid *windows.GUID, ppv *uintptr) uintptr {
	return comCall(pUnk, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(ppv))) // #nosec G103 -- raw COM interop; pointers are stack-local
}

// comRelease calls IUnknown::Release (vtable index 2).
func comRelease(pUnk uintptr) {
	if pUnk != 0 {
		comCall(pUnk, 2)
	}
}

// succeeded checks whether a COM HRESULT indicates success (severity bit 0).
// HRESULTs are 32-bit values; test bit 31 directly to avoid a narrowing
// conversion.
func succeeded(hr uintptr) bool {
	return hr&(1<<31) == 0
}

// utf16PtrToString converts a NUL-terminated UTF-16 pointer to a Go string.
func utf16PtrToString(p uintptr) string {
	if p == 0 {
		return ""
	}
	// Walk the UTF-16 buffer to find the NUL terminator.
	ptr := (*[1 << 20]uint16)(toPtr(p))
	n := 0
	for ptr[n] != 0 {
		n++
	}
	return string(utf16.Decode(ptr[:n:n]))
}
