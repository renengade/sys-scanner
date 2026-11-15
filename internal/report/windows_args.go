package report

// windowsOpenArgs returns the arguments used to open a file with its default
// Windows handler.
//
// rundll32 is used instead of `cmd /c start` for two reasons:
//   - It does not go through cmd.exe, so paths containing &, ^, % or quotes
//     cannot be interpreted as shell syntax.
//   - The path is passed as a real process argument, so Go's exec quoting is
//     not doubled into a path like "C:\\Users\\..." (which Windows reports as
//     "file not found").
func windowsOpenArgs(path string) []string {
	return []string{"url.dll,FileProtocolHandler", path}
}
