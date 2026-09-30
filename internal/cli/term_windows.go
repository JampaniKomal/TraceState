package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether f is a console that can render ANSI escapes,
// enabling virtual terminal processing on older Windows consoles. If that
// can't be enabled, colour is turned off rather than printing raw escapes.
func isTerminal(f *os.File) bool {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
