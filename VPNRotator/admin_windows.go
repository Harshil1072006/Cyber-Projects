//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ensureAdmin checks if the process has administrator privileges.
// If it does not, it relaunches itself with UAC elevation and exits the current process.
// Call this at the very start of main().
func ensureAdmin() {
	if isAdmin() {
		return // Already elevated — nothing to do
	}

	// Not admin — relaunch self with "runas" verb to trigger UAC prompt
	exe, err := os.Executable()
	if err != nil {
		return // Can't determine own path — just continue
	}

	verb, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)

	shell32 := windows.NewLazyDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")

	// ShellExecuteW(hwnd, verb, file, params, dir, showCmd)
	// SW_NORMAL = 1
	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exePtr)),
		0,
		0,
		1,
	)

	if ret > 32 {
		// Successfully launched elevated process — exit this one
		os.Exit(0)
	}
	// If elevation failed (user clicked No), just continue without admin
	// The app will show a warning in the UI
}

// isAdmin returns true if the current process has Windows administrator privileges.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
