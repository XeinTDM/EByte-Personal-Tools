package antidebug

import "syscall"

var (
    User32DLL       = syscall.NewLazyDLL("user32.dll")
    EnumWindowsProc = User32DLL.NewProc("EnumWindows")
    GetWindowText   = User32DLL.NewProc("GetWindowTextA")
    GetWindowThread = User32DLL.NewProc("GetWindowThreadProcessId")

    Kernel32DLL          = syscall.NewLazyDLL("kernel32.dll")
    IsDebugger           = Kernel32DLL.NewProc("IsDebuggerPresent")
    DebugString          = Kernel32DLL.NewProc("OutputDebugStringA")
    ProcOpenProcess      = Kernel32DLL.NewProc("OpenProcess")
    ProcTerminateProcess = Kernel32DLL.NewProc("TerminateProcess")
)


var ProcessNameBlacklist = []string{
    "ksdumperclient", "regedit", "ida64", "vmtoolsd", "vgauthservice",
    "wireshark", "x32dbg", "ollydbg", "vboxtray", "df5serv", "vmsrvc",
    "vmusrvc", "taskmgr", "vmwaretray", "xenservice", "pestudio", "vmwareservice",
    "qemu-ga", "prl_cc", "prl_tools", "joeboxcontrol", "vmacthlp",
    "httpdebuggerui", "processhacker", "joeboxserver", "fakenet", "ksdumper",
    "vmwareuser", "fiddler", "x96dbg", "dumpcap", "vboxservice",
}

var WindowTitleBlacklist = []string{
    "simpleassemblyexplorer", "dojandqwklndoqwd", "procmon64", "process hacker",
    "sharpod", "http debugger", "dbgclr", "x32dbg", "sniffer", "petools",
    "simpleassembly", "ksdumper", "dnspy", "x96dbg", "de4dot", "exeinfope",
    "windbg", "mdb", "harmony", "systemexplorerservice", "megadumper",
    "system explorer", "mdbg", "kdb", "charles", "stringdecryptor", "phantom",
    "debugger", "extremedumper", "pc-ret", "folderchangesview", "james",
    "process monitor", "protection_id", "de4dotmodded", "x32_dbg", "pizza", "fiddler",
    "x64_dbg", "httpanalyzer", "strongod", "wireshark", "gdb", "graywolf", "x64dbg",
    "ksdumper v1.1 - by equifox", "wpe pro", "ilspy", "dbx", "ollydbg", "x64netdumper",
    "scyllahide", "kgdb", "systemexplorer", "proxifier", "debug", "httpdebug",
    "httpdebugger", "0harmony", "mitmproxy", "ida -", "codecracker", "ghidra",
    "titanhide", "hxd", "reversal",
}
