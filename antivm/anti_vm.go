package antivm

import (
    "errors"
    "fmt"
    "os"
    "strings"
    "syscall"
    "unsafe"
)

func CheckAndExit() {
    if isVM, err := IsVirtualMachine(); err != nil {
        fmt.Printf("Error during VM detection: %v\n", err)
        os.Exit(1)
    } else if isVM {
        fmt.Println("Virtual machine environment detected. Exiting.")
        os.Exit(1)
    }
}

func IsVirtualMachine() (bool, error) {
    if isHypervisorPresent() {
        return true, nil
    }
    if isScreenResolutionSuspicious() {
        return true, nil
    }
    if hasBlacklistedProcesses() {
        return true, nil
    }
    if hasBlacklistedFiles() {
        return true, nil
    }
    if hasBlacklistedMAC() {
        return true, nil
    }
    if hasBlacklistedRegistryKeys() {
        return true, nil
    }
    return false, nil
}

// Using the CPUID instruction.
func isHypervisorPresent() bool {
    eax := uint32(1)
    ecx := uint32(0)

    _, _, ecx, _ = cpuid(eax, ecx)
    hypervisorPresent := ecx&(1<<31) != 0

    return hypervisorPresent
}

// Executes the CPUID instruction with the given EAX and ECX values.
func cpuid(eax, ecx uint32) (a, b, c, d uint32) {
    asm := syscall.NewLazyDLL("kernel32.dll").NewProc("IsProcessorFeaturePresent")
    var info [4]uint32
    _, _, _ = asm.Call(uintptr(unsafe.Pointer(&eax)), uintptr(unsafe.Pointer(&ecx)), uintptr(unsafe.Pointer(&info)))
    return info[0], info[1], info[2], info[3]
}

// Checks if the screen resolution is below typical values.
func isScreenResolutionSuspicious() bool {
    user32 := syscall.NewLazyDLL("user32.dll")
    getSystemMetrics := user32.NewProc("GetSystemMetrics")

    smCxScreen := 0
    smCyScreen := 1

    width, _, _ := getSystemMetrics.Call(uintptr(smCxScreen))
    height, _, _ := getSystemMetrics.Call(uintptr(smCyScreen))

    if width < 1024 || height < 768 {
        return true
    }
    return false
}

func hasBlacklistedProcesses() bool {
    blacklistedProcesses := []string{
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmsrvc.exe",
        "vmusrvc.exe",
        "prl_cc.exe",
        "prl_tools.exe",
        "xenservice.exe",
    }

    processes, err := enumerateProcesses()
    if err != nil {
        return false
    }

    for _, proc := range processes {
        for _, blacklisted := range blacklistedProcesses {
            if strings.EqualFold(proc, blacklisted) {
                return true
            }
        }
    }
    return false
}

// Retrieves a list of running process names.
func enumerateProcesses() ([]string, error) {
    var processNames []string

    snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return nil, err
    }
    defer syscall.CloseHandle(snapshot)

    var entry syscall.ProcessEntry32
    entry.Size = uint32(unsafe.Sizeof(entry))

    err = syscall.Process32First(snapshot, &entry)
    if err != nil {
        return nil, err
    }

    for {
        processName := syscall.UTF16ToString(entry.ExeFile[:])
        processNames = append(processNames, processName)
        err = syscall.Process32Next(snapshot, &entry)
        if err != nil {
            if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
                break
            }
            return nil, err
        }
    }
    return processNames, nil
}

func hasBlacklistedFiles() bool {
    systemRoot := os.Getenv("SystemRoot")
    if systemRoot == "" {
        systemRoot = "C:\\Windows"
    }

    blacklistedFiles := []string{
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
    }

    for _, filePath := range blacklistedFiles {
        if fileExists(filePath) {
            return true
        }
    }
    return false
}

// Checks if a file exists at the given path.
func fileExists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}

func hasBlacklistedMAC() bool {
    blacklistedMACPrefixes := []string{
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
        "00:15:5D", // Hyper-V
        "00:03:FF", // Microsoft Virtual PC
        "00:1C:42", // Parallels
        "08:00:27", // VirtualBox
    }

    interfaces, err := getNetworkInterfaces()
    if err != nil {
        return false
    }

    for _, iface := range interfaces {
        mac := iface.HardwareAddr.String()
        for _, prefix := range blacklistedMACPrefixes {
            if strings.HasPrefix(strings.ToUpper(mac), strings.ToUpper(prefix)) {
                return true
            }
        }
    }
    return false
}

func getNetworkInterfaces() ([]net.Interface, error) {
    return net.Interfaces()
}

func hasBlacklistedRegistryKeys() bool {
    blacklistedKeys := []string{
        `HARDWARE\ACPI\DSDT\VBOX__`,
        `HARDWARE\ACPI\FADT\VBOX__`,
        `HARDWARE\ACPI\RSDT\VBOX__`,
        `HARDWARE\ACPI\RSDT\VBOX__`,
        `SOFTWARE\Oracle\VirtualBox Guest Additions`,
        `SYSTEM\ControlSet001\Services\VBoxGuest`,
        `SYSTEM\ControlSet001\Services\VBoxService`,
        `SYSTEM\ControlSet001\Services\VBoxSF`,
        `SYSTEM\ControlSet001\Services\VBoxVideo`,
    }

    for _, keyPath := range blacklistedKeys {
        if registryKeyExists(syscall.HKEY_LOCAL_MACHINE, keyPath) {
            return true
        }
    }
    return false
}

// Checks if a registry key exists.
func registryKeyExists(root syscall.Handle, path string) bool {
    key, err := syscall.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ)
    if err == nil {
        syscall.RegCloseKey(key)
        return true
    }
    return false
}
