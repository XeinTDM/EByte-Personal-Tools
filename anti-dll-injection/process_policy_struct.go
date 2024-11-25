package process_protection

import "syscall"

const (
	ProcessSignaturePolicyMitigation = 8
)

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	MicrosoftSignedOnly uint32
}

var (
	modkernelbase                  = syscall.NewLazyDLL("kernelbase.dll")
	procSetProcessMitigationPolicy = modkernelbase.NewProc("SetProcessMitigationPolicy")
)
