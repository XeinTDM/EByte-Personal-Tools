package process_protection

import (
	"unsafe"
)

func SetProcessMitigationPolicy(policy int, lpBuffer *PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, size uint32) (bool, error) {
	ret, _, err := procSetProcessMitigationPolicy.Call(uintptr(policy), uintptr(unsafe.Pointer(lpBuffer)), uintptr(size))
	if ret != 0 {
		return true, nil
	}
	if err != nil && err.Error() != "The operation completed successfully." {
		return false, err
	}
	return false, nil
}
