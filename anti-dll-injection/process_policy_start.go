package process_protection

import (
	"unsafe"
)

func ConfigureProcessMitigationPolicy() error {
	var OnlyMicrosoftBinaries PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
	OnlyMicrosoftBinaries.MicrosoftSignedOnly = 1

	_, err := SetProcessMitigationPolicy(
		ProcessSignaturePolicyMitigation,
		&OnlyMicrosoftBinaries,
		uint32(unsafe.Sizeof(OnlyMicrosoftBinaries)),
	)
	return err
}
