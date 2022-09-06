package signer

func NewLocalHSMSignThresholdEd25519Signature() ThresholdEd25519Signature {
	panic("Not Implemented")

	// return localsigner
}

type LocalHSMsignThresholdEd25519Signature struct {
	// TODO: Implement HSM Signer
}

func (localsigner *LocalHSMsignThresholdEd25519Signature) DealShares(
	req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	panic("Not Implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) SetEphemeralSecretPart(
	req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) error {
	panic("Not Implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) (
	CosignerEphemeralSecretPart, error) {
	panic("Not Implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) Sign(
	req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error) {
	panic("Not Implemented")
}

// Implements the ThresholdEd25519Signature interface from threshold_ed25519_signer.go
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetID() (int, error) {
	panic("Not implemented")
}
