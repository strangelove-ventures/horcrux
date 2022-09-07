package signer

func NewThresholdSignerHSM() ThresholdSigner {
	panic("Not Implemented")
}

type ThresholdSignerHSM struct {
	// TODO: Implement HSM Signer
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) Type() string {
	return "hsm"
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) DealShares(
	req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) SetEphemeralSecretPart(
	req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) error {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) (
	CosignerEphemeralSecretPart, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) Sign(
	req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error) {
	panic("Not Implemented")
}

// Implements ThresholdSigner
func (hsmSigner *ThresholdSignerHSM) GetID() (int, error) {
	panic("Not implemented")
}
