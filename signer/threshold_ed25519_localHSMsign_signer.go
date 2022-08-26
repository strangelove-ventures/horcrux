package signer

import (
	"errors"
)

// Inistiates the LocalHSMsignThresholdEd25519SignatureConfig
func NewLocalHSMSignThresholdEd25519SignatureConfig(
	cfg SignerTypeConfig) LocalHSMsignThresholdEd25519SignatureConfig {

	panic("Not Implemented")
}

// Placeholder for Local LocalHSMsignThresholdEd25519SignatureConfig
type LocalHSMsignThresholdEd25519SignatureConfig struct {
}

func (cfg *LocalHSMsignThresholdEd25519SignatureConfig) NewThresholdEd25519Signature() ThresholdEd25519Signature {
	panic("Not Implemented")

	// return localsigner
}

type LocalHSMsignThresholdEd25519Signature struct {
	// TODO: Implement HSM Signer
}

func (localsigner *LocalHSMsignThresholdEd25519Signature) DealShares(
	req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {

	// panic("Not Implemented")
	return HrsMetadata{}, errors.New("method dealShares not implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) SetEphemeralSecretPart(
	req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) error {

	// panic("Not Implemented")
	return errors.New("method setEphemeralSecretPart not implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct, peers map[int]CosignerPeer) (
	CosignerEphemeralSecretPart, error) {

	panic("Not Implemented")
	// return CosignerEphemeralSecretPart{}, errors.New("method getEphemeralSecretPart")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) Sign(
	req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error) {

	panic("Not Implemented")
	// return CosignerSignResponse{}, errors.New("method sign not implemented")
}

// Implements the ThresholdEd25519Signature interface from threshold_ed25519_signer.go
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetID() (int, error) {

	panic("Not implemented")
	// return 0, errors.New("method GetID not implemented")
}
