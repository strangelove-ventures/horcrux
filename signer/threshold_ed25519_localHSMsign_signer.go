package signer

import (
	"errors"
)

func NewLocalHSMSignThresholdEd25519SignatureConfig(cfg LocalCosignerConfig) LocalHSMsignThresholdEd25519SignatureConfig {
	// inistiates the LocalSoftSignThresholdEd25519SignatureConfig
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
	// panic("Not Implemented") // TODO: Implement HSM Signer
	// UnimplementedThresholdEd25519Signature // embedding UnimplementedCosignerGRPCServer
}

func (localsigner *LocalHSMsignThresholdEd25519Signature) DealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	//panic("Not Implemented")
	return HrsMetadata{}, errors.New("method dealShares not implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest, m *LastSignStateStruct,
	peers map[int]CosignerPeer) error {
	//panic("Not Implemented")
	return errors.New("method setEphemeralSecretPart not implemented")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest, m *LastSignStateStruct,
	peers map[int]CosignerPeer) (CosignerEphemeralSecretPart, error) {
	//panic("Not Implemented")
	return CosignerEphemeralSecretPart{}, errors.New("method getEphemeralSecretPart")
}
func (localsigner *LocalHSMsignThresholdEd25519Signature) Sign(req CosignerSignRequest, m *LastSignStateStruct) (CosignerSignResponse, error) {
	//panic("Not Implemented")
	return CosignerSignResponse{}, errors.New("method sign not implemented")
}

// Implements the ThresholdEd25519Signature interface from threshold_ed25519_signer.go
func (localsigner *LocalHSMsignThresholdEd25519Signature) GetID() (int, error) {
	//panic("Not implemented")
	return 0, errors.New("method GetID not implemented")
}

/*

// UnimplementedThresholdEd25519Signature must be embedded to have forward compatible implementations.
type UnimplementedThresholdEd25519Signature struct {
}

func (UnimplementedThresholdEd25519Signature) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	return HrsMetadata{}, errors.New("method dealShares not implemented")
}
func (UnimplementedThresholdEd25519Signature) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	return errors.New("method setEphemeralSecretPart not implemented")
}
func (UnimplementedThresholdEd25519Signature) getEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	return CosignerEphemeralSecretPart{}, errors.New("method getEphemeralSecretPart")
}
func (UnimplementedThresholdEd25519Signature) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	return CosignerSignResponse{}, errors.New("method sign not implemented")
}

*/
