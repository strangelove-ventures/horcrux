package signer

import (
	"errors"
)

// RemoteCosigner uses tendermint rpc to request signing from a remote cosigner
type RemoteCosigner struct {
	id          int
	address     string
	raftAddress string
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string, raftAddress string) *RemoteCosigner {
	cosigner := &RemoteCosigner{
		id:          id,
		address:     address,
		raftAddress: raftAddress,
	}
	return cosigner
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetID() int {
	return cosigner.id
}

// GetAddress returns the RPC URL of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetAddress() string {
	return cosigner.address
}

// GetRaftAddress returns the Raft hostname of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetRaftAddress() string {
	return cosigner.raftAddress
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) Sign(req CosignerSignRequest) (res CosignerSignResponse, err error) {
	return res, CallRPC(cosigner.address, "Sign", req, &res)
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	return CosignerEphemeralSecretPart{}, errors.New("not Implemented")
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) HasEphemeralSecretPart(
	req CosignerHasEphemeralSecretPartRequest) (CosignerHasEphemeralSecretPartResponse, error) {
	return CosignerHasEphemeralSecretPartResponse{}, errors.New("not Implemented")
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) SetEphemeralSecretPart(req CosignerEphemeralSecretPart) error {
	return CallRPC(cosigner.address, "SetEphemeralSecretPart", req, &EmptyRPCResponse{})
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) SignBlock(req CosignerSignBlockRequest) (res CosignerSignBlockResponse, err error) {
	return res, CallRPC(cosigner.address, "SignBlock", req, &res)
}

// Implements the cosigner interface
func (cosigner *RemoteCosigner) EmitEphemeralSecretPartReceipt(req CosignerEmitEphemeralSecretReceiptRequest) error {
	return CallRPC(cosigner.address, "EmitEphemeralSecretPartReceipt", req, &EmptyRPCResponse{})
}
