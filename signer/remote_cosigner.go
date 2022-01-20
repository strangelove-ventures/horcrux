package signer

import (
	"context"
	"errors"
)

var (
	ctx = context.Background()
)

// RemoteCosigner uses tendermint rpc to request signing from a remote cosigner
type RemoteCosigner struct {
	id      int
	address string
}

// NewRemoteCosigner returns a newly initialized RemoteCosigner
func NewRemoteCosigner(id int, address string) *RemoteCosigner {
	cosigner := &RemoteCosigner{
		id:      id,
		address: address,
	}
	return cosigner
}

// GetID returns the ID of the remote cosigner
// Implements the cosigner interface
func (cosigner *RemoteCosigner) GetID() int {
	return cosigner.id
}

func (cosigner *RemoteCosigner) Sign(signReq CosignerSignRequest) (CosignerSignResponse, error) {
	return CosignerSignResponse{}, errors.New("Not Implemented")
}

func (cosigner *RemoteCosigner) GetEphemeralSecretPart(req CosignerGetEphemeralSecretPartRequest) (CosignerGetEphemeralSecretPartResponse, error) {
	return CosignerGetEphemeralSecretPartResponse{}, errors.New("Not Implemented")
}

func (cosigner *RemoteCosigner) HasEphemeralSecretPart(req CosignerHasEphemeralSecretPartRequest) (CosignerHasEphemeralSecretPartResponse, error) {
	return CosignerHasEphemeralSecretPartResponse{}, errors.New("Not Implemented")
}

func (cosigner *RemoteCosigner) SetEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {
	return errors.New("Not Implemented")
}
