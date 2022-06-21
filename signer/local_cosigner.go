package signer

import (
	"crypto/rsa"
	"time"

	"sync"
)

type CosignerPeer struct {
	ID        int
	PublicKey rsa.PublicKey
}

type CosignerGetEphemeralSecretPartRequest struct {
	ID        int
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type LastSignStateStruct struct {
	// signing is thread safe - lastSignStateMutex is used for putting locks so only one goroutine can r/w to the function
	LastSignStateMutex sync.Mutex

	// lastSignState stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	LastSignState *SignState
}

// LocalCosigner responds to sign requests using their share key
// The cosigner maintains a watermark to avoid double-signing
// TODO: Clarify what you mean with cosinger here.
// LocalCosigner signing is thread safe
// Local cosigner "embedd" the threshold signer.

type LocalCosignerConfig struct {
	CosignerKey CosignerKey
	SignState   *SignState
	RsaKey      rsa.PrivateKey
	Peers       []CosignerPeer
	Address     string
	RaftAddress string
	Total       uint8
	Threshold   uint8
	// Localsigner LocalSoftSignThresholdEd25519Signature
}

// TODO refactorise temporary aliasing ThresholdEd25519Signature
type thresholdEd25519Signature = *LocalSoftSignThresholdEd25519Signature

type LocalCosigner struct {
	LastSignStateStruct *LastSignStateStruct
	total               uint8
	address             string
	Peers               map[int]CosignerPeer
	localsigner         thresholdEd25519Signature
}

func NewLocalCosigner(cfg LocalCosignerConfig) *LocalCosigner {

	LastSignStateStruct := LastSignStateStruct{
		LastSignStateMutex: sync.Mutex{},
		LastSignState:      cfg.SignState,
	}
	cosigner := &LocalCosigner{
		LastSignStateStruct: &LastSignStateStruct,
		total:               cfg.Total,
		address:             cfg.Address,
		// TODO take localsigner as parameter
		// TODO: localsigner should be passed as a parameter in the cfg rather than constructed here.

		localsigner: NewLocalSoftSignThresholdEd25519Signature(cfg),
		Peers:       make(map[int]CosignerPeer),
	}

	for _, peer := range cfg.Peers {
		cosigner.Peers[peer.ID] = peer
	}

	return cosigner
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState SignStateConsensus) error {
	return cosigner.LastSignStateStruct.LastSignState.Save(signState, &cosigner.LastSignStateStruct.LastSignStateMutex)
}

// GetID returns the id of the cosigner
// Implements cosigner interface
func (cosigner *LocalCosigner) GetID() int {
	return cosigner.localsigner.GetID()
}

// GetAddress returns the GRPC URL of the cosigner
// Implements cosigner interface
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// GetEphemeralSecretParts
// Implements cosigner interface
func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	hrst HRSTKey) (*CosignerEphemeralSecretPartsResponse, error) {
	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.Peers)-1),
	}
	for _, peer := range cosigner.Peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.localsigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:        peer.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		}, cosigner.LastSignStateStruct,
			cosigner.Peers)

		if err != nil {
			return nil, err
		}

		res.EncryptedSecrets = append(res.EncryptedSecrets, secretPart)
	}
	return res, nil
}

// SetEphemeralSecretPartsAndSign
// Implements cosigner interface
func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.localsigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRST.Height,
			Round:                          req.HRST.Round,
			Step:                           req.HRST.Step,
			Timestamp:                      time.Unix(0, req.HRST.Timestamp),
		}, cosigner.LastSignStateStruct, cosigner.Peers)
		if err != nil {
			return nil, err
		}
	}

	res, err := cosigner.localsigner.Sign(CosignerSignRequest{req.SignBytes}, cosigner.LastSignStateStruct)
	return &res, err
}
