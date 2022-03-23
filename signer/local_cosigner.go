package signer

import (
	"crypto/rsa"
	"sync"
	"time"

	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
	tsed25519 "gitlab.com/polychainlabs/threshold-ed25519/pkg"
)

// return true if we are less than the other key
func (hrst *HRSTKey) Less(other HRSTKey) bool {
	if hrst.Height < other.Height {
		return true
	}

	if hrst.Height > other.Height {
		return false
	}

	// height is equal, check round

	if hrst.Round < other.Round {
		return true
	}

	if hrst.Round > other.Round {
		return false
	}

	// round is equal, check step

	if hrst.Step < other.Step {
		return true
	}

	// HRS is greater or equal
	return false
}

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

type LocalCosignerConfig struct {
	CosignerKey               CosignerKey
	SignState                 *SignState
	RsaKey                    rsa.PrivateKey
	Peers                     []CosignerPeer
	Address                   string
	RaftAddress               string
	Total                     uint8
	Threshold                 uint8
	ThresholdEd25519Signature ThresholdEd25519Signature
}

type PeerMetadata struct {
	Share                    []byte
	EphemeralSecretPublicKey []byte
}

type HrsMetadata struct {
	// need to be _total_ entries per player
	Secret      []byte
	DealtShares []tsed25519.Scalar
	Peers       []PeerMetadata
}

// LocalCosigner responds to sign requests using their share key
// The cosigner maintains a watermark to avoid double-signing
// TODO: Please clarify what you mean with cosinger here.
// LocalCosigner signing is thread safe
type LocalCosigner struct {
	pubKeyBytes []byte
	key         CosignerKey
	rsaKey      rsa.PrivateKey
	total       uint8
	threshold   uint8

	// stores the last sign state for a share we have fully signed
	// incremented whenever we are asked to sign a share
	lastSignState *SignState

	// signing is thread safe
	lastSignStateMutex sync.Mutex

	// Height, Round, Step -> metadata
	hrsMeta map[HRSTKey]HrsMetadata
	peers   map[int]CosignerPeer

	address string

	thresholdEd25519SignatureImplementation ThresholdEd25519Signature
}

func (cosigner *LocalCosigner) SaveLastSignedState(signState SignStateConsensus) error {
	return cosigner.lastSignState.Save(signState, &cosigner.lastSignStateMutex)
}

func NewLocalCosigner(cfg LocalCosignerConfig) *LocalCosigner {
	cosigner := &LocalCosigner{
		key:                                     cfg.CosignerKey,
		lastSignState:                           cfg.SignState,
		rsaKey:                                  cfg.RsaKey,
		hrsMeta:                                 make(map[HRSTKey]HrsMetadata),
		peers:                                   make(map[int]CosignerPeer),
		total:                                   cfg.Total,
		threshold:                               cfg.Threshold,
		address:                                 cfg.Address,
		thresholdEd25519SignatureImplementation: localThresholdSignatureImplementation //cfg.ThresholdEd25519Signature,
	}

	for _, peer := range cfg.Peers {
		cosigner.peers[peer.ID] = peer
	}

	// cache the public key bytes for signing operations
	switch ed25519Key := cosigner.key.PubKey.(type) {
	case tmCryptoEd25519.PubKey:
		cosigner.pubKeyBytes = make([]byte, len(ed25519Key))
		copy(cosigner.pubKeyBytes, ed25519Key[:])
	default:
		panic("Not an ed25519 public key")
	}

	return cosigner
}

// GetID returns the id of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetID() int {
	return cosigner.key.ID
}

// GetAddress returns the GRPC URL of the cosigner
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetAddress() string {
	return cosigner.address
}

// GetEphemeralSecretParts
// Implements Cosigner interface
func (cosigner *LocalCosigner) GetEphemeralSecretParts(
	hrst HRSTKey) (*CosignerEphemeralSecretPartsResponse, error) {
	res := &CosignerEphemeralSecretPartsResponse{
		EncryptedSecrets: make([]CosignerEphemeralSecretPart, 0, len(cosigner.peers)-1),
	}
	for _, peer := range cosigner.peers {
		if peer.ID == cosigner.GetID() {
			continue
		}
		secretPart, err := cosigner.thresholdEd25519SignatureImplementation.getEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:        peer.ID,
			Height:    hrst.Height,
			Round:     hrst.Round,
			Step:      hrst.Step,
			Timestamp: time.Unix(0, hrst.Timestamp),
		})

		if err != nil {
			return nil, err
		}

		res.EncryptedSecrets = append(res.EncryptedSecrets, secretPart)
	}
	return res, nil
}

// SetEphemeralSecretPartsAndSign
// Implements Cosigner interface
func (cosigner *LocalCosigner) SetEphemeralSecretPartsAndSign(
	req CosignerSetEphemeralSecretPartsAndSignRequest) (*CosignerSignResponse, error) {
	for _, secretPart := range req.EncryptedSecrets {
		err := cosigner.thresholdEd25519SignatureImplementation.setEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
			SourceID:                       secretPart.SourceID,
			SourceEphemeralSecretPublicKey: secretPart.SourceEphemeralSecretPublicKey,
			EncryptedSharePart:             secretPart.EncryptedSharePart,
			SourceSig:                      secretPart.SourceSig,
			Height:                         req.HRST.Height,
			Round:                          req.HRST.Round,
			Step:                           req.HRST.Step,
			Timestamp:                      time.Unix(0, req.HRST.Timestamp),
		})
		if err != nil {
			return nil, err
		}
	}

	res, err := cosigner.thresholdEd25519SignatureImplementation.sign(CosignerSignRequest{req.SignBytes})
	return &res, err
}
