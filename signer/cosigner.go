package signer

import (
	"time"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/strangelove-ventures/horcrux/signer/proto"
)

type HRSKey struct {
	Height int64
	Round  int64
	Step   int8
}

type HRSTKey struct {
	Height    int64
	Round     int64
	Step      int8
	Timestamp int64
}

func HRSTKeyFromProto(hrs *proto.HRST) HRSTKey {
	return HRSTKey{
		Height:    hrs.GetHeight(),
		Round:     hrs.GetRound(),
		Step:      int8(hrs.GetStep()),
		Timestamp: hrs.GetTimestamp(),
	}
}

func (hrst HRSTKey) toProto() *proto.HRST {
	return &proto.HRST{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      int32(hrst.Step),
		Timestamp: hrst.Timestamp,
	}
}

// CosignerSignRequest is sent to a co-signer to obtain their signature for the SignBytes
// The SignBytes should be a serialized block
type CosignerSignRequest struct {
	ChainID   string
	SignBytes []byte
}

type CosignerSignResponse struct {
	NoncePublic []byte
	Timestamp   time.Time
	Signature   []byte
}

type CosignerNonce struct {
	SourceID      int
	DestinationID int
	PubKey        []byte
	Share         []byte
	Signature     []byte
}

func (secretPart *CosignerNonce) toProto() *proto.Nonce {
	return &proto.Nonce{
		SourceID:      int32(secretPart.SourceID),
		DestinationID: int32(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

type CosignerNonces []CosignerNonce

func (secretParts CosignerNonces) toProto() (out []*proto.Nonce) {
	for _, secretPart := range secretParts {
		out = append(out, secretPart.toProto())
	}
	return
}

func CosignerNonceFromProto(secretPart *proto.Nonce) CosignerNonce {
	return CosignerNonce{
		SourceID:      int(secretPart.SourceID),
		DestinationID: int(secretPart.DestinationID),
		PubKey:        secretPart.PubKey,
		Share:         secretPart.Share,
		Signature:     secretPart.Signature,
	}
}

func CosignerNoncesFromProto(
	secretParts []*proto.Nonce) (out []CosignerNonce) {
	for _, secretPart := range secretParts {
		out = append(out, CosignerNonceFromProto(secretPart))
	}
	return
}

type CosignerSetNonceRequest struct {
	ChainID   string
	SourceID  int
	PubKey    []byte
	Share     []byte
	Signature []byte
	Height    int64
	Round     int64
	Step      int8
	Timestamp time.Time
}

type CosignerSignBlockRequest struct {
	ChainID string
	Block   *Block
}

type CosignerSignBlockResponse struct {
	Signature []byte
}

type CosignerNoncesResponse struct {
	Nonces []CosignerNonce
}

type CosignerSetNoncesAndSignRequest struct {
	ChainID   string
	Nonces    []CosignerNonce
	HRST      HRSTKey
	SignBytes []byte
}

// Cosigner interface is a set of methods for an m-of-n threshold signature.
// This interface abstracts the underlying key storage and management
type Cosigner interface {
	// Get the ID of the cosigner
	// The ID is the shamir index: 1, 2, etc...
	GetID() int

	// Get the P2P URL (GRPC and Raft)
	GetAddress() string

	// Get the combined public key
	GetPubKey(chainID string) (cometcrypto.PubKey, error)

	VerifySignature(chainID string, payload, signature []byte) bool

	// Get nonces for all cosigner shards
	GetNonces(chainID string, hrst HRSTKey) (*CosignerNoncesResponse, error)

	// Sign the requested bytes
	SetNoncesAndSign(req CosignerSetNoncesAndSignRequest) (*CosignerSignResponse, error)
}
