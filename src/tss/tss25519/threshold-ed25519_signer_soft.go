package tss25519

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/strangelove-ventures/horcrux/src/types"

	"gitlab.com/unit410/edwards25519"
	ted25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// var _ IThresholdSigner = &ThresholdSignerSoft{}

// GenerateSignatureShards creates a map of shards from a private key
func GenerateSignatureShards(pv []byte, threshold, shards uint8) map[uint8][]byte {
	privShards := ted25519.DealShares(ted25519.ExpandSecret(pv[:32]), threshold, shards)
	// TODO: Check that the length of privShards is equal to the number of shards
	// TODO: Check that the pubkey is the same for all shards
	out := make(map[uint8][]byte, shards)
	for id, shard := range privShards {
		id := uint8(id + 1)
		out[id] = shard
	}
	return out
}

/*
type AssymetricKey struct {
	privateKey   []byte
	privateShard []byte
}

type AssymetricKeyShard struct {
	AssymetricKey
	threshold uint8
	total     uint8
	id        uint8 // ID is the Shamir index or this shard.

}

type SignerDealer struct {
	SignerSoft
}
*/

// SignerSoft is a threshold signer that uses the threshold-ed25519 library
// to perform the signing operations.
// Its only responsibility is to sign a payload and combine signatures
type SignerSoft struct {
	privateKeyShard []byte
	pubKey          []byte
	threshold       uint8
	total           uint8
	id              uint8
}

func NewSignerSoft(privateKeyShard []byte, pubKey []byte, threshold, total, id uint8) (*SignerSoft, error) {
	s := SignerSoft{
		privateKeyShard: privateKeyShard,
		pubKey:          pubKey,
		threshold:       threshold,
		total:           total,
		id:              id,
	}

	return &s, nil
}

func (s *SignerSoft) GetPubKey() []byte {
	return s.pubKey
}

// Sign signs a byte payload with the provided nonces.
// The return are a "partial  signature".
func (s *SignerSoft) Sign(nonces []types.Nonce, payload []byte) ([]byte, error) {
	// sum the nonces to get the ephemeral public key and share
	nonceShare, noncePub, err := sumNonces(nonces)
	if err != nil {
		return nil, fmt.Errorf("failed to combine nonces: %w", err)
	}

	sig := ted25519.SignWithShare(
		payload, s.privateKeyShard, nonceShare, s.pubKey, noncePub)
	return append(noncePub, sig...), nil
}

func sumNonces(nonces []types.Nonce) (ted25519.Scalar, ted25519.Element, error) {
	shareParts := make([]ted25519.Scalar, len(nonces))
	publicKeys := make([]ted25519.Element, len(nonces))

	for i, n := range nonces {
		shareParts[i] = n.Share
		publicKeys[i] = n.PubKey
	}

	nonceShare := ted25519.AddScalars(shareParts)
	noncePub := ted25519.AddElements(publicKeys)

	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
	if len(nonceShare) != 32 {
		return nil, nil, errors.New("ephemeral share is out of bounds")
	}

	var scalarBytes [32]byte
	copy(scalarBytes[:], nonceShare)
	if !edwards25519.ScMinimal(&scalarBytes) {
		return nil, nil, errors.New("ephemeral share is out of bounds")
	}

	return nonceShare, noncePub, nil
}

type NonceGenerator struct {
}

// GenerateNonces is a function (methods) that generates Nonces to be used in the MPC signature
func (ng NonceGenerator) GenerateNonces(threshold, total uint8) (types.Nonces, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return types.Nonces{}, err
	}

	nonces := types.Nonces{
		PubKey: ted25519.ScalarMultiplyBase(secret),
		Shares: make([][]byte, total),
	}

	// The length of shares is equal to total
	shares := ted25519.DealShares(secret, threshold, total)

	for i, sh := range shares {
		nonces.Shares[i] = sh
	}

	return nonces, nil
}

// CombineSignatures combines partial signatures into a full signature
func (s *SignerSoft) CombineSignatures(signatures []types.PartialSignature) ([]byte, error) {
	sigIds := make([]int, len(signatures))
	shareSigs := make([][]byte, len(signatures))
	var ephPub []byte

	for i, sig := range signatures {
		sigIds[i] = sig.Index
		if i == 0 {
			ephPub = sig.Signature[:32]
		} else if !bytes.Equal(sig.Signature[:32], ephPub) {
			return nil, fmt.Errorf("ephemeral public keys do not match")
		}
		shareSigs[i] = sig.Signature[32:]
	}
	combinedSig := ted25519.CombineShares(s.total, sigIds, shareSigs)

	return append(ephPub, combinedSig...), nil
}
