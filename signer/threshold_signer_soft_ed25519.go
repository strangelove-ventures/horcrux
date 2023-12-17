package signer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

var _ ThresholdSigner = &ThresholdSignerSoftEd25519{}

type ThresholdSignerSoftEd25519 struct {
	privateKeyShard []byte
	pubKey          []byte
	threshold       uint8
	total           uint8
}

func NewThresholdSignerSoftEd25519(key CosignerKey, threshold, total uint8) *ThresholdSignerSoftEd25519 {
	return &ThresholdSignerSoftEd25519{
		privateKeyShard: key.PrivateShard,
		pubKey:          key.PubKey,
		threshold:       threshold,
		total:           total,
	}
}

func (s *ThresholdSignerSoftEd25519) PubKey() []byte {
	return s.pubKey
}

func (s *ThresholdSignerSoftEd25519) Sign(nonces []Nonce, payload []byte) ([]byte, error) {
	nonceShare, noncePub, err := s.sumNonces(nonces)
	if err != nil {
		return nil, fmt.Errorf("failed to combine nonces: %w", err)
	}

	sig := tsed25519.SignWithShare(
		payload, s.privateKeyShard, nonceShare, s.pubKey, noncePub)
	return append(noncePub, sig...), nil
}

func (s *ThresholdSignerSoftEd25519) sumNonces(nonces []Nonce) (tsed25519.Scalar, tsed25519.Element, error) {
	shareParts := make([]tsed25519.Scalar, len(nonces))
	publicKeys := make([]tsed25519.Element, len(nonces))

	for i, n := range nonces {
		shareParts[i] = n.Share
		publicKeys[i] = n.PubKey
	}

	nonceShare := tsed25519.AddScalars(shareParts)
	noncePub := tsed25519.AddElements(publicKeys)

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

func GenerateNoncesEd25519(threshold, total uint8) (Nonces, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Nonces{}, err
	}

	nonces := Nonces{
		PubKey: tsed25519.ScalarMultiplyBase(secret),
		Shares: make([][]byte, total),
	}

	shares := tsed25519.DealShares(secret, threshold, total)

	for i, sh := range shares {
		nonces.Shares[i] = sh
	}

	return nonces, nil
}

func (s *ThresholdSignerSoftEd25519) CombineSignatures(signatures []PartialSignature) ([]byte, error) {
	sigIds := make([]int, len(signatures))
	shareSigs := make([][]byte, len(signatures))
	var ephPub []byte

	for i, sig := range signatures {
		sigIds[i] = sig.ID
		if i == 0 {
			ephPub = sig.Signature[:32]
		} else if !bytes.Equal(sig.Signature[:32], ephPub) {
			return nil, fmt.Errorf("ephemeral public keys do not match")
		}
		shareSigs[i] = sig.Signature[32:]
	}
	combinedSig := tsed25519.CombineShares(s.total, sigIds, shareSigs)

	return append(ephPub, combinedSig...), nil
}

func (s *ThresholdSignerSoftEd25519) VerifySignature(payload, signature []byte) bool {
	return cometcryptoed25519.PubKey(s.pubKey).VerifySignature(payload, signature)
}
