package tss

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/strangelove-ventures/horcrux/pkg/config"
	"github.com/strangelove-ventures/horcrux/pkg/types"

	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// var _ IThresholdSigner = &ThresholdSignerSoft{}

type ThresholdSignerSoft struct {
	privateKeyShard []byte
	pubKey          []byte
	threshold       uint8
	total           uint8
}

func NewThresholdSignerSoft(config *config.RuntimeConfig, id int, chainID string) (*ThresholdSignerSoft, error) {
	keyFile, err := config.KeyFileExistsCosigner(chainID)
	if err != nil {
		return nil, err
	}

	key, err := LoadThresholdSignerEd25519Key(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading cosigner key: %s", err)
	}

	if key.ID != id {
		return nil, fmt.Errorf("key shard Index (%d) in (%s) does not match cosigner Index (%d)", key.ID, keyFile, id)
	}

	s := ThresholdSignerSoft{
		privateKeyShard: key.PrivateShard,
		pubKey:          key.PubKey.Bytes(),
		threshold:       uint8(config.Config.ThresholdModeConfig.Threshold),
		total:           uint8(len(config.Config.ThresholdModeConfig.Cosigners)),
	}

	return &s, nil
}

func (s *ThresholdSignerSoft) GetPubKey() []byte {
	return s.pubKey
}

func (s *ThresholdSignerSoft) Sign(nonces []types.Nonce, payload []byte) ([]byte, error) {
	nonceShare, noncePub, err := s.sumNonces(nonces)
	if err != nil {
		return nil, fmt.Errorf("failed to combine nonces: %w", err)
	}

	sig := tsed25519.SignWithShare(
		payload, s.privateKeyShard, nonceShare, s.pubKey, noncePub)
	return append(noncePub, sig...), nil
}

func (s *ThresholdSignerSoft) sumNonces(nonces []types.Nonce) (tsed25519.Scalar, tsed25519.Element, error) {
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

// GenerateNonces is a function that generates Nonces to be used in the MPC
func GenerateNonces(threshold, total uint8) (types.Nonces, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return types.Nonces{}, err
	}

	nonces := types.Nonces{
		PubKey: tsed25519.ScalarMultiplyBase(secret),
		Shares: make([][]byte, total),
	}

	shares := tsed25519.DealShares(secret, threshold, total)

	for i, sh := range shares {
		nonces.Shares[i] = sh
	}

	return nonces, nil
}

// Should move to the cosigner package
func (s *ThresholdSignerSoft) CombineSignatures(signatures []types.PartialSignature) ([]byte, error) {
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
	combinedSig := tsed25519.CombineShares(s.total, sigIds, shareSigs)

	return append(ephPub, combinedSig...), nil
}
