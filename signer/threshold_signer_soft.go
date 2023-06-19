package signer

import (
	"fmt"

	"github.com/coinbase/kryptology/pkg/ted25519/ted25519"
)

var _ ThresholdSigner = &ThresholdSignerSoft{}

const SignerTypeSoftSign = "SoftSign"

type ThresholdSignerSoft struct {
	privateKeyShard *ted25519.KeyShare
	pubKey          ted25519.PublicKey
	threshold       int
	total           int
}

func NewThresholdSignerSoft(config *RuntimeConfig, id int, chainID string) (*ThresholdSignerSoft, error) {
	keyFile, err := config.KeyFileExistsCosigner(chainID)
	if err != nil {
		return nil, err
	}

	key, err := LoadCosignerEd25519Key(keyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading cosigner key: %s", err)
	}

	if key.ID != id {
		return nil, fmt.Errorf("key shard ID (%d) in (%s) does not match cosigner ID (%d)", key.ID, keyFile, id)
	}

	s := ThresholdSignerSoft{
		privateKeyShard: ted25519.NewKeyShare(byte(key.ID), reverseBytes(key.PrivateShard)),
		pubKey:          key.PubKey.Bytes(),
		threshold:       config.Config.ThresholdModeConfig.Threshold,
		total:           len(config.Config.ThresholdModeConfig.Cosigners),
	}

	return &s, nil
}

func (s *ThresholdSignerSoft) Type() string {
	return SignerTypeSoftSign
}

func (s *ThresholdSignerSoft) PubKey() []byte {
	return s.pubKey.Bytes()
}

func (s *ThresholdSignerSoft) Sign(nonces []Nonce, payload []byte) ([]byte, error) {
	nonceShare, noncePub, err := s.sumNonces(nonces)
	if err != nil {
		return nil, fmt.Errorf("failed to combine nonces: %w", err)
	}
	sig := ted25519.TSign(payload, s.privateKeyShard, s.pubKey, nonceShare, noncePub)
	return sig.Sig, nil
}

func (s *ThresholdSignerSoft) sumNonces(nonces []Nonce) (*ted25519.NonceShare, ted25519.PublicKey, error) {
	var nonceShare *ted25519.NonceShare
	var noncePub ted25519.PublicKey

	for _, n := range nonces {
		thisNonce := ted25519.NewNonceShare(byte(n.ID), n.Share)
		if nonceShare == nil {
			nonceShare = thisNonce
		} else {
			nonceShare = nonceShare.Add(thisNonce)
		}

		if len(noncePub) == 0 {
			noncePub = n.PubKey
		} else {
			noncePub = ted25519.GeAdd(noncePub, n.PubKey)
		}
	}

	return nonceShare, noncePub, nil
}

func (s *ThresholdSignerSoft) GenerateNonces() (Nonces, error) {
	noncePub, nonceShares, _, err := ted25519.GenerateSharedNonce(
		&ted25519.ShareConfiguration{T: s.threshold, N: s.total},
		s.privateKeyShard,
		s.pubKey,
		ted25519.Message{},
	)
	if err != nil {
		return Nonces{}, fmt.Errorf("failed to generate nonce shares: %w", err)
	}

	nonces := Nonces{
		Shares: make([][]byte, s.total),
		PubKey: noncePub,
	}

	for i, n := range nonceShares {
		nonces.Shares[i] = n.Value.Bytes()
	}

	return nonces, nil
}
