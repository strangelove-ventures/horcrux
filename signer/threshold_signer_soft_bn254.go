package signer

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	horcrux_bn254 "github.com/strangelove-ventures/horcrux/v3/signer/bn254"
)

var _ ThresholdSigner = &ThresholdSignerSoftBn254{}

type ThresholdSignerSoftBn254 struct {
	privateKey *big.Int
	pubKey     []byte
	threshold  uint8
	total      uint8
}

func NewThresholdSignerSoftBn254(key *CosignerKey, threshold, total uint8) (*ThresholdSignerSoftBn254, error) {
	privateKey := new(big.Int)
	privateKey = privateKey.SetBytes(key.PrivateShard)
	return &ThresholdSignerSoftBn254{
		privateKey: privateKey,
		pubKey:     key.PubKey,
		threshold:  threshold,
		total:      total,
	}, nil
}

func (s *ThresholdSignerSoftBn254) PubKey() []byte {
	return s.pubKey
}

func (s *ThresholdSignerSoftBn254) Sign(_ []Nonce, msg []byte) ([]byte, error) {
	sig, err := horcrux_bn254.SignWithShard(s.privateKey, msg)
	if err != nil {
		return nil, err
	}

	compressed := sig.Bytes()

	return compressed[:], nil
}

func (s *ThresholdSignerSoftBn254) CombineSignatures(signatures []PartialSignature) ([]byte, error) {
	var sigs = make([]*bn254.G2Affine, len(signatures))
	var points = make([]int64, len(signatures))
	for i, s := range signatures {
		sig := new(bn254.G2Affine)
		_, err := sig.SetBytes(s.Signature)
		if err != nil {
			return nil, err
		}

		sigs[i] = sig
		points[i] = int64(s.ID)
	}

	combinedSig := horcrux_bn254.CombineSignatures(sigs, points...)

	compressed := combinedSig.Bytes()

	return compressed[:], nil
}

func (s *ThresholdSignerSoftBn254) VerifySignature(msg, signature []byte) bool {
	return horcrux_bn254.PubKey(s.pubKey).VerifySignature(msg, signature)
}
