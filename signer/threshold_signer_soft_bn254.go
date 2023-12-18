package signer

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls" //nolint:staticcheck
)

var _ ThresholdSigner = &ThresholdSignerSoftBn254{}

type ThresholdSignerSoftBn254 struct {
	privateKey kyber.Scalar
	pubKey     kyber.Point
	threshold  uint8
	total      uint8

	suite *bn256.Suite
}

func NewThresholdSignerSoftBn254(key *CosignerKey, threshold, total uint8) (*ThresholdSignerSoftBn254, error) {
	suite := bn256.NewSuite()
	privateKey := suite.G2().Scalar().SetBytes(key.PrivateShard)
	pubKey := suite.G2().Point()
	if err := pubKey.UnmarshalBinary(key.PubKey); err != nil {
		return nil, err
	}
	return &ThresholdSignerSoftBn254{
		privateKey: privateKey,
		pubKey:     pubKey,
		threshold:  threshold,
		total:      total,
		suite:      suite,
	}, nil
}

func (s *ThresholdSignerSoftBn254) PubKey() []byte {
	pub, err := s.pubKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return pub
}

func (s *ThresholdSignerSoftBn254) Sign(_ []Nonce, payload []byte) ([]byte, error) {
	// nonceShare, noncePub, err := s.sumNonces(nonces)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to combine nonces: %w", err)
	// }

	return bls.Sign(s.suite, s.privateKey, payload)
}

// func (s *ThresholdSignerSoftBn254) sumNonces(nonces []Nonce) (tsed25519.Scalar, tsed25519.Element, error) {
// 	shareParts := make([]tsed25519.Scalar, len(nonces))
// 	publicKeys := make([]tsed25519.Element, len(nonces))

// 	for i, n := range nonces {
// 		shareParts[i] = n.Share
// 		publicKeys[i] = n.PubKey
// 	}

// 	nonceShare := tsed25519.AddScalars(shareParts)
// 	noncePub := tsed25519.AddElements(publicKeys)

// 	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
// 	if len(nonceShare) != 32 {
// 		return nil, nil, errors.New("ephemeral share is out of bounds")
// 	}

// 	var scalarBytes [32]byte
// 	copy(scalarBytes[:], nonceShare)
// 	if !edwards25519.ScMinimal(&scalarBytes) {
// 		return nil, nil, errors.New("ephemeral share is out of bounds")
// 	}

// 	return nonceShare, noncePub, nil
// }

// func GenerateNoncesBn254(threshold, total uint8) (Nonces, error) {
// 	secret := make([]byte, 32)
// 	if _, err := rand.Read(secret); err != nil {
// 		return Nonces{}, err
// 	}

// 	nonces := Nonces{
// 		PubKey: tsed25519.ScalarMultiplyBase(secret),
// 		Shares: make([][]byte, total),
// 	}

// 	shares := tsed25519.DealShares(secret, threshold, total)

// 	for i, sh := range shares {
// 		nonces.Shares[i] = sh
// 	}

// 	return nonces, nil
// }

func (s *ThresholdSignerSoftBn254) CombineSignatures(signatures []PartialSignature) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range signatures {
		i := sig.ID - 1

		point := s.suite.G1().Point()
		if err := point.UnmarshalBinary(sig.Signature); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= int(s.threshold) {
			break
		}
	}
	commit, err := share.RecoverCommit(s.suite.G1(), pubShares, int(s.threshold), int(s.total))
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (s *ThresholdSignerSoftBn254) VerifySignature(payload, signature []byte) bool {
	if err := bls.Verify(s.suite, s.pubKey, payload, signature); err != nil {
		fmt.Printf("Failed to verify signature: %v\n", err)
		return false
	}
	return true
}
