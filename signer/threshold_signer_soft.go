package signer

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometjson "github.com/cometbft/cometbft/libs/json"
	"gitlab.com/unit410/edwards25519"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// ThresholdSignerSoft implements the interface and signs the message for each local signer.
// ThresholdSignerSoft is the implementation of a soft sign signer at the local level.
type ThresholdSignerSoft struct {
	pubKeyBytes []byte
	key         CosignerEd25519Key
	rsaKey      CosignerRSAKey
	// total signers
	total     uint8
	threshold uint8
	// Height, Round, Step, Timestamp --> metadata
	hrsMeta map[HRSTKey]HrsMetadata

	pendingDiskWG sync.WaitGroup
}

// NewThresholdSignerSoft constructs a ThresholdSigner
// that signs using the local key share file.
func NewThresholdSignerSoft(key CosignerEd25519Key, rsaKey CosignerRSAKey, threshold, total uint8) ThresholdSigner {
	softSigner := &ThresholdSignerSoft{
		key:       key,
		rsaKey:    rsaKey,
		hrsMeta:   make(map[HRSTKey]HrsMetadata),
		total:     total,
		threshold: threshold,
	}

	// cache the public key bytes for signing operations.
	// Ensures casting else it will naturally panic.
	ed25519Key := softSigner.key.PubKey.(cometcryptoed25519.PubKey)
	softSigner.pubKeyBytes = make([]byte, len(ed25519Key))
	softSigner.pubKeyBytes = ed25519Key[:]

	return softSigner
}

func (softSigner *ThresholdSignerSoft) Stop() {
	softSigner.waitForSignStatesToFlushToDisk()
}

func (softSigner *ThresholdSignerSoft) waitForSignStatesToFlushToDisk() {
	softSigner.pendingDiskWG.Wait()
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) Type() string {
	return SignerTypeSoftSign
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) GetID() (int, error) {
	return softSigner.key.ID, nil
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) Sign(
	req CosignerSignRequest, m *LastSignStateWrapper) (CosignerSignResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	res := CosignerSignResponse{}
	lss := m.LastSignState

	hrst, err := UnpackHRST(req.SignBytes)
	if err != nil {
		return res, err
	}

	sameHRS, err := lss.CheckHRS(hrst)
	if err != nil {
		return res, err
	}
	// If the HRS is the same the sign bytes may still differ by timestamp
	// It is ok to re-sign a different timestamp if that is the only difference in the sign bytes
	// same HRS, and only differ by timestamp  its ok to sign again
	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			res.NoncePublic = lss.NoncePublic
			res.Signature = lss.Signature
			return res, nil
		} else if err := lss.OnlyDifferByTimestamp(req.SignBytes); err != nil {
			return res, err // same HRS, and only differ by timestamp  its ok to sign again
		}
	}

	meta, ok := softSigner.hrsMeta[hrst]
	if !ok {
		return res, errors.New("no metadata at HRS")
	}

	shareParts := make([]tsed25519.Scalar, 0)
	publicKeys := make([]tsed25519.Element, 0)

	// calculate secret and public keys
	for _, c := range meta.Cosigners {
		if len(c.Share) == 0 {
			continue
		}
		shareParts = append(shareParts, c.Share)
		publicKeys = append(publicKeys, c.NoncePublicKey)
	}

	nonceShare := tsed25519.AddScalars(shareParts)
	noncePublic := tsed25519.AddElements(publicKeys)

	// check bounds for nonce share to avoid passing out of bounds valids to SignWithShare

	if len(nonceShare) != 32 {
		return res, errors.New("nonce share is out of bounds")
	}

	var scalarBytes [32]byte
	copy(scalarBytes[:], nonceShare)
	if !edwards25519.ScMinimal(&scalarBytes) {
		return res, errors.New("nonce share is out of bounds")
	}

	sig := tsed25519.SignWithShare(
		req.SignBytes, softSigner.key.PrivateShard, nonceShare, softSigner.pubKeyBytes, noncePublic)

	m.LastSignState.NoncePublic = noncePublic
	err = m.LastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, &softSigner.pendingDiskWG)
	if err != nil {
		var isSameHRSError *SameHRSError
		if !errors.As(err, &isSameHRSError) {
			return res, err
		}
	}

	for existingKey := range softSigner.hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.HRSKey().LessThan(hrst.HRSKey()) {
			delete(softSigner.hrsMeta, existingKey)
		}
	}

	res.NoncePublic = noncePublic
	res.Signature = sig
	return res, nil
}

// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) DealShares(
	req CosignerGetNonceRequest) (HrsMetadata, error) {
	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrsKey]
	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret:    secret,
		Cosigners: make([]CosignerMetadata, softSigner.total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, softSigner.threshold, softSigner.total)

	softSigner.hrsMeta[hrsKey] = meta

	return meta, nil
}

// Get the nonces for all cosigners.
// The nonce is encrypted and signed for the receiver.
// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) GetNonce(
	req CosignerGetNonceRequest, m *LastSignStateWrapper, pubKeys map[int]CosignerRSAPubKey) (
	CosignerNonce, error) {

	res := CosignerNonce{}

	// protects the meta map
	m.mu.Lock()
	defer m.mu.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := softSigner.DealShares(CosignerGetNonceRequest{
			ChainID:   req.ChainID,
			Height:    req.Height,
			Round:     req.Round,
			Step:      req.Step,
			Timestamp: req.Timestamp,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		softSigner.hrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Cosigners[softSigner.key.ID-1].Share = meta.DealtShares[softSigner.key.ID-1]
	meta.Cosigners[softSigner.key.ID-1].NoncePublicKey = ourEphPublicKey

	// grab the info for the ID being requested
	pubKey, ok := pubKeys[req.ID]
	if !ok {
		return res, errors.New("unknown cosigner ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &pubKey.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = softSigner.key.ID
	res.PubKey = ourEphPublicKey
	res.Share = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity

	jsonBytes, err := cometjson.Marshal(res)

	if err != nil {
		return res, err
	}

	digest := sha256.Sum256(jsonBytes)
	signature, err := rsa.SignPSS(rand.Reader, &softSigner.rsaKey.RSAKey, crypto.SHA256, digest[:], nil)

	if err != nil {
		return res, err
	}

	res.Signature = signature

	res.DestinationID = req.ID

	return res, nil
}

// Store a nonce provided by another cosigner
// Implements ThresholdSigner
func (softSigner *ThresholdSignerSoft) SetNonce(
	req CosignerSetNonceRequest, m *LastSignStateWrapper, pubKeys map[int]CosignerRSAPubKey) error {

	// Verify the source signature
	if req.Signature == nil {
		return errors.New("signature field is required")
	}

	digestMsg := CosignerNonce{
		SourceID: req.SourceID,
		PubKey:   req.PubKey,
		Share:    req.Share,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return err
	}

	digest := sha256.Sum256(digestBytes)
	pubKey, ok := pubKeys[req.SourceID]

	if !ok {
		return fmt.Errorf("unknown cosigner: %d", req.SourceID)
	}

	err = rsa.VerifyPSS(&pubKey.PublicKey, crypto.SHA256, digest[:], req.Signature, nil)
	if err != nil {
		return err
	}

	// protects the meta map
	m.mu.Lock()
	defer m.mu.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := softSigner.hrsMeta[hrst] // generate metadata placeholder, softSigner.HrsMeta[hrst] is non-addressable
	if !ok {
		newMeta, err := softSigner.DealShares(CosignerGetNonceRequest{
			ChainID: req.ChainID,
			Height:  req.Height,
			Round:   req.Round,
			Step:    req.Step,
		})
		if err != nil {
			return err
		}
		meta = newMeta
		softSigner.hrsMeta[hrst] = meta // updates the metadata placeholder
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &softSigner.rsaKey.RSAKey, req.Share, nil)
	if err != nil {
		return err
	}
	// set slot
	// Share & NoncePublicKey is a SLICE so its a valid change of the shared struct softSigner!
	meta.Cosigners[req.SourceID-1].Share = sharePart
	meta.Cosigners[req.SourceID-1].NoncePublicKey = req.PubKey

	return nil
}
