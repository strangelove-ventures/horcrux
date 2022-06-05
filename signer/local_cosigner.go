package signer

import (
	"crypto/rsa"
	"time"

	"sync"

	tmCryptoEd25519 "github.com/tendermint/tendermint/crypto/ed25519"
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

// TODO temporary aliasing ThresholdEd25519Signature
type thresholdEd25519Signature = *LocalSoftSignThresholdEd25519Signature

type LocalCosigner struct {
	/*
		// key         CosignerKey		- moved to threshold
		// rsaKey      rsa.PrivateKey	- moved to threshold
		// threshold uint8 				- moved to threshold

		// Height, Round, Step -> metadata 	- moved to threshold
		//hrsMeta map[HRSTKey]HrsMetadata 	- moved to threshold

	*/
	LastSignStateStruct *LastSignStateStruct
	pubKeyBytes         []byte
	total               uint8
	address             string
	Peers               map[int]CosignerPeer
	localsigner         thresholdEd25519Signature
}

func NewLocalCosigner(cfg LocalCosignerConfig) *LocalCosigner {
	// TODO: localsigner should be passed as a parameter in the cfg rather than constructed here.
	// We could add a method in the new LocalSoftSignThresholdEd25519Signature file to return this
	// config such as func NewLocalThresholdEd25519Signature(key CosignerKey, rsaKey PrivateKey, total, threshold int)
	// LocalSoftSignThresholdEd25519Signature { which could then be called and added to the LocalCosignerConfig
	//	from cmd/horcrux/cmd/cosigner.go

	// localsigner := LocalSoftSignThresholdEd25519Signature{
	// 	Key:       cfg.CosignerKey,
	// 	RsaKey:    cfg.RsaKey,
	// 	HrsMeta:   make(map[HRSTKey]HrsMetadata),
	// 	Total:     cfg.Total,
	// 	Threshold: cfg.Threshold,
	// }

	LastSignStateStruct := LastSignStateStruct{
		LastSignStateMutex: sync.Mutex{},
		LastSignState:      cfg.SignState,
	}
	cosigner := &LocalCosigner{
		//key:         cfg.CosignerKey,
		//pubKeyBytes: []byte{},
		LastSignStateStruct: &LastSignStateStruct,
		total:               cfg.Total,
		address:             cfg.Address,
		//localsigner:         &localsigner,
		localsigner: NewLocalSoftSignThresholdEd25519Signature(cfg),
		Peers:       make(map[int]CosignerPeer),
	}

	// TODO: Delete this print statements:
	// fmt.Println("\n", "LocalCosigner")
	// fmt.Printf("%+v\n", cosigner)

	// fmt.Println("\n", "Local Signer")
	// fmt.Printf("%+v\n", cosigner.localsigner)

	for _, peer := range cfg.Peers {
		cosigner.Peers[peer.ID] = peer
	}

	// cache the public key bytes for signing operations
	switch ed25519Key := cosigner.localsigner.Key.PubKey.(type) {
	case tmCryptoEd25519.PubKey:
		cosigner.localsigner.PubKeyBytes = make([]byte, len(ed25519Key))
		copy(cosigner.localsigner.PubKeyBytes, ed25519Key[:])
		cosigner.pubKeyBytes = cosigner.localsigner.PubKeyBytes
	default:
		panic("Not an ed25519 public key")
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

/*
// sign the sign request using the cosigner's share
// Return the signed bytes or an error
// Implements cosigner interface # Comment is this really true? Doesnt it implement ThresholdEd25519Signature
func (cosigner *LocalCosigner) sign(req CosignerSignRequest) (CosignerSignResponse, error) {
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	res := CosignerSignResponse{}
	lss := cosigner.lastSignState

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
	if sameHRS {
		if bytes.Equal(req.SignBytes, lss.SignBytes) {
			res.EphemeralPublic = lss.EphemeralPublic
			res.Signature = lss.Signature
			return res, nil
		} else if err := lss.OnlyDifferByTimestamp(req.SignBytes); err != nil {
			return res, err
		}

		// same HRS, and only differ by timestamp - ok to sign again
	}

	meta, ok := cosigner.hrsMeta[hrst]
	if !ok {
		return res, errors.New("no metadata at HRS")
	}

	shareParts := make([]tsed25519.Scalar, 0)
	publicKeys := make([]tsed25519.Element, 0)

	// calculate secret and public keys
	for _, peer := range meta.Peers {
		if len(peer.Share) == 0 {
			continue
		}
		shareParts = append(shareParts, peer.Share)
		publicKeys = append(publicKeys, peer.EphemeralSecretPublicKey)
	}

	ephemeralShare := tsed25519.AddScalars(shareParts)
	ephemeralPublic := tsed25519.AddElements(publicKeys)

	// check bounds for ephemeral share to avoid passing out of bounds valids to SignWithShare
	{
		if len(ephemeralShare) != 32 {
			return res, errors.New("ephemeral share is out of bounds")
		}

		var scalarBytes [32]byte
		copy(scalarBytes[:], ephemeralShare)
		if !edwards25519.ScMinimal(&scalarBytes) {
			return res, errors.New("ephemeral share is out of bounds")
		}
	}

	sig := tsed25519.SignWithShare(
		req.SignBytes, cosigner.key.ShareKey, ephemeralShare, cosigner.pubKeyBytes, ephemeralPublic)

	cosigner.lastSignState.EphemeralPublic = ephemeralPublic
	err = cosigner.lastSignState.Save(SignStateConsensus{
		Height:    hrst.Height,
		Round:     hrst.Round,
		Step:      hrst.Step,
		Signature: sig,
		SignBytes: req.SignBytes,
	}, nil)

	if err != nil {
		if _, isSameHRSError := err.(*SameHRSError); !isSameHRSError {
			return res, err
		}
	}

	for existingKey := range cosigner.hrsMeta {
		// delete any HRS lower than our signed level
		// we will not be providing parts for any lower HRS
		if existingKey.Less(hrst) {
			delete(cosigner.hrsMeta, existingKey)
		}
	}

	res.EphemeralPublic = ephemeralPublic
	res.Signature = sig
	return res, nil
}

// Implements ThresholdEd25519Signature interface
func (cosigner *LocalCosigner) dealShares(req CosignerGetEphemeralSecretPartRequest) (HrsMetadata, error) {
	hrsKey := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.hrsMeta[hrsKey]

	if ok {
		return meta, nil
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return HrsMetadata{}, err
	}

	meta = HrsMetadata{
		Secret: secret,
		Peers:  make([]PeerMetadata, cosigner.total),
	}

	// split this secret with shamirs
	// !! dealt shares need to be saved because dealing produces different shares each time!
	meta.DealtShares = tsed25519.DealShares(meta.Secret, cosigner.threshold, cosigner.total)

	cosigner.hrsMeta[hrsKey] = meta

	return meta, nil

}

// Get the ephemeral secret part for an ephemeral share
// The ephemeral secret part is encrypted for the receiver
// Implements ThresholdEd25519Signature interface
func (cosigner *LocalCosigner) getEphemeralSecretPart(
	req CosignerGetEphemeralSecretPartRequest) (CosignerEphemeralSecretPart, error) {
	res := CosignerEphemeralSecretPart{}

	// protects the meta map
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			Height:    req.Height,
			Round:     req.Round,
			Step:      req.Step,
			Timestamp: req.Timestamp,
		})

		if err != nil {
			return res, err
		}

		meta = newMeta
		cosigner.hrsMeta[hrst] = meta
	}

	ourEphPublicKey := tsed25519.ScalarMultiplyBase(meta.Secret)

	// set our values
	meta.Peers[cosigner.key.ID-1].Share = meta.DealtShares[cosigner.key.ID-1]
	meta.Peers[cosigner.key.ID-1].EphemeralSecretPublicKey = ourEphPublicKey

	// grab the peer info for the ID being requested
	peer, ok := cosigner.peers[req.ID]
	if !ok {
		return res, errors.New("unknown peer ID")
	}

	sharePart := meta.DealtShares[req.ID-1]

	// use RSA public to encrypt user's share part
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &peer.PublicKey, sharePart, nil)
	if err != nil {
		return res, err
	}

	res.SourceID = cosigner.key.ID
	res.SourceEphemeralSecretPublicKey = ourEphPublicKey
	res.EncryptedSharePart = encrypted

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity
	{
		jsonBytes, err := tmJson.Marshal(res)

		if err != nil {
			return res, err
		}

		digest := sha256.Sum256(jsonBytes)
		signature, err := rsa.SignPSS(rand.Reader, &cosigner.rsaKey, crypto.SHA256, digest[:], nil)
		if err != nil {
			return res, err
		}

		res.SourceSig = signature
	}

	res.DestinationID = req.ID

	return res, nil
}

// Store an ephemeral secret share part provided by another cosigner
// Implements ThresholdEd25519Signature interface
func (cosigner *LocalCosigner) setEphemeralSecretPart(req CosignerSetEphemeralSecretPartRequest) error {

	// Verify the source signature
	{
		if req.SourceSig == nil {
			return errors.New("SourceSig field is required")
		}

		digestMsg := CosignerEphemeralSecretPart{}
		digestMsg.SourceID = req.SourceID
		digestMsg.SourceEphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
		digestMsg.EncryptedSharePart = req.EncryptedSharePart

		digestBytes, err := tmJson.Marshal(digestMsg)
		if err != nil {
			return err
		}

		digest := sha256.Sum256(digestBytes)
		peer, ok := cosigner.peers[req.SourceID]

		if !ok {
			return fmt.Errorf("unknown cosigner: %d", req.SourceID)
		}

		peerPub := peer.PublicKey
		err = rsa.VerifyPSS(&peerPub, crypto.SHA256, digest[:], req.SourceSig, nil)
		if err != nil {
			return err
		}
	}

	// protects the meta map
	cosigner.lastSignStateMutex.Lock()
	defer cosigner.lastSignStateMutex.Unlock()

	hrst := HRSTKey{
		Height:    req.Height,
		Round:     req.Round,
		Step:      req.Step,
		Timestamp: req.Timestamp.UnixNano(),
	}

	meta, ok := cosigner.hrsMeta[hrst]
	// generate metadata placeholder
	if !ok {
		newMeta, err := cosigner.dealShares(CosignerGetEphemeralSecretPartRequest{
			Height: req.Height,
			Round:  req.Round,
			Step:   req.Step,
		})

		if err != nil {
			return err
		}

		meta = newMeta
		cosigner.hrsMeta[hrst] = meta
	}

	// decrypt share
	sharePart, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &cosigner.rsaKey, req.EncryptedSharePart, nil)
	if err != nil {
		return err
	}

	// set slot
	meta.Peers[req.SourceID-1].Share = sharePart
	meta.Peers[req.SourceID-1].EphemeralSecretPublicKey = req.SourceEphemeralSecretPublicKey
	return nil
}
*/
