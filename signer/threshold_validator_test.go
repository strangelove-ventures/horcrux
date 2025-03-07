package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"path/filepath"
	"sync"
	"time"

	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	cometcryptobn254 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/bn254"
	cometcryptoed25519 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	horcruxbn254 "github.com/strangelove-ventures/horcrux/v3/signer/bn254"
	"github.com/strangelove-ventures/horcrux/v3/types"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

func TestThresholdValidator2of2Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 2, 2)
}

func TestThresholdValidator2of2Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 2, 2)
}

func TestThresholdValidator3of3Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 3, 3)
}

func TestThresholdValidator3of3Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 3, 3)
}

func TestThresholdValidator2of3Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 2, 3)
}

func TestThresholdValidator2of3Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 2, 3)
}

func TestThresholdValidator3of5Ed25519(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeEd25519, 3, 5)
}

func TestThresholdValidator3of5Bn254(t *testing.T) {
	testThresholdValidator(t, CosignerKeyTypeBn254, 3, 5)
}

func loadKeyForLocalCosigner(
	cosigner *LocalCosigner,
	keyType string,
	pubKey []byte,
	chainID string,
	privateShard []byte,
) error {
	key := &CosignerKey{
		KeyType:      keyType,
		PubKey:       pubKey,
		PrivateShard: privateShard,
		ID:           cosigner.GetID(),
	}

	keyBz, err := json.Marshal(key)
	if err != nil {
		return err
	}

	return os.WriteFile(cosigner.config.KeyFilePathCosigner(chainID), keyBz, 0600)
}

func testThresholdValidator(t *testing.T, keyType string, threshold, total uint8) {
	cosigners := getTestLocalCosigners(t, keyType, threshold, total)

	thresholdCosigners := make([]Cosigner, 0, threshold-1)

	for i, cosigner := range cosigners {
		require.Equal(t, i+1, cosigner.GetID())

		if i != 0 && len(thresholdCosigners) != int(threshold)-1 {
			thresholdCosigners = append(thresholdCosigners, cosigner)
		}
	}

	leader := &MockLeader{id: 1}

	validator := NewThresholdValidator(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cosigners[0].config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer validator.Stop()

	leader.leader = validator

	ctx := context.Background()

	err := validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	block := types.ProposalToBlock(&proposal)

	signature, _, _, err := validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	signBytes, _, err := validator.myCosigner.SignBytes(testChainID, block)
	require.NoError(t, err)

	require.True(t, validator.myCosigner.VerifySignature(testChainID, signBytes, signature))

	firstSignature := signature

	require.Len(t, firstSignature, 64)

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	block = types.ProposalToBlock(&proposal)

	validator.nonceCache.LoadN(ctx, 1)

	// should be able to sign same proposal with only differing timestamp
	_, _, _, err = validator.Sign(ctx, testChainID, block)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed

	randHash := make([]byte, 32)
	_, err = rand.Read(randHash)
	require.NoError(t, err)

	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	validator.nonceCache.LoadN(ctx, 1)

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	signature, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, signature))

	proposal.Round = 19

	validator.nonceCache.LoadN(ctx, 1)

	// should not be able to sign lower than highest signed
	_, _, _, err = validator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.Error(t, err, "double sign!")

	validator.nonceCache.LoadN(ctx, 1)

	// lower LSS should sign for different chain ID
	_, _, _, err = validator.Sign(ctx, testChainID2, types.ProposalToBlock(&proposal))
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewThresholdValidator(
		slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cosigners[0].config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer newValidator.Stop()

	newValidator.nonceCache.LoadN(ctx, 1)

	_, _, _, err = newValidator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
	require.Error(t, err, "double sign!")

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     21,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	proposalClone := proposal
	proposalClone.Timestamp = proposal.Timestamp.Add(2 * time.Millisecond)

	proposalClone2 := proposal
	proposalClone2.Timestamp = proposal.Timestamp.Add(4 * time.Millisecond)

	var eg errgroup.Group

	newValidator.nonceCache.LoadN(ctx, 3)

	eg.Go(func() error {
		_, _, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(&proposal))
		return err
	})
	eg.Go(func() error {
		_, _, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(&proposalClone))
		return err
	})
	eg.Go(func() error {
		_, _, _, err := newValidator.Sign(ctx, testChainID, types.ProposalToBlock(&proposalClone2))
		return err
	})
	// signing higher block now should succeed
	err = eg.Wait()
	require.NoError(t, err)

	// Sign some votes from multiple sentries
	for i := 2; i < 50; i++ {
		newValidator.nonceCache.LoadN(ctx, 3)

		prevote := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrevoteType,
			Timestamp: time.Now(),
		}

		prevoteClone := prevote
		prevoteClone.Timestamp = prevote.Timestamp.Add(2 * time.Millisecond)

		prevoteClone2 := prevote
		prevoteClone2.Timestamp = prevote.Timestamp.Add(4 * time.Millisecond)

		eg.Go(func() error {
			start := time.Now()
			_, _, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(&prevote))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(&prevoteClone))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})
		eg.Go(func() error {
			start := time.Now()
			_, _, _, err := newValidator.Sign(ctx, testChainID, types.VoteToBlock(&prevoteClone2))
			t.Log("Sign time", "duration", time.Since(start))
			return err
		})

		err = eg.Wait()
		require.NoError(t, err)

		blockIDHash := mimc.NewMiMC()

		blockIDHash.Write([]byte("01234567890123456789012345678901"))

		precommit := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			BlockID:   cometproto.BlockID{Hash: blockIDHash.Sum(nil)},
			Type:      cometproto.PrecommitType,
			Timestamp: time.Now(),
			Extension: []byte("test"),
		}

		precommitClone := precommit
		precommitClone.Timestamp = precommit.Timestamp.Add(2 * time.Millisecond)

		precommitClone2 := precommit
		precommitClone2.Timestamp = precommit.Timestamp.Add(4 * time.Millisecond)

		newValidator.nonceCache.LoadN(ctx, mrand.Intn(7)) //nolint:gosec

		pubKey, err := newValidator.myCosigner.GetPubKey(testChainID)
		require.NoError(t, err)

		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			block := types.VoteToBlock(&precommit)
			sig, voteExtSig, _, err := newValidator.Sign(ctx, testChainID, block)
			if err != nil {
				return err
			}

			signBytes, voteExtSignBytes, err := newValidator.myCosigner.SignBytes(testChainID, block)
			if err != nil {
				return err
			}

			if !pubKey.VerifySignature(signBytes, sig) {
				return fmt.Errorf("signature verification failed")
			}

			if !pubKey.VerifySignature(voteExtSignBytes, voteExtSig) {
				return fmt.Errorf("vote extension signature verification failed")
			}

			return nil
		})
		eg.Go(func() error {
			start := time.Now()
			t.Log("Sign time", "duration", time.Since(start))
			block := types.VoteToBlock(&precommitClone)
			sig, voteExtSig, _, err := newValidator.Sign(ctx, testChainID, block)
			if err != nil {
				return err
			}

			signBytes, voteExtSignBytes, err := newValidator.myCosigner.SignBytes(testChainID, block)
			if err != nil {
				return err
			}

			if !pubKey.VerifySignature(signBytes, sig) {
				return fmt.Errorf("signature verification failed")
			}

			if !pubKey.VerifySignature(voteExtSignBytes, voteExtSig) {
				return fmt.Errorf("vote extension signature verification failed")
			}

			return nil
		})
		eg.Go(func() error {
			start := time.Now()
			block := types.VoteToBlock(&precommitClone2)
			sig, voteExtSig, _, err := newValidator.Sign(ctx, testChainID, block)
			t.Log("Sign time", "duration", time.Since(start))
			if err != nil {
				return err
			}

			signBytes, voteExtSignBytes, err := newValidator.myCosigner.SignBytes(testChainID, block)
			if err != nil {
				return err
			}

			if !pubKey.VerifySignature(signBytes, sig) {
				return fmt.Errorf("signature verification failed")
			}

			if !pubKey.VerifySignature(voteExtSignBytes, voteExtSig) {
				return fmt.Errorf("vote extension signature verification failed")
			}

			return nil
		})

		err = eg.Wait()
		require.NoError(t, err)
	}
}

func getTestLocalCosigners(t *testing.T, keyType string, threshold, total uint8) []*LocalCosigner {
	eciesKeys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	cosigners := make([]*LocalCosigner, total)

	for i := uint8(0); i < total; i++ {
		eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		eciesKeys[i] = eciesKey

		pubKeys[i] = &eciesKey.PublicKey
	}

	var (
		pubKey     []byte
		privShards = make([][]byte, total)
	)

	switch keyType {
	case CosignerKeyTypeEd25519:
		privateKey := cometcryptoed25519.GenPrivKey()
		privKeyBytes := privateKey[:]
		privShardsEd25519 := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)
		for i := range privShardsEd25519 {
			privShards[i] = privShardsEd25519[i][:]
		}
		pubKey = privateKey.PubKey().Bytes()
	case CosignerKeyTypeBn254:
		privateKey := cometcryptobn254.GenPrivKey()
		_, privShardsBn254 := horcruxbn254.GenFromSecret(privateKey.Bytes(), threshold, total)
		for i := range privShardsBn254 {
			privShards[i] = privShardsBn254[i].Bytes()
		}
		pubKey = privateKey.PubKey().Bytes()
	}

	tmpDir := t.TempDir()

	cosignersConfig := make(CosignersConfig, total)

	for i := range pubKeys {
		cosignersConfig[i] = CosignerConfig{
			ShardID: i + 1,
		}
	}

	for i := range pubKeys {
		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner_%d", i+1))
		err := os.MkdirAll(cosignerDir, 0777)
		require.NoError(t, err)

		cosignerConfig := &RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
			Config: Config{
				ThresholdModeConfig: &ThresholdModeConfig{
					Threshold: int(threshold),
					Cosigners: cosignersConfig,
				},
			},
		}

		cosigner := NewLocalCosigner(
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			cosignerConfig,
			NewCosignerSecurityECIES(
				CosignerECIESKey{
					ID:        i + 1,
					ECIESKey:  eciesKeys[i],
					ECIESPubs: pubKeys,
				},
			),
			"",
		)
		require.NoError(t, err)

		cosigners[i] = cosigner

		err = loadKeyForLocalCosigner(cosigner, keyType, pubKey, testChainID, privShards[i])
		require.NoError(t, err)

		err = loadKeyForLocalCosigner(cosigner, keyType, pubKey, testChainID2, privShards[i])
		require.NoError(t, err)
	}

	return cosigners
}

func testThresholdValidatorLeaderElection(t *testing.T, threshold, total uint8) {
	cosigners := getTestLocalCosigners(t, CosignerKeyTypeEd25519, threshold, total)

	thresholdValidators := make([]*ThresholdValidator, 0, total)
	var leader *ThresholdValidator
	leaders := make([]*MockLeader, total)

	ctx := context.Background()

	for i, cosigner := range cosigners {
		peers := make([]Cosigner, 0, len(cosigners)-1)
		for j, otherCosigner := range cosigners {
			if i != j {
				peers = append(peers, otherCosigner)
			}
		}
		leaders[i] = &MockLeader{id: cosigner.GetID(), leader: leader}
		tv := NewThresholdValidator(
			slog.New(slog.NewTextHandler(os.Stdout, nil)),
			cosigner.config,
			int(threshold),
			time.Second,
			1,
			cosigner,
			peers,
			leaders[i],
		)
		if i == 0 {
			leader = tv
			leaders[i].leader = tv
		}

		thresholdValidators = append(thresholdValidators, tv)
		defer tv.Stop()

		err := tv.LoadSignStateIfNecessary(testChainID)
		require.NoError(t, err)

		tv.Start(ctx)
	}

	quit := make(chan bool)
	done := make(chan bool)

	go func() {
		for i := 0; true; i++ {
			select {
			case <-quit:
				done <- true
				return
			default:
			}
			// simulate leader election
			for _, l := range leaders {
				l.SetLeader(nil)
			}
			t.Log("No leader")

			// time without a leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

			newLeader := thresholdValidators[i%len(thresholdValidators)]
			for _, l := range leaders {
				l.SetLeader(newLeader)
			}
			t.Logf("New leader: %d", newLeader.myCosigner.GetID())

			// time with new leader
			time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec
		}
	}()

	// sign 20 blocks (proposal, prevote, precommit)
	for i := 0; i < 20; i++ {
		var wg sync.WaitGroup
		wg.Add(len(thresholdValidators))
		var mu sync.Mutex
		success := false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				proposal := cometproto.Proposal{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.ProposalType,
				}

				block := types.ProposalToBlock(&proposal)

				signature, _, _, err := tv.Sign(ctx, testChainID, block)
				if err != nil {
					t.Log("Proposal sign failed", "error", err)
					return
				}

				signBytes, _, err := tv.myCosigner.SignBytes(testChainID, block)
				if err != nil {
					t.Log("Proposal sign bytes failed", "error", err)
					return
				}

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("Proposal signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 1)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				preVote := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrevoteType,
				}

				block := types.VoteToBlock(&preVote)

				signature, _, _, err := tv.Sign(ctx, testChainID, block)
				if err != nil {
					t.Log("PreVote sign failed", "error", err)
					return
				}

				signBytes, _, err := tv.myCosigner.SignBytes(testChainID, block)
				if err != nil {
					t.Log("PreVote sign bytes failed", "error", err)
					return
				}

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("PreVote signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()
		require.True(t, success) // at least one should succeed so that the block is not missed.
		wg.Add(len(thresholdValidators))
		success = false
		for _, tv := range thresholdValidators {
			tv := tv

			tv.nonceCache.LoadN(ctx, 2)

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				time.Sleep(time.Duration(mrand.Intn(50)+100) * time.Millisecond) //nolint:gosec

				var extension = []byte{0x1, 0x2, 0x3}

				blockIDHash := sha256.New()
				blockIDHash.Write([]byte("something"))

				preCommit := cometproto.Vote{
					Height:    1 + int64(i),
					Round:     1,
					BlockID:   cometproto.BlockID{Hash: blockIDHash.Sum(nil)},
					Type:      cometproto.PrecommitType,
					Extension: extension,
				}

				block := types.VoteToBlock(&preCommit)

				signature, voteExtSignature, _, err := tv.Sign(ctx, testChainID, block)
				if err != nil {
					t.Log("PreCommit sign failed", "error", err)
					return
				}

				signBytes, voteExtSignBytes, err := tv.myCosigner.SignBytes(testChainID, block)
				if err != nil {
					t.Log("PreCommit sign bytes failed", "error", err)
					return
				}

				sig := make([]byte, len(signature))
				copy(sig, signature)

				if !tv.myCosigner.VerifySignature(testChainID, signBytes, sig) {
					t.Log("PreCommit signature verification failed")
					return
				}

				voteExtSig := make([]byte, len(voteExtSignature))
				copy(voteExtSig, voteExtSignature)

				pubKey, err := tv.myCosigner.GetPubKey(testChainID)
				if err != nil {
					t.Log("PreCommit get pub key failed", "error", err)
					return
				}

				if !pubKey.VerifySignature(voteExtSignBytes, voteExtSig) {
					t.Log("PreCommit vote extension signature verification failed")
					return
				}

				mu.Lock()
				defer mu.Unlock()
				success = true
			}()
		}

		wg.Wait()

		require.True(t, success) // at least one should succeed so that the block is not missed.
	}

	quit <- true
	<-done
}

func TestThresholdValidatorLeaderElection2of3(t *testing.T) {
	testThresholdValidatorLeaderElection(t, 2, 3)
}
