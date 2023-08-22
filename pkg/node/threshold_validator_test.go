package node

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/pkg/pcosigner"

	"os"
	"testing"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometrand "github.com/cometbft/cometbft/libs/rand"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	comet "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
	"golang.org/x/sync/errgroup"
)

const (
	testChainID  = "chain-1"
	testChainID2 = "chain-2"
	bitSize      = 4096
)

func TestThresholdValidator2of2(t *testing.T) {
	testThresholdValidator(t, 2, 2)
}

func TestThresholdValidator3of3(t *testing.T) {
	testThresholdValidator(t, 3, 3)
}

func TestThresholdValidator2of3(t *testing.T) {
	testThresholdValidator(t, 2, 3)
}

func TestThresholdValidator3of5(t *testing.T) {
	testThresholdValidator(t, 3, 5)
}

func loadKeyForLocalCosigner(
	cosigner *pcosigner.LocalCosigner,
	pubKey cometcrypto.PubKey,
	chainID string,
	privateShard []byte,
) error {
	key := pcosigner.CosignerEd25519Key{
		PubKey:       pubKey,
		PrivateShard: privateShard,
		ID:           cosigner.GetID(),
	}

	keyBz, err := key.MarshalJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(cosigner.Config.KeyFilePathCosigner(chainID), keyBz, 0600)
}

func testThresholdValidator(t *testing.T, threshold, total uint8) {
	cosigners, pubKey := getTestLocalCosigners(t, threshold, total)

	thresholdCosigners := make([]pcosigner.ICosigner, 0, threshold-1)

	for i, cosigner := range cosigners {
		require.Equal(t, i+1, cosigner.GetID())

		if i != 0 && len(thresholdCosigners) != int(threshold)-1 {
			thresholdCosigners = append(thresholdCosigners, cosigner)
		}
	}

	leader := &MockLeader{id: 1}

	validator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigners[0].Config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer validator.Stop()

	leader.leader = validator

	err := validator.LoadSignStateIfNecessary(testChainID)
	require.NoError(t, err)

	proposal := cometproto.Proposal{
		Height: 1,
		Round:  20,
		Type:   cometproto.ProposalType,
	}

	signBytes := comet.ProposalSignBytes(testChainID, &proposal)

	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, pubKey.VerifySignature(signBytes, proposal.Signature))

	firstSignature := proposal.Signature

	require.Len(t, firstSignature, 64)

	proposal = cometproto.Proposal{
		Height:    1,
		Round:     20,
		Type:      cometproto.ProposalType,
		Timestamp: time.Now(),
	}

	// should be able to sign same proposal with only differing timestamp
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	// construct different block ID for proposal at same height as highest signed
	randHash := cometrand.Bytes(tmhash.Size)
	blockID := cometproto.BlockID{Hash: randHash,
		PartSetHeader: cometproto.PartSetHeader{Total: 5, Hash: randHash}}

	proposal = cometproto.Proposal{
		Height:  1,
		Round:   20,
		Type:    cometproto.ProposalType,
		BlockID: blockID,
	}

	// different than single-signer mode, threshold mode will be successful for this,
	// but it will return the same signature as before.
	err = validator.SignProposal(testChainID, &proposal)
	require.NoError(t, err)

	require.True(t, bytes.Equal(firstSignature, proposal.Signature))

	proposal = cometproto.Proposal{
		Height: 1,
		Round:  19,
		Type:   cometproto.ProposalType,
	}

	// should not be able to sign lower than highest signed
	err = validator.SignProposal(testChainID, &proposal)
	require.Error(t, err, "double sign!")

	// lower LSS should sign for different chain ID
	err = validator.SignProposal(testChainID2, &proposal)
	require.NoError(t, err)

	// reinitialize validator to make sure new runtime will not allow double sign
	newValidator := NewThresholdValidator(
		cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
		cosigners[0].Config,
		int(threshold),
		time.Second,
		1,
		cosigners[0],
		thresholdCosigners,
		leader,
	)
	defer newValidator.Stop()

	err = newValidator.SignProposal(testChainID, &proposal)
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

	eg.Go(func() error {
		return newValidator.SignProposal(testChainID, &proposal)
	})
	eg.Go(func() error {
		return newValidator.SignProposal(testChainID, &proposalClone)
	})
	eg.Go(func() error {
		return newValidator.SignProposal(testChainID, &proposalClone2)
	})
	// signing higher block now should succeed
	err = eg.Wait()
	require.NoError(t, err)

	// Sign some votes from multiple sentries
	for i := 2; i < 50; i++ {
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
			return newValidator.SignVote(testChainID, &prevote)
		})
		eg.Go(func() error {
			return newValidator.SignVote(testChainID, &prevoteClone)
		})
		eg.Go(func() error {
			return newValidator.SignVote(testChainID, &prevoteClone2)
		})

		err = eg.Wait()
		require.NoError(t, err)

		precommit := cometproto.Vote{
			Height:    int64(i),
			Round:     0,
			Type:      cometproto.PrecommitType,
			Timestamp: time.Now(),
		}

		precommitClone := precommit
		precommitClone.Timestamp = precommit.Timestamp.Add(2 * time.Millisecond)

		precommitClone2 := precommit
		precommitClone2.Timestamp = precommit.Timestamp.Add(4 * time.Millisecond)

		eg.Go(func() error {
			return newValidator.SignVote(testChainID, &precommit)
		})
		eg.Go(func() error {
			return newValidator.SignVote(testChainID, &precommitClone)
		})
		eg.Go(func() error {
			return newValidator.SignVote(testChainID, &precommitClone2)
		})

		err = eg.Wait()
		require.NoError(t, err)
	}
}

func getTestLocalCosigners(t *testing.T, threshold, total uint8) ([]*pcosigner.LocalCosigner, cometcrypto.PubKey) {
	eciesKeys := make([]*ecies.PrivateKey, total)
	pubKeys := make([]*ecies.PublicKey, total)
	cosigners := make([]*pcosigner.LocalCosigner, total)

	for i := uint8(0); i < total; i++ {
		eciesKey, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		eciesKeys[i] = eciesKey

		pubKeys[i] = &eciesKey.PublicKey
	}

	privateKey := cometcryptoed25519.GenPrivKey()
	privKeyBytes := privateKey[:]
	privShards := tsed25519.DealShares(tsed25519.ExpandSecret(privKeyBytes[:32]), threshold, total)

	tmpDir := t.TempDir()

	cosignersConfig := make(pcosigner.CosignersConfig, total)

	for i := range pubKeys {
		cosignersConfig[i] = pcosigner.CosignerConfig{
			ShardID: i + 1,
		}
	}

	for i := range pubKeys {
		cosignerDir := filepath.Join(tmpDir, fmt.Sprintf("cosigner_%d", i+1))
		err := os.MkdirAll(cosignerDir, 0777)
		require.NoError(t, err)

		cosignerConfig := &pcosigner.RuntimeConfig{
			HomeDir:  cosignerDir,
			StateDir: cosignerDir,
			Config: pcosigner.Config{
				ThresholdModeConfig: &pcosigner.ThresholdModeConfig{
					Threshold: int(threshold),
					Cosigners: cosignersConfig,
				},
			},
		}

		cosigner := pcosigner.NewLocalCosigner(
			cometlog.NewNopLogger(),
			cosignerConfig,
			pcosigner.NewCosignerSecurityECIES(
				pcosigner.CosignerECIESKey{
					ID:        i + 1,
					ECIESKey:  eciesKeys[i],
					ECIESPubs: pubKeys,
				},
			),
			"",
		)
		require.NoError(t, err)

		cosigners[i] = cosigner

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID, privShards[i])
		require.NoError(t, err)

		err = loadKeyForLocalCosigner(cosigner, privateKey.PubKey(), testChainID2, privShards[i])
		require.NoError(t, err)
	}

	return cosigners, privateKey.PubKey()
}

func testThresholdValidatorLeaderElection(t *testing.T, threshold, total uint8) {
	cosigners, pubKey := getTestLocalCosigners(t, threshold, total)

	thresholdValidators := make([]*ThresholdValidator, 0, total)
	var leader *ThresholdValidator
	leaders := make([]*MockLeader, total)
	for i, cosigner := range cosigners {
		peers := make([]pcosigner.ICosigner, 0, len(cosigners)-1)
		for j, otherCosigner := range cosigners {
			if i != j {
				peers = append(peers, otherCosigner)
			}
		}
		leaders[i] = &MockLeader{id: cosigner.GetID(), leader: leader}
		tv := NewThresholdValidator(
			cometlog.NewTMLogger(cometlog.NewSyncWriter(os.Stdout)).With("module", "validator"),
			cosigner.Config,
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
	}

	go func() {
		for i := 0; true; i++ {
			// simulate leader election
			for _, l := range leaders {
				l.SetLeader(nil)
			}
			t.Log("No leader")

			rnd, err := rand.Int(rand.Reader, big.NewInt(50))
			require.NoError(t, err)
			// time without a leader
			time.Sleep(time.Duration(int(rnd.Int64())+100) * time.Millisecond)

			newLeader := thresholdValidators[i%len(thresholdValidators)]
			for _, l := range leaders {
				l.SetLeader(newLeader)
			}
			t.Logf("New leader: %d", newLeader.myCosigner.GetID())

			// time with new leader
			rnd, err = rand.Int(rand.Reader, big.NewInt(50))
			require.NoError(t, err)
			time.Sleep(time.Duration(int(rnd.Int64())+100) * time.Millisecond)
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

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				rnd, err := rand.Int(rand.Reader, big.NewInt(50))
				require.NoError(t, err)
				// ime without a leader
				time.Sleep(time.Duration(int(rnd.Int64())+100) * time.Millisecond)

				proposal := cometproto.Proposal{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.ProposalType,
				}

				if err := tv.SignProposal(testChainID, &proposal); err != nil {
					t.Log("Proposal sign failed", "error", err)
					return
				}

				signBytes := comet.ProposalSignBytes(testChainID, &proposal)

				if !pubKey.VerifySignature(signBytes, proposal.Signature) {
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

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				rnd, err := rand.Int(rand.Reader, big.NewInt(50))
				require.NoError(t, err)
				// time without a leader
				time.Sleep(time.Duration(int(rnd.Int64())+100) * time.Millisecond)

				preVote := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrevoteType,
				}

				if err := tv.SignVote(testChainID, &preVote); err != nil {
					t.Log("PreVote sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preVote)

				if !pubKey.VerifySignature(signBytes, preVote.Signature) {
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

			go func() {
				defer wg.Done()
				// stagger signing requests with random sleep
				rnd, err := rand.Int(rand.Reader, big.NewInt(50))
				require.NoError(t, err)
				// time without a leader
				time.Sleep(time.Duration(int(rnd.Int64())+100) * time.Millisecond)

				preCommit := cometproto.Vote{
					Height: 1 + int64(i),
					Round:  1,
					Type:   cometproto.PrecommitType,
				}

				if err := tv.SignVote(testChainID, &preCommit); err != nil {
					t.Log("PreCommit sign failed", "error", err)
					return
				}

				signBytes := comet.VoteSignBytes(testChainID, &preCommit)

				if !pubKey.VerifySignature(signBytes, preCommit.Signature) {
					t.Log("PreCommit signature verification failed")
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
}

func TestThresholdValidatorLeaderElection2of3(t *testing.T) {
	testThresholdValidatorLeaderElection(t, 2, 3)
}
