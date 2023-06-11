package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ory/dockertest"
	dto "github.com/prometheus/client_model/go"
	"github.com/strangelove-ventures/horcrux/signer"
	crypto "github.com/tendermint/tendermint/crypto"
	ed25519 "github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/privval"
)

type TestValidator struct {
	Index         int
	Sentries      TestNodes
	Signers       TestSigners
	tl            TestLogger
	Home          string
	PubKey        crypto.PubKey
	PrivKeyShares []signer.CosignerKey
	Threshold     int
}

func NewHorcruxValidator(
	tl TestLogger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
) (*TestValidator, error) {
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  MakeTestNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl),
		Signers:   MakeTestSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
	}
	if err := testValidator.genPrivKeyAndShares(); err != nil {
		return nil, err
	}
	return testValidator, nil
}

func NewHorcruxValidatorWithPrivValKey(
	tl TestLogger,
	pool *dockertest.Pool,
	networkID string,
	home string,
	chainID string,
	index int,
	numSentries int,
	numSigners int,
	threshold int,
	chainType *ChainType,
	privValKey privval.FilePVKey,
) (*TestValidator, error) {
	testValidator := &TestValidator{
		Index:     index,
		Sentries:  MakeTestNodes(index, numSentries, home, chainID, chainType, pool, networkID, tl),
		Signers:   MakeTestSigners(index, numSigners, home, pool, networkID, tl),
		tl:        tl,
		Home:      home,
		Threshold: threshold,
	}
	if err := testValidator.generateShares(privValKey); err != nil {
		return nil, err
	}
	return testValidator, nil
}

// Name is the name of the test validator
func (tv *TestValidator) Name() string {
	return fmt.Sprintf("validator-%d-%s", tv.Index, tv.tl.Name())
}

// Dir is the directory where the test validator files are stored
func (tv *TestValidator) Dir() string {
	return filepath.Join(tv.Home, tv.Name())
}

// Generate Ed25519 Private Key
func (tv *TestValidator) genPrivKeyAndShares() error {
	privKey := ed25519.GenPrivKey()
	pubKey := privKey.PubKey()
	filePVKey := privval.FilePVKey{
		Address: pubKey.Address(),
		PubKey:  pubKey,
		PrivKey: privKey,
	}
	return tv.generateShares(filePVKey)
}

func (tv *TestValidator) generateShares(filePVKey privval.FilePVKey) error {
	tv.PubKey = filePVKey.PubKey
	shares, err := signer.CreateCosignerShares(filePVKey, int64(tv.Threshold), int64(len(tv.Signers)))
	if err != nil {
		return err
	}
	tv.PrivKeyShares = shares
	for i, s := range tv.Signers {
		tv.tl.Logf("{%s} -> Writing Key Share To File... ", s.Name())
		if err := os.MkdirAll(s.Dir(), 0700); err != nil {
			return err
		}
		privateFilename := filepath.Join(s.Dir(), "share.json")
		if err := signer.WriteCosignerShareFile(shares[i], privateFilename); err != nil {
			return err
		}
	}
	return nil
}

func (tv *TestValidator) StartHorcruxCluster(
	ctx context.Context,
	sentriesPerSigner int,
) error {
	return StartCosignerContainers(tv.Signers, tv.Sentries,
		tv.Threshold, len(tv.Signers), sentriesPerSigner)
}

func (tv *TestValidator) WaitForConsecutiveBlocks(blocks int64) error {
	return tv.Sentries[0].WaitForConsecutiveBlocks(blocks, tv.PubKey.Address())
}

func (tv *TestValidator) EnsureNotSlashed() error {
	return tv.Sentries[0].EnsureNotSlashed(tv.PubKey.Address())
}

func (tv *TestValidator) CaptureCosignerMetrics(ctx context.Context) {
	for _, s := range tv.Signers {
		s := s
		ticker := time.NewTicker(time.Second)

		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					m, err := s.GetMetrics(ctx)

					if err != nil {
						tv.tl.Logf("-------------------------------------------------\n")
						tv.tl.Logf("{%s} -> Error getting metrics : %v", s.Name(), err)
						tv.tl.Logf("-------------------------------------------------\n")

					}
					tv.tl.Logf("-------------------------------------------------\n")
					fmt.Println("Got Metrics", m)
					ConvertMapToJSON(m)
					tv.tl.Logf("-------------------------------------------------\n")

				}
			}
		}()
	}
}

func ConvertMapToJSON(data map[string]*dto.MetricFamily) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		panic(err)
	}

	signerCosignerSignLagSeconds := result["signer_cosigner_sign_lag_seconds"]
	jsonData, err = json.Marshal(signerCosignerSignLagSeconds)
	if err != nil {
		return "", err
	}

	err = AppendJSONToFile(string(jsonData), "./output.json")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func AppendJSONToFile(jsonData string, filePath string) error {
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(jsonData + "\n"); err != nil {
		return err
	}

	return nil
}
