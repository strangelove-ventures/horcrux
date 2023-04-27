package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
	"time"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

// Test_StoreInMemOpenSingleNode tests that a command can be applied to the log
// stored in RAM.
func Test_StoreInMemOpenSingleNode(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "store_test")
	defer os.RemoveAll(tmpDir)

	dummyPub := cometcryptoed25519.PubKey{}

	bitSize := 4096
	rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	key := CosignerKey{
		PubKey:   dummyPub,
		ShareKey: []byte{},
		ID:       1,
	}

	cosigner := NewLocalCosigner(
		&RuntimeConfig{},
		key,
		*rsaKey,
		[]CosignerPeer{{
			ID:        1,
			PublicKey: rsaKey.PublicKey,
		}},
		"",
		0, 0,
	)

	s := &RaftStore{
		NodeID:      "1",
		RaftDir:     tmpDir,
		RaftBind:    "127.0.0.1:0",
		RaftTimeout: 1 * time.Second,
		m:           make(map[string]string),
		logger:      nil,
		cosigner:    cosigner,
		Peers:       []Cosigner{},
	}

	if _, err := s.Open(); err != nil {
		t.Fatalf("failed to open store: %s", err)
	}

	// Simple way to ensure there is a leader.
	time.Sleep(3 * time.Second)

	if err := s.Set("foo", "bar"); err != nil {
		t.Fatalf("failed to set key: %s", err.Error())
	}

	// Wait for committed log entry to be applied.
	time.Sleep(500 * time.Millisecond)
	value, err := s.Get("foo")
	if err != nil {
		t.Fatalf("failed to get key: %s", err.Error())
	}
	if value != "bar" {
		t.Fatalf("key has wrong value: %s", value)
	}

	if err := s.Delete("foo"); err != nil {
		t.Fatalf("failed to delete key: %s", err.Error())
	}

	// Wait for committed log entry to be applied.
	time.Sleep(500 * time.Millisecond)
	value, err = s.Get("foo")
	if err != nil {
		t.Fatalf("failed to get key: %s", err.Error())
	}
	if value != "" {
		t.Fatalf("key has wrong value: %s", value)
	}
}
