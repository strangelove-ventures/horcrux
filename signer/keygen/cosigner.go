package keygen

import (
	"fmt"

	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/keygen"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/helpers"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

// Cosigner corresponds to a horcrux cosigner, but in this case strictly for the purposes of
// DKG key combination (sharding without a trusted "dealer").
type Cosigner struct {
	ID           party.ID
	allCosigners party.IDSlice
	threshold    uint16

	state  *state.State   // private, do not share with other cosigners
	output *keygen.Output // private, do not share with other cosigners
}

// NewCosigner builds a Cosigner ready to participate in the DKG rounds.
func NewCosigner(id uint8, threshold uint8, total uint8) (Cosigner, error) {
	c := Cosigner{
		ID:           party.ID(id),
		allCosigners: helpers.GenerateSet(party.ID(total)),
		threshold:    uint16(threshold - 1),
	}

	var err error
	c.state, c.output, err = frost.NewKeygenState(c.ID, c.allCosigners, party.ID(c.threshold), 0)
	return c, err
}

// Round1 is the first DKG round. It produces messages that must be shared with all of the other Cosigners before the second round.
func (c Cosigner) Round1() ([][]byte, error) {
	return helpers.PartyRoutine(nil, c.state)
}

// Round2 is the second DKG round. It requires all of the Cosigners messages from the first round, and produces messages for the third round.
func (c Cosigner) Round2(round1Msgs [][]byte) ([][]byte, error) {
	if len(round1Msgs) != len(c.allCosigners) {
		return nil, fmt.Errorf("length of messages (%d) must match number of cosigners (%d) for round 2", len(round1Msgs), len(c.allCosigners))
	}
	return helpers.PartyRoutine(round1Msgs, c.state)
}

// Round3 is the final DKG round. It requires all of the Cosigners messages from the second round. If successful, the shamir secret share is ready for signing.
func (c Cosigner) Round3(round2Msgs [][]byte) error {
	total := len(c.allCosigners)
	expectedLen := total * (total - 1)
	if len(round2Msgs) != expectedLen {
		return fmt.Errorf("length of messages (%d) must match N*(N-1) (%d where N = total number of cosigners %d) for round 3", len(round2Msgs), expectedLen, total)
	}
	_, err := helpers.PartyRoutine(round2Msgs, c.state)
	return err
}

// WaitForCompletion makes sure the protocol is done processing the DKG rounds.
func (c Cosigner) WaitForCompletion() error {
	return c.state.WaitForError()
}

// Public returns the public information such as the combined public key and individual public keys.
func (c Cosigner) Public() *eddsa.Public {
	return c.output.Public
}

// Secret returns the private shard.
// BE VERY CAREFUL WITH THIS METHOD.
func (c Cosigner) Secret() *eddsa.SecretShare {
	return c.output.SecretKey
}
