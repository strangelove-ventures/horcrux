package types

import (
	"errors"
	"io"

	"github.com/cometbft/cometbft/libs/protoio"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// ReadMsg reads a message from an io.Reader
func ReadMsg(reader io.Reader) (msg cometprotoprivval.Message, err error) {
	const maxRemoteSignerMsgSize = 1024 * 10
	protoReader := protoio.NewDelimitedReader(reader, maxRemoteSignerMsgSize)
	_, err = protoReader.ReadMsg(&msg)
	return msg, err
}

// WriteMsg writes a message to an io.Writer
func WriteMsg(writer io.Writer, msg cometprotoprivval.Message) (err error) {
	protoWriter := protoio.NewDelimitedWriter(writer)
	_, err = protoWriter.WriteMsg(&msg)
	return err
}

// UnpackHRS deserializes sign bytes and gets the height, round, and step
func UnpackHRST(signBytes []byte) (HRST, error) {
	{
		var proposal cometproto.CanonicalProposal
		if err := protoio.UnmarshalDelimited(signBytes, &proposal); err == nil {
			return HRST{proposal.Height, proposal.Round, StepPropose, proposal.Timestamp.UnixNano()}, nil
		}
	}

	{
		var vote cometproto.CanonicalVote
		if err := protoio.UnmarshalDelimited(signBytes, &vote); err == nil {
			return HRST{vote.Height, vote.Round, CanonicalVoteToStep(&vote), vote.Timestamp.UnixNano()}, nil
		}
	}

	return HRST{0, 0, 0, 0}, errors.New("could not UnpackHRS from sign bytes")
}
