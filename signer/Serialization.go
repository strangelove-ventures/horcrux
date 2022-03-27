package signer

import (
	"errors"
	"github.com/strangelove-ventures/horcrux/signer/localthreshold"
	"io"

	"github.com/tendermint/tendermint/libs/protoio"
	tmProtoPrivval "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// ReadMsg reads a message from an io.Reader
func ReadMsg(reader io.Reader) (msg tmProtoPrivval.Message, err error) {
	const maxRemoteSignerMsgSize = 1024 * 10
	protoReader := protoio.NewDelimitedReader(reader, maxRemoteSignerMsgSize)
	_, err = protoReader.ReadMsg(&msg)
	return msg, err
}

// WriteMsg writes a message to an io.Writer
func WriteMsg(writer io.Writer, msg tmProtoPrivval.Message) (err error) {
	protoWriter := protoio.NewDelimitedWriter(writer)
	_, err = protoWriter.WriteMsg(&msg)
	return err
}

// UnpackHRS deserializes sign bytes and gets the height, round, and step
func UnpackHRST(signBytes []byte) (localthreshold.HRSTKey, error) {
	{
		var proposal tmProto.CanonicalProposal
		if err := protoio.UnmarshalDelimited(signBytes, &proposal); err == nil {
			return localthreshold.HRSTKey{proposal.Height, proposal.Round, localthreshold.StepPropose, proposal.Timestamp.UnixNano()}, nil
		}
	}

	{
		var vote tmProto.CanonicalVote
		if err := protoio.UnmarshalDelimited(signBytes, &vote); err == nil {
			return localthreshold.HRSTKey{vote.Height, vote.Round, localthreshold.CanonicalVoteToStep(&vote), vote.Timestamp.UnixNano()}, nil
		}
	}

	return localthreshold.HRSTKey{0, 0, 0, 0}, errors.New("could not UnpackHRS from sign bytes")
}
