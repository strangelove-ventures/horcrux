package types

import (
	"io"

	"github.com/strangelove-ventures/horcrux/v3/comet/libs/protoio"
	cometprotoprivval "github.com/strangelove-ventures/horcrux/v3/comet/proto/privval"
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
