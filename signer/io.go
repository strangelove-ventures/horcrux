package signer

import (
	"io"

	"github.com/cometbft/cometbft/libs/protoio"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
)

// ReadMsg reads a message from an io.Reader
func ReadMsg(reader io.Reader, maxReadSize int) (msg cometprotoprivval.Message, err error) {
	if maxReadSize <= 0 {
		maxReadSize = 1024 * 1024 // 1MB
	}
	protoReader := protoio.NewDelimitedReader(reader, maxReadSize)
	_, err = protoReader.ReadMsg(&msg)
	return msg, err
}

// WriteMsg writes a message to an io.Writer
func WriteMsg(writer io.Writer, msg cometprotoprivval.Message) (err error) {
	protoWriter := protoio.NewDelimitedWriter(writer)
	_, err = protoWriter.WriteMsg(&msg)
	return err
}
