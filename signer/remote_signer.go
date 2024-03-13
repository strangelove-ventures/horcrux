package signer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	cometcrypto "github.com/strangelove-ventures/horcrux/v3/comet/crypto"
	cometcryptoed25519 "github.com/strangelove-ventures/horcrux/v3/comet/crypto/ed25519"
	"github.com/strangelove-ventures/horcrux/v3/comet/encoding"
	cometnet "github.com/strangelove-ventures/horcrux/v3/comet/libs/net"
	cometp2pconn "github.com/strangelove-ventures/horcrux/v3/comet/p2p/conn"
	cometprotocrypto "github.com/strangelove-ventures/horcrux/v3/comet/proto/crypto"
	cometprotoprivval "github.com/strangelove-ventures/horcrux/v3/comet/proto/privval"
	cometproto "github.com/strangelove-ventures/horcrux/v3/comet/proto/types"
	"github.com/strangelove-ventures/horcrux/v3/types"
)

const connRetrySec = 2

// PrivValidator is a wrapper for tendermint PrivValidator,
// with additional Stop method for safe shutdown.
type PrivValidator interface {
	Sign(ctx context.Context, chainID string, block types.Block) ([]byte, []byte, time.Time, error)
	GetPubKey(ctx context.Context, chainID string) ([]byte, error)
	Stop()
}

// ReconnRemoteSigner dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSigner struct {
	logger  *slog.Logger
	address string
	privKey cometcryptoed25519.PrivKey
	privVal PrivValidator

	dialer net.Dialer
}

// NewReconnRemoteSigner return a ReconnRemoteSigner that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal.
//
// If the connection is broken, the ReconnRemoteSigner will attempt to reconnect.
func NewReconnRemoteSigner(
	address string,
	logger *slog.Logger,
	privVal PrivValidator,
	dialer net.Dialer,
) *ReconnRemoteSigner {
	return &ReconnRemoteSigner{
		logger:  logger,
		address: address,
		privVal: privVal,
		dialer:  dialer,
		privKey: cometcryptoed25519.GenPrivKey(),
	}
}

// Start starts the auto-reconnecting remote signer.
func (rs *ReconnRemoteSigner) Start(ctx context.Context) {
	var conn net.Conn
	for {
		if ctx.Err() != nil {
			rs.closeConn(conn)
			return
		}

		retries := 0
		for conn == nil {
			var err error
			timer := time.NewTimer(connRetrySec * time.Second)
			conn, err = rs.establishConnection(ctx)
			if err == nil {
				sentryConnectTries.WithLabelValues(rs.address).Set(0)
				timer.Stop()
				rs.logger.Info("Connected to Sentry", "address", rs.address)
				break
			}

			sentryConnectTries.WithLabelValues(rs.address).Add(1)
			totalSentryConnectTries.WithLabelValues(rs.address).Inc()
			retries++
			rs.logger.Error(
				"Error establishing connection, will retry",
				"sleep (s)", connRetrySec,
				"address", rs.address,
				"attempt", retries,
				"err", err,
			)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				continue
			}
		}

		// since dialing can take time, we check running again
		if ctx.Err() != nil {
			rs.closeConn(conn)
			return
		}

		req, err := types.ReadMsg(conn)
		if err != nil {
			rs.logger.Error(
				"Failed to read message from connection",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
			continue
		}

		// handleRequest handles request errors. We always send back a response
		res := rs.handleRequest(req)

		err = types.WriteMsg(conn, res)
		if err != nil {
			rs.logger.Error(
				"Failed to write message to connection",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSigner) establishConnection(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connRetrySec*time.Second)
	defer cancel()

	proto, address := cometnet.ProtocolAndAddress(rs.address)
	netConn, err := rs.dialer.DialContext(ctx, proto, address)
	if err != nil {
		return nil, fmt.Errorf("dial error: %w", err)
	}

	conn, err := cometp2pconn.MakeSecretConnection(netConn, rs.privKey)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("secret connection error: %w", err)
	}

	return conn, nil
}

func (rs *ReconnRemoteSigner) handleRequest(req cometprotoprivval.Message) cometprotoprivval.Message {
	switch typedReq := req.Sum.(type) {
	case *cometprotoprivval.Message_SignVoteRequest:
		return rs.handleSignVoteRequest(typedReq.SignVoteRequest.ChainId, typedReq.SignVoteRequest.Vote)
	case *cometprotoprivval.Message_SignProposalRequest:
		return rs.handleSignProposalRequest(typedReq.SignProposalRequest.ChainId, typedReq.SignProposalRequest.Proposal)
	case *cometprotoprivval.Message_PubKeyRequest:
		return rs.handlePubKeyRequest(typedReq.PubKeyRequest.ChainId)
	case *cometprotoprivval.Message_PingRequest:
		return rs.handlePingRequest()
	default:
		rs.logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return cometprotoprivval.Message{}
	}
}

func (rs *ReconnRemoteSigner) handleSignVoteRequest(chainID string, vote *cometproto.Vote) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedVoteResponse{SignedVoteResponse: &cometprotoprivval.SignedVoteResponse{
		Vote:  cometproto.Vote{},
		Error: nil,
	}}

	sig, voteExtSig, timestamp, err := signAndTrack(
		context.TODO(),
		rs.Logger,
		rs.privVal,
		chainID,
		types.VoteToBlock(vote),
	)
	if err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	msgSum.SignedVoteResponse.Vote.Timestamp = timestamp
	msgSum.SignedVoteResponse.Vote.Signature = sig
	msgSum.SignedVoteResponse.Vote.ExtensionSignature = voteExtSig
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handleSignProposalRequest(
	chainID string,
	proposal *cometproto.Proposal,
) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &cometprotoprivval.SignedProposalResponse{
			Proposal: cometproto.Proposal{},
			Error:    nil,
		},
	}

	signature, _, timestamp, err := signAndTrack(
		context.TODO(),
		rs.logger,
		rs.privVal,
		chainID,
		types.ProposalToBlock(proposal),
	)
	if err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePubKeyRequest(chainID string) cometprotoprivval.Message {
	totalPubKeyRequests.WithLabelValues(chainID).Inc()
	msgSum := &cometprotoprivval.Message_PubKeyResponse{PubKeyResponse: &cometprotoprivval.PubKeyResponse{
		PubKey: cometprotocrypto.PublicKey{},
		Error:  nil,
	}}

	pubKey, err := rs.privVal.GetPubKey(context.TODO(), chainID)
	if err != nil {
		rs.logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	pk, err := encoding.PubKeyToProto(pubKey)
	if err != nil {
		rs.logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	msgSum.PubKeyResponse.PubKey = pk
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePingRequest() cometprotoprivval.Message {
	return cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_PingResponse{
			PingResponse: &cometprotoprivval.PingResponse{},
		},
	}
}

func getRemoteSignerError(err error) *cometprotoprivval.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &cometprotoprivval.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

// func StartRemoteSigners(
// 	services []cometservice.Service,
// 	logger *slog.Logger,
// 	privVal PrivValidator,
// 	nodes []string,
// ) ([]cometservice.Service, error) {
// 	var err error
// 	go StartMetrics()
// 	for _, node := range nodes {
// 		// CometBFT requires a connection within 3 seconds of start or crashes
// 		// A long timeout such as 30 seconds would cause the sentry to fail in loops
// 		// Use a short timeout and dial often to connect within 3 second window
// 		dialer := net.Dialer{Timeout: 2 * time.Second}
// 		s := NewReconnRemoteSigner(node, logger, privVal, dialer)

// 		err = s.Start()
// 		if err != nil {
// 			return nil, err
// 		}

// 		services = append(services, s)
// 	}
// 	return services, err
// }

func (rs *ReconnRemoteSigner) closeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		rs.logger.Error("Failed to close connection to chain node",
			"address", rs.address,
			"err", err,
		)
	}
}
