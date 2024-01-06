package connector

/*
Connector is the conections between the "sentry" (consensus cosigner) and the Horcrux node.
*/
import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/strangelove-ventures/horcrux/src/metrics"

	"github.com/strangelove-ventures/horcrux/src/types"

	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometnet "github.com/cometbft/cometbft/libs/net"
	cometservice "github.com/cometbft/cometbft/libs/service"
	cometp2pconn "github.com/cometbft/cometbft/p2p/conn"
	cometprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

const connRetrySec = 2

// ReconnRemoteSentry dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSentry struct {
	cometservice.BaseService

	address string
	privKey cometcryptoed25519.PrivKey
	privVal IPrivValidator // Responds to signature requests from the sentry

	dialer net.Dialer
}

// NewReconnRemoteSentry return a ReconnRemoteSigner that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal.
//
// If the connection is broken, the ReconnRemoteSigner will attempt to reconnect.
func NewReconnRemoteSentry(
	address string,
	logger cometlog.Logger,
	privVal IPrivValidator,
	dialer net.Dialer,
) *ReconnRemoteSentry {
	rs := &ReconnRemoteSentry{
		address: address,
		privVal: privVal,
		dialer:  dialer,
		privKey: cometcryptoed25519.GenPrivKey(),
	}

	rs.BaseService = *cometservice.NewBaseService(logger, "RemoteSigner", rs)
	return rs
}

// OnStart implements cmn.Service.
func (rs *ReconnRemoteSentry) OnStart() error {
	go rs.loop(context.Background())
	return nil
}

// OnStop implements cmn.Service.
func (rs *ReconnRemoteSentry) OnStop() {
	rs.privVal.Stop()
}

func (rs *ReconnRemoteSentry) establishConnection(ctx context.Context) (net.Conn, error) {
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

// main loop for ReconnRemoteSigner
func (rs *ReconnRemoteSentry) loop(ctx context.Context) {
	var conn net.Conn
	for {
		if !rs.IsRunning() {
			rs.closeConn(conn)
			return
		}

		retries := 0
		for conn == nil {
			var err error
			timer := time.NewTimer(connRetrySec * time.Second)
			conn, err = rs.establishConnection(ctx)
			if err == nil {
				metrics.SentryConnectTries.WithLabelValues(rs.address).Set(0)
				timer.Stop()
				rs.Logger.Info("Connected to Sentry", "address", rs.address)
				break
			}

			metrics.SentryConnectTries.WithLabelValues(rs.address).Add(1)
			metrics.TotalSentryConnectTries.WithLabelValues(rs.address).Inc()
			retries++
			rs.Logger.Error(
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
		if !rs.IsRunning() {
			rs.closeConn(conn)
			return
		}

		req, err := types.ReadMsg(conn)
		if err != nil {
			rs.Logger.Error(
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
			rs.Logger.Error(
				"Failed to write message to connection",
				"address", rs.address,
				"err", err,
			)
			rs.closeConn(conn)
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSentry) handleRequest(req cometprotoprivval.Message) cometprotoprivval.Message {
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
		rs.Logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return cometprotoprivval.Message{}
	}
}

func (rs *ReconnRemoteSentry) handleSignVoteRequest(
	chainID string, vote *cometproto.Vote) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedVoteResponse{
		SignedVoteResponse: &cometprotoprivval.SignedVoteResponse{
			Vote:  cometproto.Vote{},
			Error: nil,
		}}

	signature, timestamp, err := signAndTrack(
		context.TODO(), rs.Logger, rs.privVal, chainID, types.VoteToBlock(chainID, vote))
	if err != nil {
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	msgSum.SignedVoteResponse.Vote.Timestamp = timestamp
	msgSum.SignedVoteResponse.Vote.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSentry) handleSignProposalRequest(
	chainID string,
	proposal *cometproto.Proposal,
) cometprotoprivval.Message {
	msgSum := &cometprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &cometprotoprivval.SignedProposalResponse{
			Proposal: cometproto.Proposal{},
			Error:    nil,
		},
	}

	signature, timestamp, err := signAndTrack(
		context.TODO(),
		rs.Logger,
		rs.privVal,
		chainID,
		types.ProposalToBlock(chainID, proposal),
	)
	if err != nil {
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}

	msgSum.SignedProposalResponse.Proposal.Timestamp = timestamp
	msgSum.SignedProposalResponse.Proposal.Signature = signature
	return cometprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSentry) handlePubKeyRequest(chainID string) cometprotoprivval.Message {
	metrics.TotalPubKeyRequests.WithLabelValues(chainID).Inc()
	msgSum := &cometprotoprivval.Message_PubKeyResponse{PubKeyResponse: &cometprotoprivval.PubKeyResponse{
		PubKey: cometprotocrypto.PublicKey{},
		Error:  nil,
	}}

	pubKey, err := rs.privVal.GetPubKey(context.TODO(), chainID)
	if err != nil {
		rs.Logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return cometprotoprivval.Message{Sum: msgSum}
	}
	pk, err := cometcryptoencoding.PubKeyToProto(cometcryptoed25519.PubKey(pubKey))
	if err != nil {
		rs.Logger.Error(
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

func (rs *ReconnRemoteSentry) handlePingRequest() cometprotoprivval.Message {
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

func StartRemoteSigners(
	services []cometservice.Service,
	logger cometlog.Logger,
	privVal IPrivValidator,
	nodes []string,
) ([]cometservice.Service, error) {
	var err error
	go metrics.StartMetrics()
	for _, node := range nodes {
		// CometBFT requires a connection within 3 seconds of start or crashes
		// A long timeout such as 30 seconds would cause the sentry to fail in loops
		// Use a short timeout and dial often to connect within 3 second window
		dialer := net.Dialer{Timeout: 2 * time.Second}
		s := NewReconnRemoteSentry(node, logger, privVal, dialer) // The 'server' that sentry connects to

		err = s.Start()
		if err != nil {
			return nil, err
		}

		services = append(services, s)
	}
	return services, err
}

func (rs *ReconnRemoteSentry) closeConn(conn net.Conn) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		rs.Logger.Error("Failed to close connection to chain node",
			"address", rs.address,
			"err", err,
		)
	}
}
