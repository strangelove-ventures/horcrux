package signer

import (
	"fmt"
	"net"
	"time"

	tmcryptoed2219 "github.com/tendermint/tendermint/crypto/ed25519"
	tmcryptoencoding "github.com/tendermint/tendermint/crypto/encoding"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmnet "github.com/tendermint/tendermint/libs/net"
	tmservice "github.com/tendermint/tendermint/libs/service"
	tmp2pconn "github.com/tendermint/tendermint/p2p/conn"
	tmprotocrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	tmprotoprivval "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

// ReconnRemoteSigner dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSigner struct {
	tmservice.BaseService

	address string
	privKey tmcryptoed2219.PrivKey
	privVal tm.PrivValidator

	dialer net.Dialer
}

// NewReconnRemoteSigner return a ReconnRemoteSigner that will dial using the given
// dialer and respond to any signature requests over the connection
// using the given privVal.
//
// If the connection is broken, the ReconnRemoteSigner will attempt to reconnect.
func NewReconnRemoteSigner(
	address string,
	logger tmlog.Logger,
	privVal tm.PrivValidator,
	dialer net.Dialer,
) *ReconnRemoteSigner {
	rs := &ReconnRemoteSigner{
		address: address,
		privVal: privVal,
		dialer:  dialer,
		privKey: tmcryptoed2219.GenPrivKey(),
	}

	rs.BaseService = *tmservice.NewBaseService(logger, "RemoteSigner", rs)
	return rs
}

// OnStart implements cmn.Service.
func (rs *ReconnRemoteSigner) OnStart() error {
	go rs.loop()
	return nil
}

// main loop for ReconnRemoteSigner
func (rs *ReconnRemoteSigner) loop() {
	var conn net.Conn
	for {
		if !rs.IsRunning() {
			if conn != nil {
				if err := conn.Close(); err != nil {
					rs.Logger.Error("Close", "err", err.Error()+"closing listener failed")
				}
			}
			return
		}

		for conn == nil {
			proto, address := tmnet.ProtocolAndAddress(rs.address)
			netConn, err := rs.dialer.Dial(proto, address)
			if err != nil {
				sentryConnectTries.Add(float64(1))
				totalSentryConnectTries.Inc()
				rs.Logger.Error("Dialing", "err", err)
				rs.Logger.Info("Retrying", "sleep (s)", 3, "address", rs.address)
				time.Sleep(time.Second * 3)
				continue
			}
			sentryConnectTries.Set(0)

			rs.Logger.Info("Connected to Sentry", "address", rs.address)
			conn, err = tmp2pconn.MakeSecretConnection(netConn, rs.privKey)
			if err != nil {
				conn = nil
				rs.Logger.Error("Secret Conn", "err", err)
				rs.Logger.Info("Retrying", "sleep (s)", 3, "address", rs.address)
				time.Sleep(time.Second * 3)
				continue
			}
		}

		// since dialing can take time, we check running again
		if !rs.IsRunning() {
			if err := conn.Close(); err != nil {
				rs.Logger.Error("Close", "err", err.Error()+"closing listener failed")
			}
			return
		}

		req, err := ReadMsg(conn)
		if err != nil {
			rs.Logger.Error("readMsg", "err", err)
			conn.Close()
			conn = nil
			continue
		}

		// handleRequest handles request errors. We always send back a response
		res := rs.handleRequest(req)

		err = WriteMsg(conn, res)
		if err != nil {
			rs.Logger.Error("writeMsg", "err", err)
			conn.Close()
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSigner) handleRequest(req tmprotoprivval.Message) tmprotoprivval.Message {
	switch typedReq := req.Sum.(type) {
	case *tmprotoprivval.Message_SignVoteRequest:
		return rs.handleSignVoteRequest(typedReq.SignVoteRequest.ChainId, typedReq.SignVoteRequest.Vote)
	case *tmprotoprivval.Message_SignProposalRequest:
		return rs.handleSignProposalRequest(typedReq.SignProposalRequest.ChainId, typedReq.SignProposalRequest.Proposal)
	case *tmprotoprivval.Message_PubKeyRequest:
		return rs.handlePubKeyRequest(typedReq.PubKeyRequest.ChainId)
	case *tmprotoprivval.Message_PingRequest:
		return rs.handlePingRequest()
	default:
		rs.Logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return tmprotoprivval.Message{}
	}
}

func (rs *ReconnRemoteSigner) handleSignVoteRequest(chainID string, vote *tmproto.Vote) tmprotoprivval.Message {
	msgSum := &tmprotoprivval.Message_SignedVoteResponse{SignedVoteResponse: &tmprotoprivval.SignedVoteResponse{
		Vote:  tmproto.Vote{},
		Error: nil,
	}}

	if err := rs.privVal.SignVote(chainID, vote); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			rs.Logger.Debug(
				"Rejecting sign vote request",
				"chain_id", chainID,
				"height", vote.Height,
				"round", vote.Round,
				"type", vote.Type,
				"node", rs.address,
				"validator", fmt.Sprintf("%X", vote.ValidatorAddress),
				"reason", typedErr.msg,
			)
			beyondBlockErrors.Inc()
		default:
			rs.Logger.Error(
				"Failed to sign vote",
				"chain_id", chainID,
				"height", vote.Height,
				"round", vote.Round,
				"type", vote.Type,
				"node", rs.address,
				"validator", fmt.Sprintf("%X", vote.ValidatorAddress),
				"error", err,
			)
			failedSignVote.Inc()
		}
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return tmprotoprivval.Message{Sum: msgSum}
	}
	// Show signatures provided to each node have the same signature and timestamps
	sigLen := 6
	if len(vote.Signature) < sigLen {
		sigLen = len(vote.Signature)
	}
	rs.Logger.Info(
		"Signed vote",
		"chain_id", chainID,
		"height", vote.Height,
		"round", vote.Round,
		"type", vote.Type,
		"sig", vote.Signature[:sigLen],
		"ts", vote.Timestamp.Unix(),
		"node", rs.address,
	)

	if vote.Type == tmproto.PrecommitType {
		stepSize := vote.Height - previousPrecommitHeight
		if previousPrecommitHeight != 0 && stepSize > 1 {
			missedPrecommits.Add(float64(stepSize))
			totalMissedPrecommits.Add(float64(stepSize))
		} else {
			missedPrecommits.Set(0)
		}
		previousPrecommitHeight = vote.Height // remember last PrecommitHeight

		metricsTimeKeeper.SetPreviousPrecommit(time.Now())

		lastPrecommitHeight.Set(float64(vote.Height))
		lastPrecommitRound.Set(float64(vote.Round))
		totalPrecommitsSigned.Inc()
	}
	if vote.Type == tmproto.PrevoteType {
		// Determine number of heights since the last Prevote
		stepSize := vote.Height - previousPrevoteHeight
		if previousPrevoteHeight != 0 && stepSize > 1 {
			missedPrevotes.Add(float64(stepSize))
			totalMissedPrevotes.Add(float64(stepSize))
		} else {
			missedPrevotes.Set(0)
		}

		previousPrevoteHeight = vote.Height // remember last PrevoteHeight

		metricsTimeKeeper.SetPreviousPrevote(time.Now())

		lastPrevoteHeight.Set(float64(vote.Height))
		lastPrevoteRound.Set(float64(vote.Round))
		totalPrevotesSigned.Inc()
	}

	msgSum.SignedVoteResponse.Vote = *vote
	return tmprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handleSignProposalRequest(
	chainID string,
	proposal *tmproto.Proposal,
) tmprotoprivval.Message {
	msgSum := &tmprotoprivval.Message_SignedProposalResponse{
		SignedProposalResponse: &tmprotoprivval.SignedProposalResponse{
			Proposal: tmproto.Proposal{},
			Error:    nil,
		}}

	if err := rs.privVal.SignProposal(chainID, proposal); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			rs.Logger.Debug(
				"Rejecting proposal sign request",
				"chain_id", chainID,
				"height", proposal.Height,
				"round", proposal.Round,
				"type", proposal.Type,
				"node", rs.address,
				"reason", typedErr.msg,
			)
			beyondBlockErrors.Inc()
		default:
			rs.Logger.Error(
				"Failed to sign proposal",
				"chain_id", chainID,
				"height", proposal.Height,
				"round", proposal.Round,
				"type", proposal.Type,
				"node", rs.address,
				"error", err,
			)
		}
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return tmprotoprivval.Message{Sum: msgSum}
	}
	// Show signatures provided to each node have the same signature and timestamps
	sigLen := 6
	if len(proposal.Signature) < sigLen {
		sigLen = len(proposal.Signature)
	}
	rs.Logger.Info(
		"Signed proposal",
		"chain_id", chainID,
		"height", proposal.Height,
		"round", proposal.Round,
		"type", proposal.Type,
		"sig", proposal.Signature[:sigLen],
		"ts", proposal.Timestamp.Unix(),
		"node", rs.address,
	)
	lastProposalHeight.Set(float64(proposal.Height))
	lastProposalRound.Set(float64(proposal.Round))
	totalProposalsSigned.Inc()
	msgSum.SignedProposalResponse.Proposal = *proposal
	return tmprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePubKeyRequest(chainID string) tmprotoprivval.Message {
	totalPubKeyRequests.Inc()
	msgSum := &tmprotoprivval.Message_PubKeyResponse{PubKeyResponse: &tmprotoprivval.PubKeyResponse{
		PubKey: tmprotocrypto.PublicKey{},
		Error:  nil,
	}}

	pubKey, err := rs.privVal.GetPubKey()
	if err != nil {
		rs.Logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return tmprotoprivval.Message{Sum: msgSum}
	}
	pk, err := tmcryptoencoding.PubKeyToProto(pubKey)
	if err != nil {
		rs.Logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"node", rs.address,
			"error", err,
		)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return tmprotoprivval.Message{Sum: msgSum}
	}
	msgSum.PubKeyResponse.PubKey = pk
	return tmprotoprivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePingRequest() tmprotoprivval.Message {
	return tmprotoprivval.Message{Sum: &tmprotoprivval.Message_PingResponse{PingResponse: &tmprotoprivval.PingResponse{}}}
}

func getRemoteSignerError(err error) *tmprotoprivval.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &tmprotoprivval.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

func StartRemoteSigners(services []tmservice.Service, logger tmlog.Logger,
	privVal tm.PrivValidator, nodes []string) ([]tmservice.Service, error) {
	var err error
	go StartMetrics()
	for _, node := range nodes {
		// Tendermint requires a connection within 3 seconds of start or crashes
		// A long timeout such as 30 seconds would cause the sentry to fail in loops
		// Use a short timeout and dial often to connect within 3 second window
		dialer := net.Dialer{Timeout: 2 * time.Second}
		s := NewReconnRemoteSigner(node, logger, privVal, dialer)

		err = s.Start()
		if err != nil {
			return nil, err
		}

		services = append(services, s)
	}
	return services, err
}
