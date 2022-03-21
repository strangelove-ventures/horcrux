package signer

import (
	"fmt"
	"net"
	"time"

	tmCryptoEd2219 "github.com/tendermint/tendermint/crypto/ed25519"
	tmCryptoEncoding "github.com/tendermint/tendermint/crypto/encoding"
	tmLog "github.com/tendermint/tendermint/libs/log"
	tmNet "github.com/tendermint/tendermint/libs/net"
	tmService "github.com/tendermint/tendermint/libs/service"
	tmP2pConn "github.com/tendermint/tendermint/p2p/conn"
	tmProtoCrypto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	tmProtoPrivval "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmProto "github.com/tendermint/tendermint/proto/tendermint/types"
	tm "github.com/tendermint/tendermint/types"
)

// ReconnRemoteSigner dials using its dialer and responds to any
// signature requests using its privVal.
type ReconnRemoteSigner struct {
	tmService.BaseService

	address string
	chainID string
	privKey tmCryptoEd2219.PrivKey
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
	logger tmLog.Logger,
	chainID string,
	privVal tm.PrivValidator,
	dialer net.Dialer,
) *ReconnRemoteSigner {
	rs := &ReconnRemoteSigner{
		address: address,
		chainID: chainID,
		privVal: privVal,
		dialer:  dialer,
		privKey: tmCryptoEd2219.GenPrivKey(),
	}

	rs.BaseService = *tmService.NewBaseService(logger, "RemoteSigner", rs)
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
			proto, address := tmNet.ProtocolAndAddress(rs.address)
			netConn, err := rs.dialer.Dial(proto, address)
			if err != nil {
				rs.Logger.Error("Dialing", "err", err)
				rs.Logger.Info("Retrying", "sleep (s)", 3, "address", rs.address)
				time.Sleep(time.Second * 3)
				continue
			}

			rs.Logger.Info("Connected", "address", rs.address)
			conn, err = tmP2pConn.MakeSecretConnection(netConn, rs.privKey)
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

func (rs *ReconnRemoteSigner) handleRequest(req tmProtoPrivval.Message) tmProtoPrivval.Message {
	switch typedReq := req.Sum.(type) {
	case *tmProtoPrivval.Message_SignVoteRequest:
		return rs.handleSignVoteRequest(typedReq.SignVoteRequest.Vote)
	case *tmProtoPrivval.Message_SignProposalRequest:
		return rs.handleSignProposalRequest(typedReq.SignProposalRequest.Proposal)
	case *tmProtoPrivval.Message_PubKeyRequest:
		return rs.handlePubKeyRequest()
	case *tmProtoPrivval.Message_PingRequest:
		return rs.handlePingRequest()
	default:
		rs.Logger.Error("Unknown request", "err", fmt.Errorf("%v", typedReq))
		return tmProtoPrivval.Message{}
	}
}

func (rs *ReconnRemoteSigner) handleSignVoteRequest(vote *tmProto.Vote) tmProtoPrivval.Message {
	msgSum := &tmProtoPrivval.Message_SignedVoteResponse{SignedVoteResponse: &tmProtoPrivval.SignedVoteResponse{
		Vote:  tmProto.Vote{},
		Error: nil,
	}}
	if err := rs.privVal.SignVote(rs.chainID, vote); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			rs.Logger.Debug("Rejecting sign vote request", "reason", typedErr.msg)
		default:
			rs.Logger.Error("Failed to sign vote", "address", rs.address, "error", err, "vote_type", vote.Type,
				"height", vote.Height, "round", vote.Round, "validator", fmt.Sprintf("%X", vote.ValidatorAddress))
		}
		msgSum.SignedVoteResponse.Error = getRemoteSignerError(err)
		return tmProtoPrivval.Message{Sum: msgSum}
	}
	rs.Logger.Info("Signed vote", "node", rs.address, "height", vote.Height, "round", vote.Round, "type", vote.Type)
	msgSum.SignedVoteResponse.Vote = *vote
	return tmProtoPrivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handleSignProposalRequest(proposal *tmProto.Proposal) tmProtoPrivval.Message {
	msgSum := &tmProtoPrivval.Message_SignedProposalResponse{
		SignedProposalResponse: &tmProtoPrivval.SignedProposalResponse{
			Proposal: tmProto.Proposal{},
			Error:    nil,
		}}
	if err := rs.privVal.SignProposal(rs.chainID, proposal); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			rs.Logger.Debug("Rejecting proposal sign request", "reason", typedErr.msg)
		default:
			rs.Logger.Error("Failed to sign proposal", "address", rs.address, "error", err, "proposal", proposal)
		}
		msgSum.SignedProposalResponse.Error = getRemoteSignerError(err)
		return tmProtoPrivval.Message{Sum: msgSum}
	}
	rs.Logger.Info("Signed proposal", "node", rs.address,
		"height", proposal.Height, "round", proposal.Round, "type", proposal.Type)
	msgSum.SignedProposalResponse.Proposal = *proposal
	return tmProtoPrivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePubKeyRequest() tmProtoPrivval.Message {
	msgSum := &tmProtoPrivval.Message_PubKeyResponse{PubKeyResponse: &tmProtoPrivval.PubKeyResponse{
		PubKey: tmProtoCrypto.PublicKey{},
		Error:  nil,
	}}
	pubKey, err := rs.privVal.GetPubKey()
	if err != nil {
		rs.Logger.Error("Failed to get Pub Key", "address", rs.address, "error", err)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return tmProtoPrivval.Message{Sum: msgSum}
	}
	pk, err := tmCryptoEncoding.PubKeyToProto(pubKey)
	if err != nil {
		rs.Logger.Error("Failed to get Pub Key", "address", rs.address, "error", err)
		msgSum.PubKeyResponse.Error = getRemoteSignerError(err)
		return tmProtoPrivval.Message{Sum: msgSum}
	}
	msgSum.PubKeyResponse.PubKey = pk
	return tmProtoPrivval.Message{Sum: msgSum}
}

func (rs *ReconnRemoteSigner) handlePingRequest() tmProtoPrivval.Message {
	return tmProtoPrivval.Message{Sum: &tmProtoPrivval.Message_PingResponse{PingResponse: &tmProtoPrivval.PingResponse{}}}
}

func getRemoteSignerError(err error) *tmProtoPrivval.RemoteSignerError {
	if err == nil {
		return nil
	}
	return &tmProtoPrivval.RemoteSignerError{
		Code:        0,
		Description: err.Error(),
	}
}

func StartRemoteSigners(services []tmService.Service, logger tmLog.Logger, chainID string,
	privVal tm.PrivValidator, nodes []NodeConfig) ([]tmService.Service, error) {
	var err error
	for _, node := range nodes {
		dialer := net.Dialer{Timeout: 30 * time.Second}
		s := NewReconnRemoteSigner(node.Address, logger, chainID, privVal, dialer)

		err = s.Start()
		if err != nil {
			return nil, err
		}

		services = append(services, s)
	}
	return services, err
}
