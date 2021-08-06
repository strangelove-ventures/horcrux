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

		res, err := rs.handleRequest(req)
		if err != nil {
			// only log the error; we reply with an error in handleRequest since the reply needs to be typed based on error
			rs.Logger.Error("handleRequest", "err", err)
		}

		err = WriteMsg(conn, res)
		if err != nil {
			rs.Logger.Error("writeMsg", "err", err)
			conn.Close()
			conn = nil
		}
	}
}

func (rs *ReconnRemoteSigner) handleRequest(req tmProtoPrivval.Message) (tmProtoPrivval.Message, error) {
	msg := tmProtoPrivval.Message{}
	var err error

	switch typedReq := req.Sum.(type) {
	case *tmProtoPrivval.Message_PubKeyRequest:
		pubKey, err := rs.privVal.GetPubKey()
		if err != nil {
			rs.Logger.Error("Failed to get Pub Key", "address", rs.address, "error", err, "pubKey", typedReq)
			msg.Sum = &tmProtoPrivval.Message_PubKeyResponse{PubKeyResponse: &tmProtoPrivval.PubKeyResponse{
				PubKey: tmProtoCrypto.PublicKey{},
				Error: &tmProtoPrivval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}}
		} else {
			pk, err := tmCryptoEncoding.PubKeyToProto(pubKey)
			if err != nil {
				rs.Logger.Error("Failed to get Pub Key", "address", rs.address, "error", err, "pubKey", typedReq)
				msg.Sum = &tmProtoPrivval.Message_PubKeyResponse{PubKeyResponse: &tmProtoPrivval.PubKeyResponse{
					PubKey: tmProtoCrypto.PublicKey{},
					Error: &tmProtoPrivval.RemoteSignerError{
						Code:        0,
						Description: err.Error(),
					},
				}}
			} else {
				msg.Sum = &tmProtoPrivval.Message_PubKeyResponse{PubKeyResponse: &tmProtoPrivval.PubKeyResponse{PubKey: pk, Error: nil}}
			}
		}
	case *tmProtoPrivval.Message_SignVoteRequest:
		vote := typedReq.SignVoteRequest.Vote
		err = rs.privVal.SignVote(rs.chainID, vote)
		if err != nil {
			rs.Logger.Error("Failed to sign vote", "address", rs.address, "error", err, "vote", vote)
			msg.Sum = &tmProtoPrivval.Message_SignedVoteResponse{SignedVoteResponse: &tmProtoPrivval.SignedVoteResponse{
				Vote: tmProto.Vote{},
				Error: &tmProtoPrivval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}}
		} else {
			rs.Logger.Info("Signed vote", "node", rs.address, "height", vote.Height, "round", vote.Round, "type", vote.Type)
			msg.Sum = &tmProtoPrivval.Message_SignedVoteResponse{SignedVoteResponse: &tmProtoPrivval.SignedVoteResponse{Vote: *vote, Error: nil}}
		}
	case *tmProtoPrivval.Message_SignProposalRequest:
		proposal := typedReq.SignProposalRequest.Proposal
		err = rs.privVal.SignProposal(rs.chainID, typedReq.SignProposalRequest.Proposal)
		if err != nil {
			rs.Logger.Error("Failed to sign proposal", "address", rs.address, "error", err, "proposal", proposal)
			msg.Sum = &tmProtoPrivval.Message_SignedProposalResponse{SignedProposalResponse: &tmProtoPrivval.SignedProposalResponse{
				Proposal: tmProto.Proposal{},
				Error: &tmProtoPrivval.RemoteSignerError{
					Code:        0,
					Description: err.Error(),
				},
			}}
		} else {
			rs.Logger.Info("Signed proposal", "node", rs.address, "height", proposal.Height, "round", proposal.Round, "type", proposal.Type)
			msg.Sum = &tmProtoPrivval.Message_SignedProposalResponse{SignedProposalResponse: &tmProtoPrivval.SignedProposalResponse{
				Proposal: *proposal,
				Error:    nil,
			}}
		}
	case *tmProtoPrivval.Message_PingRequest:
		msg.Sum = &tmProtoPrivval.Message_PingResponse{PingResponse: &tmProtoPrivval.PingResponse{}}
	default:
		err = fmt.Errorf("unknown msg: %v", typedReq)
	}

	return msg, err
}
