package signer

import (
	"context"
	"fmt"

	tmCryptoEncoding "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/proto/tendermint/privval"
	tm "github.com/tendermint/tendermint/types"
)

type RemoteSignerGRPCServer struct {
	chainID string
	address string
	privVal tm.PrivValidator
	logger  log.Logger
	privval.UnimplementedPrivValidatorAPIServer
}

func newRemoteSignerGRPCServer(chainID, address string, privVal tm.PrivValidator, logger log.Logger) RemoteSignerGRPCServer {
	return RemoteSignerGRPCServer{
		chainID: chainID,
		address: address,
		privVal: privVal,
		logger:  logger,
	}
}

func (server *RemoteSignerGRPCServer) GetPubKey(
	ctx context.Context,
	req *privval.PubKeyRequest,
) (*privval.PubKeyResponse, error) {
	res := &privval.PubKeyResponse{}
	pubKey, err := server.privVal.GetPubKey()
	if err != nil {
		server.logger.Error("Failed to get Pub Key", "address", server.address, "error", err)
		res.Error = getRemoteSignerError(err)
		return res, err
	}
	pk, err := tmCryptoEncoding.PubKeyToProto(pubKey)
	if err != nil {
		server.logger.Error("Failed to encode Pub Key", "address", server.address, "error", err)
		res.Error = getRemoteSignerError(err)
		return res, err
	}
	res.PubKey = pk
	return res, nil
}

func (server *RemoteSignerGRPCServer) SignVote(
	ctx context.Context,
	req *privval.SignVoteRequest,
) (*privval.SignedVoteResponse, error) {
	vote := req.Vote
	res := &privval.SignedVoteResponse{}
	if err := server.privVal.SignVote(server.chainID, vote); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			server.logger.Debug("Rejecting sign vote request", "reason", typedErr.msg)
		default:
			server.logger.Error("Failed to sign vote", "address", server.address, "error", err, "vote_type", vote.Type,
				"height", vote.Height, "round", vote.Round, "validator", fmt.Sprintf("%X", vote.ValidatorAddress))
		}
		res.Error = getRemoteSignerError(err)
		return res, err
	}
	server.logger.Info("Signed vote", "node", server.address, "height", vote.Height,
		"round", vote.Round, "type", vote.Type)
	res.Vote = *vote
	return res, nil
}

func (server *RemoteSignerGRPCServer) SignProposal(
	ctx context.Context,
	req *privval.SignProposalRequest,
) (*privval.SignedProposalResponse, error) {
	proposal := req.Proposal
	res := &privval.SignedProposalResponse{}
	if err := server.privVal.SignProposal(server.chainID, proposal); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			server.logger.Debug("Rejecting proposal sign request", "reason", typedErr.msg)
		default:
			server.logger.Error("Failed to sign proposal", "address", server.address, "error", err, "proposal", proposal)
		}
		res.Error = getRemoteSignerError(err)
		return res, err
	}

	server.logger.Info("Signed proposal", "node", server.address,
		"height", proposal.Height, "round", proposal.Round, "type", proposal.Type)
	res.Proposal = *proposal
	return res, nil
}
