package signer

import (
	"context"
	"fmt"
	"net"
	"time"

	cometcryptoencoding "github.com/cometbft/cometbft/crypto/encoding"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/strangelove-ventures/horcrux/signer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var _ proto.RemoteSignerServer = &RemoteSignerGRPCServer{}

type RemoteSignerGRPCServer struct {
	cometservice.BaseService

	validator  PrivValidator
	logger     cometlog.Logger
	listenAddr string

	server *grpc.Server

	proto.UnimplementedRemoteSignerServer
}

func NewRemoteSignerGRPCServer(
	logger cometlog.Logger,
	validator PrivValidator,
	listenAddr string,
) *RemoteSignerGRPCServer {
	return &RemoteSignerGRPCServer{
		validator: validator,
		logger:    logger,
	}
}

func (s *RemoteSignerGRPCServer) OnStart() error {
	s.logger.Info("Remote Signer GRPC Listening", "address", s.listenAddr)
	sock, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.server = grpc.NewServer()
	proto.RegisterRemoteSignerServer(s.server, s)
	reflection.Register(s.server)
	return s.server.Serve(sock)
}

func (s *RemoteSignerGRPCServer) OnStop() {
	s.server.GracefulStop()
}

func (s *RemoteSignerGRPCServer) PubKey(_ context.Context, req *cometprotoprivval.PubKeyRequest) (*cometprotoprivval.PubKeyResponse, error) {
	totalPubKeyRequests.Inc()
	res := new(cometprotoprivval.PubKeyResponse)

	chainID := req.ChainId

	pubKey, err := s.validator.GetPubKey(chainID)
	if err != nil {
		s.logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"error", err,
		)
		res.Error = getRemoteSignerError(err)
		return res, nil
	}
	pk, err := cometcryptoencoding.PubKeyToProto(pubKey)
	if err != nil {
		s.logger.Error(
			"Failed to encode public key",
			"chain_id", chainID,
			"error", err,
		)
		res.Error = getRemoteSignerError(err)
		return res, nil
	}
	res.PubKey = pk
	return res, nil
}

func (s *RemoteSignerGRPCServer) SignVote(_ context.Context, req *cometprotoprivval.SignVoteRequest) (*cometprotoprivval.SignedVoteResponse, error) {
	res := new(cometprotoprivval.SignedVoteResponse)

	chainID := req.ChainId
	vote := req.Vote

	if err := s.validator.SignVote(chainID, vote); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			s.logger.Debug(
				"Rejecting sign vote request",
				"chain_id", chainID,
				"height", vote.Height,
				"round", vote.Round,
				"type", vote.Type,
				"validator", fmt.Sprintf("%X", vote.ValidatorAddress),
				"reason", typedErr.msg,
			)
			beyondBlockErrors.Inc()
		default:
			s.logger.Error(
				"Failed to sign vote",
				"chain_id", chainID,
				"height", vote.Height,
				"round", vote.Round,
				"type", vote.Type,
				"validator", fmt.Sprintf("%X", vote.ValidatorAddress),
				"error", err,
			)
			failedSignVote.Inc()
		}
		res.Error = getRemoteSignerError(err)
		return res, nil
	}
	// Show signatures provided to each node have the same signature and timestamps
	sigLen := 6
	if len(vote.Signature) < sigLen {
		sigLen = len(vote.Signature)
	}
	s.logger.Info(
		"Signed vote",
		"chain_id", chainID,
		"height", vote.Height,
		"round", vote.Round,
		"type", vote.Type,
		"sig", vote.Signature[:sigLen],
		"ts", vote.Timestamp.Unix(),
	)

	if vote.Type == cometproto.PrecommitType {
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
	if vote.Type == cometproto.PrevoteType {
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

	res.Vote = *vote
	return res, nil
}

func (s *RemoteSignerGRPCServer) SignProposal(_ context.Context, req *cometprotoprivval.SignProposalRequest) (*cometprotoprivval.SignedProposalResponse, error) {
	res := new(cometprotoprivval.SignedProposalResponse)

	chainID := req.ChainId
	proposal := req.Proposal

	if err := s.validator.SignProposal(chainID, proposal); err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			s.logger.Debug(
				"Rejecting proposal sign request",
				"chain_id", chainID,
				"height", proposal.Height,
				"round", proposal.Round,
				"type", proposal.Type,
				"reason", typedErr.msg,
			)
			beyondBlockErrors.Inc()
		default:
			s.logger.Error(
				"Failed to sign proposal",
				"chain_id", chainID,
				"height", proposal.Height,
				"round", proposal.Round,
				"type", proposal.Type,
				"error", err,
			)
		}
		res.Error = getRemoteSignerError(err)
		return res, nil
	}
	// Show signatures provided to each node have the same signature and timestamps
	sigLen := 6
	if len(proposal.Signature) < sigLen {
		sigLen = len(proposal.Signature)
	}
	s.logger.Info(
		"Signed proposal",
		"chain_id", chainID,
		"height", proposal.Height,
		"round", proposal.Round,
		"type", proposal.Type,
		"sig", proposal.Signature[:sigLen],
		"ts", proposal.Timestamp.Unix(),
	)
	lastProposalHeight.Set(float64(proposal.Height))
	lastProposalRound.Set(float64(proposal.Round))
	totalProposalsSigned.Inc()

	res.Proposal = *proposal
	return res, nil
}

func (s *RemoteSignerGRPCServer) Ping(context.Context, *cometprotoprivval.PingRequest) (*cometprotoprivval.PingResponse, error) {
	return new(cometprotoprivval.PingResponse), nil
}
