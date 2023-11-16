package signer

import (
	"context"
	"net"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"

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
	s := &RemoteSignerGRPCServer{
		validator:  validator,
		logger:     logger,
		listenAddr: listenAddr,
	}
	s.BaseService = *cometservice.NewBaseService(logger, "RemoteSignerGRPCServer", s)
	return s
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

func (s *RemoteSignerGRPCServer) PubKey(ctx context.Context, req *proto.PubKeyRequest) (*proto.PubKeyResponse, error) {
	totalPubKeyRequests.Inc()

	pubKey, err := s.validator.GetPubKey(ctx, req.ChainId)
	if err != nil {
		s.logger.Error(
			"Failed to get Pub Key",
			"chain_id", req.ChainId,
			"error", err,
		)
		return nil, err
	}

	return &proto.PubKeyResponse{
		PubKey: pubKey,
	}, nil
}

func (s *RemoteSignerGRPCServer) Sign(
	ctx context.Context,
	req *proto.SignBlockRequest,
) (*proto.SignBlockResponse, error) {
	chainID, block := req.ChainID, BlockFromProto(req.Block)

	signature, timestamp, err := signAndTrack(ctx, s.logger, s.validator, chainID, block)
	if err != nil {
		return nil, err
	}

	return &proto.SignBlockResponse{
		Signature: signature,
		Timestamp: timestamp.UnixNano(),
	}, nil
}

func signAndTrack(
	ctx context.Context,
	logger cometlog.Logger,
	validator PrivValidator,
	chainID string,
	block Block,
) ([]byte, time.Time, error) {
	signature, timestamp, err := validator.Sign(ctx, chainID, block)
	if err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			logger.Debug(
				"Rejecting sign request",
				"type", signType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"reason", typedErr.msg,
			)
			beyondBlockErrors.Inc()
		default:
			logger.Error(
				"Failed to sign",
				"type", signType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"error", err,
			)
			failedSignVote.Inc()
		}
		return nil, block.Timestamp, err
	}

	// Show signatures provided to each node have the same signature and timestamps
	sigLen := 6
	if len(signature) < sigLen {
		sigLen = len(signature)
	}
	logger.Info(
		"Signed",
		"type", signType(block.Step),
		"chain_id", chainID,
		"height", block.Height,
		"round", block.Round,
		"sig", signature[:sigLen],
		"ts", block.Timestamp,
	)

	switch block.Step {
	case stepPropose:
		lastProposalHeight.Set(float64(block.Height))
		lastProposalRound.Set(float64(block.Round))
		totalProposalsSigned.Inc()
	case stepPrevote:
		// Determine number of heights since the last Prevote
		stepSize := block.Height - previousPrevoteHeight
		if previousPrevoteHeight != 0 && stepSize > 1 {
			missedPrevotes.Add(float64(stepSize))
			totalMissedPrevotes.Add(float64(stepSize))
		} else {
			missedPrevotes.Set(0)
		}

		previousPrevoteHeight = block.Height // remember last PrevoteHeight

		metricsTimeKeeper.SetPreviousPrevote(time.Now())

		lastPrevoteHeight.Set(float64(block.Height))
		lastPrevoteRound.Set(float64(block.Round))
		totalPrevotesSigned.Inc()
	case stepPrecommit:
		stepSize := block.Height - previousPrecommitHeight
		if previousPrecommitHeight != 0 && stepSize > 1 {
			missedPrecommits.Add(float64(stepSize))
			totalMissedPrecommits.Add(float64(stepSize))
		} else {
			missedPrecommits.Set(0)
		}
		previousPrecommitHeight = block.Height // remember last PrecommitHeight

		metricsTimeKeeper.SetPreviousPrecommit(time.Now())

		lastPrecommitHeight.Set(float64(block.Height))
		lastPrecommitRound.Set(float64(block.Round))
		totalPrecommitsSigned.Inc()
	}

	return signature, timestamp, nil
}
