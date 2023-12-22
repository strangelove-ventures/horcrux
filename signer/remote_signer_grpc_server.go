package signer

import (
	"context"
	"log/slog"
	"net"
	"time"

	grpccosigner "github.com/strangelove-ventures/horcrux/v3/grpc/cosigner"
	grpchorcrux "github.com/strangelove-ventures/horcrux/v3/grpc/horcrux"
	"github.com/strangelove-ventures/horcrux/v3/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var _ grpchorcrux.RemoteSignerServer = &RemoteSignerGRPCServer{}

type RemoteSignerGRPCServer struct {
	validator  PrivValidator
	logger     *slog.Logger
	listenAddr string

	server *grpc.Server

	grpchorcrux.UnimplementedRemoteSignerServer
}

func NewRemoteSignerGRPCServer(
	logger *slog.Logger,
	validator PrivValidator,
	listenAddr string,
) *RemoteSignerGRPCServer {
	return &RemoteSignerGRPCServer{
		validator:  validator,
		logger:     logger,
		listenAddr: listenAddr,
	}
}

func (s *RemoteSignerGRPCServer) Start() {
	s.logger.Info("Remote Signer GRPC Listening", "address", s.listenAddr)
	sock, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		panic(err)
	}
	s.server = grpc.NewServer()
	grpchorcrux.RegisterRemoteSignerServer(s.server, s)
	reflection.Register(s.server)
	if err := s.server.Serve(sock); err != nil {
		panic(err)
	}
}

func (s *RemoteSignerGRPCServer) OnStop() {
	s.server.GracefulStop()
}

func (s *RemoteSignerGRPCServer) PubKey(
	ctx context.Context,
	req *grpchorcrux.PubKeyRequest,
) (*grpchorcrux.PubKeyResponse, error) {
	chainID := req.ChainId

	totalPubKeyRequests.WithLabelValues(chainID).Inc()

	pubKey, err := s.validator.GetPubKey(ctx, chainID)
	if err != nil {
		s.logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"error", err,
		)
		return nil, err
	}

	return &grpchorcrux.PubKeyResponse{
		PubKey: pubKey.Bytes(),
	}, nil
}

func (s *RemoteSignerGRPCServer) Sign(
	ctx context.Context,
	req *grpccosigner.SignBlockRequest,
) (*grpccosigner.SignBlockResponse, error) {
	chainID, block := req.ChainID, types.BlockFromProto(req.Block)

	signature, timestamp, err := signAndTrack(ctx, s.logger, s.validator, chainID, block)
	if err != nil {
		return nil, err
	}

	return &grpccosigner.SignBlockResponse{
		Signature: signature,
		Timestamp: timestamp.UnixNano(),
	}, nil
}

func signAndTrack(
	ctx context.Context,
	logger *slog.Logger,
	validator PrivValidator,
	chainID string,
	block types.Block,
) ([]byte, time.Time, error) {
	signature, timestamp, err := validator.Sign(ctx, chainID, block)
	if err != nil {
		switch typedErr := err.(type) {
		case *BeyondBlockError:
			logger.Debug(
				"Rejecting sign request",
				"type", types.SignType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"reason", typedErr.msg,
			)
			beyondBlockErrors.WithLabelValues(chainID).Inc()
		default:
			logger.Error(
				"Failed to sign",
				"type", types.SignType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"error", err,
			)
			failedSignVote.WithLabelValues(chainID).Inc()
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
		"type", types.SignType(block.Step),
		"chain_id", chainID,
		"height", block.Height,
		"round", block.Round,
		"sig", signature[:sigLen],
		"ts", block.Timestamp,
	)

	switch block.Step {
	case types.StepPropose:
		lastProposalHeight.WithLabelValues(chainID).Set(float64(block.Height))
		lastProposalRound.WithLabelValues(chainID).Set(float64(block.Round))
		totalProposalsSigned.WithLabelValues(chainID).Inc()
	case types.StepPrevote:
		// Determine number of heights since the last Prevote
		stepSize := block.Height - previousPrevoteHeight
		if previousPrevoteHeight != 0 && stepSize > 1 {
			missedPrevotes.WithLabelValues(chainID).Add(float64(stepSize))
			totalMissedPrevotes.WithLabelValues(chainID).Add(float64(stepSize))
		} else {
			missedPrevotes.WithLabelValues(chainID).Set(0)
		}

		previousPrevoteHeight = block.Height // remember last PrevoteHeight

		metricsTimeKeeper.SetPreviousPrevote(time.Now())

		lastPrevoteHeight.WithLabelValues(chainID).Set(float64(block.Height))
		lastPrevoteRound.WithLabelValues(chainID).Set(float64(block.Round))
		totalPrevotesSigned.WithLabelValues(chainID).Inc()
	case types.StepPrecommit:
		stepSize := block.Height - previousPrecommitHeight
		if previousPrecommitHeight != 0 && stepSize > 1 {
			missedPrecommits.WithLabelValues(chainID).Add(float64(stepSize))
			totalMissedPrecommits.WithLabelValues(chainID).Add(float64(stepSize))
		} else {
			missedPrecommits.WithLabelValues(chainID).Set(0)
		}
		previousPrecommitHeight = block.Height // remember last PrecommitHeight

		metricsTimeKeeper.SetPreviousPrecommit(time.Now())

		lastPrecommitHeight.WithLabelValues(chainID).Set(float64(block.Height))
		lastPrecommitRound.WithLabelValues(chainID).Set(float64(block.Round))
		totalPrecommitsSigned.WithLabelValues(chainID).Inc()
	}

	return signature, timestamp, nil
}
