package connector

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/strangelove-ventures/horcrux/src/metrics"

	"github.com/strangelove-ventures/horcrux/src/types"

	cometlog "github.com/cometbft/cometbft/libs/log"
	cometservice "github.com/cometbft/cometbft/libs/service"

	// "github.com/strangelove-ventures/horcrux/src/proto"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var _ proto.ConnectorServer = &SentrySignerGRPCServer{}

// SentrySignerGRPCServer is the server that listens for signing requests from the "sentry" which is the client
// Sentry (a.k.a client) -> SentrySignerGRPCServer -> Sentry
type SentrySignerGRPCServer struct {
	cometservice.BaseService

	validator  IPrivValidator
	logger     cometlog.Logger
	listenAddr string

	server *grpc.Server

	proto.UnimplementedConnectorServer
}

func NewSentrySignerGRPCServer(
	logger cometlog.Logger,
	validator IPrivValidator,
	listenAddr string,
) *SentrySignerGRPCServer {
	s := &SentrySignerGRPCServer{
		validator:  validator,
		logger:     logger,
		listenAddr: listenAddr,
	}
	s.BaseService = *cometservice.NewBaseService(logger, "RemoteSignerGRPCServer", s)
	return s
}

func (s *SentrySignerGRPCServer) OnStart() error {
	s.logger.Info("Remote Signer GRPC Listening", "address", s.listenAddr)
	sock, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.server = grpc.NewServer()
	proto.RegisterConnectorServer(s.server, s)
	reflection.Register(s.server)
	return s.server.Serve(sock)
}

func (s *SentrySignerGRPCServer) OnStop() {
	s.server.GracefulStop()
}

func (s *SentrySignerGRPCServer) PubKey(ctx context.Context, req *proto.PubKeyRequest) (*proto.PubKeyResponse, error) {
	chainID := req.ChainId

	metrics.TotalPubKeyRequests.WithLabelValues(chainID).Inc()

	pubKey, err := s.validator.GetPubKey(ctx, chainID)
	if err != nil {
		s.logger.Error(
			"Failed to get Pub Key",
			"chain_id", chainID,
			"error", err,
		)
		return nil, err
	}

	return &proto.PubKeyResponse{
		PubKey: pubKey,
	}, nil
}

func (s *SentrySignerGRPCServer) Sign(
	ctx context.Context,
	req *proto.SignBlockRequest,
) (*proto.SignBlockResponse, error) {
	chainID, block := req.ChainID, types.BlockFromProto(req.Block)

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
	validator IPrivValidator,
	chainID string,
	block types.Block,
) ([]byte, time.Time, error) {
	signature, timestamp, err := validator.Sign(ctx, chainID, block)
	if err != nil {
		var typedErr *metrics.BeyondBlockError
		switch {
		case errors.As(err, &typedErr):
			logger.Debug(
				"Rejecting sign request",
				"type", types.SignType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"reason", typedErr.Msg,
			)
			metrics.BeyondBlockErrors.WithLabelValues(chainID).Inc()
		default:
			logger.Error(
				"Failed to sign",
				"type", types.SignType(block.Step),
				"chain_id", chainID,
				"height", block.Height,
				"round", block.Round,
				"error", err,
			)
			metrics.FailedSignVote.WithLabelValues(chainID).Inc()
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
		metrics.LastProposalHeight.WithLabelValues(chainID).Set(float64(block.Height))
		metrics.LastProposalRound.WithLabelValues(chainID).Set(float64(block.Round))
		metrics.TotalProposalsSigned.WithLabelValues(chainID).Inc()
	case types.StepPrevote:
		// Determine number of heights since the last Prevote
		stepSize := block.Height - metrics.PreviousPrevoteHeight
		if metrics.PreviousPrevoteHeight != 0 && stepSize > 1 {
			metrics.MissedPrevotes.WithLabelValues(chainID).Add(float64(stepSize))
			metrics.TotalMissedPrevotes.WithLabelValues(chainID).Add(float64(stepSize))
		} else {
			metrics.MissedPrevotes.WithLabelValues(chainID).Set(0)
		}

		metrics.PreviousPrevoteHeight = block.Height // remember last PrevoteHeight

		metrics.MetricsTimeKeeper.SetPreviousPrevote(time.Now())

		metrics.LastPrevoteHeight.WithLabelValues(chainID).Set(float64(block.Height))
		metrics.LastPrevoteRound.WithLabelValues(chainID).Set(float64(block.Round))
		metrics.TotalPrevotesSigned.WithLabelValues(chainID).Inc()
	case types.StepPrecommit:
		stepSize := block.Height - metrics.PreviousPrecommitHeight
		if metrics.PreviousPrecommitHeight != 0 && stepSize > 1 {
			metrics.MissedPrecommits.WithLabelValues(chainID).Add(float64(stepSize))
			metrics.TotalMissedPrecommits.WithLabelValues(chainID).Add(float64(stepSize))
		} else {
			metrics.MissedPrecommits.WithLabelValues(chainID).Set(0)
		}

		metrics.PreviousPrecommitHeight = block.Height // remember last PrecommitHeight
		metrics.MetricsTimeKeeper.SetPreviousPrecommit(time.Now())

		metrics.LastPrecommitHeight.WithLabelValues(chainID).Set(float64(block.Height))
		metrics.LastPrecommitRound.WithLabelValues(chainID).Set(float64(block.Round))
		metrics.TotalPrecommitsSigned.WithLabelValues(chainID).Inc()
	}

	return signature, timestamp, nil
}
