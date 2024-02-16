package cosigner

import (
	// "context"
	// "fmt"

	// "github.com/strangelove-ventures/horcrux/src/types"

	"context"

	"github.com/google/uuid"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"
	"github.com/strangelove-ventures/horcrux/src/types"
	// "github.com/strangelove-ventures/horcrux/src/proto"
)

func NewCosignerServer(
	// cosigner *cosigner.LocalCosigner,
	cosigner *LocalCosigner,
) *CosignerServer {
	return &CosignerServer{
		cosigner: cosigner,
	}
}

type CosignerServer struct {
	// cosigner           *cosigner.LocalCosigner //Change to interface
	cosigner *LocalCosigner
	// thresholdValidator *ThresholdValidator
	// raftStore          *RaftStore
	// TODO: add logger and not rely on raftStore.logger

	// TODO: Decouple cosignerserver from nodeserver.
	proto.UnimplementedCosignerServer
	// proto.UnimplementedTresholdValidatorServer
}

func (rpc *CosignerServer) GetNonces(
	ctx context.Context,
	req *proto.GetNoncesRequest,
) (*proto.GetNoncesResponse, error) {
	uuids := make([]uuid.UUID, len(req.Uuids))
	for i, uuidBytes := range req.Uuids {
		uuids[i] = uuid.UUID(uuidBytes)
	}
	res, err := rpc.cosigner.GetNonces(
		ctx,
		uuids,
	)
	if err != nil {
		return nil, err
	}

	return &proto.GetNoncesResponse{
		Nonces: res.ToProto(),
	}, nil
}

// TODO: Move to cosigner server
func (rpc *CosignerServer) SetNoncesAndSign(
	ctx context.Context,
	req *proto.SetNoncesAndSignRequest,
) (*proto.SetNoncesAndSignResponse, error) {
	res, err := rpc.cosigner.SetNoncesAndSign(ctx, CosignerSetNoncesAndSignRequest{
		ChainID: req.ChainID,
		Nonces: &CosignerUUIDNonces{
			UUID:   uuid.UUID(req.Uuid),
			Nonces: FromProtoToNonces(req.GetNonces()),
		},
		HRST:      types.HRSTFromProto(req.GetHrst()),
		SignBytes: req.GetSignBytes(),
	})
	if err != nil {
		rpc.cosigner.logger.Error(
			"Failed to sign with shard",
			"chain_id", req.ChainID,
			"height", req.Hrst.Height,
			"round", req.Hrst.Round,
			"step", req.Hrst.Step,
			"error", err,
		)
		return nil, err
	}
	rpc.cosigner.logger.Info(
		"Signed with shard",
		"chain_id", req.ChainID,
		"height", req.Hrst.Height,
		"round", req.Hrst.Round,
		"step", req.Hrst.Step,
	)
	return &proto.SetNoncesAndSignResponse{
		NoncePublic: res.NoncePublic,
		Timestamp:   res.Timestamp.UnixNano(),
		Signature:   res.Signature,
	}, nil
}

func (rpc *CosignerServer) Ping(context.Context, *proto.PingRequest) (*proto.PingResponse, error) {
	return &proto.PingResponse{}, nil
}
