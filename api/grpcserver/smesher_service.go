package grpcserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	pb "github.com/spacemeshos/api/release/go/spacemesh/v1"
	"github.com/spacemeshos/post/config"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacemeshos/go-spacemesh/activation"
	"github.com/spacemeshos/go-spacemesh/common/types"
)

// SmesherService exposes endpoints to manage smeshing.
type SmesherService struct {
	postSetupProvider postSetupProvider
	smeshingProvider  activation.SmeshingProvider

	streamInterval time.Duration
	postOpts       activation.PostSetupOpts
}

// RegisterService registers this service with a grpc server instance.
func (s SmesherService) RegisterService(server *Server) {
	pb.RegisterSmesherServiceServer(server.GrpcServer, s)
}

// NewSmesherService creates a new grpc service using config data.
func NewSmesherService(post postSetupProvider, smeshing activation.SmeshingProvider, streamInterval time.Duration, postOpts activation.PostSetupOpts) *SmesherService {
	return &SmesherService{
		postSetupProvider: post,
		smeshingProvider:  smeshing,
		streamInterval:    streamInterval,
		postOpts:          postOpts,
	}
}

// IsSmeshing reports whether the node is smeshing.
func (s SmesherService) IsSmeshing(context.Context, *empty.Empty) (*pb.IsSmeshingResponse, error) {
	return &pb.IsSmeshingResponse{IsSmeshing: s.smeshingProvider.Smeshing()}, nil
}

// StartSmeshing requests that the node begin smeshing.
func (s SmesherService) StartSmeshing(ctx context.Context, in *pb.StartSmeshingRequest) (*pb.StartSmeshingResponse, error) {
	if in.Coinbase == nil {
		return nil, status.Errorf(codes.InvalidArgument, "`Coinbase` must be provided")
	}

	if in.Opts == nil {
		return nil, status.Error(codes.InvalidArgument, "`Opts` must be provided")
	}

	if in.Opts.DataDir == "" {
		return nil, status.Error(codes.InvalidArgument, "`Opts.DataDir` must be provided")
	}

	if in.Opts.NumUnits == 0 {
		return nil, status.Error(codes.InvalidArgument, "`Opts.NumUnits` must be provided")
	}

	if in.Opts.MaxFileSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "`Opts.MaxFileSize` must be provided")
	}

	// Copy provided post opts
	opts := s.postOpts
	// Overlay api provided opts
	opts.DataDir = in.Opts.DataDir
	opts.NumUnits = in.Opts.NumUnits
	opts.MaxFileSize = in.Opts.MaxFileSize
	if in.Opts.ProviderId != nil {
		opts.ProviderID.SetInt64(int64(*in.Opts.ProviderId))
	}
	opts.Throttle = in.Opts.Throttle

	coinbaseAddr, err := types.StringToAddress(in.Coinbase.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse in.Coinbase.Address `%s`: %w", in.Coinbase.Address, err)
	}
	if err := s.smeshingProvider.StartSmeshing(coinbaseAddr, opts); err != nil {
		err := fmt.Sprintf("failed to start smeshing: %v", err)
		ctxzap.Error(ctx, err)
		return nil, status.Error(codes.Internal, err)
	}

	return &pb.StartSmeshingResponse{
		Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
	}, nil
}

// StopSmeshing requests that the node stop smeshing.
func (s SmesherService) StopSmeshing(ctx context.Context, in *pb.StopSmeshingRequest) (*pb.StopSmeshingResponse, error) {
	errchan := make(chan error, 1)
	go func() {
		errchan <- s.smeshingProvider.StopSmeshing(in.DeleteFiles)
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context done: %w", ctx.Err())
	case err := <-errchan:
		if err != nil {
			err := fmt.Sprintf("failed to stop smeshing: %v", err)
			ctxzap.Error(ctx, err)
			return nil, status.Error(codes.Internal, err)
		}
	}
	return &pb.StopSmeshingResponse{
		Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
	}, nil
}

// SmesherID returns the smesher ID of this node.
func (s SmesherService) SmesherID(context.Context, *empty.Empty) (*pb.SmesherIDResponse, error) {
	return &pb.SmesherIDResponse{PublicKey: s.smeshingProvider.SmesherID().Bytes()}, nil
}

// Coinbase returns the current coinbase setting of this node.
func (s SmesherService) Coinbase(context.Context, *empty.Empty) (*pb.CoinbaseResponse, error) {
	return &pb.CoinbaseResponse{AccountId: &pb.AccountId{Address: s.smeshingProvider.Coinbase().String()}}, nil
}

// SetCoinbase sets the current coinbase setting of this node.
func (s SmesherService) SetCoinbase(_ context.Context, in *pb.SetCoinbaseRequest) (*pb.SetCoinbaseResponse, error) {
	if in.Id == nil {
		return nil, status.Errorf(codes.InvalidArgument, "`Id` must be provided")
	}

	addr, err := types.StringToAddress(in.Id.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse in.Id.Address `%s`: %w", in.Id.Address, err)
	}
	s.smeshingProvider.SetCoinbase(addr)

	return &pb.SetCoinbaseResponse{
		Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
	}, nil
}

// MinGas returns the current mingas setting of this node.
func (s SmesherService) MinGas(context.Context, *empty.Empty) (*pb.MinGasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "this endpoint is not implemented")
}

// SetMinGas sets the mingas setting of this node.
func (s SmesherService) SetMinGas(context.Context, *pb.SetMinGasRequest) (*pb.SetMinGasResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "this endpoint is not implemented")
}

// EstimatedRewards returns estimated smeshing rewards over the next epoch.
func (s SmesherService) EstimatedRewards(context.Context, *pb.EstimatedRewardsRequest) (*pb.EstimatedRewardsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "this endpoint is not implemented")
}

// PostSetupStatus returns post data status.
func (s SmesherService) PostSetupStatus(ctx context.Context, _ *empty.Empty) (*pb.PostSetupStatusResponse, error) {
	status := s.postSetupProvider.Status()
	return &pb.PostSetupStatusResponse{Status: statusToPbStatus(status)}, nil
}

// PostSetupStatusStream exposes a stream of status updates during post setup.
func (s SmesherService) PostSetupStatusStream(_ *empty.Empty, stream pb.SmesherService_PostSetupStatusStreamServer) error {
	timer := time.NewTicker(s.streamInterval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			status := s.postSetupProvider.Status()
			if err := stream.Send(&pb.PostSetupStatusStreamResponse{Status: statusToPbStatus(status)}); err != nil {
				return fmt.Errorf("send to stream: %w", err)
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

// PostSetupComputeProviders returns a list of available Post setup compute providers.
func (s SmesherService) PostSetupProviders(ctx context.Context, in *pb.PostSetupProvidersRequest) (*pb.PostSetupProvidersResponse, error) {
	providers, err := s.postSetupProvider.Providers()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get OpenCL providers: %v", err)
	}

	res := &pb.PostSetupProvidersResponse{}
	res.Providers = make([]*pb.PostSetupProvider, len(providers))
	for i, p := range providers {
		var hashesPerSec int
		if in.Benchmark {
			var err error
			hashesPerSec, err = s.postSetupProvider.Benchmark(p)
			if err != nil {
				ctxzap.Error(ctx, "failed to benchmark provider", zap.Error(err))
				return nil, status.Error(codes.Internal, "failed to benchmark provider")
			}
		}

		res.Providers[i] = &pb.PostSetupProvider{
			Id:          uint32(p.ID),
			Model:       p.Model,
			DeviceType:  pb.PostSetupProvider_DeviceType(p.DeviceType),
			Performance: uint64(hashesPerSec),
		}
	}

	return res, nil
}

// PostConfig returns the Post protocol config.
func (s SmesherService) PostConfig(context.Context, *empty.Empty) (*pb.PostConfigResponse, error) {
	cfg := s.postSetupProvider.Config()

	return &pb.PostConfigResponse{
		BitsPerLabel:  config.BitsPerLabel,
		LabelsPerUnit: cfg.LabelsPerUnit,
		MinNumUnits:   cfg.MinNumUnits,
		MaxNumUnits:   cfg.MaxNumUnits,
		K1:            cfg.K1,
		K2:            cfg.K2,
	}, nil
}

func statusToPbStatus(status *activation.PostSetupStatus) *pb.PostSetupStatus {
	pbStatus := &pb.PostSetupStatus{}

	pbStatus.State = pb.PostSetupStatus_State(status.State) // assuming enum values match.
	pbStatus.NumLabelsWritten = status.NumLabelsWritten

	if status.LastOpts != nil {
		var providerID *uint32
		if status.LastOpts.ProviderID.Value() != nil {
			providerID = new(uint32)
			*providerID = uint32(*status.LastOpts.ProviderID.Value())
		}

		pbStatus.Opts = &pb.PostSetupOpts{
			DataDir:     status.LastOpts.DataDir,
			NumUnits:    status.LastOpts.NumUnits,
			MaxFileSize: status.LastOpts.MaxFileSize,
			ProviderId:  providerID,
			Throttle:    status.LastOpts.Throttle,
		}
	}

	return pbStatus
}

// UpdatePoetServers update server that is used for generating PoETs.
func (s SmesherService) UpdatePoetServers(ctx context.Context, req *pb.UpdatePoetServersRequest) (*pb.UpdatePoetServersResponse, error) {
	err := s.smeshingProvider.UpdatePoETServers(ctx, req.Urls)
	if err == nil {
		return &pb.UpdatePoetServersResponse{
			Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
		}, nil
	}
	switch {
	case errors.Is(err, activation.ErrPoetServiceUnstable):
		return nil, status.Errorf(codes.Unavailable, "can't reach poet service (%v). retry later", err)
	}
	return nil, status.Errorf(codes.Internal, "failed to update poet server")
}
