package hcore

import (
	"context"
	"maps"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// startCoreGrpcTestServer serves the real Core service over a real gRPC
// server bound to a loopback port, mirroring StartGrpcServerByMode's
// insecure-mode registration (grpc.NewServer + RegisterCoreServer) without
// the db/libbox Setup side effects.
func startCoreGrpcTestServer(t *testing.T) CoreClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	srv := grpc.NewServer()
	RegisterCoreServer(srv, &CoreService{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewCoreClient(conn)
}

func TestGetAdaptiveStateRPCRoundTrip(t *testing.T) {
	registerFakeAdaptiveState(t, "grpc-adaptive", adaptive.Snapshot{
		Generation:            7,
		ActiveID:              "fi-9",
		LastGood:              "fi-9",
		Attempts:              12,
		UniqueCandidatesTried: 3,
		TotalAttempts:         12,
		SearchElapsed:         900 * time.Millisecond,
		LastSearchElapsed:     450 * time.Millisecond,
		SearchInProgress:      true,
		StateLoaded:           true,
		StateSaved:            true,
		StateError:            "hint dropped",
		Blackout:              true,
		BlackoutReason:        "offline",
		CoveragePercent:       70,
		CoverageTarget:        80,
		PerCandidate:          map[string]uint64{"fi-9": 12, "de-4": 5},
		CandidateCount:        5,
		SwapGeneration:        3,
	})
	client := startCoreGrpcTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.GetAdaptiveState(ctx, &GetAdaptiveStateRequest{Tag: "grpc-adaptive"})
	if err != nil {
		t.Fatalf("GetAdaptiveState: %v", err)
	}
	// The rpc must return exactly what AdaptiveStateJSON reports — every
	// snapshot field, not just the legacy six.
	want := decodeAdaptiveState(t, AdaptiveStateJSON("grpc-adaptive"))
	if resp.State != want.State || resp.ActiveId != want.ActiveID || resp.LastGood != want.LastGood ||
		resp.Generation != want.Generation || resp.Attempts != want.Attempts || resp.Closed != want.Closed ||
		resp.UniqueCandidatesTried != want.UniqueCandidatesTried || resp.TotalAttempts != want.TotalAttempts ||
		resp.SearchElapsedMs != want.SearchElapsedMs || resp.LastSearchElapsedMs != want.LastSearchElapsedMs ||
		resp.SearchInProgress != want.SearchInProgress || resp.StateLoaded != want.StateLoaded ||
		resp.StateSaved != want.StateSaved || resp.StateError != want.StateError ||
		resp.Blackout != want.Blackout || resp.BlackoutReason != want.BlackoutReason ||
		resp.CoveragePercent != int32(want.CoveragePercent) || resp.CoverageTarget != int32(want.CoverageTarget) ||
		resp.DpiGateEnabled != want.DPIGateEnabled || resp.DpiGateReason != want.DPIGateReason ||
		resp.CandidateCount != int32(want.CandidateCount) || resp.SwapGeneration != want.SwapGeneration ||
		!maps.Equal(resp.PerCandidate, want.PerCandidate) {
		t.Fatalf("rpc response = %+v, want JSON-equivalent %+v", resp, want)
	}
	if resp.State != "active" || resp.ActiveId != "fi-9" || resp.LastGood != "fi-9" || resp.Generation != 7 ||
		resp.Attempts != 12 || resp.Closed || resp.UniqueCandidatesTried != 3 || resp.TotalAttempts != 12 ||
		resp.SearchElapsedMs != 900 || resp.LastSearchElapsedMs != 450 || !resp.SearchInProgress ||
		!resp.StateLoaded || !resp.StateSaved || resp.StateError != "hint dropped" ||
		!resp.Blackout || resp.BlackoutReason != "offline" ||
		resp.CoveragePercent != 70 || resp.CoverageTarget != 80 ||
		resp.CandidateCount != 5 || resp.SwapGeneration != 3 ||
		len(resp.PerCandidate) != 2 || resp.PerCandidate["fi-9"] != 12 || resp.PerCandidate["de-4"] != 5 {
		t.Fatalf("rpc response = %+v, want the fake snapshot fields", resp)
	}
}

func TestGetAdaptiveStateRPCUnknownTag(t *testing.T) {
	client := startCoreGrpcTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.GetAdaptiveState(ctx, &GetAdaptiveStateRequest{Tag: "grpc-never-registered"})
	if err != nil {
		t.Fatalf("GetAdaptiveState: %v", err)
	}
	if resp.State != "unknown" || resp.ActiveId != "" || resp.LastGood != "" ||
		resp.Generation != 0 || resp.Attempts != 0 || resp.Closed {
		t.Fatalf("unknown tag response = %+v, want zero fields with state \"unknown\"", resp)
	}
}
