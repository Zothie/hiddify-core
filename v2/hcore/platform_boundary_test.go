package hcore

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
)

func TestAndroidPlatformBoundary(t *testing.T) {
	oldAndroid, oldStatic := androidPlatformRequired, static
	oldServers := grpcServer
	t.Cleanup(func() { androidPlatformRequired, static, grpcServer = oldAndroid, oldStatic, oldServers })
	androidPlatformRequired = true
	static = &HiddifyInstance{CoreState: CoreStates_STOPPED, logObserver: oldStatic.logObserver, coreInfoObserver: oldStatic.coreInfoObserver}
	grpcServer = make(map[SetupMode]*grpc.Server)
	for _, mode := range []SetupMode{SetupMode_GRPC_BACKGROUND, SetupMode_GRPC_BACKGROUND_INSECURE} {
		// Existing servers must not turn an invalid setup into success either.
		grpcServer[mode] = grpc.NewServer()
		if err := Setup(&SetupRequest{Mode: mode}, nil); err == nil || !strings.Contains(err.Error(), "platform") {
			t.Fatalf("Android service setup mode %v: error = %v, want missing platform", mode, err)
		}
	}
	grpcServer[SetupMode_GRPC_NORMAL_INSECURE] = grpc.NewServer()
	if err := Setup(&SetupRequest{Mode: SetupMode_GRPC_NORMAL_INSECURE}, nil); err != nil {
		t.Fatalf("UI nil setup rejected: %v", err)
	}
	for _, state := range []CoreStates{CoreStates_STOPPED, CoreStates_STARTED} {
		static.CoreState = state
		if _, err := StartService(context.Background(), &StartRequest{ConfigContent: "{}"}); err == nil || !strings.Contains(err.Error(), "platform") {
			t.Fatalf("start state %v: error = %v, want missing platform", state, err)
		}
	}
	androidPlatformRequired = false
	if err := Setup(&SetupRequest{Mode: SetupMode_GRPC_BACKGROUND_INSECURE}, nil); err != nil {
		t.Fatalf("desktop nil setup rejected: %v", err)
	}
}
