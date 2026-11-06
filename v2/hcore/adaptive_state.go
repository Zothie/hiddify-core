package hcore

import (
	"encoding/json"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// AdaptiveSnapshot is the JSON-facing copy of adaptive.Snapshot.
type AdaptiveSnapshot struct {
	State      string `json:"state"`
	Generation uint64 `json:"generation"`
	ActiveID   string `json:"active_id"`
	LastGood   string `json:"last_good"`
	Attempts   uint64 `json:"attempts"`
	Closed     bool   `json:"closed"`
}

// Stop-gap pending gRPC codegen: the Core service cannot gain a
// GetAdaptiveState rpc until protoc-gen-go-grpc is available. The Makefile
// protos target regenerates every proto file with that plugin, and neither
// protoc-gen-go-grpc nor protoc-gen-go is installed or present in the module
// cache (GOPROXY=off), so regenerating the service stubs here would mean
// hand-editing generated files. The app side is blocked the same way: the
// Dart protoc_plugin is absent, so hcore_service.pbgrpc.dart cannot be
// regenerated. Until codegen lands, this helper is reachable from Go callers
// only, and AdaptiveStateJSON is the single place to wire into the new rpc.
//
// AdaptiveStateJSON returns the coordinator state of the hydra adaptive
// outbound registered under tag. Unknown tags report {"state":"unknown"};
// live coordinators report "active" (a verified tunnel exists), "connecting"
// (attempts in flight, none verified yet) or "closed".
func AdaptiveStateJSON(tag string) string {
	snap, ok := adaptive.SnapshotByTag(tag)
	if !ok {
		return `{"state":"unknown"}`
	}
	state := "connecting"
	switch {
	case snap.Closed:
		state = "closed"
	case snap.ActiveID != "":
		state = "active"
	}
	out, err := json.Marshal(AdaptiveSnapshot{State: state, Generation: snap.Generation, ActiveID: snap.ActiveID, LastGood: snap.LastGood, Attempts: snap.Attempts, Closed: snap.Closed})
	if err != nil {
		return `{"state":"unknown"}`
	}
	return string(out)
}
