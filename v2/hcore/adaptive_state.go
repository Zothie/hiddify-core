package hcore

import (
	"context"
	"encoding/json"
	"fmt"

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

// GetAdaptiveState implements the Core gRPC rpc of the same name. It parses
// AdaptiveStateJSON so the state derivation stays in this one place; an
// unregistered tag reports State "unknown".
func (s *CoreService) GetAdaptiveState(ctx context.Context, req *GetAdaptiveStateRequest) (*GetAdaptiveStateResponse, error) {
	snap, err := decodeAdaptiveSnapshot(AdaptiveStateJSON(req.GetTag()))
	if err != nil {
		return nil, err
	}
	return &GetAdaptiveStateResponse{
		State:      snap.State,
		ActiveId:   snap.ActiveID,
		LastGood:   snap.LastGood,
		Attempts:   snap.Attempts,
		Generation: snap.Generation,
		Closed:     snap.Closed,
	}, nil
}

func decodeAdaptiveSnapshot(raw string) (AdaptiveSnapshot, error) {
	var snap AdaptiveSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return AdaptiveSnapshot{}, fmt.Errorf("decode adaptive state: %w", err)
	}
	return snap, nil
}
