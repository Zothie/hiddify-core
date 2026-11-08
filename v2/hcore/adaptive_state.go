package hcore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/protocol/hydra"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// AdaptiveSnapshot is the JSON-facing copy of adaptive.Snapshot. Durations
// travel as milliseconds; every other field passes through verbatim so the
// gRPC response mirrors the coordinator snapshot one-to-one.
type AdaptiveSnapshot struct {
	State                 string            `json:"state"`
	Generation            uint64            `json:"generation"`
	ActiveID              string            `json:"active_id"`
	LastGood              string            `json:"last_good"`
	Attempts              uint64            `json:"attempts"`
	Closed                bool              `json:"closed"`
	UniqueCandidatesTried uint64            `json:"unique_candidates_tried"`
	TotalAttempts         uint64            `json:"total_attempts"`
	SearchElapsedMs       uint64            `json:"search_elapsed_ms"`
	LastSearchElapsedMs   uint64            `json:"last_search_elapsed_ms"`
	SearchInProgress      bool              `json:"search_in_progress"`
	StateLoaded           bool              `json:"state_loaded"`
	StateSaved            bool              `json:"state_saved"`
	StateError            string            `json:"state_error"`
	Blackout              bool              `json:"blackout"`
	BlackoutReason        string            `json:"blackout_reason"`
	CoveragePercent       int               `json:"coverage_percent"`
	CoverageTarget        int               `json:"coverage_target"`
	PerCandidate          map[string]uint64 `json:"per_candidate"`
	CandidateCount        int               `json:"candidate_count"`
	SwapGeneration        uint64            `json:"swap_generation"`
	DPIGateEnabled        bool              `json:"dpi_gate_enabled"`
	DPIGateReason         string            `json:"dpi_gate_reason"`
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
	// The DPI gate status lives in the outbound layer (hydra dpigate.go),
	// not in the coordinator: merge it into the snapshot copy this seam
	// reports so both the JSON view and the gRPC response carry it.
	snap.DPIGateEnabled, snap.DPIGateReason = hydra.GateState()
	state := "connecting"
	switch {
	case snap.Closed:
		state = "closed"
	case snap.ActiveID != "":
		state = "active"
	}
	out, err := json.Marshal(AdaptiveSnapshot{
		State:                 state,
		Generation:            snap.Generation,
		ActiveID:              snap.ActiveID,
		LastGood:              snap.LastGood,
		Attempts:              snap.Attempts,
		Closed:                snap.Closed,
		UniqueCandidatesTried: snap.UniqueCandidatesTried,
		TotalAttempts:         snap.TotalAttempts,
		SearchElapsedMs:       uint64(snap.SearchElapsed.Milliseconds()),
		LastSearchElapsedMs:   uint64(snap.LastSearchElapsed.Milliseconds()),
		SearchInProgress:      snap.SearchInProgress,
		StateLoaded:           snap.StateLoaded,
		StateSaved:            snap.StateSaved,
		StateError:            snap.StateError,
		Blackout:              snap.Blackout,
		BlackoutReason:        snap.BlackoutReason,
		CoveragePercent:       snap.CoveragePercent,
		CoverageTarget:        snap.CoverageTarget,
		PerCandidate:          snap.PerCandidate,
		CandidateCount:        snap.CandidateCount,
		SwapGeneration:        snap.SwapGeneration,
		DPIGateEnabled:        snap.DPIGateEnabled,
		DPIGateReason:         snap.DPIGateReason,
	})
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
		State:                 snap.State,
		ActiveId:              snap.ActiveID,
		LastGood:              snap.LastGood,
		Attempts:              snap.Attempts,
		Generation:            snap.Generation,
		Closed:                snap.Closed,
		UniqueCandidatesTried: snap.UniqueCandidatesTried,
		TotalAttempts:         snap.TotalAttempts,
		SearchElapsedMs:       snap.SearchElapsedMs,
		LastSearchElapsedMs:   snap.LastSearchElapsedMs,
		SearchInProgress:      snap.SearchInProgress,
		StateLoaded:           snap.StateLoaded,
		StateSaved:            snap.StateSaved,
		StateError:            snap.StateError,
		Blackout:              snap.Blackout,
		BlackoutReason:        snap.BlackoutReason,
		CoveragePercent:       int32(snap.CoveragePercent),
		CoverageTarget:        int32(snap.CoverageTarget),
		PerCandidate:          snap.PerCandidate,
		CandidateCount:        int32(snap.CandidateCount),
		SwapGeneration:        snap.SwapGeneration,
		DpiGateEnabled:        snap.DPIGateEnabled,
		DpiGateReason:         snap.DPIGateReason,
	}, nil
}

func decodeAdaptiveSnapshot(raw string) (AdaptiveSnapshot, error) {
	var snap AdaptiveSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return AdaptiveSnapshot{}, fmt.Errorf("decode adaptive state: %w", err)
	}
	return snap, nil
}
