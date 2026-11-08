package hcore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

func registerFakeAdaptiveState(t *testing.T, tag string, snap adaptive.Snapshot) {
	t.Helper()
	adaptive.RegisterOutbound(tag, func() adaptive.Snapshot { return snap })
	t.Cleanup(func() { adaptive.UnregisterOutbound(tag) })
}

func decodeAdaptiveState(t *testing.T, raw string) AdaptiveSnapshot {
	t.Helper()
	var parsed AdaptiveSnapshot
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return parsed
}

func TestAdaptiveStateJSONActive(t *testing.T) {
	registerFakeAdaptiveState(t, "as-active", adaptive.Snapshot{Generation: 4, ActiveID: "fi-1", LastGood: "fi-1", Attempts: 9})
	got := decodeAdaptiveState(t, AdaptiveStateJSON("as-active"))
	if got.State != "active" || got.ActiveID != "fi-1" || got.LastGood != "fi-1" || got.Generation != 4 || got.Attempts != 9 || got.Closed {
		t.Fatalf("active state = %+v", got)
	}
}

func TestAdaptiveStateJSONConnecting(t *testing.T) {
	registerFakeAdaptiveState(t, "as-connecting", adaptive.Snapshot{Generation: 2, Attempts: 3})
	got := decodeAdaptiveState(t, AdaptiveStateJSON("as-connecting"))
	if got.State != "connecting" || got.ActiveID != "" || got.Closed || got.Attempts != 3 {
		t.Fatalf("connecting state = %+v", got)
	}
}

func TestAdaptiveStateJSONClosed(t *testing.T) {
	registerFakeAdaptiveState(t, "as-closed", adaptive.Snapshot{Generation: 5, LastGood: "de-2", Closed: true})
	got := decodeAdaptiveState(t, AdaptiveStateJSON("as-closed"))
	if got.State != "closed" || !got.Closed || got.LastGood != "de-2" {
		t.Fatalf("closed state = %+v", got)
	}
}

func TestAdaptiveStateJSONUnknownTag(t *testing.T) {
	if got := AdaptiveStateJSON("as-never-registered"); got != `{"state":"unknown"}` {
		t.Fatalf("unknown tag = %q", got)
	}
}

func TestAdaptiveStateJSONFullSnapshot(t *testing.T) {
	registerFakeAdaptiveState(t, "as-full", adaptive.Snapshot{
		Generation:            11,
		ActiveID:              "fi-3",
		LastGood:              "fi-3",
		Attempts:              21,
		UniqueCandidatesTried: 4,
		TotalAttempts:         21,
		SearchElapsed:         1500 * time.Millisecond,
		LastSearchElapsed:     300 * time.Millisecond,
		SearchInProgress:      true,
		StateLoaded:           true,
		StateSaved:            true,
		StateError:            "stale hint",
		Blackout:              true,
		BlackoutReason:        "reference probes dead",
		CoveragePercent:       85,
		CoverageTarget:        90,
		PerCandidate:          map[string]uint64{"fi-3": 12, "de-2": 9},
		CandidateCount:        3,
		SwapGeneration:        2,
	})
	got := decodeAdaptiveState(t, AdaptiveStateJSON("as-full"))
	if got.State != "active" || got.UniqueCandidatesTried != 4 || got.TotalAttempts != 21 ||
		got.SearchElapsedMs != 1500 || got.LastSearchElapsedMs != 300 || !got.SearchInProgress ||
		!got.StateLoaded || !got.StateSaved || got.StateError != "stale hint" ||
		!got.Blackout || got.BlackoutReason != "reference probes dead" ||
		got.CoveragePercent != 85 || got.CoverageTarget != 90 ||
		got.PerCandidate["fi-3"] != 12 || got.PerCandidate["de-2"] != 9 ||
		got.CandidateCount != 3 || got.SwapGeneration != 2 {
		t.Fatalf("full snapshot = %+v", got)
	}
}

func TestAdaptiveStateDPIGateState(t *testing.T) {
	registerFakeAdaptiveState(t, "as-gate", adaptive.Snapshot{Generation: 1})
	// Before any EnableDPIGate call the snapshot reports the gate off with
	// no reason — zero values, not a lie about the gate state.
	got := decodeAdaptiveState(t, AdaptiveStateJSON("as-gate"))
	if got.DPIGateEnabled || got.DPIGateReason != "" {
		t.Fatalf("pre-enable gate state = %+v", got)
	}
	// A successful EnableDPIGate flips the reported state on; the failure
	// path records the error string in dpigate.go and is covered by the
	// hydra package's own fail-to-off tests.
	if _, err := hydra.EnableDPIGate(hydra.DPIGateDefaultThreshold); err != nil {
		t.Fatalf("EnableDPIGate: %v", err)
	}
	got = decodeAdaptiveState(t, AdaptiveStateJSON("as-gate"))
	if !got.DPIGateEnabled || got.DPIGateReason != "" {
		t.Fatalf("post-enable gate state = %+v", got)
	}
}
