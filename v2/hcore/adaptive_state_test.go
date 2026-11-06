package hcore

import (
	"encoding/json"
	"testing"

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
