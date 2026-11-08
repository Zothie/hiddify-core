package hydracontrol

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
)

// Status is the JSON-facing refresher state (amendment 2: honest states,
// never silent skips) plus the G4 watermark exposure the state chip reads.
//
// State is one of:
//   - "idle"     — fully configured, daemon not started yet
//   - "disabled" — config incomplete or the daemon failed to start; Detail
//     names the reason. The runtime keeps serving the static bootstrap set.
//   - "ready"    — daemon up; last cycle succeeded (or none has run yet)
//   - "error"    — last cycle failed; Detail says why; the current candidate
//     set keeps serving, the next tick retries
type Status struct {
	State         string                      `json:"state"`
	Detail        string                      `json:"detail,omitempty"`
	VerifiedSeq   uint64                      `json:"verified_seq,omitempty"`
	SwappedSeq    uint64                      `json:"swapped_seq,omitempty"`
	SwappedTags   []string                    `json:"swapped_tags,omitempty"`
	LastRefreshAt string                      `json:"last_refresh_at,omitempty"`
	Watermark     adaptive.CatalogueWatermark `json:"watermark,omitempty"`
}

func (r *Refresher) setStatus(state, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State = state
	r.status.Detail = detail
}

func (r *Refresher) setVerified(seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.VerifiedSeq = seq
	r.status.LastRefreshAt = time.Now().UTC().Format(time.RFC3339)
}

func (r *Refresher) setSwapped(seq uint64, tags []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.SwappedSeq = seq
	r.status.SwappedTags = append([]string(nil), tags...)
}

func (r *Refresher) setWatermark(wm adaptive.CatalogueWatermark) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.Watermark = wm
}

// Snapshot returns a copy of the current status.
func (r *Refresher) Snapshot() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.status
	s.SwappedTags = append([]string(nil), r.status.SwappedTags...)
	return s
}

// latest is the most recently constructed refresher; the app runs exactly
// one per install, so the package-level accessor mirrors that reality.
var (
	latestMu sync.RWMutex
	latest   *Refresher
)

func trackLatest(r *Refresher) {
	latestMu.Lock()
	latest = r
	latestMu.Unlock()
}

// StatusJSON returns the live refresher state as JSON, or
// {"state":"disabled"} when no refresher was constructed (e.g. a build
// without the catalogue runtime) — the same honest shape the chip renders.
func StatusJSON() string {
	latestMu.RLock()
	r := latest
	latestMu.RUnlock()
	if r == nil {
		return `{"state":"disabled","detail":"catalogue runtime not constructed"}`
	}
	out, err := json.Marshal(r.Snapshot())
	if err != nil {
		return `{"state":"error","detail":"status encode failed"}`
	}
	return string(out)
}
