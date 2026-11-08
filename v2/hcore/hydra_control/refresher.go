// Package hydracontrol runs the signed-catalogue runtime distribution
// (audit G2): it fetches the capability catalogue through the app-owned Tor
// control daemon, verifies it against the pinned root pubkey, expands
// candidates with the recovery-budget check (G5) and hot-swaps them into
// LIVE hydra adaptive outbounds (matched by relay pubkey), persisting the
// sequence/revocation watermark (G4) so replayed older documents are
// rejected.
//
// Honest-disable doctrine (amendment 2): the refresher is a runtime
// companion, never a build dependency. An incomplete config or a daemon
// that fails to start puts it into a visible "disabled" state (StatusJSON);
// it never blocks config builds and never silently skips. Once running, a
// failed cycle keeps the current candidate set serving (fail-closed) and
// retries on the next tick.
package hydracontrol

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing-box/protocol/hydra/controlclient"
)

// Default tuning. The interval keeps the control plane rare by doctrine
// (TSPU: bursts earn blackholes); the catalogue carries its own expiry, so
// an hourly refresh re-verifies long before a document can lapse.
const (
	DefaultInterval    = time.Hour
	minInterval        = 15 * time.Minute
	maxInterval        = 24 * time.Hour
	DefaultFetchBudget = 2 * time.Minute
	daemonReadyTimeout = 30 * time.Second
)

// Config wires the refresher. Zero fields make the refresher DISABLED, not
// broken: absent/failed-to-start is a visible runtime state, never a build
// failure (amendment 2).
type Config struct {
	// DaemonPath is the tor-control-daemon binary. Empty disables.
	DaemonPath string
	// DataDir is the daemon's Arti state/cache dir.
	DataDir string
	// ControlOnion is the control service's onion address.
	ControlOnion string
	// SocksAddr is the daemon's loopback SOCKS listener; empty binds an
	// ephemeral loopback port (127.0.0.1:0).
	SocksAddr string
	// RootPubkey is the catalogue's Ed25519 verification root (32 bytes).
	// Wrong length disables.
	RootPubkey []byte
	// StateDir is the hydra-adaptive state directory (the same dir the
	// config builder puts group winner-hint files in); the watermark lives
	// beside them as catalogue-watermark.json. Empty disables.
	StateDir string
	// Interval is the refresh period; clamped to [15m, 24h], default 1h.
	Interval time.Duration
	// FetchTimeout bounds one fetch+verify+swap cycle; default 2m.
	FetchTimeout time.Duration
	// ExtraArgs is appended verbatim to the daemon command line (the
	// controlclient mock/test-mode seam). Must stay empty in production;
	// only the trigger's test wiring sets it.
	ExtraArgs []string
}

func (c Config) interval() time.Duration {
	if c.Interval <= 0 {
		return DefaultInterval
	}
	if c.Interval < minInterval {
		return minInterval
	}
	if c.Interval > maxInterval {
		return maxInterval
	}
	return c.Interval
}

func (c Config) fetchTimeout() time.Duration {
	if c.FetchTimeout <= 0 {
		return DefaultFetchBudget
	}
	return c.FetchTimeout
}

// disableReason returns why the refresher cannot run, or "" when fully
// configured.
func (c Config) disableReason() string {
	switch {
	case c.DaemonPath == "":
		return "no daemon path configured"
	case c.DataDir == "":
		return "no daemon data dir configured"
	case c.ControlOnion == "":
		return "no control onion configured"
	case len(c.RootPubkey) != ed25519.PublicKeySize:
		return "root pubkey must be 32 bytes"
	case c.StateDir == "":
		return "no state dir for the catalogue watermark"
	}
	return ""
}

// Refresher owns the control daemon and the refresh loop. Construct it at
// app bootstrap and Run it for the box's lifetime.
type Refresher struct {
	cfg Config

	// testInterval bypasses the production interval clamp in in-process
	// trigger tests only; production always ticks through Config.interval.
	testInterval time.Duration

	mu     sync.Mutex
	status Status
}

// tickInterval is the effective refresh period.
func (r *Refresher) tickInterval() time.Duration {
	if r.testInterval > 0 {
		return r.testInterval
	}
	return r.cfg.interval()
}

// New validates nothing eagerly: a zero-ish config constructs a DISABLED
// refresher whose StatusJSON names the missing piece (amendment 2).
func New(cfg Config) *Refresher {
	r := &Refresher{cfg: cfg}
	if reason := cfg.disableReason(); reason != "" {
		r.setStatus("disabled", reason)
	} else {
		r.setStatus("idle", "")
	}
	trackLatest(r)
	return r
}

// Run starts the daemon and refreshes until ctx is done. An incomplete
// config or a failed daemon start returns nil with the refresher left in a
// visible disabled state — the app must never fail its boot because the
// catalogue runtime cannot come up.
func (r *Refresher) Run(ctx context.Context) error {
	if reason := r.cfg.disableReason(); reason != "" {
		r.setStatus("disabled", reason)
		return nil
	}
	client, err := controlclient.Start(ctx, controlclient.Config{
		DaemonPath:   r.cfg.DaemonPath,
		SocksAddr:    r.cfg.SocksAddr,
		DataDir:      r.cfg.DataDir,
		ControlOnion: r.cfg.ControlOnion,
		ExtraArgs:    r.cfg.ExtraArgs,
	})
	if err != nil {
		r.setStatus("disabled", "daemon start: "+err.Error())
		return nil
	}
	defer client.Close()
	deadline := time.Now().Add(daemonReadyTimeout)
	for !client.Ready() {
		if ctx.Err() != nil || time.Now().After(deadline) {
			r.setStatus("disabled", "daemon not ready within "+daemonReadyTimeout.String())
			return nil
		}
		select {
		case <-ctx.Done():
			r.setStatus("disabled", "stopped before the daemon became ready")
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	r.setStatus("ready", "")
	if err := os.MkdirAll(r.cfg.StateDir, 0o700); err != nil {
		// Without the dir the watermark cannot persist; refuse to verify
		// with a weakened (zero) watermark and surface why.
		r.setStatus("error", "state dir: "+err.Error())
	}
	ticker := time.NewTicker(r.tickInterval())
	defer ticker.Stop()
	for {
		if err := r.cycle(ctx, client); err != nil {
			r.setStatus("error", err.Error())
			log.Printf("hydra catalogue refresh: %v", err)
		} else {
			r.mu.Lock()
			if r.status.State == "error" {
				r.status.State = "ready"
				r.status.Detail = ""
			}
			r.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// cycle is one fetch → verify → expand → swap → persist pass.
func (r *Refresher) cycle(ctx context.Context, client *controlclient.Client) error {
	fetchCtx, cancel := context.WithTimeout(ctx, r.cfg.fetchTimeout())
	defer cancel()
	payload, err := client.FetchCatalogue(fetchCtx)
	if err != nil {
		return fmt.Errorf("fetch catalogue: %w", err)
	}
	sigRaw, err := client.FetchPath(fetchCtx, "/catalogue.sig")
	if err != nil {
		return fmt.Errorf("fetch catalogue signature: %w", err)
	}
	sig, err := parseCatalogueSignature(sigRaw)
	if err != nil {
		return fmt.Errorf("catalogue signature: %w", err)
	}
	root := ed25519.PublicKey(r.cfg.RootPubkey)
	key := adaptive.CatalogueWatermarkKey(r.cfg.RootPubkey)
	// stateAnchor sits IN the state dir; the watermark derives its fixed
	// file name from the anchor's directory (adaptive.CatalogueWatermarkPath).
	stateAnchor := filepath.Join(r.cfg.StateDir, "catalogue.json")
	wm, have, err := adaptive.LoadCatalogueWatermark(stateAnchor, key)
	if err != nil {
		// A corrupt/unsupported watermark must NEVER downgrade to minSeq 0
		// (that would reopen replay). Keep serving the current set.
		return fmt.Errorf("catalogue watermark unusable; refusing to verify: %w", err)
	}
	minSeq := uint64(0)
	if have {
		minSeq = wm.MaxSeq
	}
	cat, err := hydra.LoadAndVerifyCatalogue(payload, sig, root, uint64(time.Now().Unix()), minSeq)
	if err != nil {
		var ce *hydra.CatalogueError
		if errors.As(err, &ce) && ce.Code == hydra.ErrCatalogueSeqTooLow {
			return fmt.Errorf("catalogue replay rejected (seq below persisted watermark %d): %w", minSeq, err)
		}
		return fmt.Errorf("catalogue verify: %w", err)
	}
	r.setVerified(cat.Seq)

	// Expand PER TARGET: each group orders recipes by its own ASN and checks
	// the budget against its own live timing, then takes only its
	// pubkey-bound candidates. A doc-level expansion bigger than one group's
	// budget fails that group loudly (G5, fail-closed — the producer must
	// split the catalogue or the caller raises the budget).
	targets := hydra.CatalogueSwapTargets()
	// An unchanged document is a no-op: equal-seq docs verify fine (the
	// watermark rejects only OLDER docs) but re-swapping the same set would
	// churn swap generations for nothing.
	alreadySwapped := false
	r.mu.Lock()
	alreadySwapped = r.status.SwappedSeq == cat.Seq
	r.mu.Unlock()
	var swapped []string
	if alreadySwapped {
		return nil
	}
	for _, target := range targets {
		if target.Pubkey == "" {
			continue
		}
		expanded, skips, err := hydra.ExpandCatalogueCandidates(cat, target.ASN, target.AttemptTimeout, target.Budget)
		for _, s := range skips {
			log.Printf("hydra catalogue refresh: %s: skip %s", target.Tag, s)
		}
		if err != nil {
			log.Printf("hydra catalogue refresh: %s: %v", target.Tag, err)
			continue
		}
		owned := ownedCandidates(expanded, target.Pubkey)
		if len(owned) == 0 {
			log.Printf("hydra catalogue refresh: %s: catalogue seq %d offers no candidates for pubkey %q", target.Tag, cat.Seq, target.Pubkey)
			continue
		}
		if err := hydra.SwapCatalogueCandidates(target.Tag, owned); err != nil {
			log.Printf("hydra catalogue refresh: %s: swap refused: %v", target.Tag, err)
			continue
		}
		swapped = append(swapped, target.Tag)
		r.setSwapped(cat.Seq, swapped)
	}
	// Persist the watermark forward on every VERIFIED doc with a higher seq,
	// independent of swap outcomes: equal-seq documents still verify on the
	// next tick, so a transient swap failure retries naturally.
	if cat.Seq > minSeq {
		merged, err := adaptive.MergeCatalogueWatermark(wm, key, cat.Seq, cat.Revocations)
		if err == nil {
			err = adaptive.StoreCatalogueWatermark(stateAnchor, merged)
		}
		if err != nil {
			return fmt.Errorf("catalogue seq %d verified; watermark persist failed: %w", cat.Seq, err)
		}
		r.setWatermark(merged)
	}
	return nil
}

// ownedCandidates keeps the expansion entries bound to one relay pubkey
// (both sides are base64 std — the catalogue loader enforces the alphabet).
func ownedCandidates(expanded []option.HydraAdaptiveCandidateOptions, pubkey string) []option.HydraAdaptiveCandidateOptions {
	out := make([]option.HydraAdaptiveCandidateOptions, 0, len(expanded))
	for _, cand := range expanded {
		if cand.Pubkey == pubkey {
			out = append(out, cand)
		}
	}
	return out
}

// parseCatalogueSignature accepts the detached signature as raw 64 bytes or
// whitespace-tolerant hex text (the producer's .sig format).
func parseCatalogueSignature(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == ed25519.SignatureSize {
		return []byte(trimmed), nil
	}
	sig, err := hex.DecodeString(trimmed)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be 64 raw bytes or hex, got %d bytes", len(raw))
	}
	return sig, nil
}
