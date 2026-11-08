package hydracontrol

// Production trigger (audit follow-up): wires the catalogue refresher into
// the hcore box lifecycle. The box start path (hcore.StartService) calls
// StartTrigger once the built config's adaptive outbounds are live; the box
// stop paths (hcore.Stop / StopAndAlert) call StopTrigger. The refresher
// swaps ALL registered adaptive targets by relay pubkey, so ONE refresher
// runs per process — StartTrigger is a singleton no-op while a previous Run
// loop is still alive, and every not-started outcome is a visible Status
// state (honest-disable doctrine, amendment 2), never a silent skip and
// never a boot failure.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TriggerConfig is the runtime wiring the host hands over at box start. It
// is derived from the hcore Setup state via RouteOptions.HydraControl —
// runtime settings, never link parameters and never the settings JSON.
type TriggerConfig struct {
	// WorkingPath is the app files dir (hcore sWorkingPath). The watermark
	// state dir derives as <WorkingPath>/data/hydra-adaptive — the same dir
	// the config builder puts the groups' winner-hint files in, so the
	// catalogue watermark sits beside them.
	WorkingPath string
	// ControlOnion is the control service's onion address. Empty keeps the
	// refresher visibly disabled (StatusJSON, state=disabled+detail).
	ControlOnion string
	// DaemonPath is the tor-control-daemon binary. An empty path or a
	// missing binary keeps the refresher visibly disabled.
	DaemonPath string
	// RootPubkeyHex is the catalogue's Ed25519 verification root, hex.
	// REQUIRED whenever ControlOnion is set: a missing/invalid root fails
	// the start with state=error — a wrong root must never verify.
	RootPubkeyHex string
	// RefreshTick is the refresh period; zero uses the refresher default
	// (1h, production-clamped to [15m, 24h]).
	RefreshTick time.Duration

	// DataDir overrides the daemon's derived Arti state dir
	// (<WorkingPath>/data/tor-control). Tests only.
	DataDir string
	// SocksAddr pins the daemon's loopback SOCKS listener; empty binds an
	// ephemeral port. Tests only.
	SocksAddr string
	// DaemonExtraArgs is appended to the daemon command line (mock/test
	// modes); must stay empty in production. Tests only.
	DaemonExtraArgs []string

	// tickOverride bypasses the production interval clamp in in-process
	// tests only.
	tickOverride time.Duration
}

var (
	triggerMu      sync.Mutex
	triggerCancel  context.CancelFunc
	triggerDone    chan struct{}
	triggerRunning bool
	// triggerGen identifies the current run slot: the Run goroutine may
	// only reset the slot when it still owns it (StopTrigger bumps the
	// generation, so a late cleanup cannot clobber a newer run).
	triggerGen uint64
)

// StartTrigger constructs the process-wide refresher and, when the config is
// complete, starts its Run loop in the background. Outcomes:
//   - a previous Run loop is still alive → singleton no-op: the passed
//     config is ignored, the running refresher's snapshot is returned;
//   - complete config → Run loop started (first cycle immediately, then
//     every RefreshTick);
//   - empty/missing daemon binary or empty onion or no state dir → the
//     refresher is constructed and left visibly disabled;
//   - onion set but root pubkey missing/invalid → state=error: a wrong
//     root must never verify, so this outranks honest-disable.
//
// StartTrigger never returns an error and never blocks: the live state is
// StatusJSON(). The returned Status is the construction-moment snapshot.
func StartTrigger(cfg TriggerConfig) Status {
	triggerMu.Lock()
	defer triggerMu.Unlock()

	if triggerRunning {
		latestMu.RLock()
		r := latest
		latestMu.RUnlock()
		if r != nil {
			return r.Snapshot()
		}
		return Status{State: "disabled", Detail: "catalogue runtime not constructed"}
	}

	rc := Config{
		DaemonPath:   cfg.DaemonPath,
		ControlOnion: cfg.ControlOnion,
		SocksAddr:    cfg.SocksAddr,
		Interval:     cfg.RefreshTick,
		ExtraArgs:    cfg.DaemonExtraArgs,
		StateDir:     triggerStateDir(cfg.WorkingPath),
		DataDir:      cfg.DataDir,
	}
	if rc.DataDir == "" && cfg.WorkingPath != "" {
		rc.DataDir = filepath.Join(cfg.WorkingPath, "data", "tor-control")
	}

	// Root pubkey first: a set onion with a bad/absent root is a
	// configuration ERROR (a wrong root must never verify), ranked above
	// the honest-disable reasons.
	var pubkeyErr string
	if cfg.ControlOnion != "" {
		switch key, hexErr := hex.DecodeString(cfg.RootPubkeyHex); {
		case cfg.RootPubkeyHex == "":
			pubkeyErr = "control onion set but root pubkey missing; catalogue verification would be unanchored"
		case hexErr != nil:
			pubkeyErr = "control onion set but root pubkey is not hex: " + hexErr.Error()
		case len(key) != ed25519.PublicKeySize:
			pubkeyErr = fmt.Sprintf("control onion set but root pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(key))
		default:
			rc.RootPubkey = key
		}
	}

	r := New(rc)
	if pubkeyErr != "" {
		r.setStatus("error", pubkeyErr)
		return r.Snapshot()
	}

	if cfg.DaemonPath != "" {
		if fi, err := os.Stat(cfg.DaemonPath); err != nil {
			r.setStatus("disabled", "daemon binary missing at "+cfg.DaemonPath)
			return r.Snapshot()
		} else if fi.IsDir() {
			r.setStatus("disabled", "daemon path is a directory: "+cfg.DaemonPath)
			return r.Snapshot()
		}
	}
	if reason := rc.disableReason(); reason != "" {
		// New() already left it disabled with this reason; the status is
		// visible through StatusJSON. Nothing runs, nothing crashes.
		return r.Snapshot()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	if cfg.tickOverride > 0 {
		r.testInterval = cfg.tickOverride
	}
	triggerGen++
	myGen := triggerGen
	triggerCancel = cancel
	triggerDone = done
	triggerRunning = true
	go func() {
		defer func() {
			triggerMu.Lock()
			if triggerRunning && triggerGen == myGen {
				// this run still owns the slot (StopTrigger has not reset it)
				triggerCancel = nil
				triggerRunning = false
				triggerGen++
			}
			triggerMu.Unlock()
			cancel()
			close(done)
		}()
		_ = r.Run(ctx)
	}()
	return r.Snapshot()
}

// StopTrigger stops the process-wide refresher (the box-stop path). It is
// idempotent and safe with nothing running; once the Run loop returns, the
// channel from TriggerDone is closed.
func StopTrigger() {
	triggerMu.Lock()
	defer triggerMu.Unlock()
	if triggerCancel != nil {
		triggerCancel()
		triggerCancel = nil
	}
	triggerRunning = false
	triggerGen++
}

// TriggerRunning reports whether the process-wide refresher's Run loop is
// alive.
func TriggerRunning() bool {
	triggerMu.Lock()
	defer triggerMu.Unlock()
	return triggerRunning
}

// TriggerDone returns the channel closed when the started refresher's Run
// loop has returned (after StopTrigger or an early internal exit). Nil when
// nothing was started in this process.
func TriggerDone() <-chan struct{} {
	triggerMu.Lock()
	defer triggerMu.Unlock()
	return triggerDone
}

// triggerStateDir derives the watermark state dir from the app files dir,
// matching the config builder's adaptive hint dir
// (builder.go: filepath.Join(WorkingDir, "data", "hydra-adaptive", ...)).
func triggerStateDir(workingPath string) string {
	if workingPath == "" {
		return ""
	}
	return filepath.Join(workingPath, "data", "hydra-adaptive")
}
