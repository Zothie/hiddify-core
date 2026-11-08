package hydracontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Production-trigger integration: the hcore box start path constructs this
// trigger, so the tests exercise the genuine Run plane (real daemon in
// --mock-tor mode, real local origin, real adaptive outbound registry) minus
// only the Tor circuit itself, mirroring refresher_integration_test.go.

// TestTriggerSwapsAndStopsOnBoxStop starts the trigger over a live adaptive
// outbound, asserts the first cycle swaps the catalogue set in, asserts the
// process-wide singleton does not double-start, then stops it (the box-stop
// path) and proves no further tick happens — both channel-based (Run
// returned) and behaviour-based (a newer signed doc is not swapped in).
func TestTriggerSwapsAndStopsOnBoxStop(t *testing.T) {
	daemon := buildDaemon(t)
	host, port, stopStall := startStall(t)
	defer stopStall()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPriv := ed25519.NewKeyFromSeed([]byte("trigger-relay-key-material-32byt")[:32])
	relayPub := relayPriv.Public().(ed25519.PublicKey)
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)

	origin := newCatalogueOrigin(t)
	origin.signDoc(t, rootPriv, newCatalogue(t, relayPub, host, port, 3, 9, nil))

	outbound := swapTargetOutbound(t, "group-trigger", relayPubB64, host, port)
	defer func() {
		if closer, ok := outbound.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	// Drive the coordinator loop like production traffic would.
	sweepCtx, cancelSweep := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelSweep()
	go func() { _, _ = outbound.DialContext(sweepCtx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:9")) }()

	st := StartTrigger(TriggerConfig{
		WorkingPath:     t.TempDir(),
		ControlOnion:    "hydracontroltest.onion",
		DaemonPath:      daemon,
		RootPubkeyHex:   hex.EncodeToString(rootPub),
		DataDir:         t.TempDir(),
		SocksAddr:       "127.0.0.1:0",
		DaemonExtraArgs: []string{"--mock-tor", origin.addr},
		tickOverride:    250 * time.Millisecond,
	})
	if st.State == "disabled" || st.State == "error" {
		t.Fatalf("fully configured trigger must run, got %+v", st)
	}
	if !TriggerRunning() {
		t.Fatal("trigger must report running after a complete config")
	}
	done := TriggerDone()
	if done == nil {
		t.Fatal("TriggerDone must expose the run loop's channel")
	}

	// First cycle runs immediately on Run: 2 statics → 3 catalogue
	// candidates, swap generation advances.
	snap := waitForCandidates(t, "group-trigger", 3, 1)
	if snap.SwapGeneration != 1 {
		t.Fatalf("first swap generation: %+v", snap)
	}

	// Process-wide singleton: a second start while running must not
	// double-start (no new refresher, no restart, same done channel).
	st2 := StartTrigger(TriggerConfig{WorkingPath: t.TempDir()})
	if st2.State == "disabled" || st2.State == "error" {
		t.Fatalf("second start must return the running refresher's state, got %+v", st2)
	}
	if !TriggerRunning() {
		t.Fatal("second start killed the running refresher")
	}
	if reflect.ValueOf(done).Pointer() != reflect.ValueOf(TriggerDone()).Pointer() {
		t.Fatal("second start restarted the refresher: done channel changed")
	}
	var live Status
	if err := json.Unmarshal([]byte(StatusJSON()), &live); err != nil {
		t.Fatal(err)
	}
	if live.State == "disabled" {
		t.Fatalf("second start clobbered the live refresher status: %s", StatusJSON())
	}

	// The box-stop path: StopTrigger must end the Run loop (channel-based
	// proof) and keep the last status visible.
	StopTrigger()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("refresher Run did not return after StopTrigger")
	}
	if TriggerRunning() {
		t.Fatal("trigger still reports running after stop")
	}

	// No tick after stop: a newer signed document would swap the live set
	// to 4 candidates / gen 2 within ~1s if a ticker survived; assert the
	// set stays frozen well past three tick periods.
	origin.signDoc(t, rootPriv, newCatalogue(t, relayPub, host, port, 4, 10, nil))
	time.Sleep(1 * time.Second)
	after, ok := adaptive.SnapshotByTag("group-trigger")
	if !ok {
		t.Fatal("tag lost after stop")
	}
	if after.CandidateCount != snap.CandidateCount || after.SwapGeneration != snap.SwapGeneration {
		t.Fatalf("refresher ticked after stop: before=%+v after=%+v", snap, after)
	}
}

// TestTriggerDisabledWithoutDaemonPath: absent daemon binary or empty
// config → the refresher is constructed, stays off, and StatusJSON carries
// state=disabled with a reason. Nothing crashes, nothing silent.
func TestTriggerDisabledWithoutDaemonPath(t *testing.T) {
	dir := t.TempDir()

	st := StartTrigger(TriggerConfig{WorkingPath: dir})
	if st.State != "disabled" || st.Detail == "" {
		t.Fatalf("unconfigured trigger must be visibly disabled: %+v", st)
	}
	if TriggerRunning() {
		t.Fatal("unconfigured trigger must not run")
	}

	st2 := StartTrigger(TriggerConfig{
		WorkingPath: dir,
		DaemonPath:  filepath.Join(dir, "absent-daemon"),
	})
	if st2.State != "disabled" {
		t.Fatalf("missing daemon binary must disable: %+v", st2)
	}
	if !strings.Contains(st2.Detail, "missing") {
		t.Fatalf("disabled detail must name the missing binary: %+v", st2)
	}
	if TriggerRunning() {
		t.Fatal("missing daemon binary must not run")
	}

	var live Status
	if err := json.Unmarshal([]byte(StatusJSON()), &live); err != nil {
		t.Fatal(err)
	}
	if live.State != "disabled" || live.Detail == "" {
		t.Fatalf("StatusJSON must surface the disabled state: %s", StatusJSON())
	}
}

// TestTriggerErrorWithoutRootPubkey: a set control onion without a usable
// root pubkey fails the start with state=error (a wrong root must never
// verify) — never a silent skip, never a run.
func TestTriggerErrorWithoutRootPubkey(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	st := StartTrigger(TriggerConfig{
		WorkingPath:  dir,
		ControlOnion: "hydracontroltest.onion",
		DaemonPath:   exe,
	})
	if st.State != "error" || !strings.Contains(st.Detail, "root pubkey") {
		t.Fatalf("missing root pubkey must error, got %+v", st)
	}
	if TriggerRunning() {
		t.Fatal("missing root pubkey must not run")
	}

	st2 := StartTrigger(TriggerConfig{
		WorkingPath:   dir,
		ControlOnion:  "hydracontroltest.onion",
		DaemonPath:    exe,
		RootPubkeyHex: "not-hex-at-all",
	})
	if st2.State != "error" || !strings.Contains(st2.Detail, "root pubkey") {
		t.Fatalf("non-hex root pubkey must error, got %+v", st2)
	}

	st3 := StartTrigger(TriggerConfig{
		WorkingPath:   dir,
		ControlOnion:  "hydracontroltest.onion",
		DaemonPath:    exe,
		RootPubkeyHex: hex.EncodeToString(make([]byte, 16)),
	})
	if st3.State != "error" || !strings.Contains(st3.Detail, "32 bytes") {
		t.Fatalf("short root pubkey must error with the size, got %+v", st3)
	}
	if TriggerRunning() {
		t.Fatal("bad root pubkey must not run")
	}

	var live Status
	if err := json.Unmarshal([]byte(StatusJSON()), &live); err != nil {
		t.Fatal(err)
	}
	if live.State != "error" || live.Detail == "" {
		t.Fatalf("StatusJSON must surface the error state: %s", StatusJSON())
	}
}
