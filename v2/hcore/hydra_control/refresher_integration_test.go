package hydracontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hydra"
	"github.com/sagernet/sing-box/protocol/hydra/adaptive"
	"github.com/sagernet/sing-box/protocol/hydra/controlclient"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Integration against the REAL tor-control-daemon in --mock-tor mode: the
// daemon's loopback SOCKS listener forwards to a real local origin serving
// /catalogue and /catalogue.sig, so the refresher exercises the genuine
// fetch plane (no fakes) minus only the Tor circuit itself. The daemon is
// built with cargo --offline (skipped when unavailable; override the binary
// path with TOR_CONTROL_DAEMON_BIN).
const daemonManifest = "/home/varingait/src/hydra-adaptive/hydra/tools/tor-control-daemon/Cargo.toml"

func buildDaemon(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("TOR_CONTROL_DAEMON_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		t.Fatalf("TOR_CONTROL_DAEMON_BIN=%q does not exist", p)
	}
	if _, err := os.Stat(daemonManifest); err != nil {
		t.Skipf("tor-control-daemon manifest not found: %s", daemonManifest)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	cmd := exec.Command("cargo", "build", "--manifest-path", daemonManifest, "--offline")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo build failed: %v\n%s", err, out)
	}
	return filepath.Join(filepath.Dir(daemonManifest), "target", "debug", "tor-control-daemon")
}

// catalogueOrigin serves the mutable doc/sig pair; tests flip the document
// to exercise replay rejection.
type catalogueOrigin struct {
	srv  *httptest.Server
	doc  atomic.Value // []byte
	sig  atomic.Value // []byte hex
	addr string
}

func newCatalogueOrigin(t *testing.T) *catalogueOrigin {
	t.Helper()
	o := &catalogueOrigin{}
	mux := http.NewServeMux()
	mux.HandleFunc("/catalogue", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(o.doc.Load().([]byte))
	})
	mux.HandleFunc("/catalogue.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(o.sig.Load().([]byte))
	})
	o.srv = httptest.NewServer(mux)
	o.addr = o.srv.Listener.Addr().String()
	t.Cleanup(o.srv.Close)
	return o
}

// signDoc marshals, signs and installs a catalogue into the origin.
func (o *catalogueOrigin) signDoc(t *testing.T, priv ed25519.PrivateKey, cat *hydra.Catalogue) {
	t.Helper()
	payload, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	o.doc.Store(payload)
	o.sig.Store([]byte(hex.EncodeToString(ed25519.Sign(priv, payload))))
}

func startDaemonFor(t *testing.T, bin, origin string) *controlclient.Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := controlclient.Start(ctx, controlclient.Config{
		DaemonPath:   bin,
		SocksAddr:    "127.0.0.1:0",
		DataDir:      t.TempDir(),
		ControlOnion: "hydracontroltest.onion",
		ExtraArgs:    []string{"--mock-tor", origin},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !c.Ready() {
		time.Sleep(50 * time.Millisecond)
	}
	if !c.Ready() {
		t.Fatal("daemon not ready")
	}
	return c
}

func newCatalogue(t *testing.T, relayPub []byte, host string, port uint16, endpoints int, seq uint64, revocations []string) *hydra.Catalogue {
	t.Helper()
	eps := make([]hydra.CatalogueEndpoint, 0, endpoints)
	for i := range endpoints {
		eps = append(eps, hydra.CatalogueEndpoint{Transport: "wss", Host: host, Port: port, Path: "/cat" + string(rune('a'+i))})
	}
	return &hydra.Catalogue{Schema: 1, Seq: seq, IssuedAt: 1, ExpiresAt: 1893456000,
		Servers:     []hydra.CatalogueServer{{ID: "relay", Pubkey: base64.StdEncoding.EncodeToString(relayPub), Endpoints: eps}},
		Recipes:     []hydra.CatalogueRecipe{{ID: "web", Server: "relay", Transport: "wss"}},
		Revocations: revocations}
}

func startStall(t *testing.T) (host string, port uint16, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = conn.Close()
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.ParseUint(p, 10, 16)
	return h, uint16(n), func() { close(done); _ = l.Close() }
}

func swapTargetOutbound(t *testing.T, tag, relayPubB64, host string, port uint16) adapter.Outbound {
	t.Helper()
	statics := []option.HydraAdaptiveCandidateOptions{
		{ID: "static-1", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: host, ServerPort: port}, Path: "/static1"},
		{ID: "static-2", Pubkey: relayPubB64, Transport: "wss", ServerOptions: option.ServerOptions{Server: host, ServerPort: port}, Path: "/static2"},
	}
	out, err := hydra.BuildAdaptiveOutboundWithDeps(t.Context(), log.NewNOPFactory().Logger(), tag, option.HydraOutboundOptions{
		Pubkey:            relayPubB64,
		NegotiateMaxFrame: 2048,
		Adaptive: &option.HydraAdaptiveOptions{
			Candidates:     statics,
			ProofURL:       "https://proof.invalid/probe",
			ProofBytes:     1024,
			AttemptTimeout: badoption.Duration(300 * time.Millisecond),
			Backoff:        badoption.Duration(10 * time.Millisecond),
			MaxBackoff:     badoption.Duration(50 * time.Millisecond),
		},
	}, hydra.OutboundDeps{DialerFactory: func(ctx context.Context, v option.HydraAdaptiveCandidateOptions) (N.Dialer, error) {
		return dialer.New(ctx, v.DialerOptions, v.ServerIsDomain())
	}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func waitForCandidates(t *testing.T, tag string, wantCount int, wantSwapGen uint64) adaptive.Snapshot {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var snap adaptive.Snapshot
	for time.Now().Before(deadline) {
		s, ok := adaptive.SnapshotByTag(tag)
		if !ok {
			t.Fatal("tag unregistered mid-test")
		}
		snap = s
		if snap.CandidateCount == wantCount && snap.SwapGeneration >= wantSwapGen {
			return snap
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("swap not observed: count=%d swaps=%d per=%v", snap.CandidateCount, snap.SwapGeneration, snap.PerCandidate)
	return snap
}

func TestRefresherDisabledWithoutConfig(t *testing.T) {
	r := New(Config{})
	if err := r.Run(t.Context()); err != nil {
		t.Fatalf("disabled refresher must not fail the app: %v", err)
	}
	st := r.Snapshot()
	if st.State != "disabled" || st.Detail == "" {
		t.Fatalf("disabled state must name the missing piece: %+v", st)
	}
}

// TestRefresherEndToEnd runs the REAL daemon against a real origin and
// checks the whole chain: fetch → verify (watermark as minSeq) → expand →
// pubkey match → live swap → watermark persist forward → replay rejection.
func TestRefresherEndToEnd(t *testing.T) {
	daemon := buildDaemon(t)
	host, port, stopStall := startStall(t)
	defer stopStall()

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPriv := ed25519.NewKeyFromSeed([]byte("catalogue-relay-key-material-32b!")[:32])
	relayPub := relayPriv.Public().(ed25519.PublicKey)
	relayPubB64 := base64.StdEncoding.EncodeToString(relayPub)

	origin := newCatalogueOrigin(t)
	origin.signDoc(t, rootPriv, newCatalogue(t, relayPub, host, port, 3, 9, nil))

	stateDir := t.TempDir()
	outbound := swapTargetOutbound(t, "group-ru", relayPubB64, host, port)
	defer func() {
		if closer, ok := outbound.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	// Drive the coordinator loop like production traffic would: the dial
	// blocks in Acquire until a tunnel verifies (never, against the stall
	// listener), which keeps the sweep attempting.
	sweepCtx, cancelSweep := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelSweep()
	go func() { _, _ = outbound.DialContext(sweepCtx, N.NetworkTCP, M.ParseSocksaddr("127.0.0.1:9")) }()

	r := New(Config{
		DaemonPath:   daemon,
		DataDir:      t.TempDir(),
		ControlOnion: "hydracontroltest.onion",
		RootPubkey:   rootPub,
		StateDir:     stateDir,
	})
	client := startDaemonFor(t, daemon, origin.addr)
	if err := r.cycle(t.Context(), client); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	st := r.Snapshot()
	if st.VerifiedSeq != 9 || st.SwappedSeq != 9 {
		t.Fatalf("status after first cycle: %+v", st)
	}
	if probe, ok := adaptive.SnapshotByTag("group-ru"); !ok {
		t.Fatalf("tag missing right after swap: ok=%v probe=%+v", ok, probe)
	}
	waitForCandidates(t, "group-ru", 3, 1)

	// G4: the watermark file exists, is 0600 and carries the verified seq.
	wmPath := adaptive.CatalogueWatermarkPath(filepath.Join(stateDir, "catalogue.json"))
	if info, err := os.Stat(wmPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("watermark file: stat=%v", err)
	}
	raw, err := os.ReadFile(wmPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored adaptive.CatalogueWatermark
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.MaxSeq != 9 || stored.Key != adaptive.CatalogueWatermarkKey(rootPub) {
		t.Fatalf("stored watermark: %+v", stored)
	}

	// G4 replay protection through the live chain: re-serve an OLDER signed
	// document; the cycle must reject it and the outbound must keep the
	// swapped set.
	origin.signDoc(t, rootPriv, newCatalogue(t, relayPub, host, port, 2, 8, nil))
	err = r.cycle(t.Context(), client)
	if err == nil {
		t.Fatal("older-seq document must be rejected by the persisted watermark")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Fatalf("error %q must name the replay", err.Error())
	}
	snap := waitForCandidates(t, "group-ru", 3, 1)
	if snap.CandidateCount != 3 || snap.SwapGeneration != 1 {
		t.Fatalf("rejected cycle mutated the live set: %+v", snap)
	}

	// A NEWER document with revocations verifies, swaps and merges the
	// revocation union into the watermark.
	origin.signDoc(t, rootPriv, newCatalogue(t, relayPub, host, port, 4, 10, []string{"ghost-recipe"}))
	if err := r.cycle(t.Context(), client); err != nil {
		t.Fatalf("seq 10 cycle: %v", err)
	}
	waitForCandidates(t, "group-ru", 4, 2)
	raw, err = os.ReadFile(wmPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.MaxSeq != 10 || len(stored.RevokedIDs) != 1 || stored.RevokedIDs[0] != "ghost-recipe" {
		t.Fatalf("revocation union: %+v", stored)
	}

	// The same document again verifies (equal seq passes) and is a swap
	// no-op.
	if err := r.cycle(t.Context(), client); err != nil {
		t.Fatalf("equal-seq re-verify: %v", err)
	}
	final, ok := adaptive.SnapshotByTag("group-ru")
	if !ok {
		t.Fatal("tag lost")
	}
	if final.SwapGeneration != 2 {
		t.Fatalf("no-op cycle must not swap again: %+v", final)
	}
	if StatusJSON() == "" {
		t.Fatal("status accessor must produce output")
	}
}
