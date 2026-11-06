package config

import (
	context "context"
	"slices"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Real 32-byte X25519 pubkeys (the parse-stage box.New validation rejects
// anything that does not decode to 32 bytes).
const (
	hydraTestPubA = "stLqUvj6Rr+Ps5gbewpszBZq8g7mlZi3KgZdBy507mA"
	hydraTestPubB = "6pGGpf8hLPcl3o4Yrxq3gfPn8e6SU8NbonbXDEVUDyQ"
)

// A subscription exercising the full adaptive plumbing: three hydra links
// share the adaptive group ru-1 (identical proof/interface/dns on every
// member, transports mixed wss/rtc/default), a fourth link stays ungrouped.
var hydraAdaptiveSub = strings.Join([]string{
	"hydra://" + hydraTestPubA + "@10.0.0.1:443/hydra?tls=1&sni=a.example&ag=ru-1&pa=https://p.example/proof&pb=131072&pi=wlan0&pd=9.9.9.9:53&at=wss#hydra-a",
	"hydra://" + hydraTestPubA + "@10.0.0.2:443/hydra?tls=1&sni=b.example&ag=ru-1&pa=https://p.example/proof&pb=131072&pi=wlan0&pd=9.9.9.9:53&at=rtc#hydra-b",
	"hydra://" + hydraTestPubA + "@10.0.0.3:443/hydra?tls=1&sni=c.example&ag=ru-1&pa=https://p.example/proof&pb=131072&pi=wlan0&pd=9.9.9.9:53#hydra-c",
	"hydra://" + hydraTestPubB + "@10.0.0.4:443/hydra?tls=1&sni=d.example#solo",
}, "\n")

// Three grouped links + one ungrouped must build into ONE adaptive hydra
// outbound (tag = group id) with three candidates in profile order, proof and
// physical settings lifted from the member links, members removed, and the
// ungrouped link left static.
func TestHydraAdaptiveGroupCollapse(t *testing.T) {
	opts, err := ParseBuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{Content: hydraAdaptiveSub})
	if err != nil {
		t.Fatal(err)
	}

	var adaptive *option.HydraOutboundOptions
	adaptiveTag := ""
	soloSeen := false
	hydraCount := 0
	for i := range opts.Outbounds {
		ob := &opts.Outbounds[i]
		h, ok := ob.Options.(*option.HydraOutboundOptions)
		if !ok {
			continue
		}
		hydraCount++
		if h.Adaptive == nil {
			if strings.Contains(ob.Tag, "solo") {
				soloSeen = true
				if h.AdaptiveGroup != "" || h.AdaptiveProof != "" || h.Transport != "" {
					t.Fatalf("solo outbound carries adaptive plumbing: %+v", h)
				}
				if h.TLS == nil || !h.TLS.Enabled {
					t.Fatalf("solo outbound lost its TLS block")
				}
			}
			continue
		}
		if adaptive != nil {
			t.Fatalf("more than one adaptive hydra outbound: %q", ob.Tag)
		}
		adaptive, adaptiveTag = h, ob.Tag
	}
	if adaptive == nil {
		t.Fatal("no adaptive hydra outbound in built config")
	}
	if adaptiveTag != "ru-1" {
		t.Fatalf("adaptive outbound tag = %q, want ru-1", adaptiveTag)
	}
	if hydraCount != 2 {
		t.Fatalf("hydra outbound count = %d, want 2 (adaptive head + solo)", hydraCount)
	}
	if !soloSeen {
		t.Fatal("ungrouped link did not survive as a static outbound")
	}

	a := adaptive.Adaptive
	if a.ProofURL != "https://p.example/proof" {
		t.Fatalf("proof url = %q", a.ProofURL)
	}
	if a.ProofBytes != 131072 {
		t.Fatalf("proof bytes = %d", a.ProofBytes)
	}
	if a.PhysicalInterface != "wlan0" {
		t.Fatalf("physical interface = %q", a.PhysicalInterface)
	}
	if want := []string{"9.9.9.9:53"}; !slices.Equal(a.PhysicalDNSServers, want) {
		t.Fatalf("physical dns = %v, want %v", a.PhysicalDNSServers, want)
	}

	cs := a.Candidates
	if len(cs) != 3 {
		t.Fatalf("candidates = %d, want 3", len(cs))
	}
	wantIDs := []string{"hydra-a", "hydra-b", "hydra-c"}
	wantServers := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	wantTransport := []string{"wss", "rtc", ""}
	for i, c := range cs {
		if c.ID != wantIDs[i] {
			t.Fatalf("candidate %d id = %q, want %q", i, c.ID, wantIDs[i])
		}
		if c.Server != wantServers[i] || c.ServerPort != 443 {
			t.Fatalf("candidate %d endpoint = %s:%d, want %s:443", i, c.Server, c.ServerPort, wantServers[i])
		}
		if c.Transport != wantTransport[i] {
			t.Fatalf("candidate %d transport = %q, want %q", i, c.Transport, wantTransport[i])
		}
		if c.Path != "/hydra" {
			t.Fatalf("candidate %d path = %q", i, c.Path)
		}
		if c.TLS == nil || !c.TLS.Enabled || c.TLS.ServerName == "" {
			t.Fatalf("candidate %d lost its TLS block: %+v", i, c.TLS)
		}
	}
	if adaptive.Pubkey != hydraTestPubA+"=" {
		t.Fatalf("adaptive head pubkey = %q, want %s=", adaptive.Pubkey, hydraTestPubA)
	}

	// Members must be gone and every plumbing field must be stripped from the
	// final option structs (they are parse-time state, not config).
	for i := range opts.Outbounds {
		ob := &opts.Outbounds[i]
		for _, member := range []string{"hydra-a", "hydra-b", "hydra-c"} {
			if strings.HasPrefix(ob.Tag, member+" § ") {
				t.Fatalf("group member still present: %q", ob.Tag)
			}
		}
		if h, ok := ob.Options.(*option.HydraOutboundOptions); ok {
			if h.AdaptiveGroup != "" || h.AdaptiveProof != "" || h.AdaptiveProofBytes != 0 ||
				h.AdaptiveInterface != "" || h.AdaptiveDNS != nil {
				t.Fatalf("adaptive plumbing leaked on outbound %q", ob.Tag)
			}
		}
	}

	// The adaptive outbound must be selectable: present in the balancer and
	// the selector, removed members absent from both.
	assertAdaptiveSelected(t, opts, true)
}

// The marshal step the app consumes (ParseBuildConfigBytes) must serialise the
// adaptive block and must not leak the parse-time plumbing keys.
func TestHydraAdaptiveGroupJsonRoundTrip(t *testing.T) {
	opts, err := ParseBuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{Content: hydraAdaptiveSub})
	if err != nil {
		t.Fatal(err)
	}
	b, err := opts.MarshalJSONContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	json := string(b)
	if !strings.Contains(json, `"adaptive":`) {
		t.Fatal("marshalled config has no adaptive block")
	}
	if !strings.Contains(json, `"proof_url":"https://p.example/proof"`) {
		t.Fatal("marshalled config lost the proof url")
	}
	if !strings.Contains(json, `"transport":"rtc"`) {
		t.Fatal("marshalled config lost the rtc candidate transport")
	}
	if strings.Contains(json, "adaptive_group") || strings.Contains(json, "adaptive_proof") ||
		strings.Contains(json, "adaptive_dns") || strings.Contains(json, "adaptive_interface") {
		t.Fatal("parse-time plumbing keys leaked into the final config")
	}
}

// The kill switch must demote the group: every link stays a separate static
// outbound and no adaptive block reaches the final config.
func TestHydraAdaptiveDisableDemotes(t *testing.T) {
	hopts := DefaultHiddifyOptions()
	hopts.HydraAdaptiveDisable = true
	opts, err := ParseBuildConfig(context.Background(), hopts, &ReadOptions{Content: hydraAdaptiveSub})
	if err != nil {
		t.Fatal(err)
	}
	hydraCount := 0
	for i := range opts.Outbounds {
		h, ok := opts.Outbounds[i].Options.(*option.HydraOutboundOptions)
		if !ok {
			continue
		}
		hydraCount++
		if h.Adaptive != nil {
			t.Fatalf("adaptive block survived the kill switch on %q", opts.Outbounds[i].Tag)
		}
		if h.AdaptiveGroup != "" || h.AdaptiveProof != "" || h.AdaptiveProofBytes != 0 ||
			h.AdaptiveInterface != "" || h.AdaptiveDNS != nil {
			t.Fatalf("plumbing survived the kill switch on %q", opts.Outbounds[i].Tag)
		}
	}
	if hydraCount != 4 {
		t.Fatalf("hydra outbound count = %d, want 4 (all links demoted to static)", hydraCount)
	}
}

// A lone ag= link has no group to adapt across: it must stay a normal static
// outbound (with its transport override kept).
func TestHydraAdaptiveLoneMemberStaysStatic(t *testing.T) {
	sub := "hydra://" + hydraTestPubA + "@10.0.0.1:443/hydra?tls=1&sni=a.example&ag=lonely&pa=https://p.example/proof&pb=2048&at=rtc#only"
	opts, err := ParseBuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{Content: sub})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range opts.Outbounds {
		ob := &opts.Outbounds[i]
		h, ok := ob.Options.(*option.HydraOutboundOptions)
		if !ok {
			continue
		}
		found = true
		if h.Adaptive != nil {
			t.Fatal("lone group member was merged into an adaptive outbound")
		}
		if h.AdaptiveGroup != "" || h.AdaptiveProof != "" || h.AdaptiveProofBytes != 0 {
			t.Fatalf("lone member kept its group marker: %+v", h)
		}
		if h.Transport != "rtc" {
			t.Fatalf("lone member lost its transport override: %q", h.Transport)
		}
		if !strings.HasPrefix(ob.Tag, "only") {
			t.Fatalf("lone member tag = %q", ob.Tag)
		}
	}
	if !found {
		t.Fatal("no hydra outbound in built config")
	}
}

// Group members must agree on the relay pubkey.
func TestHydraAdaptiveGroupPubkeyMismatchFails(t *testing.T) {
	sub := strings.Join([]string{
		"hydra://" + hydraTestPubA + "@10.0.0.1:443/hydra?ag=g&pa=https://p.example/proof&pb=2048#a",
		"hydra://" + hydraTestPubB + "@10.0.0.2:443/hydra?ag=g&pa=https://p.example/proof&pb=2048#b",
	}, "\n")
	_, err := ParseBuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{Content: sub})
	if err == nil || !strings.Contains(err.Error(), "pubkey") {
		t.Fatalf("expected pubkey mismatch build error, got %v", err)
	}
}

// Group members must agree on every shared adaptive setting.
func TestHydraAdaptiveGroupProofMismatchFails(t *testing.T) {
	sub := strings.Join([]string{
		"hydra://" + hydraTestPubA + "@10.0.0.1:443/hydra?ag=g&pa=https://p.example/proof&pb=2048#a",
		"hydra://" + hydraTestPubA + "@10.0.0.2:443/hydra?ag=g&pa=https://other.example/proof&pb=2048#b",
	}, "\n")
	_, err := ParseBuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{Content: sub})
	if err == nil || !strings.Contains(err.Error(), "proof url") {
		t.Fatalf("expected proof mismatch build error, got %v", err)
	}
}

// A group id colliding with a surviving tag must fail the build instead of
// producing a config sing-box rejects for duplicate tags. The parse path
// cannot produce a bare colliding tag (ray2sing suffixes every link tag with
// " § N"), so this drives the collapse directly with a hand-built input.
func TestHydraAdaptiveGroupTagCollisionFails(t *testing.T) {
	member := func(server string) *option.HydraOutboundOptions {
		return &option.HydraOutboundOptions{
			Pubkey:             "AAAA=",
			AdaptiveGroup:      "ru-1",
			AdaptiveProof:      "https://p.example/proof",
			AdaptiveProofBytes: 2048,
			ServerOptions:      option.ServerOptions{Server: server, ServerPort: 443},
		}
	}
	outbounds := []option.Outbound{
		{Type: C.TypeHydra, Tag: "member-1", Options: member("10.0.0.1")},
		{Type: C.TypeHydra, Tag: "member-2", Options: member("10.0.0.2")},
		{Type: C.TypeHydra, Tag: "ru-1", Options: &option.HydraOutboundOptions{Pubkey: "CCCC=", ServerOptions: option.ServerOptions{Server: "10.0.0.3", ServerPort: 443}}},
	}
	_, err := collapseHydraAdaptiveGroups(outbounds, DefaultHiddifyOptions())
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected tag collision build error, got %v", err)
	}
}

func assertAdaptiveSelected(t *testing.T, opts *option.Options, want bool) {
	t.Helper()
	inBalancer, inSelector := false, false
	for i := range opts.Outbounds {
		ob := &opts.Outbounds[i]
		switch o := ob.Options.(type) {
		case *option.BalancerOutboundOptions:
			if slices.Contains(o.Outbounds, "ru-1") {
				inBalancer = true
			}
			for _, tag := range o.Outbounds {
				if strings.HasPrefix(tag, "hydra-a § ") {
					t.Fatalf("balancer still ranks a removed member: %q", tag)
				}
			}
		case *option.SelectorOutboundOptions:
			if slices.Contains(o.Outbounds, "ru-1") {
				inSelector = true
			}
		}
	}
	if want && (!inBalancer || !inSelector) {
		t.Fatalf("adaptive outbound not selectable: balancer=%v selector=%v", inBalancer, inSelector)
	}
}
