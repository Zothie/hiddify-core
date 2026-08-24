package config

import (
	"encoding/json"
	"testing"
)

// The auto group must default to throughput selection. Latency ranking is what
// lets a frozen node win, so defaulting to it would leave the bug in place.
func TestAutoGroupDefaultsToThroughput(t *testing.T) {
	if got := autoGroupStrategy(&HiddifyOptions{}); got != balancerStrategyThroughput {
		t.Fatalf("expected throughput by default, got %q", got)
	}
}

// An explicit user choice must always win over the default.
func TestExplicitStrategyIsRespected(t *testing.T) {
	for _, want := range []string{
		balancerStrategyLowestDelay,
		balancerStrategyPriority,
		balancerStrategyThroughput,
	} {
		got := autoGroupStrategy(&HiddifyOptions{BalancerStrategy: want})
		if got != want {
			t.Fatalf("explicit %q was overridden with %q", want, got)
		}
	}
}

// An unrecognised value must fall back to the safe default rather than being
// passed through, which the core would reject at startup.
func TestUnknownStrategyFallsBack(t *testing.T) {
	got := autoGroupStrategy(&HiddifyOptions{BalancerStrategy: "nonsense"})
	if got != balancerStrategyThroughput {
		t.Fatalf("unknown strategy should fall back, got %q", got)
	}
}

// Bulk probing costs the user real bandwidth, so it must be armed only when
// something will actually consume the verdict.
func TestProbeOnlyEnabledWhenUsed(t *testing.T) {
	if opts := throughputProbeOptions(&HiddifyOptions{}); opts == nil {
		t.Fatal("probe should be enabled when auto defaults to throughput")
	}
	if opts := throughputProbeOptions(&HiddifyOptions{
		BalancerStrategy: balancerStrategyLowestDelay,
	}); opts != nil {
		t.Fatal("probe must stay off for latency-only selection")
	}
	if opts := throughputProbeOptions(&HiddifyOptions{
		BalancerStrategy: balancerStrategyPriority,
	}); opts != nil {
		t.Fatal("probe must stay off for priority selection")
	}
}

// The probe cadence must not be aggressive: bursts of bulk transfers are what
// arm the censor's per-flow drop penalty.
func TestProbeCadenceIsConservative(t *testing.T) {
	opts := throughputProbeOptions(&HiddifyOptions{})
	if opts.EveryNCycles < 2 {
		t.Fatalf("probe cadence %d is too aggressive", opts.EveryNCycles)
	}
	// Options must survive JSON round-trip into the core config.
	b, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || string(b) == "{}" {
		t.Fatalf("probe options serialised to %q", b)
	}
}
