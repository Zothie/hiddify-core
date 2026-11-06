package config

import (
	"encoding/json"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The rules must exist only when explicitly requested; a default install must
// not gain surprise bypass rules.
func TestDirectBypassRulesDisabledByDefault(t *testing.T) {
	rules := directBypassRules(&HiddifyOptions{})
	if len(rules) != 0 {
		t.Fatalf("expected no bypass rules by default, got %d", len(rules))
	}
}

// Steam classic game ports must be routed out of the tunnel when the
// direct-game-ports flag is set: UDP 27000:27100, UDP 4380, TCP 27015
// (Valve, "Required Ports for Steam"), each to the direct outbound.
func TestDirectGamePortsRules(t *testing.T) {
	hopts := DefaultHiddifyOptions()
	hopts.DirectGamePorts = true

	rules := directBypassRules(hopts)
	if len(rules) != 3 {
		t.Fatalf("expected 3 game port rules, got %d", len(rules))
	}

	want := []struct {
		network   []string
		portRange []string
		port      []uint16
	}{
		{network: []string{"udp"}, portRange: []string{"27000:27100"}},
		{network: []string{"udp"}, port: []uint16{4380}},
		{network: []string{"tcp"}, port: []uint16{27015}},
	}
	for i, w := range want {
		raw := rules[i].DefaultOptions.RawDefaultRule
		action := rules[i].DefaultOptions.RuleAction
		if len(raw.Network) != 1 || raw.Network[0] != w.network[0] {
			t.Fatalf("rule %d: network = %v, want %v", i, raw.Network, w.network)
		}
		if len(raw.PortRange) != len(w.portRange) {
			t.Fatalf("rule %d: port ranges = %v, want %v", i, raw.PortRange, w.portRange)
		}
		for j, pr := range w.portRange {
			if raw.PortRange[j] != pr {
				t.Fatalf("rule %d: port range = %q, want %q", i, raw.PortRange[j], pr)
			}
		}
		if len(raw.Port) != len(w.port) {
			t.Fatalf("rule %d: ports = %v, want %v", i, raw.Port, w.port)
		}
		for j, p := range w.port {
			if raw.Port[j] != p {
				t.Fatalf("rule %d: port = %d, want %d", i, raw.Port[j], p)
			}
		}
		if action.Action != C.RuleActionTypeRoute || action.RouteOptions.Outbound != OutboundDirectTag {
			t.Fatalf("rule %d: action/outbound = %v/%q, want route/%q", i, action.Action, action.RouteOptions.Outbound, OutboundDirectTag)
		}
		if rules[i].Type != C.RuleTypeDefault {
			t.Fatalf("rule %d: type = %v, want default", i, rules[i].Type)
		}
	}
}

// Desktop process names (Radmin VPN etc.) must become a single process_name
// rule to the direct outbound.
func TestDirectProcessNamesRule(t *testing.T) {
	hopts := DefaultHiddifyOptions()
	hopts.DirectProcessNames = []string{"RadminVPN.exe", "radmin.exe", "RadminVpnService"}

	rules := directBypassRules(hopts)
	if len(rules) != 1 {
		t.Fatalf("expected 1 process rule, got %d", len(rules))
	}
	raw := rules[0].DefaultOptions.RawDefaultRule
	if len(raw.ProcessName) != 3 || raw.ProcessName[0] != "RadminVPN.exe" {
		t.Fatalf("process names = %v", raw.ProcessName)
	}
	action := rules[0].DefaultOptions.RuleAction
	if action.Action != C.RuleActionTypeRoute || action.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("action/outbound = %v/%q, want route/%q", action.Action, action.RouteOptions.Outbound, OutboundDirectTag)
	}
}

// The app reaches the core through ChangeHiddifySettings, which json.Unmarshals
// its HiddifySettingsJson into HiddifyOptions. The kebab-case keys sent by the
// app's SingboxConfigOption must therefore land on the RouteOptions fields.
func TestDirectBypassOptionsJsonRoundTrip(t *testing.T) {
	const payload = `{"direct-game-ports":true,"direct-process-names":["RadminVPN.exe","radmin.exe"]}`
	hopts := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(payload), hopts); err != nil {
		t.Fatal(err)
	}
	if !hopts.DirectGamePorts {
		t.Fatal("direct-game-ports did not unmarshal into DirectGamePorts")
	}
	if len(hopts.DirectProcessNames) != 2 || hopts.DirectProcessNames[0] != "RadminVPN.exe" {
		t.Fatalf("direct-process-names = %v", hopts.DirectProcessNames)
	}
}

// The injected rules must sit at the END of the rule list, i.e. after every
// built-in rule but BEFORE the Final catch-all (which is a separate field),
// so the proxy cannot swallow game traffic first.
func TestDirectRulesPlacedBeforeFinalCatchAll(t *testing.T) {
	opts := &option.Options{DNS: &option.DNSOptions{}}
	hopts := DefaultHiddifyOptions()
	hopts.DirectGamePorts = true
	hopts.DirectProcessNames = []string{"RadminVPN.exe"}

	if err := setRoutingOptions(opts, hopts); err != nil {
		t.Fatal(err)
	}

	if opts.Route.Final != OutboundMainDetour {
		t.Fatalf("final catch-all = %q, want %q", opts.Route.Final, OutboundMainDetour)
	}
	rules := opts.Route.Rules
	if len(rules) < 4 {
		t.Fatalf("expected at least 4 rules, got %d", len(rules))
	}
	last := rules[len(rules)-1].DefaultOptions.RawDefaultRule
	if len(last.ProcessName) != 1 || last.ProcessName[0] != "RadminVPN.exe" {
		t.Fatalf("last rule is not the process rule: %v", last.ProcessName)
	}
	udpRange := rules[len(rules)-4].DefaultOptions.RawDefaultRule
	if len(udpRange.PortRange) != 1 || udpRange.PortRange[0] != "27000:27100" {
		t.Fatalf("4th from last rule is not the UDP game range: %v", udpRange.PortRange)
	}
}
