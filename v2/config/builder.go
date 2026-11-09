package config

import (
	context "context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	sync "sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/hutils"
	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/wireguard-go/hiddify"
)

const (
	DNSRemoteTag         = "dns-remote"
	DNSRemoteTagFallback = "dns-remote-fallback"
	DNSLocalTag          = "dns-local"
	DNSStaticTag         = "dns-static"
	DNSDirectTag         = "dns-direct"
	DNSRemoteNoWarpTag   = "dns-remote-no-warp"
	// DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"
	// DNSMultiDirectTag  = "dns-multi-direct"
	// DNSMultiRemoteTag  = "dns-multi-remote"
	DNSMultiDirectTag = "dns-direct"
	DNSMultiRemoteTag = "dns-remote"

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "best"
	OutboundRoundRobinTag     = "balance"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	WARPConfigTag = "🔒 WARP"

	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in"
	InboundTProxy    = "tproxy-in"
	InboundRedirect  = "redirect-in"
	InboundDirectTag = "dns-in"
)

var (
	OutboundMainDetour       = OutboundSelectTag
	OutboundWARPConfigDetour = ""
	PredefinedOutboundTags   = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag, WARPConfigTag}
)

// TODO include selectors
func BuildConfig(ctx context.Context, hopts *HiddifyOptions, inputOpt *ReadOptions) (*option.Options, error) {

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)

	setLog(&options, hopts)
	setInbound(&options, hopts)
	staticIPs := make(map[string][]string)
	// staticIPs["api.cloudflareclient.com"] = []string{"104.16.192.82", "2606:4700::6810:1854", getRandomWarpIP()}
	// setNTP(&options)
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}
	if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, hopts); err != nil {
		return nil, err
	}

	return &options, nil
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
		DialerOptions: option.DialerOptions{
			Detour: OutboundDirectTag,
		},
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	// OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	OutboundMainDetour = OutboundSelectTag
	OutboundWARPConfigDetour = ""
	hasPsiphon := false
	profileOutbounds, err := collapseHydraAdaptiveGroups(input.Outbounds, opt)
	if err != nil {
		return err
	}
	for _, out := range profileOutbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom:
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if out.Type == C.TypePsiphon {
				if hasPsiphon {
					continue
				}
				hasPsiphon = true
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
			}
			// OutboundWARPConfigDetour = OutboundSelectTag
			out = *patchHiddifyWarpFromConfig(&out, *opt)
			outbounds = append(outbounds, out)
		}
	}

	if opt.Warp.EnableWarp {
		// wg := getOrGenerateWarpLocallyIfNeeded(&opt.Warp)

		// out, err := GenerateWarpSingbox(wg, opt.Warp.CleanIP, opt.Warp.CleanPort, &option.WireGuardHiddify{
		// 	FakePackets:      opt.Warp.FakePackets,
		// 	FakePacketsSize:  opt.Warp.FakePacketSize,
		// 	FakePacketsDelay: opt.Warp.FakePacketDelay,
		// 	FakePacketsMode:  opt.Warp.FakePacketMode,
		// })
		out, err := GenerateWarpSingboxNew("p1", &hiddify.NoiseOptions{})
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = WARPConfigTag
		if opts, ok := out.Options.(*option.WARPEndpointOptions); ok {
			if opt.Warp.Mode == "warp_over_proxy" {
				opts.Detour = OutboundSelectTag
				opts.MTU = 1280
			} else {
				opts.Detour = OutboundDirectTag
				opt.MTU = max(opt.MTU, 1340)
			}

		}

		OutboundMainDetour = WARPConfigTag
		// patchWarp(out, opt, true, nil)
		out, err = patchEndpoint(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, *out)
	}
	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		if opt.Warp.EnableWarp {
			if end.Type == C.TypeWARP {
				if opts, ok := end.Options.(*option.WARPEndpointOptions); ok {
					if opts.UniqueIdentifier == "p1" {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
			if end.Type == C.TypeWireGuard {
				if opts, ok := end.Options.(*option.WireGuardEndpointOptions); ok {
					if opts.PrivateKey == opt.Warp.WireguardConfig.PrivateKey {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}

		if !strings.Contains(out.Tag, "§hide§") {
			tags = append(tags, out.Tag)
		}

		endpoints = append(endpoints, *out)
	}
	if len(opt.ConnectionTestUrls) == 0 {
		opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl, "https://www.google.com/generate_204", "http://captive.apple.com/generate_204", "https://cp.cloudflare.com"}
		if isBlockedConnectionTestUrl(opt.ConnectionTestUrl) {
			opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl}
		}
	}
	// urlTest := option.Outbound{
	// 	Type: C.TypeURLTest,
	// 	Tag:  OutboundURLTestTag,
	// 	Options: &option.URLTestOutboundOptions{
	// 		Outbounds: tags,
	// 		URL:       opt.ConnectionTestUrl,
	// 		URLs:      opt.ConnectionTestUrls,
	// 		Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
	// 		// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
	// 		Tolerance:                 1,
	// 		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
	// 		InterruptExistConnections: true,
	// 	},
	// }
	autoStrategy := autoGroupStrategy(opt)
	urlTest := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundURLTestTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            tags,
			Strategy:             autoStrategy,
			DelayAcceptableRatio: 2,
			// URL:       opt.ConnectionTestUrl,
			// URLs:      opt.ConnectionTestUrls,
			// Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			Tolerance: 1,
			// IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: true,
		},
	}

	defaultSelect := tags[0]

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}

	selectorTags := tags
	if len(tags) > 1 {
		if OutboundMainDetour == WARPConfigTag {
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag}, selectorTags...)
			defaultSelect = urlTest.Tag
		} else {
			// Only the "best" group is published. Round-robin was dropped
			// deliberately: it keeps feeding a share of every request into
			// whichever node is currently frozen, which is precisely the
			// failure this build exists to avoid. "best" filters out nodes that
			// cannot carry data before ranking the rest.
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag}, selectorTags...)
			defaultSelect = urlTest.Tag
		}
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector}, outbounds...)

	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						// TLS fragmentation is commented out below, which used to
						// leave this outbound completely empty — and newer
						// sing-box refuses to start at all when anything detours
						// to an empty direct outbound. Setting one harmless
						// explicit field keeps it distinguishable from a bare
						// direct while fragmentation stays disabled.
						TCPFastOpen:        false,
						TCPMultiPath:       false,
						UDPFragmentDefault: true,

						// TLSFragment: option.TLSFragmentOptions{
						// 	Enabled: true,
						// 	Size:    opt.TLSTricks.FragmentSize,
						// 	Sleep:   opt.TLSTricks.FragmentSleep,
						// },
					},
				},
			},
		}...,
	)

	return nil
}

// collapseHydraAdaptiveGroups merges the hydra outbounds that ray2sing marked
// as members of one adaptive group (the ag= link param, with the shared group
// settings pa/pb/pi/pd riding on every member link) into ONE adaptive hydra
// outbound per group: its Adaptive.Candidates carry one entry per member, in
// profile order, and the member outbounds are removed from the output.
//
// Semantics:
//   - HydraAdaptiveDisable (the escape hatch): no merging at all — every
//     member stays a plain static outbound with the adaptive plumbing fields
//     stripped, so the output matches the pre-adaptive link format. Transport
//     (at=) is kept, it is a per-outbound setting, not group state.
//   - A lone link marked with ag= has no group to adapt across; it stays a
//     normal static outbound. Its group marker is likewise stripped.
//   - All members of a merged group must agree on pa/pb/pi/pd; a disagreement
//     fails the build (the producer mixed links that would probe against the
//     wrong proof or interface). The relay pubkey is per-candidate instead:
//     every member's key rides onto its own candidate, so one group may span
//     relays with different keys.
//   - The merged outbound takes the group id as its tag: stable across
//     profile refreshes, where member remarks and their position-suffix
//     counter (ray2sing appends " § N") churn. A group id that collides with
//     another surviving tag fails the build instead of producing a config
//     sing-box rejects for duplicate tags.
//   - Every tuning axis parsed onto a member link (frag ranges, split delay,
//     disorder, pad ladder, rtc engine, TLS surface) rides onto that member's
//     candidate; a candidate axis left at zero inherits the FIRST member's
//     value (candidate-else-group-default, mirroring the nested resolver's
//     axesOrDefault), and the first member's axes also become the group
//     defaults on the merged head for the runtime parent fallback. max_frame
//     is copied verbatim and its zero-candidate inheritance stays governed
//     by the RecipeID rule inside the nested outbound. Members differing
//     only in axes are never merged here: one candidate per member, and the
//     axes-aware effective-identity dedup lives in the nested outbound.
//
// The input slice and its options are never mutated: parsed profiles may be
// reused by the caller.
func collapseHydraAdaptiveGroups(outbounds []option.Outbound, opt *HiddifyOptions) ([]option.Outbound, error) {
	hydraOpts := map[int]*option.HydraOutboundOptions{}
	groups := map[string][]int{}
	var groupOrder []string
	for i, ob := range outbounds {
		if ob.Type != C.TypeHydra {
			continue
		}
		h, ok := ob.Options.(*option.HydraOutboundOptions)
		if !ok || h.AdaptiveGroup == "" {
			continue
		}
		hydraOpts[i] = h
		if _, ok := groups[h.AdaptiveGroup]; !ok {
			groupOrder = append(groupOrder, h.AdaptiveGroup)
		}
		groups[h.AdaptiveGroup] = append(groups[h.AdaptiveGroup], i)
	}
	if len(groups) == 0 {
		return outbounds, nil
	}

	// stripHydraPlumbing returns a copy of h without the adaptive plumbing
	// fields, ready to serve as a plain static outbound.
	stripHydraPlumbing := func(h *option.HydraOutboundOptions) *option.HydraOutboundOptions {
		stripped := *h
		stripped.AdaptiveGroup = ""
		stripped.AdaptiveProof = ""
		stripped.AdaptiveProofBytes = 0
		stripped.AdaptiveInterface = ""
		stripped.AdaptiveDNS = nil
		stripped.AdaptiveASN = ""
		return &stripped
	}

	if opt.HydraAdaptiveDisable {
		out := make([]option.Outbound, len(outbounds))
		copy(out, outbounds)
		for i := range hydraOpts {
			out[i] = option.Outbound{
				Type:    out[i].Type,
				Tag:     out[i].Tag,
				Options: stripHydraPlumbing(hydraOpts[i]),
			}
		}
		return out, nil
	}

	replace := map[int]option.Outbound{}
	remove := map[int]bool{}
	mergedTags := map[string]bool{}
	for _, gid := range groupOrder {
		members := groups[gid]
		if len(members) < 2 {
			// Lone member: stays static, group marker stripped.
			i := members[0]
			replace[i] = option.Outbound{
				Type:    outbounds[i].Type,
				Tag:     outbounds[i].Tag,
				Options: stripHydraPlumbing(hydraOpts[i]),
			}
			continue
		}
		if err := hydraAdaptiveGroupConsistent(gid, members, hydraOpts); err != nil {
			return nil, err
		}
		first := hydraOpts[members[0]]
		groupDefaults := hydraMemberAxes(first)
		seenIDs := map[string]bool{}
		candidates := make([]option.HydraAdaptiveCandidateOptions, 0, len(members))
		for _, mi := range members {
			m := hydraOpts[mi]
			id := hydraCandidateID(outbounds[mi].Tag, seenIDs)
			seenIDs[id] = true
			// One candidate per member — members differing only in axes stay
			// distinct here (the axes-aware effective-identity dedup is the
			// nested outbound's job). Tuning axes resolve candidate-else-
			// group-default; max_frame is copied verbatim, its zero-candidate
			// inheritance guarded by the RecipeID rule in the nested outbound.
			c := hydraMemberAxes(m)
			c.ID = id
			c.ServerOptions = m.ServerOptions
			c.DialerOptions = m.DialerOptions
			c.Path = m.Path
			c.TLS = m.TLS
			c.Transport = m.Transport
			// Per-candidate relay key: members may span relays with different
			// keys; the runtime uses v.Pubkey first (head key is the empty-
			// candidate fallback only).
			c.Pubkey = m.Pubkey
			c.NegotiateMaxFrame = m.NegotiateMaxFrame
			candidates = append(candidates, hydraCandidateAxes(c, groupDefaults))
		}
		adaptive := &option.HydraAdaptiveOptions{
			Candidates:         candidates,
			ProofURL:           first.AdaptiveProof,
			ProofBytes:         first.AdaptiveProofBytes,
			PhysicalInterface:  first.AdaptiveInterface,
			PhysicalDNSServers: first.AdaptiveDNS,
			// Catalogue recipe hint ordering (asn= link param); an ordering
			// hint only, so group members are not required to agree on it —
			// the first member's value wins.
			CatalogueASN: first.AdaptiveASN,
		}
		// Persistence: the last-good candidate hint lives under the app files
		// dir the host plumbs in via HiddifyOptions.WorkingDir. The hint is
		// scoped to one physical network by NetworkKey, so a group without a
		// caller-supplied network key gets no state file at all (the runtime
		// refuses StatePath without NetworkKey; deriving the key is a
		// separately documented rule and is deliberately not done here). With
		// no dir resolvable, persistence is skipped with a visible reason — a
		// path is never guessed.
		if strings.TrimSpace(adaptive.NetworkKey) != "" {
			dir := strings.TrimSpace(opt.WorkingDir)
			if dir == "" {
				log.Printf("hydra adaptive: persistence disabled for group %q: no app files dir resolvable", gid)
			} else {
				statePath := filepath.Join(dir, "data", "hydra-adaptive", hydraAdaptiveStateFileName(gid))
				if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
					log.Printf("hydra adaptive: persistence disabled for group %q: state dir: %v", gid, err)
				} else {
					adaptive.StatePath = statePath
				}
			}
		}
		replace[members[0]] = option.Outbound{
			Type: C.TypeHydra,
			Tag:  gid,
			Options: &option.HydraOutboundOptions{
				// The head carries the first member's endpoint so the merged
				// outbound stays a well-formed hydra config for every path
				// that ignores Adaptive; the adaptive outbound dials through
				// Candidates.
				Adaptive:      adaptive,
				DialerOptions: first.DialerOptions,
				ServerOptions: first.ServerOptions,
				Pubkey:        first.Pubkey,
				Path:          first.Path,
				TLS:           first.TLS,
				// The first member's axes ride on the head as the group
				// defaults: candidates above were resolved against them, and
				// the runtime parent fallback (axesOrDefault, the RecipeID-
				// guarded max_frame rule) reads them from the head exactly
				// as it reads a solo tuned link's passthrough fields.
				NegotiateMaxFrame:   first.NegotiateMaxFrame,
				FragFirstMin:        groupDefaults.FragFirstMin,
				FragFirstMax:        groupDefaults.FragFirstMax,
				FragRestMin:         groupDefaults.FragRestMin,
				FragRestMax:         groupDefaults.FragRestMax,
				FragSplitDelayMs:    groupDefaults.FragSplitDelayMs,
				Disorder:            groupDefaults.Disorder,
				DisorderDelayMs:     groupDefaults.DisorderDelayMs,
				PadBuckets:          groupDefaults.PadBuckets,
				MaxPad:              groupDefaults.MaxPad,
				BigPadMax:           groupDefaults.BigPadMax,
				RTCChunk:            groupDefaults.RTCChunk,
				RTCWindow:           groupDefaults.RTCWindow,
				RTORtoMinMs:         groupDefaults.RTORtoMinMs,
				RTORtoMaxMs:         groupDefaults.RTORtoMaxMs,
				RTCBufferCap:        groupDefaults.RTCBufferCap,
				RTCKeepaliveEveryMs: groupDefaults.RTCKeepaliveEveryMs,
				TLSFragment:         groupDefaults.TLSFragment,
				TLSMinVersion:       groupDefaults.TLSMinVersion,
				TLSMaxVersion:       groupDefaults.TLSMaxVersion,
				TLSALPN:             groupDefaults.TLSALPN,
			},
		}
		mergedTags[gid] = true
		for _, mi := range members[1:] {
			remove[mi] = true
		}
	}

	out := make([]option.Outbound, 0, len(outbounds))
	for i, ob := range outbounds {
		if remove[i] {
			continue
		}
		if r, ok := replace[i]; ok {
			ob = r
		}
		out = append(out, ob)
	}
	// A group id must not collide with any other surviving tag: sing-box
	// refuses a config with duplicate outbound tags at startup.
	for gid := range mergedTags {
		count := 0
		for _, ob := range out {
			if ob.Tag == gid {
				count++
			}
		}
		if count > 1 {
			return nil, fmt.Errorf("hydra adaptive group tag %q collides with an existing outbound tag", gid)
		}
	}
	return out, nil
}

// hydraAdaptiveStateFileName maps a group id to a flat, filesystem-safe
// state file name. The group id comes from the ag= link param and may carry
// arbitrary characters; only [A-Za-z0-9._-] survive, the rest is replaced
// with '_' and the name is length-capped so it cannot escape the state dir.
func hydraAdaptiveStateFileName(gid string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, gid)
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" || name == "." || name == ".." {
		name = "group"
	}
	return name + ".json"
}

// hydraAdaptiveGroupConsistent rejects a group whose members disagree on any
// of the shared adaptive settings (pa/pb/pi/pd). The settings ride identically
// on every member link by contract; a disagreement means the producer mixed
// links that do not share one proof or physical layer, which would make
// candidates prove against the wrong endpoint. The relay pubkey is NOT part of
// the shared contract: each member's key rides onto its own candidate (set in
// the collapse loop) and the runtime resolves the candidate pubkey first,
// falling back to the head's only when a candidate leaves it empty — so one
// group may span relays with different keys (e.g. kvm-hop + kh2).
func hydraAdaptiveGroupConsistent(gid string, members []int, hydraOpts map[int]*option.HydraOutboundOptions) error {
	first := hydraOpts[members[0]]
	for _, mi := range members[1:] {
		m := hydraOpts[mi]
		if m.AdaptiveProof != first.AdaptiveProof {
			return fmt.Errorf("hydra adaptive group %q: members disagree on proof url", gid)
		}
		if m.AdaptiveProofBytes != first.AdaptiveProofBytes {
			return fmt.Errorf("hydra adaptive group %q: members disagree on proof bytes", gid)
		}
		if m.AdaptiveInterface != first.AdaptiveInterface {
			return fmt.Errorf("hydra adaptive group %q: members disagree on physical interface", gid)
		}
		if !slices.Equal(m.AdaptiveDNS, first.AdaptiveDNS) {
			return fmt.Errorf("hydra adaptive group %q: members disagree on physical dns", gid)
		}
	}
	return nil
}

// hydraCandidateID derives a candidate ID from a member's outbound tag.
// ray2sing appends a position counter (" § N") to every parsed link tag to
// keep tags unique; the counter shifts whenever the subscription changes, so
// the stable remark (the tag without the suffix) is the better ID. If the
// remark is empty or already used inside the group, the full tag is used.
func hydraCandidateID(tag string, seen map[string]bool) string {
	id := tag
	if i := strings.LastIndex(tag, " § "); i >= 0 {
		remark := tag[:i]
		suffix := tag[i+len(" § "):]
		if isDecimalDigits(suffix) && remark != "" && !seen[remark] {
			id = remark
		}
	}
	return id
}

// hydraMemberAxes views the tuning-axis passthrough fields of one parsed
// member link (HydraOutboundOptions) as a candidate axis set — the
// builder-side twin of the nested resolver's hydraParentAxes
// (protocol/hydra/axes.go). Identity fields (ID, endpoints, TLS, transport)
// stay zero; NegotiateMaxFrame is not an axis here (see hydraCandidateAxes).
func hydraMemberAxes(h *option.HydraOutboundOptions) option.HydraAdaptiveCandidateOptions {
	return option.HydraAdaptiveCandidateOptions{
		FragFirstMin:        h.FragFirstMin,
		FragFirstMax:        h.FragFirstMax,
		FragRestMin:         h.FragRestMin,
		FragRestMax:         h.FragRestMax,
		FragSplitDelayMs:    h.FragSplitDelayMs,
		Disorder:            h.Disorder,
		DisorderDelayMs:     h.DisorderDelayMs,
		PadBuckets:          h.PadBuckets,
		MaxPad:              h.MaxPad,
		BigPadMax:           h.BigPadMax,
		RTCChunk:            h.RTCChunk,
		RTCWindow:           h.RTCWindow,
		RTORtoMinMs:         h.RTORtoMinMs,
		RTORtoMaxMs:         h.RTORtoMaxMs,
		RTCBufferCap:        h.RTCBufferCap,
		RTCKeepaliveEveryMs: h.RTCKeepaliveEveryMs,
		TLSFragment:         h.TLSFragment,
		TLSMinVersion:       h.TLSMinVersion,
		TLSMaxVersion:       h.TLSMaxVersion,
		TLSALPN:             h.TLSALPN,
	}
}

// hydraCandidateAxes resolves one candidate's axes against the group
// defaults (the FIRST member's axes), mirroring the nested resolver's
// axesOrDefault (protocol/hydra/axes.go): a candidate axis left at zero
// inherits the group default, so a plain link under a tuned first member
// resolves to the same effective configuration the runtime would compute.
// NegotiateMaxFrame is deliberately NOT resolved here: its candidate-else-
// head inheritance is guarded by the RecipeID rule inside the nested
// outbound (catalogued candidates never inherit), which must stay the
// single authority for that field.
func hydraCandidateAxes(member, groupDefaults option.HydraAdaptiveCandidateOptions) option.HydraAdaptiveCandidateOptions {
	merged := member
	if merged.FragFirstMin == 0 {
		merged.FragFirstMin = groupDefaults.FragFirstMin
	}
	if merged.FragFirstMax == 0 {
		merged.FragFirstMax = groupDefaults.FragFirstMax
	}
	if merged.FragRestMin == 0 {
		merged.FragRestMin = groupDefaults.FragRestMin
	}
	if merged.FragRestMax == 0 {
		merged.FragRestMax = groupDefaults.FragRestMax
	}
	if merged.FragSplitDelayMs == 0 {
		merged.FragSplitDelayMs = groupDefaults.FragSplitDelayMs
	}
	if !merged.Disorder {
		merged.Disorder = groupDefaults.Disorder
	}
	if merged.DisorderDelayMs == 0 {
		merged.DisorderDelayMs = groupDefaults.DisorderDelayMs
	}
	if len(merged.PadBuckets) == 0 {
		merged.PadBuckets = groupDefaults.PadBuckets
	}
	if merged.MaxPad == 0 {
		merged.MaxPad = groupDefaults.MaxPad
	}
	if merged.BigPadMax == 0 {
		merged.BigPadMax = groupDefaults.BigPadMax
	}
	if merged.RTCChunk == 0 {
		merged.RTCChunk = groupDefaults.RTCChunk
	}
	if merged.RTCWindow == 0 {
		merged.RTCWindow = groupDefaults.RTCWindow
	}
	if merged.RTORtoMinMs == 0 {
		merged.RTORtoMinMs = groupDefaults.RTORtoMinMs
	}
	if merged.RTORtoMaxMs == 0 {
		merged.RTORtoMaxMs = groupDefaults.RTORtoMaxMs
	}
	if merged.RTCBufferCap == 0 {
		merged.RTCBufferCap = groupDefaults.RTCBufferCap
	}
	if merged.RTCKeepaliveEveryMs == 0 {
		merged.RTCKeepaliveEveryMs = groupDefaults.RTCKeepaliveEveryMs
	}
	if !merged.TLSFragment {
		merged.TLSFragment = groupDefaults.TLSFragment
	}
	if merged.TLSMinVersion == "" {
		merged.TLSMinVersion = groupDefaults.TLSMinVersion
	}
	if merged.TLSMaxVersion == "" {
		merged.TLSMaxVersion = groupDefaults.TLSMaxVersion
	}
	if len(merged.TLSALPN) == 0 {
		merged.TLSALPN = groupDefaults.TLSALPN
	}
	return merged
}

func isDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl, "http://captive.apple.com/generate_204", "https://cp.cloudflare.com", "https://google.com/generate_204"}
		if isBlockedConnectionTestUrl(hopt.ConnectionTestUrl) {
			hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl}
		}
	}
	if hopt.EnableClashApi {
		if hopt.ClashApiSecret == "" {
			hopt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{
				Enabled: true,
			},
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", hopt.ClashApiPort),
				Secret:             hopt.ClashApiSecret,
			},

			CacheFile: &option.CacheFileOptions{
				Enabled:         true,
				StoreWARPConfig: true,
				Path:            "data/clash.db",
			},

			Monitoring: &option.MonitoringOptions{
				URLs:           hopt.ConnectionTestUrls,
				Interval:       badoption.Duration(hopt.URLTestInterval.Duration()),
				DebounceWindow: badoption.Duration(time.Millisecond * 500),
				IdleTimeout:    badoption.Duration(hopt.URLTestInterval.Duration().Nanoseconds() * 3),
				Throughput:     throughputProbeOptions(hopt),
			},
		}
	}
}

const (
	balancerStrategyThroughput  = "throughput"
	balancerStrategyPriority    = "priority"
	balancerStrategyLowestDelay = "lowest-delay"
)

// autoGroupStrategy decides how the "auto" group picks a profile.
//
// The default is "throughput": first discard the profiles that cannot
// demonstrably move bytes, then among those pick the fastest by measured
// goodput. This is what the user means by "find the working ones and use the
// best" — and it is specifically not what latency ranking does. A censor's
// frozen node answers a ping instantly, so lowest-delay would select it and
// send traffic into a path that carries nothing; and even among healthy nodes
// latency ranks by proximity, pinning traffic to a nearby relay over a distant
// but much faster exit.
//
// An explicit user choice always wins over this default.
func autoGroupStrategy(opt *HiddifyOptions) string {
	switch opt.BalancerStrategy {
	case balancerStrategyLowestDelay, balancerStrategyPriority, balancerStrategyThroughput:
		return opt.BalancerStrategy
	}
	return balancerStrategyThroughput
}

// throughputProbeOptions enables the bulk (sized-GET) probe, but only when a
// group is actually going to use its verdict.
//
// The probe is what lets selection tell a working node from one a censor has
// frozen — a frozen node completes TLS and answers a latency probe instantly
// while carrying nothing, so latency alone cannot see the failure. But it costs
// real user bandwidth on every run, so it stays off for the latency-based
// strategies that would ignore the result anyway.
//
// Returning nil leaves the monitor in its original latency-only behaviour.
func throughputProbeOptions(hopt *HiddifyOptions) *option.ThroughputProbeOptions {
	if autoGroupStrategy(hopt) != balancerStrategyThroughput &&
		hopt.BalancerStrategy != balancerStrategyThroughput {
		return nil
	}
	return &option.ThroughputProbeOptions{
		// Defaults in the core cover request size, pass mark, cadence, jitter
		// and backoff. They are deliberately conservative: bulk transfers are
		// the pattern that arms the censor's per-flow drop penalty, so probing
		// too eagerly would manufacture the outage it is meant to detect.
		EveryNCycles: 4,
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	// Timestamps are mandatory here, not cosmetic: the only way to tell whether
	// a stall was the core's doing or the network's is to line the core's own
	// events up against the per-layer monitor, and without a clock on each line
	// that correlation is impossible. The log was previously written with none.
	lvl := opt.LogLevel
	if lvl == "" || lvl == "warn" {
		// "warn" hides connection open/close events, which is exactly the
		// evidence needed when the proxy stops forwarding while the network is
		// demonstrably fine. "info" costs a few MB a day and is worth it.
		lvl = "info"
	}
	options.Log = &option.LogOptions{
		Level:        lvl,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    true,
		DisableColor: true,
	}
}
func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}
func setInbound(options *option.Options, hopt *HiddifyOptions) {
	// var inboundDomainStrategy option.DomainStrategy
	// if !opt.ResolveDestination {
	// 	inboundDomainStrategy = option.DomainStrategy(dns.DomainStrategyAsIS)
	// } else {
	// 	inboundDomainStrategy = opt.IPv6Mode
	// }
	ipv6Enable := isIPv6Supported()
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:       hopt.TUNStack,
			MTU:         hopt.MTU,
			AutoRoute:   true,
			StrictRoute: hopt.StrictRoute,

			// EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",

		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}
		// switch hopt.IPv6Mode {
		// case option.DomainStrategy(dns.DomainStrategyUseIPv4):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("172.19.0.1/28"),
		// 	}
		// case option.DomainStrategy(dns.DomainStrategyUseIPv6):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		// 	}
		// default:

		// }
		// v4 only on the tun. With a v6 address present the OS hands the tun
		// every literal-IPv6 destination too (apps that bypass DNS, e.g.
		// WebRTC ICE candidates), and none of our servers can carry v6.
		// Without a v6 route those packets have nowhere to go and the app
		// falls back to v4 at once instead of waiting on a dead candidate.
		_ = ipv6Enable
		opts.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/28")}

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		if ipv6Enable {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		if ipv6Enable {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		options.Inbounds = append(
			options.Inbounds,
			option.Inbound{
				Type: C.TypeMixed,
				Tag:  InboundMixedTag + bind,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &addr,
						ListenPort: hopt.MixedPort,
						// InboundOptions: option.InboundOptions{
						// 	SniffEnabled:             true,
						// 	SniffOverrideDestination: true,
						// 	DomainStrategy:           inboundDomainStrategy,
						// },
					},
					SetSystemProxy: hopt.SetSystemProxy,
				},
			},
		)
		if C.IsLinux && !C.IsAndroid && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

func setRoutingOptions(options *option.Options, hopt *HiddifyOptions) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	// if opt.EnableTun && runtime.GOOS == "android" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,

	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			Inbound:     []string{InboundTUNTag},
	// 	// 			PackageName: []string{"app.hiddify.com"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }
	// if opt.EnableTun && runtime.GOOS == "windows" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,
	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			ProcessName: []string{"Hiddify", "Hiddify.exe", "HiddifyCli", "HiddifyCli.exe"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }

	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSStaticTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	forceDirectRules, err := addForceDirect(options, hopt)
	if err != nil {
		return err
	}

	dnsRules = append(dnsRules, forceDirectRules...)

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Protocol: []string{C.ProtocolDNS},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeHijackDNS,
			},
		},
	})

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,

		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: []string{
					"10.10.34.0/24",
					"2001:4188:2:600:10:10:34:0/120",
				},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundMainDetour,
				},
			},
		},
	})
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Direct",
	// 		Outbound:  OutboundDirectTag,
	// 	},
	// },
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Global",
	// 		Outbound:  OutboundMainProxyTag,
	// 	},
	// },	}

	if hopt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	// for _, rule := range opt.Rules {
	// 	routeRule := rule.MakeRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		routeRule.Outbound = OutboundBypassTag
	// 	case "block":
	// 		routeRule.Outbound = OutboundBlockTag
	// 	case "proxy":
	// 		routeRule.Outbound = OutboundMainProxyTag
	// 	}

	// 	if routeRule.IsValid() {
	// 		routeRules = append(
	// 			routeRules,
	// 			option.Rule{
	// 				Type:           C.RuleTypeDefault,
	// 				DefaultOptions: routeRule,
	// 			},
	// 		)
	// 	}

	// 	dnsRule := rule.MakeDNSRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		dnsRule.Server = DNSDirectTag
	// 	case "block":
	// 		dnsRule.Server = DNSBlockTag
	// 		dnsRule.DisableCache = true
	// 	case "proxy":
	// 		if opt.EnableFakeDNS {
	// 			fakeDnsRule := dnsRule
	// 			fakeDnsRule.Server = DNSFakeTag
	// 			fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
	// 			dnsRules = append(dnsRules, fakeDnsRule)
	// 		}
	// 		dnsRule.Server = DNSRemoteTag
	// 	}
	// 	dnsRules = append(dnsRules, dnsRule)
	// }
	forceDirectRoute := make([]string, 0)
	if options.NTP != nil && options.NTP.Enabled {
		forceDirectRoute = append(forceDirectRoute, options.NTP.Server)
	}

	// parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	// if err == nil {
	// 	dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 		Domain:       []string{parsedURL.Host},
	// 		Server:       DNSRemoteTag,
	// 		RewriteTTL:   &dnsCPttl,
	// 		DisableCache: false,
	// 	})
	// }

	if len(forceDirectRoute) > 0 {

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: forceDirectRoute,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSMultiDirectTag,
					Strategy:       hopt.DirectDnsDomainStrategy,
					RewriteTTL:     &DEFAULT_DNS_TTL,
					DisableCache:   false,
					BypassIfFailed: false,
				},
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: forceDirectRoute,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	rejectRCode := (option.DNSRCode(sdns.RcodeRefused))
	rejectDnsAction := option.DNSRuleAction{
		Action: C.RuleActionTypePredefined,
		PredefinedOptions: option.DNSRouteActionPredefined{
			Rcode: &rejectRCode,
		},
	}
	if hopt.BlockAds {
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-ads",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-category-ads-all.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-cryptominers",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-cryptominers.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geosite-ads",
						"geosite-malware",
						"geosite-phishing",
						"geosite-cryptominers",
						"geoip-malware",
						"geoip-phishing",
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{

				RuleSet: []string{
					"geosite-ads",
					"geosite-malware",
					"geosite-phishing",
					"geosite-cryptominers",
				},
			},
			DNSRuleAction: rejectDnsAction,
		})
	}
	if hopt.Region != "other" {
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				DomainSuffix: []string{"." + hopt.Region},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSMultiDirectTag,
					Strategy:       hopt.DirectDnsDomainStrategy,
					RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: false,
				},
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					DomainSuffix: []string{"." + hopt.Region},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{

				RuleSet: []string{
					"geosite-" + hopt.Region,
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSMultiDirectTag,
					Strategy:       hopt.DirectDnsDomainStrategy,
					RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: false,
				},
			},
		})

		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-" + hopt.Region,
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geoip-" + hopt.Region + ".srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-" + hopt.Region,
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-" + hopt.Region + ".srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geoip-" + hopt.Region,
						"geosite-" + hopt.Region,
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	if hopt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolQUIC},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
	}
	// Game/process bypass rules. They are appended AFTER every built-in rule
	// and BEFORE the Final catch-all below, so the catch-all cannot send
	// latency-sensitive game traffic into the proxy first.
	routeRules = append(routeRules, directBypassRules(hopt)...)
	options.Route = &option.RouteOptions{
		Rules:               routeRules,
		Final:               OutboundMainDetour,
		AutoDetectInterface: (!C.IsAndroid && !C.IsIos) && (hopt.EnableTun || hopt.EnableTunService),
		DefaultDomainResolver: &option.DomainResolveOptions{
			Server:   DNSMultiDirectTag,
			Strategy: hopt.DirectDnsDomainStrategy,
		},
		// OverrideAndroidVPN: hopt.EnableTun && C.IsAndroid,
		RuleSet:     rulesets,
		FindProcess: false,
		// GeoIP: &option.GeoIPOptions{
		// 	Path: opt.GeoIPPath,
		// },
		// Geosite: &option.GeositeOptions{
		// 	Path: opt.GeoSitePath,
		// },
	}
	// if opt.EnableDNSRouting {
	if hopt.EnableFakeDNS {
		// inbounds := []string{InboundTUNTag}
		// for _, inp := range options.Inbounds {
		// 	if strings.Contains(inp.Tag, InboundDirectTag) || strings.Contains(inp.Tag, InboundRedirect) || strings.Contains(inp.Tag, InboundTProxy) {
		// 		inbounds = append(inbounds, inp.Tag)
		// 	}
		// }
		dnsRules = append(
			dnsRules,
			option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					// Inbound: inbounds,
					QueryType: badoption.Listable[option.DNSQueryType]{
						option.DNSQueryType(mDNS.StringToType["A"]),
						option.DNSQueryType(mDNS.StringToType["AAAA"]),
					},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server:         DNSFakeTag,
						Strategy:       hopt.RemoteDnsDomainStrategy,
						RewriteTTL:     &DEFAULT_DNS_TTL,
						DisableCache:   true,
						BypassIfFailed: false,
					},
				},
			})

	}

	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSMultiRemoteTag,
				Strategy:       hopt.RemoteDnsDomainStrategy,
				RewriteTTL:     &DEFAULT_DNS_TTL,
				BypassIfFailed: false,
			},
		},
	},
	)
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSRemoteTagFallback,
	// 			Strategy:       hopt.RemoteDnsDomainStrategy,
	// 			RewriteTTL:     &DEFAULT_DNS_TTL,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	// dnsRules = append(dnsRules, option.DefaultDNSRule{

	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSTricksDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server: DNSLocalTag,
	// 			// BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	for _, dnsRule := range dnsRules {
		if dnsRule.IsValid() {
			options.DNS.Rules = append(
				options.DNS.Rules,
				option.DNSRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: dnsRule,
				},
			)
		}
	}
	// }
	return nil
}

// directBypassRules builds the "don't tunnel" rules requested by the app:
//
//   - DirectGamePorts: the classic game-server port set. Ports follow Valve's
//     documented Steam requirements (help.steampowered.com, "Required Ports
//     for Steam"): UDP 27000-27100 game server traffic, UDP 4380 P2P/
//     matchmaking, TCP 27015 Source dedicated server query/RCON. sing-box
//     port ranges use the colon format ("27000:27100").
//   - DirectProcessNames: desktop-only process_name rules (sing-box resolves
//     process owners when a rule needs them; the router enables process
//     lookup automatically for such rules).
//
// All rules route to the plain direct outbound. The historical "bypass
// §hide§" outbound is NOT instantiated by this builder, so referencing it
// would fail sing-box validation.
func directBypassRules(hopt *HiddifyOptions) []option.Rule {
	rules := []option.Rule{}
	if hopt.DirectGamePorts {
		rules = append(rules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Network:   []string{"udp"},
						PortRange: []string{"27000:27100"},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Network: []string{"udp"},
						Port:    []uint16{4380},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						Network: []string{"tcp"},
						Port:    []uint16{27015},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}
	if len(hopt.DirectProcessNames) > 0 {
		rules = append(rules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					ProcessName: hopt.DirectProcessNames,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	return rules
}

func patchHiddifyWarpFromConfig(out *option.Outbound, opt HiddifyOptions) *option.Outbound {
	if out.Type == C.TypePsiphon {
		return out
	}
	if opt.Warp.EnableWarp && opt.Warp.Mode == "proxy_over_warp" {
		if opts, ok := out.Options.(option.DialerOptionsWrapper); ok {
			dialer := opts.TakeDialerOptions()
			dialer.Detour = WARPConfigTag
			opts.ReplaceDialerOptions(dialer)
		}
	}
	return out
}

var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateRandomString(length int) string {
	// Determine the number of bytes needed
	bytesNeeded := (length*6 + 7) / 8

	// Generate random bytes
	randomBytes := make([]byte, bytesNeeded)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "hiddify"
	}

	// Encode random bytes to base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim padding characters and return the string
	return randomString[:length]
}
