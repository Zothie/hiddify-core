// Command genconf renders a Hiddify subscription into a sing-box config using
// the real production builder, so the emitted auto group can be inspected.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hiddify/hiddify-core/v2/config"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: genconf <sub-file> <out.json>")
		os.Exit(2)
	}
	opts := config.DefaultHiddifyOptions()
	// Every listening port is moved well clear of 12334-12337, which the
	// user's live Hiddify owns; colliding there would cut their internet.
	opts.MixedPort = 11897
	opts.RedirectPort = 11899
	opts.DirectPort = 11900
	opts.TProxyPort = 11901
	opts.EnableTun = false
	opts.SetSystemProxy = false
	opts.EnableTunService = false
	// The monitoring block (which carries the throughput probe) is only
	// emitted when the clash API is on.
	opts.EnableClashApi = true
	opts.ClashApiPort = 11898

	ctx := context.Background()
	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	// The subscription is a v2ray-style URI list, not sing-box JSON, so it has
	// to go through the parser before the group builder can consume it.
	parsed, err := config.ParseConfig(ctx, &config.ReadOptions{Content: string(content)}, false, opts, false)
	if err != nil {
		panic(err)
	}
	out, err := config.BuildConfigJson(ctx, opts, &config.ReadOptions{Options: parsed})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], out, 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote", os.Args[2])
}
