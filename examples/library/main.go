package main

import (
	"context"
	"fmt"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func main() {
	fmt.Printf("cb-mpc-go version: %s\n", cbmpc.WrapperVersion())
	fmt.Printf("cb-mpc upstream: %s\n", cbmpc.UpstreamVersion())

	cfg := cbmpc.Config{}
	lib, err := cbmpc.Open(cfg)
	if err != nil {
		fmt.Printf("library unavailable (expected pre-binding stub): %v\n", err)
		return
	}
	defer lib.Close()

	ctx := context.Background()
	if err := runSigningDemo(ctx, lib); err != nil {
		fmt.Printf("TODO: implement signing demo (error: %v)\n", err)
	}
}

func runSigningDemo(ctx context.Context, lib *cbmpc.Library) error {
	_ = ctx
	_ = lib
	// TODO: create KeySet and Signer once bindings are available.
	return nil
}
