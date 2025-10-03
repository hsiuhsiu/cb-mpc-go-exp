package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func main() {
	log.Printf("cb-mpc-go version: %s", cbmpc.WrapperVersion())
	log.Printf("cb-mpc upstream: %s (%s)", cbmpc.UpstreamVersion(), cbmpc.UpstreamDir)

	cfg := cbmpc.Config{}
	lib, err := cbmpc.Open(cfg)
	if err != nil {
		if errors.Is(err, cbmpc.ErrCGONotEnabled) || errors.Is(err, cbmpc.ErrNotBuilt) {
			fmt.Printf("library unavailable: %v\n", err)
			return
		}
		log.Fatalf("unexpected failure opening library: %v", err)
	}
	defer func() {
		if cerr := lib.Close(); cerr != nil {
			log.Printf("close error: %v", cerr)
		}
	}()

	fmt.Println("library opened successfully (placeholder)")
}
