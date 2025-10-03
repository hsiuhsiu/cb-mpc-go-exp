package main

import (
	"fmt"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func main() {
	cfg := cbmpc.Config{
		HomeDir:           "/tmp/cbmpc",
		EnableZeroization: true,
	}

	fmt.Printf("config: %+v (TODO: wire into Library once available)\n", cfg)
}
