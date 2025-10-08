package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/coinbase/cb-mpc-go/examples/common"
	"github.com/coinbase/cb-mpc-go/examples/tlsnet"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func main() {
	var (
		configPath = flag.String("config", "examples/agree-random-2p/cluster.json", "path to cluster configuration")
		selfName   = flag.String("self", "", "name of this party in the cluster configuration")
		bitlen     = flag.Int("bitlen", 256, "bit length for agree-random")
	)
	flag.Parse()

	if *selfName == "" {
		log.Fatal("--self flag is required")
	}

	cfg, err := common.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if len(cfg.Parties) != 2 {
		log.Fatalf("2-party demo requires exactly two parties (got %d)", len(cfg.Parties))
	}

	names := make([]string, 2)
	addresses := make([]string, 2)
	selfIndex := -1
	for i, p := range cfg.Parties {
		names[i] = p.Name
		addresses[i] = p.Address
		if p.Name == *selfName {
			selfIndex = i
		}
	}
	if selfIndex < 0 {
		log.Fatalf("self name %q not present in config", *selfName)
	}

	cert, err := common.LoadKeyPair(cfg.Parties[selfIndex].Cert, cfg.Parties[selfIndex].Key)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}

	caPool, err := common.LoadCertPool(cfg.CACert)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	transport, err := tlsnet.New(tlsnet.Config{
		Self:        selfIndex,
		Names:       names,
		Addresses:   addresses,
		Certificate: cert,
		RootCAs:     caPool,
	})
	if err != nil {
		log.Fatalf("start tls transport: %v", err)
	}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if selfIndex < 0 || selfIndex >= len(names) {
		log.Fatalf("self index %d out of range", selfIndex)
	}
	if selfIndex > math.MaxUint8 {
		log.Fatalf("self index %d exceeds role capacity", selfIndex)
	}
	job, err := cbmpc.NewJob2P(transport, cbmpc.Role(selfIndex), [2]string{names[0], names[1]})
	if err != nil {
		log.Fatalf("NewJob2P: %v", err)
	}
	defer job.Close()

	out, err := cbmpc.AgreeRandom(ctx, job, *bitlen)
	if err != nil {
		log.Fatalf("AgreeRandom: %v", err)
	}
	fmt.Printf("Party %s produced %d-bit random: %x\n", names[selfIndex], *bitlen, out)
}
