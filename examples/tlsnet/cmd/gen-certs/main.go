package main

import (
	"flag"
	"log"
	"strings"

	"github.com/coinbase/cb-mpc-go/examples/tlsnet"
)

func main() {
	var (
		outputDir = flag.String("output", "examples/tlsnet/certs", "directory to write certificates")
		namesFlag = flag.String("names", "p0,p1,p2", "comma-separated party names")
	)
	flag.Parse()

	names := strings.Split(*namesFlag, ",")
	if err := tlsnet.GenerateCertificates(names, *outputDir); err != nil {
		log.Fatalf("generate certificates: %v", err)
	}
}
