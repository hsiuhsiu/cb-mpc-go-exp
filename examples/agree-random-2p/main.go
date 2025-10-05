package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coinbase/cb-mpc-go/examples/tlsnet"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

type partyConfig struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

type clusterConfig struct {
	CACert  string        `json:"ca_cert"`
	Parties []partyConfig `json:"parties"`
}

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

	cfg, err := loadConfig(*configPath)
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

	cert, err := tls.LoadX509KeyPair(cfg.Parties[selfIndex].Cert, cfg.Parties[selfIndex].Key)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}

	caPool, err := loadCertPool(cfg.CACert)
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

func loadConfig(path string) (*clusterConfig, error) {
	absPath, err := securePath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(absPath) // #nosec G304 -- absPath validated by securePath
	if err != nil {
		return nil, err
	}
	var cfg clusterConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Parties) < 2 {
		return nil, errors.New("cluster must contain at least two parties")
	}
	return &cfg, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	absPath, err := securePath(path)
	if err != nil {
		return nil, err
	}
	pemData, err := os.ReadFile(absPath) // #nosec G304 -- absPath validated by securePath
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return pool, nil
}

func securePath(path string) (string, error) {
	clean := filepath.Clean(path)
	absPath, err := filepath.Abs(clean)
	if err != nil {
		return "", err
	}
	base, err := os.Getwd()
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, absPath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes working directory", path)
	}
	return absPath, nil
}
