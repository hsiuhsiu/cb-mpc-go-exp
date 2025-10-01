package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

// Config represents the JSON configuration file
type Config struct {
	Parties []struct {
		Index    int    `json:"index"`
		Address  string `json:"address"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	} `json:"parties"`
	CACertPath     string `json:"ca_cert_path"`
	BitLength      int    `json:"bit_length"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func main() {
	// Parse command-line flags
	partyIndex := flag.Int("party", -1, "Party index (0-based)")
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	if *partyIndex < 0 {
		log.Fatal("Must specify -party flag with party index (0, 1, etc.)")
	}

	fmt.Println("=== CB-MPC Production Example: Agree Random with mTLS ===")
	fmt.Printf("Party Index: %d\n", *partyIndex)
	fmt.Printf("Config File: %s\n", *configPath)
	fmt.Println()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Validate party index
	if *partyIndex >= len(config.Parties) {
		log.Fatalf("Invalid party index %d (config has %d parties)", *partyIndex, len(config.Parties))
	}

	// Find this party's configuration
	var myPartyConfig *struct {
		Index    int    `json:"index"`
		Address  string `json:"address"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	}
	for i := range config.Parties {
		if config.Parties[i].Index == *partyIndex {
			myPartyConfig = &config.Parties[i]
			break
		}
	}
	if myPartyConfig == nil {
		log.Fatalf("Party %d not found in config", *partyIndex)
	}

	fmt.Printf("My address: %s\n", myPartyConfig.Address)
	fmt.Printf("Total parties: %d\n", len(config.Parties))
	fmt.Println()

	// Load CA certificate
	caCert, err := os.ReadFile(config.CACertPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	// Load this party's certificate and key
	cert, err := tls.LoadX509KeyPair(myPartyConfig.CertPath, myPartyConfig.KeyPath)
	if err != nil {
		log.Fatalf("Failed to load party certificate: %v", err)
	}

	// Build party configurations for mTLS
	parties := make(map[int]mpc.PartyConfig)
	nameToIndex := make(map[string]int)

	for _, p := range config.Parties {
		// Load each party's certificate for verification
		certPEM, err := os.ReadFile(p.CertPath)
		if err != nil {
			log.Fatalf("Failed to read certificate for party %d: %v", p.Index, err)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Fatalf("Failed to decode PEM for party %d", p.Index)
		}

		partyCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate for party %d: %v", p.Index, err)
		}

		// Generate party name from certificate
		partyName, err := mpc.PartyNameFromCertificate(partyCert)
		if err != nil {
			log.Fatalf("Failed to get party name for party %d: %v", p.Index, err)
		}

		parties[p.Index] = mpc.PartyConfig{
			Address: p.Address,
			Cert:    partyCert,
		}
		nameToIndex[partyName] = p.Index
	}

	fmt.Println("Setting up mTLS connections...")
	fmt.Println()

	// Create mTLS session
	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	session, err := mpc.NewMTLSSession(mpc.MTLSConfig{
		MyIndex:     *partyIndex,
		Parties:     parties,
		CertPool:    certPool,
		TLSCert:     cert,
		NameToIndex: nameToIndex,
		Timeout:     timeout,
	})
	if err != nil {
		log.Fatalf("Failed to create mTLS session: %v", err)
	}
	defer session.Close()

	fmt.Println("✅ All mTLS connections established")
	fmt.Println()

	// Run the protocol
	bitLen := config.BitLength
	if bitLen == 0 {
		bitLen = 256
	}

	fmt.Printf("Running AgreeRandom protocol (%d bits)...\n", bitLen)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var result []byte
	if len(config.Parties) == 2 {
		result, err = mpc.AgreeRandom2PC(ctx, session, bitLen)
	} else {
		result, err = mpc.AgreeRandomMPC(ctx, session, bitLen)
	}

	if err != nil {
		log.Fatalf("Protocol failed: %v", err)
	}

	fmt.Println()
	fmt.Println("=== Protocol completed successfully ===")
	fmt.Printf("Party %d result: %s\n", *partyIndex, hex.EncodeToString(result))
	fmt.Println()
	fmt.Println("✅ All parties should have identical values above")
	fmt.Println()
	fmt.Println("🎉 Production-ready mTLS example completed!")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config JSON: %w", err)
	}

	return &config, nil
}
