package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/coinbase/cb-mpc-go/examples"
	"github.com/coinbase/cb-mpc-go/pkg/mpc"
)

func main() {
	var (
		party      = flag.Int("party", 0, "Party index (0 or 1)")
		serverAddr = flag.String("server", "localhost:8443", "Server address for party 0")
		clientAddr = flag.String("client", "localhost:8444", "Client address for party 1")
		certDir    = flag.String("certs", "./certs", "Certificate directory")
		message    = flag.String("message", "Hello, MPC ECDSA with mTLS!", "Message to sign")
	)
	flag.Parse()

	if *party < 0 || *party > 1 {
		log.Fatal("Party must be 0 or 1")
	}

	fmt.Printf("🔐 Starting ECDSA 2PC with mTLS - Party %d\n", *party)

	// Load TLS configuration
	var caCert, clientCert, clientKey string
	if *party == 0 {
		// Party 0 uses server certificates and acts as server
		caCert = fmt.Sprintf("%s/ca-cert.pem", *certDir)
		clientCert = fmt.Sprintf("%s/server-cert.pem", *certDir)
		clientKey = fmt.Sprintf("%s/server-key.pem", *certDir)
	} else {
		// Party 1 uses client certificates
		caCert = fmt.Sprintf("%s/ca-cert.pem", *certDir)
		clientCert = fmt.Sprintf("%s/client1-cert.pem", *certDir)
		clientKey = fmt.Sprintf("%s/client1-key.pem", *certDir)
	}

	tlsConfig, err := examples.LoadTLSConfig(caCert, clientCert, clientKey, *party == 0)
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	// Set up addresses for mTLS session
	var serverAddress string
	var clientAddrs []string

	if *party == 0 {
		// Party 0 is the server
		serverAddress = *serverAddr
		clientAddrs = []string{"", *clientAddr} // Empty string for self, client address for party 1
	} else {
		// Party 1 is a client
		serverAddress = ""
		clientAddrs = []string{*serverAddr, ""} // Server address for party 0, empty for self
	}

	// Create mTLS session
	session, err := examples.NewMTLSSession(*party, 2, serverAddress, clientAddrs, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to create mTLS session: %v", err)
	}
	defer session.Close()

	// Give some time for connections to establish
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Phase 1: Key Generation
	fmt.Printf("📋 Phase 1: Key Generation\n")
	ecdsa := mpc.NewECDSA2PC(mpc.SECP256R1)

	keyShare, err := ecdsa.KeyGen(ctx, session)
	if err != nil {
		log.Fatalf("Key generation failed: %v", err)
	}
	defer keyShare.Close()

	// Get public key
	pubKey, err := keyShare.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get public key: %v", err)
	}

	role := keyShare.(*mpc.ECDSA2PKey).GetRole()
	fmt.Printf("✅ Key generation completed! Party %d has role %d\n", *party, role)
	fmt.Printf("📋 Public key length: %d bytes\n", len(pubKey))

	// Phase 2: Signing
	fmt.Printf("\n📋 Phase 2: Message Signing\n")
	fmt.Printf("📋 Message: %s\n", *message)

	// Hash the message
	hasher := sha256.New()
	hasher.Write([]byte(*message))
	messageHash := hasher.Sum(nil)

	signature, err := keyShare.(*mpc.ECDSA2PKey).Sign(ctx, session, messageHash)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	if len(signature) > 0 {
		fmt.Printf("✅ Signature generated! Length: %d bytes\n", len(signature))

		// Phase 3: Signature Verification
		fmt.Printf("\n📋 Phase 3: Signature Verification\n")
		err = keyShare.(*mpc.ECDSA2PKey).VerifySignature([]byte(*message), signature)
		if err != nil {
			log.Fatalf("Signature verification failed: %v", err)
		}
		fmt.Printf("✅ Signature verification successful!\n")

		// Test with wrong message
		err = keyShare.(*mpc.ECDSA2PKey).VerifySignature([]byte("Wrong message"), signature)
		if err == nil {
			log.Fatal("❌ Signature verification should have failed for wrong message")
		}
		fmt.Printf("✅ Signature correctly rejected for wrong message\n")
	} else {
		fmt.Printf("📋 Party %d: No signature output (expected for party 1 in 2PC ECDSA)\n", *party)
	}

	// Phase 4: Key Refresh (optional demonstration)
	fmt.Printf("\n📋 Phase 4: Key Refresh\n")
	refreshedKey, err := keyShare.(*mpc.ECDSA2PKey).Refresh(ctx, session)
	if err != nil {
		log.Fatalf("Key refresh failed: %v", err)
	}
	defer refreshedKey.Close()

	// Verify public key is the same after refresh
	refreshedPubKey, err := refreshedKey.PublicKey()
	if err != nil {
		log.Fatalf("Failed to get refreshed public key: %v", err)
	}

	if len(pubKey) != len(refreshedPubKey) {
		log.Fatal("❌ Public key length changed after refresh")
	}

	equal := true
	for i := range pubKey {
		if pubKey[i] != refreshedPubKey[i] {
			equal = false
			break
		}
	}

	if !equal {
		log.Fatal("❌ Public key changed after refresh")
	}

	fmt.Printf("✅ Key refresh completed! Public key preserved\n")

	// Test signing with refreshed key
	refreshedSignature, err := refreshedKey.(*mpc.ECDSA2PKey).Sign(ctx, session, messageHash)
	if err != nil {
		log.Fatalf("Signing with refreshed key failed: %v", err)
	}

	if len(refreshedSignature) > 0 {
		err = refreshedKey.(*mpc.ECDSA2PKey).VerifySignature([]byte(*message), refreshedSignature)
		if err != nil {
			log.Fatalf("Refreshed key signature verification failed: %v", err)
		}
		fmt.Printf("✅ Refreshed key signature verification successful!\n")
	}

	fmt.Printf("\n🎉 ECDSA 2PC with mTLS demo completed successfully for Party %d!\n", *party)
	fmt.Printf("🔒 Secure multi-party computation demonstrated with mutual TLS authentication\n")
}