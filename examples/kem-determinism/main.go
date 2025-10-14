// Example demonstrating determinism in RSA-OAEP KEM for PVE.
//
// This example shows that the same (public_key, rho) produces
// identical ciphertexts (byte-for-byte), which is required for
// Publicly Verifiable Encryption (PVE).
//
// Build and run:
//
//	go run examples/kem-determinism/main.go
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
)

func main() {
	fmt.Println("=== KEM Determinism Example ===")
	fmt.Println()

	// Create a KEM
	fmt.Println("Step 1: Creating RSA KEM (2048-bit)...")
	kem, err := rsa.New(2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("✓ KEM created")
	fmt.Println()

	// Generate key pair
	fmt.Println("Step 2: Generating key pair...")
	_, ek, err := kem.Generate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("✓ Key pair generated (public key: %d bytes)\n", len(ek))
	fmt.Println()

	// Fixed rho (seed)
	var rho [32]byte
	copy(rho[:], []byte("deterministic-seed-1234567890123"))
	fmt.Printf("Step 3: Using fixed seed (rho): %q\n", string(rho[:]))
	fmt.Println()

	// Encrypt twice with same (ek, rho)
	fmt.Println("Step 4: Encrypting twice with same (ek, rho)...")
	ct1, ss1, err := kem.Encapsulate(ek, rho)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  First encryption:  ct=%d bytes, ss=%d bytes\n", len(ct1), len(ss1))

	ct2, ss2, err := kem.Encapsulate(ek, rho)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  Second encryption: ct=%d bytes, ss=%d bytes\n", len(ct2), len(ss2))
	fmt.Println()

	// Verify determinism
	fmt.Println("Step 5: Verifying determinism...")
	if bytes.Equal(ct1, ct2) {
		fmt.Println("✓ SUCCESS: Ciphertexts are IDENTICAL (byte-for-byte)")
		fmt.Println("  This is the deterministic property required for PVE.")
	} else {
		fmt.Println("✗ FAIL: Ciphertexts differ!")
		log.Fatal("Determinism verification failed!")
	}

	if bytes.Equal(ss1, ss2) {
		fmt.Println("✓ SUCCESS: Shared secrets are identical")
	} else {
		fmt.Println("✗ FAIL: Shared secrets differ!")
		log.Fatal("Determinism verification failed!")
	}
	fmt.Println()

	fmt.Println("=== Determinism Example Complete ===")
	fmt.Println()
	fmt.Println("Summary:")
	fmt.Println("  ✓ Same (ek, rho) produces identical ciphertext")
	fmt.Println("  ✓ This deterministic property is essential for PVE")
	fmt.Println("  ⚠️  NEVER use this for general-purpose encryption!")
}
