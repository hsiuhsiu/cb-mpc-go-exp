// Example demonstrating a complete PVE round-trip with RSA-OAEP KEM.
//
// This example shows:
//   - PVE encryption with deterministic RSA KEM
//   - Public verification (proof of correct encryption)
//   - PVE decryption
//
// Build and run:
//
//	go run examples/kem-pve-roundtrip/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("=== PVE Round-Trip Example ===")
	fmt.Println()

	// 1. Create KEM
	fmt.Println("Step 1: Creating RSA KEM (2048-bit)...")
	kem, err := rsa.New(2048)
	if err != nil {
		log.Fatalf("Failed to create KEM: %v", err)
	}
	fmt.Println("✓ KEM created")
	fmt.Println()

	// 2. Generate key pair
	fmt.Println("Step 2: Generating key pair...")
	skRef, ek, err := kem.Generate()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("✓ Key pair generated (public key: %d bytes, private key ref: %d bytes)\n", len(ek), len(skRef))
	fmt.Println()

	// 3. Create private key handle
	fmt.Println("Step 3: Creating private key handle...")
	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		log.Fatalf("Failed to create private key handle: %v", err)
	}
	defer func() {
		if err := kem.FreePrivateKeyHandle(dkHandle); err != nil {
			log.Printf("Warning: Failed to free handle: %v", err)
		}
	}()
	fmt.Println("✓ Private key handle created")
	fmt.Println()

	// 4. Create PVE instance
	fmt.Println("Step 4: Creating PVE instance...")
	pveInstance, err := pve.New(kem)
	if err != nil {
		log.Fatalf("Failed to create PVE instance: %v", err)
	}
	fmt.Println("✓ PVE instance created")
	fmt.Println()

	// 5. Encrypt a scalar value
	secretValue := "123456789012345678901234567890"
	label := []byte("my-label")
	fmt.Printf("Step 5: Encrypting secret value...\n")
	fmt.Printf("  Secret: %s\n", secretValue)
	fmt.Printf("  Label:  %s\n", label)

	x, err := curve.NewScalarFromString(secretValue)
	if err != nil {
		log.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: cbmpc.CurveP256,
		X:     x,
	})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("✓ Encryption successful (ciphertext: %d bytes)\n", len(encryptResult.Ciphertext))
	fmt.Println()

	// 6. Extract Q for verification
	fmt.Println("Step 6: Extracting public commitment Q...")
	Q, err := encryptResult.Ciphertext.Q()
	if err != nil {
		log.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()
	QBytes, _ := Q.Bytes()
	fmt.Printf("✓ Q extracted (%d bytes, curve: %s)\n", len(QBytes), Q.Curve().String())
	fmt.Println()

	// 7. Verify ciphertext (publicly verifiable proof)
	fmt.Println("Step 7: Verifying ciphertext (publicly verifiable proof)...")
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Q:          Q,
		Label:      label,
	})
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Println("✓ Ciphertext verified - proof of correct encryption!")
	fmt.Println()

	// 8. Decrypt
	fmt.Println("Step 8: Decrypting ciphertext...")
	decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	defer decryptResult.X.Free()

	decryptedValue := decryptResult.X.String()
	fmt.Printf("✓ Decryption successful\n")
	fmt.Printf("  Original:  %s\n", secretValue)
	fmt.Printf("  Decrypted: %s\n", decryptedValue)

	if secretValue == decryptedValue {
		fmt.Println("✓ Values match!")
	} else {
		log.Fatalf("✗ ERROR: Decrypted value doesn't match original!")
	}
	fmt.Println()

	// 9. Cleanup
	fmt.Println("Step 9: Cleanup...")
	cbmpc.ZeroizeBytes(skRef)
	fmt.Println("✓ Sensitive data zeroized")
	fmt.Println()

	fmt.Println("=== PVE Round-Trip Complete ===")
	fmt.Println()
	fmt.Println("Summary:")
	fmt.Println("  ✓ Successfully encrypted data with PVE")
	fmt.Println("  ✓ Successfully verified ciphertext (proof of correct encryption)")
	fmt.Println("  ✓ Successfully decrypted ciphertext")
	fmt.Println("  ✓ Original and decrypted values match")
	fmt.Println("  ✓ Deterministic RSA KEM (2048-bit) used throughout")
}
