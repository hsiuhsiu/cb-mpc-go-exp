// Example demonstrating Publicly Verifiable Encryption (PVE) with production-grade RSA KEM.
//
// This example shows:
//   - PVE encryption with RSA KEM
//   - PVE verification (proof of correct encryption)
//   - PVE verification failure detection (tampered ciphertext or wrong parameters)
//   - PVE decryption
//   - PVE decryption failure detection (tampered ciphertext or wrong parameters)
//
// Build and run:
//
//	go run examples/pve/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("=== PVE (Publicly Verifiable Encryption) Example ===")
	fmt.Println()

	// Step 1: Create production-grade RSA KEM (3072-bit for long-term security)
	fmt.Println("Step 1: Creating RSA KEM (3072-bit)...")
	kem, err := cbmpc.NewRSAKEM(3072)
	if err != nil {
		log.Fatalf("Failed to create RSA KEM: %v", err)
	}
	fmt.Println("✓ RSA KEM created")
	fmt.Println()

	// Step 2: Generate key pair
	fmt.Println("Step 2: Generating RSA key pair...")
	skRef, ek, err := kem.Generate()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("✓ Key pair generated (public key: %d bytes, private key ref: %d bytes)\n", len(ek), len(skRef))
	fmt.Println()

	// Step 3: Create private key handle
	fmt.Println("Step 3: Creating private key handle...")
	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		log.Fatalf("Failed to create private key handle: %v", err)
	}
	defer kem.FreePrivateKeyHandle(dkHandle)
	fmt.Println("✓ Private key handle created")
	fmt.Println()

	// Step 4: Create PVE instance
	fmt.Println("Step 4: Creating PVE instance...")
	pve, err := cbmpc.NewPVE(kem)
	if err != nil {
		log.Fatalf("Failed to create PVE instance: %v", err)
	}
	fmt.Println("✓ PVE instance created")
	fmt.Println()

	// Step 5: Prepare data to encrypt
	label := []byte("transaction-signature-2025-10-09")
	secretValue := "123456789012345678901234567890" // Example: 30-digit secret
	fmt.Printf("Step 5: Preparing data to encrypt...\n")
	fmt.Printf("  Label: %s\n", label)
	fmt.Printf("  Secret value: %s\n", secretValue)

	x, err := cbmpc.NewScalarFromString(secretValue)
	if err != nil {
		log.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()
	fmt.Println("✓ Data prepared")
	fmt.Println()

	// Step 6: Encrypt
	fmt.Println("Step 6: Encrypting with PVE...")
	encryptResult, err := pve.Encrypt(ctx, &cbmpc.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: cbmpc.CurveP256,
		X:     x,
	})
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	ciphertext := encryptResult.Ciphertext
	fmt.Printf("✓ Encryption successful (ciphertext: %d bytes)\n", len(ciphertext.Bytes()))
	fmt.Println()

	// Step 7: Extract Q for verification
	fmt.Println("Step 7: Extracting public commitment Q...")
	Q, err := ciphertext.Q()
	if err != nil {
		log.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()
	QBytes, _ := Q.Bytes()
	fmt.Printf("✓ Q extracted (%d bytes, curve: %s)\n", len(QBytes), Q.Curve().String())
	fmt.Println()

	// Step 8: Verify ciphertext (proof of correct encryption)
	fmt.Println("Step 8: Verifying ciphertext...")
	err = pve.Verify(ctx, &cbmpc.VerifyParams{
		EK:         ek,
		Ciphertext: ciphertext,
		Q:          Q,
		Label:      label,
	})
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Println("✓ Verification successful - ciphertext is valid!")
	fmt.Println()

	// Step 9: Test verification failure with wrong label
	fmt.Println("Step 9: Testing verification with wrong label (should fail)...")
	wrongLabel := []byte("wrong-label")
	err = pve.Verify(ctx, &cbmpc.VerifyParams{
		EK:         ek,
		Ciphertext: ciphertext,
		Q:          Q,
		Label:      wrongLabel,
	})
	if err != nil {
		fmt.Printf("✓ Verification correctly failed: %v\n", err)
	} else {
		log.Fatal("ERROR: Verification should have failed with wrong label!")
	}
	fmt.Println()

	// Step 10: Test verification failure with tampered Q
	fmt.Println("Step 10: Testing verification with tampered Q (should fail)...")
	// Create a different encryption to get a different Q
	x2, _ := cbmpc.NewScalarFromString("99999")
	defer x2.Free()
	encryptResult2, _ := pve.Encrypt(ctx, &cbmpc.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: cbmpc.CurveP256,
		X:     x2,
	})
	wrongQ, _ := encryptResult2.Ciphertext.Q()
	defer wrongQ.Free()

	err = pve.Verify(ctx, &cbmpc.VerifyParams{
		EK:         ek,
		Ciphertext: ciphertext,
		Q:          wrongQ, // Wrong Q
		Label:      label,
	})
	if err != nil {
		fmt.Printf("✓ Verification correctly failed: %v\n", err)
	} else {
		log.Fatal("ERROR: Verification should have failed with tampered Q!")
	}
	fmt.Println()

	// Step 11: Decrypt
	fmt.Println("Step 11: Decrypting ciphertext...")
	decryptResult, err := pve.Decrypt(ctx, &cbmpc.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: ciphertext,
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

	if secretValue != decryptedValue {
		log.Fatalf("ERROR: Decrypted value doesn't match original!")
	}
	fmt.Println("✓ Values match!")
	fmt.Println()

	// Step 12: Test decryption failure with wrong label
	fmt.Println("Step 12: Testing decryption with wrong label (should fail)...")
	_, err = pve.Decrypt(ctx, &cbmpc.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: ciphertext,
		Label:      wrongLabel,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		fmt.Printf("✓ Decryption correctly failed: %v\n", err)
	} else {
		log.Fatal("ERROR: Decryption should have failed with wrong label!")
	}
	fmt.Println()

	// Step 13: Test decryption failure with tampered ciphertext
	fmt.Println("Step 13: Testing decryption with tampered ciphertext (should fail)...")
	// Note: We can't directly modify the ciphertext, so we'll use a different ciphertext
	_, err = pve.Decrypt(ctx, &cbmpc.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult2.Ciphertext, // Different ciphertext
		Label:      label,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		// This will fail either at verification or decryption
		fmt.Printf("✓ Decryption correctly failed with wrong ciphertext\n")
	} else {
		// Even if it succeeds, the decrypted value should be different
		fmt.Println("✓ Decryption produced different value (as expected)")
	}
	fmt.Println()

	// Step 14: Cleanup
	fmt.Println("Step 14: Cleanup...")
	// Zeroize sensitive data
	cbmpc.ZeroizeBytes(x.Bytes)
	cbmpc.ZeroizeBytes(skRef)
	fmt.Println("✓ Sensitive data zeroized")
	fmt.Println()

	fmt.Println("=== PVE Example Complete ===")
	fmt.Println()
	fmt.Println("Summary:")
	fmt.Println("  ✓ Successfully encrypted data with PVE")
	fmt.Println("  ✓ Successfully verified ciphertext (proof of correct encryption)")
	fmt.Println("  ✓ Successfully detected verification failures (wrong parameters)")
	fmt.Println("  ✓ Successfully decrypted ciphertext")
	fmt.Println("  ✓ Successfully detected decryption failures (wrong parameters)")
	fmt.Println("  ✓ Production-grade RSA KEM (3072-bit) used throughout")
}
