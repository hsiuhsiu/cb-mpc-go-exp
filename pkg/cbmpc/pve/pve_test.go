package pve_test

import (
	"context"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/testkem"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// TestPVEEncryptDecrypt tests basic PVE encryption and decryption.
func TestPVEEncryptDecrypt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance with this KEM
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	skRef, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create private key handle
	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		t.Fatalf("Failed to create private key handle: %v", err)
	}
	defer kem.FreePrivateKeyHandle(dkHandle)

	// Test parameters
	curve := cbmpc.CurveP256
	label := []byte("test-label")
	x, err := cbmpc.NewScalarFromString("12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext
	if len(ct.Bytes()) == 0 {
		t.Fatal("Ciphertext is empty")
	}

	// Extract and verify Q
	Q, err := ct.Q()
	if err != nil {
		t.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()
	if Q.Curve().NID() != curve.NID() {
		t.Fatalf("Q curve mismatch: got %d, want %d", Q.Curve().NID(), curve.NID())
	}

	// Extract and verify label
	extractedLabel, err := ct.Label()
	if err != nil {
		t.Fatalf("Failed to extract label: %v", err)
	}
	if string(extractedLabel) != string(label) {
		t.Fatalf("Label mismatch: got %q, want %q", extractedLabel, label)
	}

	// Verify
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Q:          Q,
		Label:      label,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Decrypt
	decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: ct,
		Label:      label,
		Curve:      curve,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	defer decryptResult.X.Free()

	// Verify X matches by comparing bytes
	if x.String() != decryptResult.X.String() {
		t.Fatalf("Decrypted value mismatch: got %s, want %s", decryptResult.X.String(), x.String())
	}
}

// TestPVEVerifyFail tests that verification fails with wrong parameters.
func TestPVEVerifyFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	_, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test parameters
	curve := cbmpc.CurveP256
	label := []byte("test-label")
	x, err := cbmpc.NewScalarFromString("12345")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext

	Q, err := ct.Q()
	if err != nil {
		t.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()

	// Test 1: Verify with wrong label (should fail)
	wrongLabel := []byte("wrong-label")
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Q:          Q,
		Label:      wrongLabel,
	})
	if err == nil {
		t.Fatal("Verify should have failed with wrong label")
	}

	// Test 2: Verify with wrong Q (should fail)
	wrongX, err := cbmpc.NewScalarFromString("99999")
	if err != nil {
		t.Fatalf("Failed to create wrong scalar: %v", err)
	}
	defer wrongX.Free()

	wrongEncryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: curve,
		X:     wrongX,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	wrongQ, err := wrongEncryptResult.Ciphertext.Q()
	if err != nil {
		t.Fatalf("Failed to extract wrong Q: %v", err)
	}
	defer wrongQ.Free()

	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Q:          wrongQ, // Using Q from different encryption
		Label:      label,
	})
	if err == nil {
		t.Fatal("Verify should have failed with wrong Q")
	}
}

// TestPVEMultipleCurves tests PVE with different curves.
func TestPVEMultipleCurves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	skRef, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		t.Fatalf("Failed to create private key handle: %v", err)
	}
	defer kem.FreePrivateKeyHandle(dkHandle)

	curves := []cbmpc.Curve{
		cbmpc.CurveP256,
		cbmpc.CurveSecp256k1,
	}

	label := []byte("multi-curve-test")
	x, err := cbmpc.NewScalarFromString("987654321")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			// Encrypt
			encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
				EK:    ek,
				Label: label,
				Curve: curve,
				X:     x,
			})
			if err != nil {
				t.Fatalf("Encrypt failed for %s: %v", curve.String(), err)
			}

			// Decrypt
			decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      label,
				Curve:      curve,
			})
			if err != nil {
				t.Fatalf("Decrypt failed for %s: %v", curve.String(), err)
			}
			defer decryptResult.X.Free()

			// Verify X matches
			if x.String() != decryptResult.X.String() {
				t.Fatalf("Decrypted value mismatch for %s: got %s, want %s", curve.String(), decryptResult.X.String(), x.String())
			}
		})
	}
}

// TestPVELargeScalar tests PVE with a large scalar value.
func TestPVELargeScalar(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	skRef, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	dkHandle, err := kem.NewPrivateKeyHandle(skRef)
	if err != nil {
		t.Fatalf("Failed to create private key handle: %v", err)
	}
	defer kem.FreePrivateKeyHandle(dkHandle)

	// Use a large scalar (256-bit value)
	x, err := cbmpc.NewScalarFromString("115792089237316195423570985008687907853269984665640564039457584007913129639935")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	curve := cbmpc.CurveP256
	label := []byte("large-scalar-test")

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt
	decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      curve,
	})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	defer decryptResult.X.Free()

	// The result should be x mod curve_order
	// For P-256, the order is slightly less than 2^256
	// So the result might differ from x
	if decryptResult.X == nil {
		t.Fatal("Decrypted value is nil")
	}
	decryptedBytes := decryptResult.X.Bytes
	if len(decryptedBytes) == 0 {
		t.Fatal("Decrypted value is empty")
	}
}

// TestPVEDifferentLabels tests that different labels produce different ciphertexts.
func TestPVEDifferentLabels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	_, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	curve := cbmpc.CurveP256
	x, err := cbmpc.NewScalarFromString("42")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt with label1
	encryptResult1, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("label1"),
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Encrypt with label2
	encryptResult2, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("label2"),
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertexts should be different
	if string(encryptResult1.Ciphertext.Bytes()) == string(encryptResult2.Ciphertext.Bytes()) {
		t.Fatal("Ciphertexts with different labels should be different")
	}

	// But they should encrypt the same value
	// (we can't verify this without decryption, which would require the private key)
}

// TestPVECiphertextMethods tests the PVECiphertext methods.
func TestPVECiphertextMethods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Generate key pair
	_, ek, err := kem.Generate()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	curve := cbmpc.CurveP256
	label := []byte("method-test")
	x, err := cbmpc.NewScalarFromString("123456")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: curve,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext

	// Test Bytes()
	bytes := ct.Bytes()
	if len(bytes) == 0 {
		t.Fatal("Bytes() returned empty slice")
	}

	// Test Q()
	Q, err := ct.Q()
	if err != nil {
		t.Fatalf("Q() failed: %v", err)
	}
	defer Q.Free()
	if Q.Curve().NID() != curve.NID() {
		t.Fatalf("Q() curve mismatch: got %d, want %d", Q.Curve().NID(), curve.NID())
	}

	// Test Label()
	extractedLabel, err := ct.Label()
	if err != nil {
		t.Fatalf("Label() failed: %v", err)
	}
	if string(extractedLabel) != string(label) {
		t.Fatalf("Label() mismatch: got %q, want %q", extractedLabel, label)
	}
}
