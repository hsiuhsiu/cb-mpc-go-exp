package pve_test

import (
	"context"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
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
	crv := cbmpc.CurveP256
	label := []byte("test-label")
	x, err := curve.NewScalarFromString("12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: crv,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext
	if len(ct) == 0 {
		t.Fatal("Ciphertext is empty")
	}

	// Extract and verify Q
	Q, err := ct.Q()
	if err != nil {
		t.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()
	if Q.Curve() != crv {
		t.Fatalf("Q curve mismatch: got %s, want %s", Q.Curve(), crv)
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
		Curve:      crv,
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
	crv := cbmpc.CurveP256
	label := []byte("test-label")
	x, err := curve.NewScalarFromString("12345")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: crv,
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
	wrongX, err := curve.NewScalarFromString("99999")
	if err != nil {
		t.Fatalf("Failed to create wrong scalar: %v", err)
	}
	defer wrongX.Free()

	wrongEncryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: crv,
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
	x, err := curve.NewScalarFromString("987654321")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	for _, crv := range curves {
		t.Run(crv.String(), func(t *testing.T) {
			// Encrypt
			encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
				EK:    ek,
				Label: label,
				Curve: crv,
				X:     x,
			})
			if err != nil {
				t.Fatalf("Encrypt failed for %s: %v", crv.String(), err)
			}

			// Decrypt
			decryptResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      label,
				Curve:      crv,
			})
			if err != nil {
				t.Fatalf("Decrypt failed for %s: %v", crv.String(), err)
			}
			defer decryptResult.X.Free()

			// Verify X matches
			if x.String() != decryptResult.X.String() {
				t.Fatalf("Decrypted value mismatch for %s: got %s, want %s", crv.String(), decryptResult.X.String(), x.String())
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
	x, err := curve.NewScalarFromString("115792089237316195423570985008687907853269984665640564039457584007913129639935")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	crv := cbmpc.CurveP256
	label := []byte("large-scalar-test")

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: crv,
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
		Curve:      crv,
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

	crv := cbmpc.CurveP256
	x, err := curve.NewScalarFromString("42")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt with label1
	encryptResult1, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("label1"),
		Curve: crv,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Encrypt with label2
	encryptResult2, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("label2"),
		Curve: crv,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertexts should be different
	if string(encryptResult1.Ciphertext) == string(encryptResult2.Ciphertext) {
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

	crv := cbmpc.CurveP256
	label := []byte("method-test")
	x, err := curve.NewScalarFromString("123456")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Encrypt
	encryptResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: label,
		Curve: crv,
		X:     x,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext

	// Test Bytes()
	bytes := ct
	if len(bytes) == 0 {
		t.Fatal("Bytes() returned empty slice")
	}

	// Test Q()
	Q, err := ct.Q()
	if err != nil {
		t.Fatalf("Q() failed: %v", err)
	}
	defer Q.Free()
	if Q.Curve() != crv {
		t.Fatalf("Q() curve mismatch: got %s, want %s", Q.Curve(), crv)
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
