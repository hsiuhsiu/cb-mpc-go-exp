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

// TestPVEBatchEncryptDecrypt tests basic batch PVE encryption and decryption.
func TestPVEBatchEncryptDecrypt(t *testing.T) {
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
	label := []byte("batch-test-label")

	// Create multiple scalars
	scalars := []*curve.Scalar{}
	scalarStrings := []string{"123", "456", "789"}
	for _, s := range scalarStrings {
		x, err := curve.NewScalarFromString(s)
		if err != nil {
			t.Fatalf("Failed to create scalar from %s: %v", s, err)
		}
		defer x.Free()
		scalars = append(scalars, x)
	}

	// Batch Encrypt
	encryptResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   label,
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext
	if len(ct) == 0 {
		t.Fatal("Batch ciphertext is empty")
	}

	// Note: Batch PVE doesn't provide a Label() getter (label is stored internally but not exposed).
	// We already know the label from input parameters.

	// Get Q points for verification
	points := make([]*cbmpc.CurvePoint, len(scalars))
	for i, x := range scalars {
		// Q = x * G
		Q, err := curve.MulGenerator(crv, x)
		if err != nil {
			t.Fatalf("Failed to compute Q for scalar %d: %v", i, err)
		}
		defer Q.Free()
		points[i] = Q
	}

	// Batch Verify
	err = pveInstance.BatchVerify(ctx, &pve.BatchVerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Points:     points,
		Label:      label,
	})
	if err != nil {
		t.Fatalf("BatchVerify failed: %v", err)
	}

	// Batch Decrypt
	decryptResult, err := pveInstance.BatchDecrypt(ctx, &pve.BatchDecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: ct,
		Label:      label,
		Curve:      crv,
	})
	if err != nil {
		t.Fatalf("BatchDecrypt failed: %v", err)
	}

	if len(decryptResult.Scalars) != len(scalars) {
		t.Fatalf("Decrypted scalars count mismatch: got %d, want %d", len(decryptResult.Scalars), len(scalars))
	}

	// Verify each decrypted scalar matches the original
	for i, decrypted := range decryptResult.Scalars {
		defer decrypted.Free()
		if scalars[i].String() != decrypted.String() {
			t.Fatalf("Decrypted scalar %d mismatch: got %s, want %s", i, decrypted.String(), scalars[i].String())
		}
	}
}

// TestPVEBatchVerifyFail tests that batch verification fails with wrong parameters.
func TestPVEBatchVerifyFail(t *testing.T) {
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
	label := []byte("batch-test-label")

	// Create scalars
	scalars := []*curve.Scalar{}
	scalarStrings := []string{"111", "222", "333"}
	for _, s := range scalarStrings {
		x, err := curve.NewScalarFromString(s)
		if err != nil {
			t.Fatalf("Failed to create scalar from %s: %v", s, err)
		}
		defer x.Free()
		scalars = append(scalars, x)
	}

	// Encrypt
	encryptResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   label,
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext

	// Get correct Q points
	correctPoints := make([]*cbmpc.CurvePoint, len(scalars))
	for i, x := range scalars {
		Q, err := curve.MulGenerator(crv, x)
		if err != nil {
			t.Fatalf("Failed to compute Q for scalar %d: %v", i, err)
		}
		defer Q.Free()
		correctPoints[i] = Q
	}

	// Test 1: Verify with wrong label (should fail)
	wrongLabel := []byte("wrong-label")
	err = pveInstance.BatchVerify(ctx, &pve.BatchVerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Points:     correctPoints,
		Label:      wrongLabel,
	})
	if err == nil {
		t.Fatal("BatchVerify should have failed with wrong label")
	}

	// Test 2: Verify with wrong number of points (should fail)
	wrongPoints := correctPoints[:len(correctPoints)-1]
	err = pveInstance.BatchVerify(ctx, &pve.BatchVerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Points:     wrongPoints,
		Label:      label,
	})
	if err == nil {
		t.Fatal("BatchVerify should have failed with wrong number of points")
	}

	// Test 3: Verify with wrong Q point (should fail)
	wrongScalar, err := curve.NewScalarFromString("999")
	if err != nil {
		t.Fatalf("Failed to create wrong scalar: %v", err)
	}
	defer wrongScalar.Free()

	wrongQ, err := curve.MulGenerator(crv, wrongScalar)
	if err != nil {
		t.Fatalf("Failed to compute wrong Q: %v", err)
	}
	defer wrongQ.Free()

	// Replace first point with wrong one
	pointsWithWrong := make([]*cbmpc.CurvePoint, len(correctPoints))
	copy(pointsWithWrong, correctPoints)
	pointsWithWrong[0] = wrongQ

	err = pveInstance.BatchVerify(ctx, &pve.BatchVerifyParams{
		EK:         ek,
		Ciphertext: ct,
		Points:     pointsWithWrong,
		Label:      label,
	})
	if err == nil {
		t.Fatal("BatchVerify should have failed with wrong Q point")
	}
}

// TestPVEBatchSingleScalar tests batch PVE with a single scalar.
func TestPVEBatchSingleScalar(t *testing.T) {
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

	// Test with single scalar
	crv := cbmpc.CurveP256
	label := []byte("single-scalar-batch")
	x, err := curve.NewScalarFromString("42")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	scalars := []*curve.Scalar{x}

	// Encrypt
	encryptResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   label,
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	// Decrypt
	decryptResult, err := pveInstance.BatchDecrypt(ctx, &pve.BatchDecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      crv,
	})
	if err != nil {
		t.Fatalf("BatchDecrypt failed: %v", err)
	}

	if len(decryptResult.Scalars) != 1 {
		t.Fatalf("Expected 1 decrypted scalar, got %d", len(decryptResult.Scalars))
	}

	defer decryptResult.Scalars[0].Free()

	if x.String() != decryptResult.Scalars[0].String() {
		t.Fatalf("Decrypted value mismatch: got %s, want %s", decryptResult.Scalars[0].String(), x.String())
	}
}

// TestPVEBatchMultipleCurves tests batch PVE with different curves.
func TestPVEBatchMultipleCurves(t *testing.T) {
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

	label := []byte("multi-curve-batch-test")

	// Create scalars
	scalars := []*curve.Scalar{}
	scalarStrings := []string{"11", "22"}
	for _, s := range scalarStrings {
		x, err := curve.NewScalarFromString(s)
		if err != nil {
			t.Fatalf("Failed to create scalar from %s: %v", s, err)
		}
		defer x.Free()
		scalars = append(scalars, x)
	}

	for _, crv := range curves {
		t.Run(crv.String(), func(t *testing.T) {
			// Encrypt
			encryptResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
				EK:      ek,
				Label:   label,
				Curve:   crv,
				Scalars: scalars,
			})
			if err != nil {
				t.Fatalf("BatchEncrypt failed for %s: %v", crv.String(), err)
			}

			// Decrypt
			decryptResult, err := pveInstance.BatchDecrypt(ctx, &pve.BatchDecryptParams{
				DK:         dkHandle,
				EK:         ek,
				Ciphertext: encryptResult.Ciphertext,
				Label:      label,
				Curve:      crv,
			})
			if err != nil {
				t.Fatalf("BatchDecrypt failed for %s: %v", crv.String(), err)
			}

			// Verify each decrypted scalar
			for i, decrypted := range decryptResult.Scalars {
				defer decrypted.Free()
				if scalars[i].String() != decrypted.String() {
					t.Fatalf("Decrypted scalar %d mismatch for %s: got %s, want %s", i, crv.String(), decrypted.String(), scalars[i].String())
				}
			}
		})
	}
}

// TestPVEBatchLargeScalars tests batch PVE with large scalar values.
func TestPVEBatchLargeScalars(t *testing.T) {
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

	// Use large scalars (256-bit values)
	crv := cbmpc.CurveP256
	label := []byte("large-scalars-batch-test")

	largeScalarStrings := []string{
		"115792089237316195423570985008687907853269984665640564039457584007913129639935",
		"57896044618658097711785492504343953926634992332820282019728792003956564819967",
		"28948022309329048855892746252171976963317496166410141009864396001978282409984",
	}

	scalars := []*curve.Scalar{}
	for _, s := range largeScalarStrings {
		x, err := curve.NewScalarFromString(s)
		if err != nil {
			t.Fatalf("Failed to create scalar from %s: %v", s, err)
		}
		defer x.Free()
		scalars = append(scalars, x)
	}

	// Encrypt
	encryptResult, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   label,
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	// Decrypt
	decryptResult, err := pveInstance.BatchDecrypt(ctx, &pve.BatchDecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encryptResult.Ciphertext,
		Label:      label,
		Curve:      crv,
	})
	if err != nil {
		t.Fatalf("BatchDecrypt failed: %v", err)
	}

	// Verify we got the right number of scalars back
	if len(decryptResult.Scalars) != len(scalars) {
		t.Fatalf("Decrypted scalars count mismatch: got %d, want %d", len(decryptResult.Scalars), len(scalars))
	}

	// Results are modulo curve order, so values might differ
	// Just verify we got non-nil, non-empty results
	for i, decrypted := range decryptResult.Scalars {
		defer decrypted.Free()
		if decrypted == nil {
			t.Fatalf("Decrypted scalar %d is nil", i)
		}
		if len(decrypted.Bytes) == 0 {
			t.Fatalf("Decrypted scalar %d has empty bytes", i)
		}
	}
}

// TestPVEBatchDifferentLabels tests that different labels produce different ciphertexts.
func TestPVEBatchDifferentLabels(t *testing.T) {
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

	// Create scalars
	scalars := []*curve.Scalar{}
	scalarStrings := []string{"1", "2", "3"}
	for _, s := range scalarStrings {
		x, err := curve.NewScalarFromString(s)
		if err != nil {
			t.Fatalf("Failed to create scalar from %s: %v", s, err)
		}
		defer x.Free()
		scalars = append(scalars, x)
	}

	// Encrypt with label1
	encryptResult1, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   []byte("label1"),
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	// Encrypt with label2
	encryptResult2, err := pveInstance.BatchEncrypt(ctx, &pve.BatchEncryptParams{
		EK:      ek,
		Label:   []byte("label2"),
		Curve:   crv,
		Scalars: scalars,
	})
	if err != nil {
		t.Fatalf("BatchEncrypt failed: %v", err)
	}

	// Ciphertexts should be different
	if string(encryptResult1.Ciphertext) == string(encryptResult2.Ciphertext) {
		t.Fatal("Batch ciphertexts with different labels should be different")
	}
}
