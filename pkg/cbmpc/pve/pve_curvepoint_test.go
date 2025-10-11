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

// TestPVEWithCurvePoint demonstrates using CurvePoint for more efficient operations.
// This avoids serialization/deserialization overhead when extracting and verifying Q.
func TestPVEWithCurvePoint(t *testing.T) {
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

	// Test parameters
	crv := cbmpc.CurveP256
	label := []byte("test-curvepoint")
	x, err := curve.NewScalarFromString("98765432109876543210")
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

	ciphertext := encryptResult.Ciphertext

	// Extract Q as CurvePoint (efficient - no serialization)
	Q, err := ciphertext.Q()
	if err != nil {
		t.Fatalf("Failed to extract Q: %v", err)
	}
	defer Q.Free()

	// Verify Q point is on the correct curve
	if Q.Curve().NID() != crv.NID() {
		t.Fatalf("Q point curve mismatch: got %d, want %d", Q.Curve().NID(), crv.NID())
	}

	// Verify using CurvePoint (efficient - no deserialization)
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: ciphertext,
		Q:          Q,
		Label:      label,
	})
	if err != nil {
		t.Fatalf("Verify with CurvePoint failed: %v", err)
	}

	// Verify that Q can be serialized to bytes
	QBytes, err := Q.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize Q: %v", err)
	}
	if len(QBytes) == 0 {
		t.Fatal("Q serialized to empty bytes")
	}

	t.Logf("✓ CurvePoint API works correctly")
	t.Logf("✓ Q point on curve %s", Q.Curve().String())
	t.Logf("✓ Verification with CurvePoint avoids serialization overhead")
}

// TestCurvePointRoundTrip tests creating a CurvePoint from bytes and back.
func TestCurvePointRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)
	pveInstance, _ := pve.New(kem)

	// Generate key pair
	_, ek, _ := kem.Generate()

	// Encrypt to get a ciphertext with Q
	x, _ := curve.NewScalarFromString("12345")
	defer x.Free()

	encryptResult, _ := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: []byte("test"),
		Curve: cbmpc.CurveSecp256k1,
		X:     x,
	})

	// Extract Q as CurvePoint
	Q, err := encryptResult.Ciphertext.Q()
	if err != nil {
		t.Fatalf("Failed to get Q: %v", err)
	}
	defer Q.Free()

	// Verify curve matches
	if Q.Curve().NID() != cbmpc.CurveSecp256k1.NID() {
		t.Fatalf("Curve mismatch: got %d, want %d", Q.Curve().NID(), cbmpc.CurveSecp256k1.NID())
	}

	// Serialize to bytes
	QBytes, err := Q.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize Q: %v", err)
	}

	// Create CurvePoint from bytes
	Q2, err := cbmpc.NewCurvePointFromBytes(cbmpc.CurveSecp256k1, QBytes)
	if err != nil {
		t.Fatalf("Failed to create CurvePoint from bytes: %v", err)
	}
	defer Q2.Free()

	// Verify curve matches
	if Q2.Curve().NID() != cbmpc.CurveSecp256k1.NID() {
		t.Fatalf("Q2 curve mismatch: got %d, want %d", Q2.Curve().NID(), cbmpc.CurveSecp256k1.NID())
	}

	// Serialize back to bytes
	Q2Bytes, err := Q2.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize Q2: %v", err)
	}

	// Verify bytes match
	if string(Q2Bytes) != string(QBytes) {
		t.Fatalf("Round trip failed: bytes don't match")
	}

	t.Logf("✓ CurvePoint round trip successful")
}
