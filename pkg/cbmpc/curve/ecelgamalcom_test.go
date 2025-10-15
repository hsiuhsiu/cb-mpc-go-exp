//go:build cgo && !windows

package curve_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
)

// TestNewECElGamalCom tests creating an EC ElGamal commitment from two points.
func TestNewECElGamalCom(t *testing.T) {
	curves := []curve.Curve{
		curve.P256,
		curve.P384,
		curve.Secp256k1,
	}

	for _, c := range curves {
		t.Run(c.String(), func(t *testing.T) {
			// Generate two random points
			scalar1, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("RandomScalar failed: %v", err)
			}
			defer scalar1.Free()

			scalar2, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("RandomScalar failed: %v", err)
			}
			defer scalar2.Free()

			pointL, err := curve.MulGenerator(c, scalar1)
			if err != nil {
				t.Fatalf("MulGenerator failed for L: %v", err)
			}
			defer pointL.Free()

			pointR, err := curve.MulGenerator(c, scalar2)
			if err != nil {
				t.Fatalf("MulGenerator failed for R: %v", err)
			}
			defer pointR.Free()

			// Create com
			com, err := curve.NewECElGamalCom(pointL, pointR)
			if err != nil {
				t.Fatalf("NewECElGamalCom failed: %v", err)
			}
			defer com.Free()

			if com == nil {
				t.Fatal("NewECElGamalCom returned nil com")
			}

			t.Logf("Successfully created EC ElGamal commitment for %s", c.String())
		})
	}
}

// TestECElGamalComSerialization tests serializing and deserializing EC ElGamal commitments.
func TestECElGamalComSerialization(t *testing.T) {
	c := curve.P256

	// Create two random points
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar2.Free()

	pointL, err := curve.MulGenerator(c, scalar1)
	if err != nil {
		t.Fatalf("MulGenerator failed for L: %v", err)
	}
	defer pointL.Free()

	pointR, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed for R: %v", err)
	}
	defer pointR.Free()

	// Create com
	com1, err := curve.NewECElGamalCom(pointL, pointR)
	if err != nil {
		t.Fatalf("NewECElGamalCom failed: %v", err)
	}
	defer com1.Free()

	// Serialize
	bytes, err := com1.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	if len(bytes) == 0 {
		t.Fatal("Bytes returned empty bytes")
	}

	t.Logf("Serialized EC ElGamal commitment to %d bytes", len(bytes))

	// Deserialize
	com2, err := curve.LoadECElGamalCom(cbmpc.CurveP256, bytes)
	if err != nil {
		t.Fatalf("LoadECElGamalCom failed: %v", err)
	}
	defer com2.Free()

	// Compare serialized forms
	bytes2, err := com2.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed on loaded EC ElGamal commitment: %v", err)
	}

	if len(bytes) != len(bytes2) {
		t.Fatalf("EC ElGamal commitment bytes length mismatch: %d != %d", len(bytes), len(bytes2))
	}

	for i := range bytes {
		if bytes[i] != bytes2[i] {
			t.Fatal("EC ElGamal commitment bytes mismatch after round-trip")
		}
	}

	t.Log("Commitment serialization round-trip successful")
}

// TestECElGamalComGetPoints tests extracting L and R points from an EC ElGamal commitment.
func TestECElGamalComGetPoints(t *testing.T) {
	c := curve.P256

	// Create two random points
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar2.Free()

	pointL, err := curve.MulGenerator(c, scalar1)
	if err != nil {
		t.Fatalf("MulGenerator failed for L: %v", err)
	}
	defer pointL.Free()

	pointR, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed for R: %v", err)
	}
	defer pointR.Free()

	// Get original point bytes
	bytesL, err := pointL.Bytes()
	if err != nil {
		t.Fatalf("failed to get L bytes: %v", err)
	}

	bytesR, err := pointR.Bytes()
	if err != nil {
		t.Fatalf("failed to get R bytes: %v", err)
	}

	// Create com
	com, err := curve.NewECElGamalCom(pointL, pointR)
	if err != nil {
		t.Fatalf("NewECElGamalCom failed: %v", err)
	}
	defer com.Free()

	// Extract points from com
	extractedL, err := com.PointL()
	if err != nil {
		t.Fatalf("PointL failed: %v", err)
	}
	defer extractedL.Free()

	extractedR, err := com.PointR()
	if err != nil {
		t.Fatalf("PointR failed: %v", err)
	}
	defer extractedR.Free()

	// Get extracted point bytes
	extractedBytesL, err := extractedL.Bytes()
	if err != nil {
		t.Fatalf("failed to get extracted L bytes: %v", err)
	}

	extractedBytesR, err := extractedR.Bytes()
	if err != nil {
		t.Fatalf("failed to get extracted R bytes: %v", err)
	}

	// Compare L points
	if len(bytesL) != len(extractedBytesL) {
		t.Fatalf("L point bytes length mismatch: %d != %d", len(bytesL), len(extractedBytesL))
	}

	for i := range bytesL {
		if bytesL[i] != extractedBytesL[i] {
			t.Fatal("L point bytes mismatch")
		}
	}

	// Compare R points
	if len(bytesR) != len(extractedBytesR) {
		t.Fatalf("R point bytes length mismatch: %d != %d", len(bytesR), len(extractedBytesR))
	}

	for i := range bytesR {
		if bytesR[i] != extractedBytesR[i] {
			t.Fatal("R point bytes mismatch")
		}
	}

	t.Log("Successfully extracted L and R points from EC ElGamal commitment")
}

// TestECElGamalComRoundTripWithSerialization tests creating, serializing, deserializing, and extracting points.
func TestECElGamalComRoundTripWithSerialization(t *testing.T) {
	c := curve.P256

	// Create two random points
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar2.Free()

	pointL, err := curve.MulGenerator(c, scalar1)
	if err != nil {
		t.Fatalf("MulGenerator failed for L: %v", err)
	}
	defer pointL.Free()

	pointR, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed for R: %v", err)
	}
	defer pointR.Free()

	// Get original point bytes
	bytesL, err := pointL.Bytes()
	if err != nil {
		t.Fatalf("failed to get L bytes: %v", err)
	}

	bytesR, err := pointR.Bytes()
	if err != nil {
		t.Fatalf("failed to get R bytes: %v", err)
	}

	// Create com
	com1, err := curve.NewECElGamalCom(pointL, pointR)
	if err != nil {
		t.Fatalf("NewECElGamalCom failed: %v", err)
	}
	defer com1.Free()

	// Serialize
	bytes, err := com1.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Deserialize
	com2, err := curve.LoadECElGamalCom(cbmpc.CurveP256, bytes)
	if err != nil {
		t.Fatalf("LoadECElGamalCom failed: %v", err)
	}
	defer com2.Free()

	// Extract points from deserialized com
	extractedL, err := com2.PointL()
	if err != nil {
		t.Fatalf("PointL failed: %v", err)
	}
	defer extractedL.Free()

	extractedR, err := com2.PointR()
	if err != nil {
		t.Fatalf("PointR failed: %v", err)
	}
	defer extractedR.Free()

	// Get extracted point bytes
	extractedBytesL, err := extractedL.Bytes()
	if err != nil {
		t.Fatalf("failed to get extracted L bytes: %v", err)
	}

	extractedBytesR, err := extractedR.Bytes()
	if err != nil {
		t.Fatalf("failed to get extracted R bytes: %v", err)
	}

	// Compare L points
	if len(bytesL) != len(extractedBytesL) {
		t.Fatalf("L point bytes length mismatch: %d != %d", len(bytesL), len(extractedBytesL))
	}

	for i := range bytesL {
		if bytesL[i] != extractedBytesL[i] {
			t.Fatal("L point bytes mismatch after round-trip")
		}
	}

	// Compare R points
	if len(bytesR) != len(extractedBytesR) {
		t.Fatalf("R point bytes length mismatch: %d != %d", len(bytesR), len(extractedBytesR))
	}

	for i := range bytesR {
		if bytesR[i] != extractedBytesR[i] {
			t.Fatal("R point bytes mismatch after round-trip")
		}
	}

	t.Log("Full round-trip successful: create -> serialize -> deserialize -> extract points")
}

// TestECElGamalComNilInputs tests that nil inputs return explicit errors.
func TestECElGamalComNilInputs(t *testing.T) {
	c := curve.P256

	// Create a valid point
	scalar, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar.Free()

	point, err := curve.MulGenerator(c, scalar)
	if err != nil {
		t.Fatalf("MulGenerator failed: %v", err)
	}
	defer point.Free()

	// Test NewECElGamalCom with nil L
	_, err = curve.NewECElGamalCom(nil, point)
	if err == nil {
		t.Fatal("expected error from NewECElGamalCom with nil L, got nil")
	}
	if err.Error() != "nil point" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test NewECElGamalCom with nil R
	_, err = curve.NewECElGamalCom(point, nil)
	if err == nil {
		t.Fatal("expected error from NewECElGamalCom with nil R, got nil")
	}
	if err.Error() != "nil point" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test NewECElGamalCom with both nil
	_, err = curve.NewECElGamalCom(nil, nil)
	if err == nil {
		t.Fatal("expected error from NewECElGamalCom with both nil, got nil")
	}
	if err.Error() != "nil point" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test methods on nil EC ElGamal commitment
	var nilCom *curve.ECElGamalCom

	_, err = nilCom.Bytes()
	if err == nil {
		t.Fatal("expected error from nil com Bytes, got nil")
	}
	if err.Error() != "nil EC ElGamal commitment" {
		t.Fatalf("unexpected error message: %v", err)
	}

	_, err = nilCom.PointL()
	if err == nil {
		t.Fatal("expected error from nil com PointL, got nil")
	}
	if err.Error() != "nil EC ElGamal commitment" {
		t.Fatalf("unexpected error message: %v", err)
	}

	_, err = nilCom.PointR()
	if err == nil {
		t.Fatal("expected error from nil com PointR, got nil")
	}
	if err.Error() != "nil EC ElGamal commitment" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test Free on nil EC ElGamal commitment (should not panic)
	nilCom.Free()

	t.Log("All nil input validations return explicit errors")
}

// TestECElGamalComDefensiveCopy tests that Bytes() returns a defensive copy.
func TestECElGamalComDefensiveCopy(t *testing.T) {
	c := curve.P256

	// Create two random points
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar2.Free()

	pointL, err := curve.MulGenerator(c, scalar1)
	if err != nil {
		t.Fatalf("MulGenerator failed for L: %v", err)
	}
	defer pointL.Free()

	pointR, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed for R: %v", err)
	}
	defer pointR.Free()

	// Create com
	com, err := curve.NewECElGamalCom(pointL, pointR)
	if err != nil {
		t.Fatalf("NewECElGamalCom failed: %v", err)
	}
	defer com.Free()

	// Get bytes twice
	bytes1, err := com.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	bytes2, err := com.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Verify they're equal
	if len(bytes1) != len(bytes2) {
		t.Fatalf("bytes length mismatch: %d != %d", len(bytes1), len(bytes2))
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatal("bytes mismatch")
		}
	}

	// Mutate bytes1
	if len(bytes1) > 0 {
		bytes1[0] ^= 0xFF
	}

	// Get bytes again and verify it's unchanged
	bytes3, err := com.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// bytes3 should match original bytes2, not mutated bytes1
	for i := range bytes3 {
		if bytes3[i] != bytes2[i] {
			t.Fatal("Bytes() did not return defensive copy - mutation affected internal state")
		}
	}

	t.Log("Bytes() returns defensive copy that prevents external mutation")
}

// TestECElGamalComLoadInvalidCurve tests that LoadECElGamalCom validates curve.
func TestECElGamalComLoadInvalidCurve(t *testing.T) {
	// Create EC ElGamal commitment on P256
	c := curve.P256

	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar2.Free()

	pointL, err := curve.MulGenerator(c, scalar1)
	if err != nil {
		t.Fatalf("MulGenerator failed for L: %v", err)
	}
	defer pointL.Free()

	pointR, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed for R: %v", err)
	}
	defer pointR.Free()

	com, err := curve.NewECElGamalCom(pointL, pointR)
	if err != nil {
		t.Fatalf("NewECElGamalCom failed: %v", err)
	}
	defer com.Free()

	// Serialize
	bytes, err := com.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}

	// Try to load with wrong curve (Secp256k1 instead of P256)
	_, err = curve.LoadECElGamalCom(cbmpc.CurveSecp256k1, bytes)
	if err == nil {
		t.Fatal("expected error when loading P256 EC ElGamal commitment as Secp256k1, got nil")
	}

	t.Logf("LoadECElGamalCom correctly rejected wrong curve: %v", err)
}
