//go:build cgo && !windows

package curve_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
)

// TestRandomScalar tests generating random scalars for different curves.
func TestRandomScalar(t *testing.T) {
	curves := []curve.Curve{
		curve.P256,
		curve.P384,
		curve.Secp256k1,
	}

	for _, c := range curves {
		t.Run(c.String(), func(t *testing.T) {
			scalar, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("RandomScalar failed: %v", err)
			}
			defer scalar.Free()

			if scalar == nil {
				t.Fatal("RandomScalar returned nil scalar")
			}

			if len(scalar.Bytes) == 0 {
				t.Fatal("RandomScalar returned empty bytes")
			}

			t.Logf("Generated random scalar of %d bytes for %s", len(scalar.Bytes), c.String())
		})
	}
}

// TestGenerator tests getting the generator point for different curves.
func TestGenerator(t *testing.T) {
	curves := []curve.Curve{
		curve.P256,
		curve.P384,
		curve.Secp256k1,
	}

	for _, c := range curves {
		t.Run(c.String(), func(t *testing.T) {
			gen, err := curve.Generator(c)
			if err != nil {
				t.Fatalf("Generator failed: %v", err)
			}
			defer gen.Free()

			if gen == nil {
				t.Fatal("Generator returned nil point")
			}

			genBytes, err := gen.Bytes()
			if err != nil {
				t.Fatalf("failed to get generator bytes: %v", err)
			}

			if len(genBytes) == 0 {
				t.Fatal("Generator returned empty bytes")
			}

			t.Logf("Generator point has %d bytes for %s", len(genBytes), c.String())
		})
	}
}

// TestMulGenerator tests multiplying the generator by a scalar.
func TestMulGenerator(t *testing.T) {
	c := curve.P256

	// Generate a random scalar
	scalar, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar.Free()

	// Multiply generator by scalar
	point, err := curve.MulGenerator(c, scalar)
	if err != nil {
		t.Fatalf("MulGenerator failed: %v", err)
	}
	defer point.Free()

	if point == nil {
		t.Fatal("MulGenerator returned nil point")
	}

	pointBytes, err := point.Bytes()
	if err != nil {
		t.Fatalf("failed to get point bytes: %v", err)
	}

	if len(pointBytes) == 0 {
		t.Fatal("MulGenerator returned empty bytes")
	}

	// Verify the point is on the correct curve
	if point.Curve() != c {
		t.Fatalf("point curve mismatch: got %v, want %v", point.Curve(), c)
	}

	t.Logf("MulGenerator result has %d bytes", len(pointBytes))
}

// TestPointMul tests multiplying a point by a scalar.
func TestPointMul(t *testing.T) {
	c := curve.P256

	// Get generator
	gen, err := curve.Generator(c)
	if err != nil {
		t.Fatalf("Generator failed: %v", err)
	}
	defer gen.Free()

	// Generate a random scalar
	scalar, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar.Free()

	// Multiply generator by scalar using point.Mul
	point, err := gen.Mul(scalar)
	if err != nil {
		t.Fatalf("Point.Mul failed: %v", err)
	}
	defer point.Free()

	if point == nil {
		t.Fatal("Point.Mul returned nil point")
	}

	pointBytes, err := point.Bytes()
	if err != nil {
		t.Fatalf("failed to get point bytes: %v", err)
	}

	if len(pointBytes) == 0 {
		t.Fatal("Point.Mul returned empty bytes")
	}

	// Verify the point is on the correct curve
	if point.Curve() != c {
		t.Fatalf("point curve mismatch: got %v, want %v", point.Curve(), c)
	}

	t.Logf("Point.Mul result has %d bytes", len(pointBytes))
}

// TestMulGeneratorVsPointMul verifies that MulGenerator and Point.Mul give the same result.
func TestMulGeneratorVsPointMul(t *testing.T) {
	c := curve.P256

	// Generate a random scalar
	scalar, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar.Free()

	// Method 1: MulGenerator
	point1, err := curve.MulGenerator(c, scalar)
	if err != nil {
		t.Fatalf("MulGenerator failed: %v", err)
	}
	defer point1.Free()

	// Method 2: Generator + Mul
	gen, err := curve.Generator(c)
	if err != nil {
		t.Fatalf("Generator failed: %v", err)
	}
	defer gen.Free()

	point2, err := gen.Mul(scalar)
	if err != nil {
		t.Fatalf("Point.Mul failed: %v", err)
	}
	defer point2.Free()

	// Compare the results
	bytes1, err := point1.Bytes()
	if err != nil {
		t.Fatalf("failed to get point1 bytes: %v", err)
	}

	bytes2, err := point2.Bytes()
	if err != nil {
		t.Fatalf("failed to get point2 bytes: %v", err)
	}

	if len(bytes1) != len(bytes2) {
		t.Fatalf("point bytes length mismatch: %d != %d", len(bytes1), len(bytes2))
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatal("MulGenerator and Point.Mul returned different results")
		}
	}

	t.Log("MulGenerator and Point.Mul produced identical results")
}

// TestScalarPointOperations tests a more complex operation: (scalar1 * (scalar2 * G)).
func TestScalarPointOperations(t *testing.T) {
	c := curve.P256

	// Generate two random scalars
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed for scalar1: %v", err)
	}
	defer scalar1.Free()

	scalar2, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed for scalar2: %v", err)
	}
	defer scalar2.Free()

	// Compute scalar2 * G
	point1, err := curve.MulGenerator(c, scalar2)
	if err != nil {
		t.Fatalf("MulGenerator failed: %v", err)
	}
	defer point1.Free()

	// Compute scalar1 * (scalar2 * G)
	point2, err := point1.Mul(scalar1)
	if err != nil {
		t.Fatalf("Point.Mul failed: %v", err)
	}
	defer point2.Free()

	if point2 == nil {
		t.Fatal("final point is nil")
	}

	pointBytes, err := point2.Bytes()
	if err != nil {
		t.Fatalf("failed to get point bytes: %v", err)
	}

	if len(pointBytes) == 0 {
		t.Fatal("final point has empty bytes")
	}

	// Verify the point is on the correct curve
	if point2.Curve() != c {
		t.Fatalf("point curve mismatch: got %v, want %v", point2.Curve(), c)
	}

	t.Logf("Successfully computed scalar1 * (scalar2 * G), result has %d bytes", len(pointBytes))
}

// TestNewScalarFromBytesWithRandomScalar verifies that NewScalarFromBytes works with RandomScalar output.
func TestNewScalarFromBytesWithRandomScalar(t *testing.T) {
	c := curve.P256

	// Generate random scalar
	scalar1, err := curve.RandomScalar(c)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar1.Free()

	// Get bytes
	bytes1 := scalar1.Bytes

	// Create new scalar from those bytes
	scalar2, err := curve.NewScalarFromBytes(bytes1)
	if err != nil {
		t.Fatalf("NewScalarFromBytes failed: %v", err)
	}
	defer scalar2.Free()

	// Compare bytes
	bytes2 := scalar2.Bytes
	if len(bytes1) != len(bytes2) {
		t.Fatalf("scalar bytes length mismatch: %d != %d", len(bytes1), len(bytes2))
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatal("scalar bytes mismatch after round-trip")
		}
	}

	t.Log("NewScalarFromBytes successfully round-tripped RandomScalar output")
}

// TestNewPointFromBytesWithGenerator verifies that NewPointFromBytes works with Generator output.
func TestNewPointFromBytesWithGenerator(t *testing.T) {
	c := curve.P256

	// Get generator
	gen1, err := curve.Generator(c)
	if err != nil {
		t.Fatalf("Generator failed: %v", err)
	}
	defer gen1.Free()

	// Get bytes
	bytes1, err := gen1.Bytes()
	if err != nil {
		t.Fatalf("failed to get generator bytes: %v", err)
	}

	// Create new point from those bytes
	gen2, err := curve.NewPointFromBytes(cbmpc.CurveP256, bytes1)
	if err != nil {
		t.Fatalf("NewPointFromBytes failed: %v", err)
	}
	defer gen2.Free()

	// Compare bytes
	bytes2, err := gen2.Bytes()
	if err != nil {
		t.Fatalf("failed to get gen2 bytes: %v", err)
	}

	if len(bytes1) != len(bytes2) {
		t.Fatalf("point bytes length mismatch: %d != %d", len(bytes1), len(bytes2))
	}

	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			t.Fatal("point bytes mismatch after round-trip")
		}
	}

	t.Log("NewPointFromBytes successfully round-tripped Generator output")
}

// TestNilInputsReturnExplicitErrors verifies that nil inputs return explicit errors rather than (nil, nil).
func TestNilInputsReturnExplicitErrors(t *testing.T) {
	// Test Point.Mul with nil point
	var nilPoint *curve.Point
	scalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("RandomScalar failed: %v", err)
	}
	defer scalar.Free()

	_, err = nilPoint.Mul(scalar)
	if err == nil {
		t.Fatal("expected error from nil point Mul, got nil")
	}
	if err.Error() != "nil point" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test Point.Mul with nil scalar
	gen, err := curve.Generator(curve.P256)
	if err != nil {
		t.Fatalf("Generator failed: %v", err)
	}
	defer gen.Free()

	_, err = gen.Mul(nil)
	if err == nil {
		t.Fatal("expected error from nil scalar Mul, got nil")
	}
	if err.Error() != "nil scalar" {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Test Point.Bytes with nil point
	_, err = nilPoint.Bytes()
	if err == nil {
		t.Fatal("expected error from nil point Bytes, got nil")
	}
	if err.Error() != "nil point" {
		t.Fatalf("unexpected error message: %v", err)
	}

	t.Log("All nil input validations return explicit errors")
}
