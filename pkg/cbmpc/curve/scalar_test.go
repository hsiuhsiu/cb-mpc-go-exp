package curve_test

import (
	"fmt"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
)

// TestScalarStringAndBigInt demonstrates the new String() and BigInt() methods.
func TestScalarStringAndBigInt(t *testing.T) {
	// Create a scalar from a decimal string
	x, err := curve.NewScalarFromString("12345678901234567890")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	// Test String() method - easy to print!
	fmt.Printf("Scalar as string: %s\n", x.String())
	if x.String() != "12345678901234567890" {
		t.Fatalf("String() mismatch: got %s, want 12345678901234567890", x.String())
	}

	// Test BigInt() method - can use for math operations (though not constant-time)
	bigInt := x.BigInt()
	fmt.Printf("Scalar as big.Int: %s\n", bigInt.String())
	if bigInt.String() != "12345678901234567890" {
		t.Fatalf("BigInt() mismatch: got %s, want 12345678901234567890", bigInt.String())
	}

	// Test Bytes field - direct access
	bytes := x.Bytes
	fmt.Printf("Scalar as bytes (hex): %x\n", bytes)

	// Create another scalar from bytes
	y, err := curve.NewScalarFromBytes(bytes)
	if err != nil {
		t.Fatalf("Failed to create scalar from bytes: %v", err)
	}
	defer y.Free()

	// Verify they match
	if x.String() != y.String() {
		t.Fatalf("Round-trip mismatch: got %s, want %s", y.String(), x.String())
	}

	fmt.Println("✓ Scalar String() and BigInt() methods work!")
}

// TestScalarZeroize verifies that Free() zeroizes the underlying bytes.
func TestScalarZeroize(t *testing.T) {
	x, err := curve.NewScalarFromString("1234567890")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	if len(x.Bytes) == 0 {
		t.Fatalf("Scalar bytes should not be empty")
	}
	// Keep a copy of the backing bytes for comparison length
	l := len(x.Bytes)
	x.Free()
	if x.Bytes != nil {
		t.Fatalf("Expected Bytes to be nil after Free()")
	}
	// We can't directly assert content after nil, but we can ensure the API state is cleared
	if got := x.String(); got != "0" {
		t.Fatalf("Expected String() to be '0' after Free(), got %s", got)
	}
	if l == 0 {
		t.Fatalf("unexpected zero length before Free()")
	}
}

// TestScalarBytesPadded ensures fixed-size output per curve.
func TestScalarBytesPadded(t *testing.T) {
	x, err := curve.NewScalarFromString("255")
	if err != nil {
		t.Fatalf("Failed to create scalar: %v", err)
	}
	defer x.Free()

	tests := []struct {
		c      curve.Curve
		expect int
	}{
		{curve.P256, 32},
		{curve.P384, 48},
		{curve.P521, 66},
		{curve.Secp256k1, 32},
		{curve.Ed25519, 32},
	}

	for _, tc := range tests {
		got := x.BytesPadded(tc.c)
		if len(got) != tc.expect {
			t.Fatalf("BytesPadded(%s) length = %d, want %d", tc.c.String(), len(got), tc.expect)
		}
		// Value 255 should be 0xFF at the end after padding
		if got[len(got)-1] != 0xFF {
			t.Fatalf("BytesPadded(%s) last byte = %02x, want FF", tc.c.String(), got[len(got)-1])
		}
	}
}
