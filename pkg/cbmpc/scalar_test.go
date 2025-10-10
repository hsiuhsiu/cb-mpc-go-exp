package cbmpc_test

import (
	"fmt"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// TestScalarStringAndBigInt demonstrates the new String() and BigInt() methods.
func TestScalarStringAndBigInt(t *testing.T) {
	// Create a scalar from a decimal string
	x, err := cbmpc.NewScalarFromString("12345678901234567890")
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
	y, err := cbmpc.NewScalarFromBytes(bytes)
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
