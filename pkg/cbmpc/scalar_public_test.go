package cbmpc_test

import (
	"fmt"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// TestScalarPublicBytes demonstrates direct access to the public Bytes field.
func TestScalarPublicBytes(t *testing.T) {
	// Create a scalar
	x, _ := cbmpc.NewScalarFromString("12345")
	defer x.Free()

	// Direct access to bytes - no method call needed!
	fmt.Printf("Direct access: x.Bytes = %x\n", x.Bytes)

	// Can also print as string easily
	fmt.Printf("As string: x.String() = %s\n", x.String())

	// Can manipulate bytes directly if needed (though be careful!)
	bytesCopy := make([]byte, len(x.Bytes))
	copy(bytesCopy, x.Bytes)
	fmt.Printf("Copied bytes: %x\n", bytesCopy)

	// Create another scalar from the bytes
	y, _ := cbmpc.NewScalarFromBytes(x.Bytes)
	defer y.Free()

	fmt.Printf("Created from x.Bytes: y.String() = %s\n", y.String())

	if x.String() != y.String() {
		t.Fatalf("Values don't match: %s != %s", x.String(), y.String())
	}

	fmt.Println("✓ Public Bytes field works great!")
	fmt.Println("✓ Easy to access without method calls!")
}
