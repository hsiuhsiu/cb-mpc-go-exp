package curve_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
)

// TestPointBytesMutationProtection verifies that mutating the slice returned by
// Point.Bytes() does not affect the internal point state.
func TestPointBytesMutationProtection(t *testing.T) {
	// Create a test point from known bytes (P-256 generator point compressed)
	// This is the generator point G on P-256
	generatorBytes := []byte{
		0x02, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
		0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
		0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
		0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
		0x96,
	}

	point, err := curve.NewPointFromBytes(curve.P256, generatorBytes)
	if err != nil {
		t.Fatalf("Failed to create point: %v", err)
	}
	defer point.Free()

	// Get point bytes
	pointBytes1, err := point.Bytes()
	if err != nil {
		t.Fatalf("Failed to get point bytes: %v", err)
	}

	// Make a copy of the original bytes for comparison
	originalBytes := make([]byte, len(pointBytes1))
	copy(originalBytes, pointBytes1)

	// Mutate the returned slice
	for i := range pointBytes1 {
		pointBytes1[i] = 0xFF
	}

	// Get point bytes again - should be unchanged
	pointBytes2, err := point.Bytes()
	if err != nil {
		t.Fatalf("Failed to get point bytes second time: %v", err)
	}

	// Verify that the point bytes are unchanged
	if len(pointBytes2) != len(originalBytes) {
		t.Fatalf("Point bytes length changed: got %d, want %d", len(pointBytes2), len(originalBytes))
	}

	for i := range pointBytes2 {
		if pointBytes2[i] != originalBytes[i] {
			t.Fatalf("Point bytes mutated at index %d: got %02x, want %02x", i, pointBytes2[i], originalBytes[i])
		}
	}

	t.Logf("✓ Point.Bytes() is protected from mutation")
}
