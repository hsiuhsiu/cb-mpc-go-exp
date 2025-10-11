//go:build !windows

package backend_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// TestCurveToNID tests the CurveToNID mapping function.
func TestCurveToNID(t *testing.T) {
	tests := []struct {
		name    string
		curve   backend.Curve
		wantNID int
		wantErr bool
	}{
		{"P256", backend.P256, 415, false},
		{"P384", backend.P384, 715, false},
		{"P521", backend.P521, 716, false},
		{"Secp256k1", backend.Secp256k1, 714, false},
		{"Ed25519", backend.Ed25519, 1087, false},
		{"Unknown", backend.Unknown, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nid, err := backend.CurveToNID(tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("CurveToNID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && nid != tt.wantNID {
				t.Errorf("CurveToNID() = %v, want %v", nid, tt.wantNID)
			}
		})
	}
}

// TestNIDToCurve tests the NIDToCurve mapping function.
func TestNIDToCurve(t *testing.T) {
	tests := []struct {
		name      string
		nid       int
		wantCurve backend.Curve
		wantErr   bool
	}{
		{"NID_X9_62_prime256v1", 415, backend.P256, false},
		{"NID_secp384r1", 715, backend.P384, false},
		{"NID_secp521r1", 716, backend.P521, false},
		{"NID_secp256k1", 714, backend.Secp256k1, false},
		{"NID_ED25519", 1087, backend.Ed25519, false},
		{"Invalid NID", 999, backend.Unknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crv, err := backend.NIDToCurve(tt.nid)
			if (err != nil) != tt.wantErr {
				t.Errorf("NIDToCurve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && crv != tt.wantCurve {
				t.Errorf("NIDToCurve() = %v, want %v", crv, tt.wantCurve)
			}
		})
	}
}

// TestRoundTrip tests that Curve -> NID -> Curve round trip works correctly.
func TestRoundTrip(t *testing.T) {
	curves := []backend.Curve{
		backend.P256,
		backend.P384,
		backend.P521,
		backend.Secp256k1,
		backend.Ed25519,
	}

	for _, original := range curves {
		t.Run(original.String(), func(t *testing.T) {
			// Convert to NID
			nid, err := backend.CurveToNID(original)
			if err != nil {
				t.Fatalf("CurveToNID(%s) failed: %v", original, err)
			}

			// Convert back to Curve
			result, err := backend.NIDToCurve(nid)
			if err != nil {
				t.Fatalf("NIDToCurve(%d) failed: %v", nid, err)
			}

			// Verify round trip
			if result != original {
				t.Errorf("Round trip failed: got %s, want %s", result, original)
			}
		})
	}
}
