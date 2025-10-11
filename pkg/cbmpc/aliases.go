package cbmpc

import (
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem"
)

// Type aliases for backward compatibility.
// These allow existing code to continue using cbmpc.Curve, cbmpc.CurvePoint, etc.

// Curve is an alias for curve.Curve for backward compatibility.
type Curve = curve.Curve

// CurvePoint is an alias for curve.Point for backward compatibility.
type CurvePoint = curve.Point

// KEM is an alias for kem.KEM for backward compatibility.
type KEM = kem.KEM

// Standard curve constants re-exported for backward compatibility.
var (
	CurveP256      = curve.P256
	CurveP384      = curve.P384
	CurveP521      = curve.P521
	CurveSecp256k1 = curve.Secp256k1
	CurveEd25519   = curve.Ed25519
)

// NewCurvePointFromBytes creates a CurvePoint from compressed bytes.
func NewCurvePointFromBytes(c Curve, bytes []byte) (*CurvePoint, error) {
	return curve.NewPointFromBytes(c, bytes)
}

// NewCurvePointFromBackend creates a CurvePoint from a backend ECCPoint.
// This is exported for use by protocol subpackages.
func NewCurvePointFromBackend(cpoint interface{}) *CurvePoint {
	// This needs the backend package import, but we can't import it here
	// because it would expose internal package to public API
	// The subpackages should use curve.NewPointFromBackend directly
	panic("deprecated: use curve.NewPointFromBackend directly")
}
