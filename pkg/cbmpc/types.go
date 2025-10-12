package cbmpc

import (
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem"
)

// Type aliases for convenience and backward compatibility.
// These allow subpackages to reference cbmpc.Curve, cbmpc.CurvePoint, etc.
// without importing the subpackages directly.

// Curve is an alias for curve.Curve.
type Curve = curve.Curve

// CurvePoint is an alias for curve.Point.
type CurvePoint = curve.Point

// KEM is an alias for kem.KEM.
type KEM = kem.KEM

// Standard curve constants re-exported for convenience.
var (
	CurveUnknown   = curve.Unknown
	CurveP256      = curve.P256
	CurveP384      = curve.P384
	CurveP521      = curve.P521
	CurveSecp256k1 = curve.Secp256k1
	CurveEd25519   = curve.Ed25519
)
