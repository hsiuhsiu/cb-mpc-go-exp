package cbmpc

// Curve represents an elliptic curve for cryptographic operations.
type Curve struct {
	nid int
}

// Standard curves supported by the MPC protocols.
var (
	CurveP256      = Curve{nid: 415}  // NID_X9_62_prime256v1
	CurveP384      = Curve{nid: 715}  // NID_secp384r1
	CurveP521      = Curve{nid: 716}  // NID_secp521r1
	CurveSecp256k1 = Curve{nid: 714}  // NID_secp256k1
	CurveEd25519   = Curve{nid: 1087} // NID_ED25519
)

// NID returns the OpenSSL NID (numeric identifier) for the curve.
func (c Curve) NID() int {
	return c.nid
}

// String returns a human-readable name for the curve.
func (c Curve) String() string {
	switch c.nid {
	case 415:
		return "P-256"
	case 715:
		return "P-384"
	case 716:
		return "P-521"
	case 714:
		return "secp256k1"
	case 1087:
		return "Ed25519"
	default:
		return "Unknown"
	}
}
