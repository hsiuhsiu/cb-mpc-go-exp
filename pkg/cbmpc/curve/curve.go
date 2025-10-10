package curve

// Curve represents an elliptic curve for cryptographic operations.
type Curve struct {
	nid int
}

// Standard curves supported by the MPC protocols.
var (
	P256      = Curve{nid: 415}  // NID_X9_62_prime256v1
	P384      = Curve{nid: 715}  // NID_secp384r1
	P521      = Curve{nid: 716}  // NID_secp521r1
	Secp256k1 = Curve{nid: 714}  // NID_secp256k1
	Ed25519   = Curve{nid: 1087} // NID_ED25519
)

// NID returns the OpenSSL NID (numeric identifier) for the curve.
func (c Curve) NID() int {
	return c.nid
}

// NewFromNID creates a Curve from an OpenSSL NID.
// This is exported for use by protocol subpackages.
func NewFromNID(nid int) Curve {
	return Curve{nid: nid}
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

// MaxHashSize returns the maximum hash size in bytes for this curve.
// This is the size of the curve order, which is the maximum valid message hash size.
func (c Curve) MaxHashSize() int {
	switch c.nid {
	case 415: // P-256
		return 32
	case 715: // P-384
		return 48
	case 716: // P-521
		return 66
	case 714: // secp256k1
		return 32
	case 1087: // Ed25519
		return 32
	default:
		return 0
	}
}
