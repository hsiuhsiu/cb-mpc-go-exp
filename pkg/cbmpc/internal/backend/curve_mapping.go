//go:build !windows

package backend

import "errors"

// CurveToNID converts a Curve enum to an OpenSSL NID.
// This is the only place where the mapping between Go enums and OpenSSL NIDs exists.
func CurveToNID(c Curve) (int, error) {
	switch c {
	case P256:
		return 415, nil // NID_X9_62_prime256v1
	case P384:
		return 715, nil // NID_secp384r1
	case P521:
		return 716, nil // NID_secp521r1
	case Secp256k1:
		return 714, nil // NID_secp256k1
	case Ed25519:
		return 1087, nil // NID_ED25519
	default:
		return 0, errors.New("unsupported curve")
	}
}

// NIDToCurve converts an OpenSSL NID to a Curve enum.
// This is the only place where the mapping between OpenSSL NIDs and Go enums exists.
func NIDToCurve(nid int) (Curve, error) {
	switch nid {
	case 415: // NID_X9_62_prime256v1
		return P256, nil
	case 715: // NID_secp384r1
		return P384, nil
	case 716: // NID_secp521r1
		return P521, nil
	case 714: // NID_secp256k1
		return Secp256k1, nil
	case 1087: // NID_ED25519
		return Ed25519, nil
	default:
		return Unknown, errors.New("unsupported NID")
	}
}
