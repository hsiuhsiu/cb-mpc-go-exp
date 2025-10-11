package kem

// KEM is the interface for Key Encapsulation Mechanisms used by PVE.
// Implementations provide encryption key generation, encapsulation, and decapsulation.
//
// This interface allows plugging in custom KEM schemes (e.g., ML-KEM, RSA-KEM, etc.)
// for use with publicly verifiable encryption.
//
// Note: The Decapsulate method's skHandle parameter can be any Go type, including
// types containing Go pointers. The backend layer automatically handles converting
// this to a CGO-safe handle when passing through C code.
type KEM interface {
	// Encapsulate generates a ciphertext and shared secret for the given public key.
	// rho is a 32-byte random seed for deterministic encapsulation.
	// Returns (ciphertext, shared_secret, error).
	Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the private key.
	// skHandle can be any Go value representing the private key.
	// Returns (shared_secret, error).
	Decapsulate(skHandle any, ct []byte) (ss []byte, err error)

	// DerivePub derives the public key from a private key reference.
	// skRef is a serialized reference to the private key.
	// Returns (public_key, error).
	DerivePub(skRef []byte) ([]byte, error)
}
