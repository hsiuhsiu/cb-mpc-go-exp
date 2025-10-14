package kem

// KEM is the interface for DETERMINISTIC Key Encapsulation Mechanisms used by PVE.
//
// SECURITY WARNING: This is NOT a general-purpose randomized KEM!
//
// All implementations in this package are DETERMINISTIC and specifically designed
// for Publicly Verifiable Encryption (PVE). The encapsulation uses a deterministic
// seed (rho) instead of random bytes, which is REQUIRED for PVE's verifiability
// properties but UNSAFE for general encryption use cases.
//
// Key security properties:
//   - Deterministic: Same (ek, rho) produces identical ciphertext
//   - Domain-separated: Different keys with same rho produce different ciphertexts
//   - Key-bound: Ciphertexts are bound to the public key via OAEP label
//
// DO NOT use these KEM implementations for:
//   - General-purpose public-key encryption
//   - Applications requiring IND-CCA2 security against adaptive attacks
//   - Any use case where rho could be reused across different messages
//
// Safe use requires:
//   - Fresh, unpredictable rho for each encryption
//   - PVE protocol context where determinism is intentional
//   - Understanding that security relies on rho never being reused
//
// This interface allows plugging in custom deterministic KEM schemes
// (e.g., deterministic RSA-OAEP, ML-KEM with fixed randomness) for PVE.
//
// Note: The Decapsulate method's skHandle parameter can be any Go type, including
// types containing Go pointers. The backend layer automatically handles converting
// this to a CGO-safe handle when passing through C code.
type KEM interface {
	// Encapsulate generates a ciphertext and shared secret for the given public key.
	//
	// DETERMINISTIC: Uses rho as a deterministic seed instead of random bytes.
	// The same (ek, rho) pair will always produce the same ciphertext.
	//
	// Parameters:
	//   - ek: Public key (format depends on implementation)
	//   - rho: 32-byte DETERMINISTIC seed (must be fresh and unpredictable)
	//
	// Returns (ciphertext, shared_secret, error).
	Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the private key.
	//
	// Parameters:
	//   - skHandle: Private key handle (can be any Go value)
	//   - ct: Ciphertext to decrypt
	//
	// Returns (shared_secret, error).
	Decapsulate(skHandle any, ct []byte) (ss []byte, err error)

	// DerivePub derives the public key from a private key reference.
	//
	// Parameters:
	//   - skRef: Serialized reference to the private key
	//
	// Returns (public_key, error).
	DerivePub(skRef []byte) ([]byte, error)
}
