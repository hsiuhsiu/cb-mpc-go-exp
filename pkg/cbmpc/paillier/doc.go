// Package paillier provides a Go wrapper for the Paillier homomorphic cryptosystem.
//
// The Paillier cryptosystem is a probabilistic asymmetric algorithm for public key
// cryptography with additive homomorphic properties. It allows computation on encrypted
// data without decrypting it first.
//
// # Key Operations
//
//   - Generate(): Create a new keypair (2048-bit modulus)
//   - FromPublicKey(): Create from modulus N (public key only)
//   - FromPrivateKey(): Create from N, p, q (full private key)
//   - Encrypt(): Encrypt plaintext to ciphertext
//   - Decrypt(): Decrypt ciphertext to plaintext (requires private key)
//   - AddCiphers(): Homomorphically add two ciphertexts (E(a) + E(b) = E(a+b))
//   - MulScalar(): Homomorphically multiply ciphertext by scalar (E(a) * k = E(a*k))
//   - VerifyCipher(): Verify that a ciphertext is well-formed
//   - Serialize()/Deserialize(): Save and load keys
//
// # Memory Management
//
// Paillier instances hold C++ resources and must be freed by calling Close() when done.
// Alternatively, rely on the finalizer for automatic cleanup (though explicit Close() is recommended).
//
// # Homomorphic Properties
//
// The Paillier cryptosystem supports:
//   - Additive homomorphism: E(m1) * E(m2) = E(m1 + m2)
//   - Scalar multiplication: E(m)^k = E(k * m)
//
// These properties are exposed via AddCiphers() and MulScalar() methods.
//
// # Usage Example
//
//	// Generate a keypair
//	paillier, err := paillier.Generate()
//	if err != nil {
//	    return err
//	}
//	defer paillier.Close()
//
//	// Encrypt two values
//	c1, err := paillier.Encrypt([]byte{0x03})
//	c2, err := paillier.Encrypt([]byte{0x05})
//
//	// Homomorphically add them: E(3) + E(5) = E(8)
//	cSum, err := paillier.AddCiphers(c1, c2)
//
//	// Decrypt the sum
//	plaintext, err := paillier.Decrypt(cSum)
//	// plaintext contains 0x08
//
// See cb-mpc/src/cbmpc/crypto/base_paillier.h for implementation details.
package paillier
