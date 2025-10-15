// Package pve provides Publicly Verifiable Encryption (PVE) protocols.
//
// Publicly Verifiable Encryption allows anyone to verify that a ciphertext was
// correctly generated for a specific public key and plaintext commitment, without
// revealing the plaintext or requiring the private key. This is essential for
// secure multi-party computation where parties need to prove they encrypted
// values correctly.
//
// # Protocol Overview
//
// PVE combines:
//   - Deterministic public-key encryption (via KEM)
//   - Commitment to the plaintext (elliptic curve point Q = x*G)
//   - Zero-knowledge proof binding the ciphertext to the commitment
//
// The verifier can check:
//   - The ciphertext was generated using the correct public key
//   - The ciphertext encrypts a value x such that Q = x*G
//   - The encryption was performed honestly
//
// # Key Operations
//
//   - Encrypt: Creates a PVE ciphertext with proof
//   - Verify: Verifies a PVE ciphertext against a commitment
//   - Decrypt: Decrypts a PVE ciphertext to recover the scalar
//
// # KEM Requirements
//
// PVE requires a deterministic KEM (Key Encapsulation Mechanism). The KEM must:
//   - Use deterministic encryption (same seed → same ciphertext)
//   - Provide domain separation (different keys → different ciphertexts)
//   - Implement the cbmpc.KEM interface
//
// See pkg/cbmpc/kem for available KEM implementations.
//
// # Security Properties
//
// PVE provides:
//   - Public verifiability: Anyone can verify correct encryption
//   - UC security: Universally composable in the random oracle model
//   - Hiding: Ciphertext does not reveal the plaintext without the private key
//   - Binding: Prover cannot create valid proofs for incorrect ciphertexts
//
// # Usage Example
//
//	import (
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
//	)
//
//	// Create KEM and PVE instance
//	kem, _ := rsa.New(2048)
//	_, ek, _ := kem.Generate()
//	pveInstance, _ := pve.New(kem)
//
//	// Encrypt a scalar value
//	x, _ := curve.NewScalarFromString("123456789")
//	defer x.Free()
//
//	result, _ := pveInstance.Encrypt(ctx, &pve.EncryptParams{
//	    EK:    ek,
//	    Label: []byte("my-label"),
//	    Curve: cbmpc.CurveP256,
//	    X:     x,
//	})
//
//	// Extract commitment Q for verification
//	Q, _ := result.Ciphertext.Q()
//	defer Q.Free()
//
//	// Anyone can verify the ciphertext
//	err := pveInstance.Verify(ctx, &pve.VerifyParams{
//	    EK:         ek,
//	    Ciphertext: result.Ciphertext,
//	    Q:          Q,
//	    Label:      []byte("my-label"),
//	})
//	// err == nil means verification succeeded
//
// See cb-mpc/src/cbmpc/protocol/pve.h for protocol implementation details.
package pve
