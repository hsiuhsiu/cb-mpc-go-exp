// Package kem provides a Key Encapsulation Mechanism (KEM) abstraction for PVE.
//
// IMPORTANT: This package provides DETERMINISTIC KEMs specifically designed for
// Publicly Verifiable Encryption (PVE). These are NOT general-purpose randomized
// KEMs and should ONLY be used within the PVE protocol context.
//
// # Security Warning
//
// All KEM implementations in this package are DETERMINISTIC:
//   - Same (public_key, rho) → same ciphertext
//   - NOT suitable for general public-key encryption
//   - ONLY safe within the PVE protocol (see pkg/cbmpc/pve)
//   - Each encryption must use a fresh, unpredictable rho value
//
// DO NOT use these KEMs for:
//   - General-purpose public-key encryption
//   - Applications requiring IND-CCA2 security
//   - Standard PKI/TLS applications
//   - File or message encryption outside of PVE
//
// # Available Implementations
//
// Currently supported:
//   - rsa: Deterministic RSA-OAEP (2048/3072/4096-bit)
//
// # Why Determinism?
//
// PVE requires deterministic encryption because:
//   - Verifiers must be able to recompute the ciphertext
//   - The ciphertext must be cryptographically bound to a commitment Q
//   - The proof system uses Fiat-Shamir transformation
//
// The deterministic property is essential for public verifiability but makes
// these KEMs unsafe for general encryption use cases.
//
// # Domain Separation
//
// To prevent cross-key attacks with deterministic encryption, implementations
// provide domain separation:
//   - Each public key has a unique OAEP label
//   - Seed derivation includes the public key hash
//   - Same rho with different keys produces different ciphertexts
//
// # Interface
//
// The cbmpc.KEM interface defines:
//
//	type KEM interface {
//	    Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error)
//	    Decapsulate(skHandle any, ct []byte) (ss []byte, err error)
//	    DerivePub(skRef []byte) ([]byte, error)
//	}
//
// # Usage
//
// KEMs are typically used through the pve package:
//
//	import (
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
//	)
//
//	// Create KEM
//	kem, _ := rsa.New(2048)
//
//	// Use with PVE (recommended)
//	pveInstance, _ := pve.New(kem)
//	// ... use pveInstance for Encrypt/Verify/Decrypt
//
// See pkg/cbmpc/kem/README.md for detailed security documentation.
package kem
