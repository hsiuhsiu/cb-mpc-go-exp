// Package schnorr2p provides two-party Schnorr signature protocols.
//
// This package implements secure two-party Schnorr signature protocols supporting
// both EdDSA (Ed25519) and BIP340 (Bitcoin Schnorr) signature schemes. The protocols
// enable two parties to jointly generate a Schnorr key pair and create signatures
// without reconstructing the full private key on a single device.
//
// # Supported Variants
//
//   - EdDSA (Ed25519): Edwards-curve Digital Signature Algorithm
//   - BIP340: Bitcoin Improvement Proposal 340 (Schnorr signatures on secp256k1)
//
// The variant determines message handling:
//   - EdDSA: Signs raw messages (not pre-hashed, any length)
//   - BIP340: Signs pre-hashed messages (must be exactly 32 bytes)
//
// # Key Operations
//
//   - DKG: Distributed Key Generation
//   - Sign: Generate a Schnorr signature
//   - SignBatch: Generate multiple Schnorr signatures efficiently
//
// # Security Properties
//
// Two-party Schnorr provides:
//   - Security against a malicious adversary controlling one party
//   - No single point of compromise (key shares never combined)
//   - Deterministic signatures (no need for secure randomness per signature)
//   - Batch signing support for efficient multi-message signing
//
// # Memory Management
//
// Keys contain sensitive cryptographic material and must be explicitly freed:
//
//	result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{Curve: cbmpc.CurveEd25519})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
//
// # Usage Example
//
//	// EdDSA (Ed25519) signing
//	result, _ := schnorr2p.DKG(ctx, job1, &schnorr2p.DKGParams{Curve: cbmpc.CurveEd25519})
//	defer result.Key.Close()
//
//	message := []byte("message to sign")
//	sig, _ := schnorr2p.Sign(ctx, job1, &schnorr2p.SignParams{
//	    Key:     result.Key,
//	    Message: message, // Raw message (EdDSA hashes it internally)
//	    Variant: schnorr2p.VariantEdDSA,
//	})
//
//	// BIP340 (secp256k1) signing
//	result2, _ := schnorr2p.DKG(ctx, job2, &schnorr2p.DKGParams{Curve: cbmpc.CurveSecp256k1})
//	defer result2.Key.Close()
//
//	messageHash := sha256.Sum256([]byte("message to sign"))
//	sig2, _ := schnorr2p.Sign(ctx, job2, &schnorr2p.SignParams{
//	    Key:     result2.Key,
//	    Message: messageHash[:], // Must be exactly 32 bytes for BIP340
//	    Variant: schnorr2p.VariantBIP340,
//	})
//
// See cb-mpc/src/cbmpc/protocol/schnorr_2p.h for protocol implementation details.
package schnorr2p
