// Package ecdsamp provides multi-party ECDSA protocols with threshold signing.
//
// This package implements threshold ECDSA protocols that allow n parties to jointly
// generate an ECDSA key and create signatures with a threshold of t+1 parties (where
// t < n). The protocols support both key generation and signing with flexible threshold
// parameters.
//
// # Threshold Signing
//
// Threshold ECDSA allows a subset of parties to cooperate to create signatures:
//   - Key generation involves all n parties
//   - Signing requires any t+1 parties (threshold)
//   - The private key is never reconstructed on a single device
//   - The scheme is secure as long as at most t parties are compromised
//
// # Key Operations
//
//   - DKG: Distributed Key Generation for n parties with threshold t
//   - Sign: Threshold signature generation (requires t+1 parties)
//   - Refresh: Key share refresh while preserving the public key
//
// # Memory Management
//
// Keys contain sensitive cryptographic material and must be explicitly freed:
//
//	result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{
//	    Curve:     cbmpc.CurveP256,
//	    Threshold: 2,
//	})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
//
// # Usage Example
//
//	// 3-of-5 threshold: 5 parties generate keys, any 3 can sign
//	params := &ecdsamp.DKGParams{
//	    Curve:     cbmpc.CurveP256,
//	    Threshold: 2, // t=2 means 3 parties needed to sign (t+1)
//	}
//
//	// All 5 parties run DKG
//	result1, _ := ecdsamp.DKG(ctx, job1, params)
//	defer result1.Key.Close()
//	// ... (parties 2-5 also run DKG)
//
//	// Any 3 parties can cooperate to sign
//	messageHash := sha256.Sum256([]byte("message to sign"))
//	sig1, _ := ecdsamp.Sign(ctx, job1, &ecdsamp.SignParams{
//	    Key:     result1.Key,
//	    Message: messageHash[:],
//	})
//	// ... (2 other parties also sign)
//
// See cb-mpc/src/cbmpc/protocol/ecdsa_mp.h for protocol implementation details.
package ecdsamp
