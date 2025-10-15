// Package schnorrmp provides multi-party threshold Schnorr signature protocols.
//
// This package implements threshold Schnorr signature protocols supporting both
// EdDSA (Ed25519) and BIP340 (Bitcoin Schnorr) schemes. The protocols allow n
// parties to jointly generate a Schnorr key with threshold t, where any t+1
// parties can cooperate to create signatures.
//
// # Threshold Signing
//
// Threshold Schnorr allows a subset of parties to cooperate to create signatures:
//   - Key generation involves all n parties
//   - Signing requires any t+1 parties (threshold)
//   - The private key is never reconstructed on a single device
//   - Secure as long as at most t parties are compromised
//
// # Supported Variants
//
//   - EdDSA (Ed25519): Signs raw messages (any length)
//   - BIP340: Signs pre-hashed messages (exactly 32 bytes)
//
// # Key Operations
//
//   - DKG: Distributed Key Generation for n parties with threshold t
//   - Sign: Threshold Schnorr signature generation
//   - SignBatch: Batch threshold signing for multiple messages
//   - Refresh: Key share refresh while preserving the public key
//
// # Memory Management
//
// Keys contain sensitive cryptographic material and must be explicitly freed:
//
//	result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
//	    Curve:     cbmpc.CurveEd25519,
//	    Threshold: 2, // Requires 3 parties to sign (t+1)
//	})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
//
// # Usage Example
//
//	// 3-of-5 threshold EdDSA: 5 parties generate keys, any 3 can sign
//	params := &schnorrmp.DKGParams{
//	    Curve:     cbmpc.CurveEd25519,
//	    Threshold: 2, // t=2 means 3 parties needed (t+1)
//	}
//
//	result, _ := schnorrmp.DKG(ctx, job1, params)
//	defer result.Key.Close()
//
//	// Any 3 parties cooperate to sign
//	message := []byte("message to sign")
//	sig, _ := schnorrmp.Sign(ctx, job1, &schnorrmp.SignParams{
//	    Key:     result.Key,
//	    Message: message,
//	    Variant: schnorrmp.VariantEdDSA,
//	})
//
// See cb-mpc/src/cbmpc/protocol/schnorr_mp.h for protocol implementation details.
package schnorrmp
