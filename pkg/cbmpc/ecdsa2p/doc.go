// Package ecdsa2p provides two-party ECDSA (Elliptic Curve Digital Signature Algorithm) protocols.
//
// This package implements secure two-party ECDSA protocols for distributed key generation,
// signing, and key refresh. The protocols allow two parties to jointly generate an ECDSA
// key pair and create signatures without ever reconstructing the full private key on a
// single device.
//
// # Security Model
//
// The 2-party ECDSA implementation provides security against a malicious adversary who
// controls one of the two parties. Even if one party is compromised, the attacker cannot:
//   - Learn the complete private key
//   - Create valid signatures without the honest party's cooperation
//   - Forge signatures on arbitrary messages
//
// # Key Operations
//
//   - DKG: Distributed Key Generation - Creates a shared ECDSA key
//   - Sign: Generates an ECDSA signature on a message hash
//   - SignBatch: Generates multiple ECDSA signatures efficiently
//   - SignWithGlobalAbort: Signing with enhanced security checks
//   - SignWithGlobalAbortBatch: Batch signing with enhanced security checks
//   - Refresh: Refreshes a key share while preserving the public key
//
// # Memory Management
//
// Keys contain sensitive cryptographic material and must be explicitly freed:
//
//	result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
//
// Key bytes returned by Key.Bytes() contain sensitive data and should be zeroized:
//
//	keyBytes, err := key.Bytes()
//	if err != nil {
//	    return err
//	}
//	defer cbmpc.ZeroizeBytes(keyBytes)
//
// # Usage Example
//
//	// Party 1 and Party 2 run DKG to generate key shares
//	result1, err := ecdsa2p.DKG(ctx, job1, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	defer result1.Key.Close()
//
//	result2, err := ecdsa2p.DKG(ctx, job2, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	defer result2.Key.Close()
//
//	// Both parties generate the same public key
//	pubKey1, _ := result1.Key.PublicKey()
//	pubKey2, _ := result2.Key.PublicKey()
//	// pubKey1 == pubKey2
//
//	// Sign a message hash
//	messageHash := sha256.Sum256([]byte("message to sign"))
//	sig1, err := ecdsa2p.Sign(ctx, job1, &ecdsa2p.SignParams{
//	    Key:     result1.Key,
//	    Message: messageHash[:],
//	})
//
//	sig2, err := ecdsa2p.Sign(ctx, job2, &ecdsa2p.SignParams{
//	    Key:     result2.Key,
//	    Message: messageHash[:],
//	})
//	// sig1.Signature == sig2.Signature (both parties compute the same signature)
//
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol implementation details.
package ecdsa2p
