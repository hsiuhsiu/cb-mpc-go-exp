// Package mpc provides Go bindings for Coinbase's MPC (Multi-Party Computation) library.
//
// This package enables secure threshold cryptography protocols including:
//   - Two-party and multi-party ECDSA signing
//   - EdDSA/Schnorr signatures
//   - Distributed key generation
//   - Hierarchical deterministic key derivation
//   - Publicly verifiable encryption
//
// # Architecture
//
// The MPC protocols require coordination between multiple parties. Each party
// runs the same protocol functions simultaneously, communicating via a Session.
//
// Example two-party ECDSA key generation and signing:
//
//	// Party 1
//	session := NewLocalSession(parties, 0)
//	ecdsa := mpc.NewECDSA2PC(mpc.SECP256K1)
//	keyShare, err := ecdsa.KeyGen(ctx, session)
//	sig, err := ecdsa.Sign(ctx, session, keyShare, messageHash)
//
//	// Party 2
//	session := NewLocalSession(parties, 1)
//	ecdsa := mpc.NewECDSA2PC(mpc.SECP256K1)
//	keyShare, err := ecdsa.KeyGen(ctx, session)
//	sig, err := ecdsa.Sign(ctx, session, keyShare, messageHash)
//
// # Security Considerations
//
// - All cryptographic operations are designed to be constant-time to prevent
//   timing attacks. However, this depends on the compiler and CPU architecture.
//
// - The underlying C++ library is NOT thread-safe. Do not share Sessions or
//   KeyShares across goroutines without proper synchronization.
//
// - Key shares should be stored securely. Compromise of all key shares allows
//   recovery of the full private key.
//
// - Network communication between parties should use authenticated and encrypted
//   channels (e.g., mTLS) to prevent man-in-the-middle attacks.
//
// # Performance
//
// CGO calls have significant overhead (~100-200ns per call). This library
// minimizes CGO boundary crossings by batching operations where possible.
// For best performance:
//
//   - Reuse Session objects across multiple operations
//   - Sign multiple messages in batch when supported
//   - Use appropriate network transport (avoid unnecessary latency)
package mpc
