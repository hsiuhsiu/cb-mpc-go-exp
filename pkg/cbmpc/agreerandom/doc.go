// Package agreerandom provides secure multi-party random value agreement protocols.
//
// This package implements various protocols for two or more parties to jointly
// generate shared random values without requiring trust in any single party.
// Each protocol provides different security guarantees and is suitable for
// different use cases in secure multi-party computation.
//
// # Available Protocols
//
//   - AgreeRandom: Two-party random agreement (fully secure)
//   - MultiAgreeRandom: Multi-party random agreement (fully secure)
//   - WeakMultiAgreeRandom: Multi-party random agreement (faster, weaker security)
//   - MultiPairwiseAgreeRandom: Multi-party pairwise random agreement (fully secure)
//
// # Usage
//
//	// Two-party example
//	random, err := agreerandom.AgreeRandom(ctx, job2P, 256)
//
//	// Multi-party example
//	random, err := agreerandom.MultiAgreeRandom(ctx, jobMP, 256)
//
//	// Pairwise random values (n parties generate n pairwise randoms)
//	randoms, err := agreerandom.MultiPairwiseAgreeRandom(ctx, jobMP, 256)
//
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol implementation details.
package agreerandom
