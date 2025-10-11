// Package cbmpc provides Go bindings for the Coinbase cb-mpc library.
//
// This package is a thin wrapper around the C++ MPC protocol implementations
// in the cb-mpc submodule. It uses CGO to bridge between Go and C++.
//
// # Architecture
//
// The package is organized in layers:
//   - pkg/cbmpc/ - Public Go API (this package)
//   - pkg/cbmpc/internal/backend/ - CGO bindings layer
//   - cb-mpc/ - C++ MPC protocol implementations (git submodule)
//
// # Build Requirements
//
// This package requires CGO and is not available on Windows. On non-CGO builds
// or Windows, stub implementations return ErrNotBuilt.
//
// # Protocol Documentation
//
// Protocol details and specifications are documented in the C++ headers.
// See cb-mpc/src/cbmpc/protocol/ for protocol implementations.
//
// # Example Usage
//
//	// Create a mock network for testing
//	net := mocknet.New()
//
//	// Set up two-party job
//	p1 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP1), cbmpc.RoleID(cbmpc.RoleP2))
//	p2 := net.Ep2P(cbmpc.RoleID(cbmpc.RoleP2), cbmpc.RoleID(cbmpc.RoleP1))
//	names := [2]string{"party1", "party2"}
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//	defer cancel()
//
//	job1, _ := cbmpc.NewJob2PWithContext(ctx, p1, cbmpc.RoleP1, names)
//	defer job1.Close()
//
//	job2, _ := cbmpc.NewJob2PWithContext(ctx, p2, cbmpc.RoleP2, names)
//	defer job2.Close()
//
//	// Run protocol
//	result1, _ := agreerandom.AgreeRandom(ctx, job1, 256)
//	result2, _ := agreerandom.AgreeRandom(ctx, job2, 256)
//
// # Subpackages
//
// Protocol implementations are organized into subpackages:
//   - agreerandom - Agree Random protocols
//   - ecdsa2p - 2-party ECDSA protocols
//   - pve - Publicly Verifiable Encryption
package cbmpc
