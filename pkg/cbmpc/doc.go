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
// or Windows, functions that require the native library return ErrNotBuilt.
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
//	// Set up two-party jobs
//	names := [2]string{"party1", "party2"}
//	transport1 := net.Ep2P(cbmpc.RoleID(0), cbmpc.RoleID(1))
//	transport2 := net.Ep2P(cbmpc.RoleID(1), cbmpc.RoleID(0))
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//	defer cancel()
//
//	job1, _ := cbmpc.NewJob2P(transport1, cbmpc.RoleP1, names)
//	defer job1.Close()
//
//	job2, _ := cbmpc.NewJob2P(transport2, cbmpc.RoleP2, names)
//	defer job2.Close()
//
//	// Run protocol
//	result1, _ := agreerandom.AgreeRandom(ctx, job1, 256)
//	result2, _ := agreerandom.AgreeRandom(ctx, job2, 256)
//
// # Subpackages
//
// Protocol implementations and support packages:
//   - accessstructure - DSL for access control structures
//   - agreerandom - Multi-party random agreement protocols
//   - curve - Elliptic curve types and operations
//   - ecdsa2p - 2-party ECDSA protocols
//   - ecdsamp - Multi-party threshold ECDSA protocols
//   - kem - Key Encapsulation Mechanism (KEM) for PVE
//   - logging - Minimal logging facade (slog adapter)
//   - mocknet - In-memory transport for tests and examples
//   - paillier - Homomorphic Paillier cryptosystem
//   - pve - Publicly Verifiable Encryption
//   - schnorr2p - 2-party Schnorr signature protocols
//   - schnorrmp - Multi-party threshold Schnorr protocols
//   - zk - Zero-knowledge proof protocols
package cbmpc
