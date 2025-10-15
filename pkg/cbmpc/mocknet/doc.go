// Package mocknet provides an in-memory transport implementation for testing and examples.
//
// Mocknet implements the cbmpc.Transport interface using in-memory channels,
// allowing MPC protocol tests to run without actual network communication.
// It provides sequenced, reliable message delivery between parties and is
// ideal for unit tests, integration tests, and local examples.
//
// # Features
//
//   - Sequenced message delivery (guarantees message ordering)
//   - Support for both 2-party and multi-party protocols
//   - Context-based cancellation support
//   - Thread-safe concurrent operations
//   - No external dependencies (pure Go)
//
// # Usage
//
// Create a network and endpoints for each party:
//
//	import (
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
//	)
//
//	// Create mock network
//	net := mocknet.New()
//
//	// Two-party setup
//	ep1 := net.Ep2P(cbmpc.RoleID(0), cbmpc.RoleID(1)) // Party 0 communicates with Party 1
//	ep2 := net.Ep2P(cbmpc.RoleID(1), cbmpc.RoleID(0)) // Party 1 communicates with Party 0
//
//	// Multi-party setup (3 parties)
//	allParties := []cbmpc.RoleID{0, 1, 2}
//	ep1 := net.EpMP(cbmpc.RoleID(0), allParties)
//	ep2 := net.EpMP(cbmpc.RoleID(1), allParties)
//	ep3 := net.EpMP(cbmpc.RoleID(2), allParties)
//
// # Creating Jobs
//
// Use mocknet endpoints to create Job2P or JobMP instances:
//
//	// Two-party job
//	job1, _ := cbmpc.NewJob2PWithContext(ctx, ep1, cbmpc.RoleP1, [2]string{"party1", "party2"})
//	defer job1.Close()
//
//	// Multi-party job (threshold t=1, 3 parties total)
//	jobMP, _ := cbmpc.NewJobMPWithContext(ctx, epMP, cbmpc.RoleID(0), 1, 3, []string{"p0", "p1", "p2"})
//	defer jobMP.Close()
//
// # Running Protocols
//
// Run protocol operations concurrently using goroutines:
//
//	var wg sync.WaitGroup
//	wg.Add(2)
//
//	go func() {
//	    defer wg.Done()
//	    result1, _ := ecdsa2p.DKG(ctx, job1, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	    defer result1.Key.Close()
//	}()
//
//	go func() {
//	    defer wg.Done()
//	    result2, _ := ecdsa2p.DKG(ctx, job2, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	    defer result2.Key.Close()
//	}()
//
//	wg.Wait()
//
// # Testing Tips
//
//   - Always use context.WithTimeout to prevent test hangs
//   - Run parties in separate goroutines to simulate concurrent execution
//   - Use sync.WaitGroup to coordinate protocol completion
//   - Check for errors from both parties (protocol failures should be symmetric)
//
// # Limitations
//
// Mocknet is designed for testing and examples only:
//   - No encryption or authentication
//   - No network latency simulation
//   - No packet loss or reordering
//   - Not suitable for production use
//
// For production deployments, implement cbmpc.Transport using actual network
// protocols (e.g., TLS, gRPC, WebSocket). See examples/tlsnet for a TLS-based
// transport implementation.
package mocknet
