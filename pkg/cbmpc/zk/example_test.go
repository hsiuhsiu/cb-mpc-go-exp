//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Example demonstrates basic usage of UC_DL proofs.
func Example() {
	if err := runExample(); err != nil {
		log.Fatalf("example failed: %v", err)
	}
	// Output:
	// Generated proof
	// Proof verified successfully!
}

func runExample() error {
	// Generate a random discrete logarithm (exponent) using C++ library
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return fmt.Errorf("failed to generate exponent: %w", err)
	}
	defer exponent.Free()

	// Compute point Q = exponent*G using C++ library
	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		return fmt.Errorf("failed to compute point: %w", err)
	}
	defer point.Free()

	// Generate session ID for proof security
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Create proof that proves knowledge of exponent such that Q = exponent*G
	// Proof is just []byte - no Close() needed, safe to copy and serialize
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	fmt.Println("Generated proof")

	// Proof can be used directly - it's already serialized bytes
	// Can pass across goroutines, store in database, send over network, etc.

	// Verify proof
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	fmt.Println("Proof verified successfully!")
	return nil
}
