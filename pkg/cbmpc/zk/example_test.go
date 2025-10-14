//go:build cgo && !windows

package zk_test

import (
	"crypto/elliptic"
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
	// Use P-256 curve
	ecCurve := elliptic.P256()

	// Generate a random discrete logarithm (exponent)
	exponentBig, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		return fmt.Errorf("failed to generate exponent: %w", err)
	}

	// Compute point Q = exponent*G
	qx, qy := ecCurve.ScalarBaseMult(exponentBig.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	// Create scalar
	exponent, err := curve.NewScalarFromBytes(exponentBig.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create scalar: %w", err)
	}
	defer exponent.Free()

	// Create curve point
	point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		return fmt.Errorf("failed to create point: %w", err)
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
	proof, err := zk.Prove(&zk.DLProveParams{
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
	err = zk.Verify(&zk.DLVerifyParams{
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
