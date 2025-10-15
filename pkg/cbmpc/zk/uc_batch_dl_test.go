//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestBatchDLProofBasic tests basic UC_Batch_DL proof generation and verification.
func TestBatchDLProofBasic(t *testing.T) {
	// Generate 3 random exponents and corresponding points using C++ library
	numPoints := 3
	points := make([]*curve.Point, numPoints)
	scalars := make([]*curve.Scalar, numPoints)

	for i := 0; i < numPoints; i++ {
		exponent, err := curve.RandomScalar(curve.P256)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}
		scalars[i] = exponent
		defer exponent.Free()

		// Compute Q[i] = w[i]*G using C++ library
		point, err := curve.MulGenerator(curve.P256, exponent)
		if err != nil {
			t.Fatalf("failed to compute point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()
	}

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    points,
		Exponents: scalars,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveBatch failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("proof is empty")
	}

	// Verify proof
	err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
		Proof:     proof,
		Points:    points,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("VerifyBatch failed: %v", err)
	}
}

// TestBatchDLProofSinglePoint tests that batch proof works with a single point.
func TestBatchDLProofSinglePoint(t *testing.T) {
	// Generate a single exponent and point using C++ library
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}
	defer exponent.Free()

	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		t.Fatalf("failed to compute point: %v", err)
	}
	defer point.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof with single point
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    []*curve.Point{point},
		Exponents: []*curve.Scalar{exponent},
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveBatch failed: %v", err)
	}

	// Verify proof
	err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
		Proof:     proof,
		Points:    []*curve.Point{point},
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("VerifyBatch failed: %v", err)
	}
}

// TestBatchDLProofWrongPoint tests that verification fails with wrong point.
func TestBatchDLProofWrongPoint(t *testing.T) {
	// Generate 2 points with exponents using C++ library
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 2)

	for i := 0; i < 2; i++ {
		exponent, err := curve.RandomScalar(curve.P256)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}
		scalars[i] = exponent
		defer exponent.Free()

		point, err := curve.MulGenerator(curve.P256, exponent)
		if err != nil {
			t.Fatalf("failed to compute point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    points,
		Exponents: scalars,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveBatch failed: %v", err)
	}

	// Generate a different point using C++ library
	exponent3, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate third exponent: %v", err)
	}
	defer exponent3.Free()

	point3, err := curve.MulGenerator(curve.P256, exponent3)
	if err != nil {
		t.Fatalf("failed to compute third point: %v", err)
	}
	defer point3.Free()

	// Verify with wrong point should fail
	wrongPoints := []*curve.Point{points[0], point3}
	err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
		Proof:     proof,
		Points:    wrongPoints,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("VerifyBatch should have failed with wrong point")
	}
}

// TestBatchDLProofWrongSessionID tests that verification fails with wrong session ID.
func TestBatchDLProofWrongSessionID(t *testing.T) {
	// Generate 2 points with exponents using C++ library
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 2)

	for i := 0; i < 2; i++ {
		exponent, err := curve.RandomScalar(curve.P256)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}
		scalars[i] = exponent
		defer exponent.Free()

		point, err := curve.MulGenerator(curve.P256, exponent)
		if err != nil {
			t.Fatalf("failed to compute point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    points,
		Exponents: scalars,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveBatch failed: %v", err)
	}

	// Generate a different session ID
	wrongSessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(wrongSessionIDBytes); err != nil {
		t.Fatalf("failed to generate wrong session ID: %v", err)
	}
	wrongSessionID := cbmpc.NewSessionID(wrongSessionIDBytes)

	// Verify with wrong session ID should fail
	err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
		Proof:     proof,
		Points:    points,
		SessionID: wrongSessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("VerifyBatch should have failed with wrong session ID")
	}
}

// TestBatchDLProofCountMismatch tests that providing mismatched counts fails.
func TestBatchDLProofCountMismatch(t *testing.T) {
	// Generate 2 points but only 1 exponent using C++ library
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 1)

	for i := 0; i < 2; i++ {
		exponent, err := curve.RandomScalar(curve.P256)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}

		point, err := curve.MulGenerator(curve.P256, exponent)
		if err != nil {
			t.Fatalf("failed to compute point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		if i == 0 {
			scalars[i] = exponent
			defer exponent.Free()
		} else {
			exponent.Free()
		}
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof with mismatched counts should fail
	_, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    points,
		Exponents: scalars,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("ProveBatch should have failed with count mismatch")
	}
}
