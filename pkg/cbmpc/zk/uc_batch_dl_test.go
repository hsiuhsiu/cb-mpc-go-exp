//go:build cgo && !windows

package zk_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestBatchDLProofBasic tests basic UC_Batch_DL proof generation and verification.
func TestBatchDLProofBasic(t *testing.T) {
	// Use P-256 curve
	ecCurve := elliptic.P256()

	// Generate 3 random exponents and corresponding points
	numPoints := 3
	exponents := make([]*big.Int, numPoints)
	points := make([]*curve.Point, numPoints)
	scalars := make([]*curve.Scalar, numPoints)

	for i := 0; i < numPoints; i++ {
		w, err := rand.Int(rand.Reader, ecCurve.Params().N)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}
		exponents[i] = w

		// Compute Q[i] = w[i]*G
		qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
		qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

		point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
		if err != nil {
			t.Fatalf("failed to create point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		scalar, err := curve.NewScalarFromBytes(w.Bytes())
		if err != nil {
			t.Fatalf("failed to create scalar %d: %v", i, err)
		}
		scalars[i] = scalar
		defer scalar.Free()
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
	ecCurve := elliptic.P256()

	// Generate a single exponent and point
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create point: %v", err)
	}
	defer point.Free()

	scalar, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer scalar.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof with single point
	proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
		Points:    []*curve.Point{point},
		Exponents: []*curve.Scalar{scalar},
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
	ecCurve := elliptic.P256()

	// Generate 2 points with exponents
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 2)

	for i := 0; i < 2; i++ {
		w, err := rand.Int(rand.Reader, ecCurve.Params().N)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}

		qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
		qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

		point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
		if err != nil {
			t.Fatalf("failed to create point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		scalar, err := curve.NewScalarFromBytes(w.Bytes())
		if err != nil {
			t.Fatalf("failed to create scalar %d: %v", i, err)
		}
		scalars[i] = scalar
		defer scalar.Free()
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

	// Generate a different point
	w3, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate third exponent: %v", err)
	}

	q3x, q3y := ecCurve.ScalarBaseMult(w3.Bytes())
	q3Bytes := elliptic.MarshalCompressed(ecCurve, q3x, q3y)

	point3, err := curve.NewPointFromBytes(cbmpc.CurveP256, q3Bytes)
	if err != nil {
		t.Fatalf("failed to create third point: %v", err)
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
	ecCurve := elliptic.P256()

	// Generate 2 points with exponents
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 2)

	for i := 0; i < 2; i++ {
		w, err := rand.Int(rand.Reader, ecCurve.Params().N)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}

		qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
		qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

		point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
		if err != nil {
			t.Fatalf("failed to create point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		scalar, err := curve.NewScalarFromBytes(w.Bytes())
		if err != nil {
			t.Fatalf("failed to create scalar %d: %v", i, err)
		}
		scalars[i] = scalar
		defer scalar.Free()
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
	ecCurve := elliptic.P256()

	// Generate 2 points but only 1 exponent
	points := make([]*curve.Point, 2)
	scalars := make([]*curve.Scalar, 1)

	for i := 0; i < 2; i++ {
		w, err := rand.Int(rand.Reader, ecCurve.Params().N)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}

		qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
		qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

		point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
		if err != nil {
			t.Fatalf("failed to create point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		if i == 0 {
			scalar, err := curve.NewScalarFromBytes(w.Bytes())
			if err != nil {
				t.Fatalf("failed to create scalar %d: %v", i, err)
			}
			scalars[i] = scalar
			defer scalar.Free()
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
