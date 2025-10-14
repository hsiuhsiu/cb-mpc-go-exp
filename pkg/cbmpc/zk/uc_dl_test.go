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

// TestDLProofBasic tests basic UC_DL proof generation and verification.
func TestDLProofBasic(t *testing.T) {
	// Use P-256 curve
	ecCurve := elliptic.P256()

	// Generate a random exponent w
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	// Compute Q = w*G
	qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	// Create curve point
	point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create point: %v", err)
	}
	defer point.Free()

	// Create scalar
	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof (returns []byte, no Close needed)
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("proof is empty")
	}

	// Verify proof (pass DLProof directly, not pointer)
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// TestDLProofSerialization tests that proofs are just bytes and can be copied freely.
func TestDLProofSerialization(t *testing.T) {
	ecCurve := elliptic.P256()

	// Generate exponent and point
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

	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("proof bytes are empty")
	}

	// Make a copy (proof is just []byte)
	proofCopy := make(zk.DLProof, len(proof))
	copy(proofCopy, proof)

	// Verify original proof
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Verify original failed: %v", err)
	}

	// Verify copied proof
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proofCopy,
		Point:     point,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Verify copy failed: %v", err)
	}
}

// TestDLProofWrongPoint tests that verification fails with wrong point.
func TestDLProofWrongPoint(t *testing.T) {
	ecCurve := elliptic.P256()

	// Generate exponent and point
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

	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Generate a different point
	w2, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate second exponent: %v", err)
	}

	q2x, q2y := ecCurve.ScalarBaseMult(w2.Bytes())
	q2Bytes := elliptic.MarshalCompressed(ecCurve, q2x, q2y)

	point2, err := curve.NewPointFromBytes(cbmpc.CurveP256, q2Bytes)
	if err != nil {
		t.Fatalf("failed to create second point: %v", err)
	}
	defer point2.Free()

	// Verify with wrong point should fail
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point2,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("Verify should have failed with wrong point")
	}
}

// TestDLProofWrongSessionID tests that verification fails with wrong session ID.
func TestDLProofWrongSessionID(t *testing.T) {
	ecCurve := elliptic.P256()

	// Generate exponent and point
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

	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Generate a different session ID
	wrongSessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(wrongSessionIDBytes); err != nil {
		t.Fatalf("failed to generate wrong session ID: %v", err)
	}
	wrongSessionID := cbmpc.NewSessionID(wrongSessionIDBytes)

	// Verify with wrong session ID should fail
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: wrongSessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("Verify should have failed with wrong session ID")
	}
}

// TestDLProofWrongAux tests that verification fails with wrong auxiliary data.
func TestDLProofWrongAux(t *testing.T) {
	ecCurve := elliptic.P256()

	// Generate exponent and point
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

	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Verify with wrong aux should fail
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       aux + 1,
	})
	if err == nil {
		t.Fatal("Verify should have failed with wrong aux")
	}
}

// TestDLProofMultiple tests multiple proofs can be generated and verified independently.
func TestDLProofMultiple(t *testing.T) {
	ecCurve := elliptic.P256()

	numProofs := 5
	proofs := make([]zk.DLProof, numProofs)
	exponents := make([]*big.Int, numProofs)
	points := make([]*curve.Point, numProofs)
	sessionIDs := make([]cbmpc.SessionID, numProofs)

	// Generate multiple proofs
	for i := 0; i < numProofs; i++ {
		w, err := rand.Int(rand.Reader, ecCurve.Params().N)
		if err != nil {
			t.Fatalf("failed to generate exponent %d: %v", i, err)
		}
		exponents[i] = w

		qx, qy := ecCurve.ScalarBaseMult(w.Bytes())
		qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

		point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
		if err != nil {
			t.Fatalf("failed to create point %d: %v", i, err)
		}
		points[i] = point
		defer point.Free()

		exponent, err := curve.NewScalarFromBytes(w.Bytes())
		if err != nil {
			t.Fatalf("failed to create scalar %d: %v", i, err)
		}
		defer exponent.Free()

		sessionIDBytes := make([]byte, 32)
		if _, err := rand.Read(sessionIDBytes); err != nil {
			t.Fatalf("failed to generate session ID %d: %v", i, err)
		}
		sessionID := cbmpc.NewSessionID(sessionIDBytes)
		sessionIDs[i] = sessionID

		proof, err := zk.ProveDL(&zk.DLProveParams{
			Point:     point,
			Exponent:  exponent,
			SessionID: sessionID,
			Aux:       uint64(i),
		})
		if err != nil {
			t.Fatalf("Prove %d failed: %v", i, err)
		}
		proofs[i] = proof
	}

	// Verify all proofs
	for i := 0; i < numProofs; i++ {
		err := zk.VerifyDL(&zk.DLVerifyParams{
			Proof:     proofs[i],
			Point:     points[i],
			SessionID: sessionIDs[i],
			Aux:       uint64(i),
		})
		if err != nil {
			t.Fatalf("Verify %d failed: %v", i, err)
		}
	}

	// Verify that cross-verification fails (proof i with point j where i != j)
	if numProofs >= 2 {
		err := zk.VerifyDL(&zk.DLVerifyParams{
			Proof:     proofs[0],
			Point:     points[1],
			SessionID: sessionIDs[0],
			Aux:       0,
		})
		if err == nil {
			t.Fatal("Cross-verification should have failed")
		}
	}
}

// TestDLProofValueSemantics tests that proofs have value semantics and can be safely copied.
func TestDLProofValueSemantics(t *testing.T) {
	ecCurve := elliptic.P256()

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

	exponent, err := curve.NewScalarFromBytes(w.Bytes())
	if err != nil {
		t.Fatalf("failed to create scalar: %v", err)
	}
	defer exponent.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	proof, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	// Test that proof can be copied and both work
	proof2 := proof // Simple assignment copies the bytes

	// Verify original
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Verify original failed: %v", err)
	}

	// Verify copy
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     proof2,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Verify copy failed: %v", err)
	}

	// Test empty proof returns error
	emptyProof := zk.DLProof(nil)
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     emptyProof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err == nil {
		t.Fatal("Verify with empty proof should return error")
	}
}
