//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestDHProofBasic tests basic DH proof generation and verification.
func TestDHProofBasic(t *testing.T) {
	// Generate a random scalar for Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	// Compute Q = qScalar * G
	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate a random exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}
	defer exponent.Free()

	// Compute A = w*G
	aPoint, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bPoint, err := qPoint.Mul(exponent)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDH(&zk.DHProveParams{
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveDH failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("proof is empty")
	}

	// Verify proof
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof,
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("VerifyDH failed: %v", err)
	}
}

// TestDHProofWrongB tests that verification fails with wrong B point.
func TestDHProofWrongB(t *testing.T) {
	// Generate a random scalar for Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	// Compute Q = qScalar * G
	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}
	defer exponent.Free()

	// Compute A = w*G
	aPoint, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bPoint, err := qPoint.Mul(exponent)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDH(&zk.DHProveParams{
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveDH failed: %v", err)
	}

	// Generate a different B point
	w2, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate second exponent: %v", err)
	}
	defer w2.Free()

	b2Point, err := qPoint.Mul(w2)
	if err != nil {
		t.Fatalf("failed to create second B point: %v", err)
	}
	defer b2Point.Free()

	// Verify with wrong B should fail
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof,
		Q:         qPoint,
		A:         aPoint,
		B:         b2Point,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("VerifyDH should have failed with wrong B point")
	}
}

// TestDHProofWrongSessionID tests that verification fails with wrong session ID.
func TestDHProofWrongSessionID(t *testing.T) {
	// Generate a random scalar for Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	// Compute Q = qScalar * G
	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}
	defer exponent.Free()

	// Compute A = w*G
	aPoint, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bPoint, err := qPoint.Mul(exponent)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDH(&zk.DHProveParams{
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveDH failed: %v", err)
	}

	// Generate a different session ID
	wrongSessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(wrongSessionIDBytes); err != nil {
		t.Fatalf("failed to generate wrong session ID: %v", err)
	}
	wrongSessionID := cbmpc.NewSessionID(wrongSessionIDBytes)

	// Verify with wrong session ID should fail
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof,
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		SessionID: wrongSessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("VerifyDH should have failed with wrong session ID")
	}
}

// TestDHProofValueSemantics tests that DH proofs have value semantics.
func TestDHProofValueSemantics(t *testing.T) {
	// Generate a random scalar for Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	// Compute Q = qScalar * G
	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}
	defer exponent.Free()

	// Compute A = w*G
	aPoint, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bPoint, err := qPoint.Mul(exponent)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveDH(&zk.DHProveParams{
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveDH failed: %v", err)
	}

	// Test that proof can be copied and both work
	proof2 := proof // Simple assignment copies the bytes

	// Verify original
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof,
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Verify original failed: %v", err)
	}

	// Verify copy
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     proof2,
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("Verify copy failed: %v", err)
	}

	// Test empty proof returns error
	emptyProof := zk.DHProof(nil)
	err = zk.VerifyDH(&zk.DHVerifyParams{
		Proof:     emptyProof,
		Q:         qPoint,
		A:         aPoint,
		B:         bPoint,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Fatal("Verify with empty proof should return error")
	}
}
