//go:build cgo && !windows

package zk_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestDHProofBasic tests basic DH proof generation and verification.
func TestDHProofBasic(t *testing.T) {
	// Use P-256 curve
	ecCurve := elliptic.P256()

	// Generate a random base point Q
	qPriv, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate Q exponent: %v", err)
	}
	qx, qy := ecCurve.ScalarBaseMult(qPriv.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	qPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate a random exponent w
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	// Compute A = w*G
	ax, ay := ecCurve.ScalarBaseMult(w.Bytes())
	aBytes := elliptic.MarshalCompressed(ecCurve, ax, ay)

	aPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, aBytes)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bx, by := ecCurve.ScalarMult(qx, qy, w.Bytes())
	bBytes := elliptic.MarshalCompressed(ecCurve, bx, by)

	bPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, bBytes)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

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
	ecCurve := elliptic.P256()

	// Generate Q point
	qPriv, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate Q exponent: %v", err)
	}
	qx, qy := ecCurve.ScalarBaseMult(qPriv.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	qPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	// Compute A = w*G
	ax, ay := ecCurve.ScalarBaseMult(w.Bytes())
	aBytes := elliptic.MarshalCompressed(ecCurve, ax, ay)

	aPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, aBytes)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bx, by := ecCurve.ScalarMult(qx, qy, w.Bytes())
	bBytes := elliptic.MarshalCompressed(ecCurve, bx, by)

	bPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, bBytes)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

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
	w2, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate second exponent: %v", err)
	}

	b2x, b2y := ecCurve.ScalarMult(qx, qy, w2.Bytes())
	b2Bytes := elliptic.MarshalCompressed(ecCurve, b2x, b2y)

	b2Point, err := curve.NewPointFromBytes(cbmpc.CurveP256, b2Bytes)
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
	ecCurve := elliptic.P256()

	// Generate Q point
	qPriv, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate Q exponent: %v", err)
	}
	qx, qy := ecCurve.ScalarBaseMult(qPriv.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	qPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	// Compute A = w*G
	ax, ay := ecCurve.ScalarBaseMult(w.Bytes())
	aBytes := elliptic.MarshalCompressed(ecCurve, ax, ay)

	aPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, aBytes)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bx, by := ecCurve.ScalarMult(qx, qy, w.Bytes())
	bBytes := elliptic.MarshalCompressed(ecCurve, bx, by)

	bPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, bBytes)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

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
	ecCurve := elliptic.P256()

	// Generate Q point
	qPriv, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate Q exponent: %v", err)
	}
	qx, qy := ecCurve.ScalarBaseMult(qPriv.Bytes())
	qBytes := elliptic.MarshalCompressed(ecCurve, qx, qy)

	qPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate exponent w
	w, err := rand.Int(rand.Reader, ecCurve.Params().N)
	if err != nil {
		t.Fatalf("failed to generate exponent: %v", err)
	}

	// Compute A = w*G
	ax, ay := ecCurve.ScalarBaseMult(w.Bytes())
	aBytes := elliptic.MarshalCompressed(ecCurve, ax, ay)

	aPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, aBytes)
	if err != nil {
		t.Fatalf("failed to create A point: %v", err)
	}
	defer aPoint.Free()

	// Compute B = w*Q
	bx, by := ecCurve.ScalarMult(qx, qy, w.Bytes())
	bBytes := elliptic.MarshalCompressed(ecCurve, bx, by)

	bPoint, err := curve.NewPointFromBytes(cbmpc.CurveP256, bBytes)
	if err != nil {
		t.Fatalf("failed to create B point: %v", err)
	}
	defer bPoint.Free()

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
