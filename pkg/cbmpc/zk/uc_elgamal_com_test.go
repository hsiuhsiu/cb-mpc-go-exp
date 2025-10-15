//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestElGamalComProofBasic tests basic ElGamal commitment proof generation and verification.
func TestElGamalComProofBasic(t *testing.T) {
	// Generate a random scalar for Q (base point)
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

	// Generate secret value x
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	// Generate randomness r
	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
	// The C++ make_commitment(Q, x, r) creates exactly this structure: (r*G, x*Q + r*G)
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		t.Fatalf("failed to create ElGamal commitment: %v", err)
	}
	defer commitment.Free()

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("ProveElGamalCom failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("proof is empty")
	}

	// Verify proof
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("VerifyElGamalCom failed: %v", err)
	}
}

// TestElGamalComProofWrongX tests that verification fails with wrong secret x.
func TestElGamalComProofWrongX(t *testing.T) {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate secret x
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	// Generate randomness r
	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		t.Fatalf("failed to create ElGamal commitment: %v", err)
	}
	defer commitment.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof with correct x
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("ProveElGamalCom failed: %v", err)
	}

	// Create a different commitment with wrong x
	x2, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x2: %v", err)
	}
	defer x2.Free()

	commitment2, err := curve.MakeElGamalCom(qPoint, x2, r)
	if err != nil {
		t.Fatalf("failed to create commitment2: %v", err)
	}
	defer commitment2.Free()

	// Verify with wrong commitment should fail
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment2,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err == nil {
		t.Fatal("VerifyElGamalCom should have failed with wrong commitment")
	}
}

// TestElGamalComProofWrongSessionID tests that verification fails with wrong session ID.
func TestElGamalComProofWrongSessionID(t *testing.T) {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate x and r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		t.Fatalf("failed to create ElGamal commitment: %v", err)
	}
	defer commitment.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("ProveElGamalCom failed: %v", err)
	}

	// Generate wrong session ID
	wrongSessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(wrongSessionIDBytes); err != nil {
		t.Fatalf("failed to generate wrong session ID: %v", err)
	}
	wrongSessionID := cbmpc.NewSessionID(wrongSessionIDBytes)

	// Verify with wrong session ID should fail
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  wrongSessionID,
		Aux:        aux,
	})
	if err == nil {
		t.Fatal("VerifyElGamalCom should have failed with wrong session ID")
	}
}

// TestElGamalComProofWrongAux tests that verification fails with wrong aux data.
func TestElGamalComProofWrongAux(t *testing.T) {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate x and r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		t.Fatalf("failed to create ElGamal commitment: %v", err)
	}
	defer commitment.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("ProveElGamalCom failed: %v", err)
	}

	// Verify with wrong aux should fail
	wrongAux := uint64(2)
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        wrongAux,
	})
	if err == nil {
		t.Fatal("VerifyElGamalCom should have failed with wrong aux")
	}
}

// TestElGamalComProofValueSemantics tests that ElGamal commitment proofs have value semantics.
func TestElGamalComProofValueSemantics(t *testing.T) {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate x and r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
	commitment, err := curve.MakeElGamalCom(qPoint, x, r)
	if err != nil {
		t.Fatalf("failed to create ElGamal commitment: %v", err)
	}
	defer commitment.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Generate proof
	proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
		BasePoint:  qPoint,
		Commitment: commitment,
		X:          x,
		R:          r,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("ProveElGamalCom failed: %v", err)
	}

	// Test that proof can be copied and both work
	proof2 := proof // Simple assignment copies the bytes

	// Verify original
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("Verify original failed: %v", err)
	}

	// Verify copy
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      proof2,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("Verify copy failed: %v", err)
	}

	// Test empty proof returns error
	emptyProof := zk.ElGamalComProof(nil)
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      emptyProof,
		BasePoint:  qPoint,
		Commitment: commitment,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err == nil {
		t.Fatal("Verify with empty proof should return error")
	}
}

// TestElGamalComProofMultipleCurves tests ElGamal commitment proofs on different curves.
func TestElGamalComProofMultipleCurves(t *testing.T) {
	curves := []curve.Curve{
		curve.P256,
		curve.P384,
		curve.Secp256k1,
	}

	for _, c := range curves {
		t.Run(c.String(), func(t *testing.T) {
			// Generate base point Q
			qScalar, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("failed to generate Q scalar: %v", err)
			}
			defer qScalar.Free()

			qPoint, err := curve.MulGenerator(c, qScalar)
			if err != nil {
				t.Fatalf("failed to create Q point: %v", err)
			}
			defer qPoint.Free()

			// Generate x and r
			x, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("failed to generate x: %v", err)
			}
			defer x.Free()

			r, err := curve.RandomScalar(c)
			if err != nil {
				t.Fatalf("failed to generate r: %v", err)
			}
			defer r.Free()

			// Create EC ElGamal commitment UV = (L, R) where L = r*G and R = x*Q + r*G
			commitment, err := curve.MakeElGamalCom(qPoint, x, r)
			if err != nil {
				t.Fatalf("failed to create ElGamal commitment: %v", err)
			}
			defer commitment.Free()

			sessionIDBytes := make([]byte, 32)
			if _, err := rand.Read(sessionIDBytes); err != nil {
				t.Fatalf("failed to generate session ID: %v", err)
			}
			sessionID := cbmpc.NewSessionID(sessionIDBytes)

			aux := uint64(1)

			// Generate proof
			proof, err := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
				BasePoint:  qPoint,
				Commitment: commitment,
				X:          x,
				R:          r,
				SessionID:  sessionID,
				Aux:        aux,
			})
			if err != nil {
				t.Fatalf("ProveElGamalCom failed: %v", err)
			}

			// Verify proof
			err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
				Proof:      proof,
				BasePoint:  qPoint,
				Commitment: commitment,
				SessionID:  sessionID,
				Aux:        aux,
			})
			if err != nil {
				t.Fatalf("VerifyElGamalCom failed: %v", err)
			}

			t.Logf("Successfully proved and verified ElGamal commitment on %s", c.String())
		})
	}
}

// TestMakeElGamalComWithProof tests the convenience function that creates commitment + proof together.
func TestMakeElGamalComWithProof(t *testing.T) {
	// Generate base point Q
	qScalar, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	qPoint, err := curve.MulGenerator(curve.P256, qScalar)
	if err != nil {
		t.Fatalf("failed to create Q point: %v", err)
	}
	defer qPoint.Free()

	// Generate x and r
	x, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}
	defer x.Free()

	r, err := curve.RandomScalar(curve.P256)
	if err != nil {
		t.Fatalf("failed to generate r: %v", err)
	}
	defer r.Free()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	aux := uint64(1)

	// Create commitment and proof in one step
	result, err := zk.MakeElGamalComWithProof(qPoint, x, r, sessionID, aux)
	if err != nil {
		t.Fatalf("MakeElGamalComWithProof failed: %v", err)
	}
	defer result.Commitment.Free()

	// Verify the proof works
	err = zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
		Proof:      result.Proof,
		BasePoint:  qPoint,
		Commitment: result.Commitment,
		SessionID:  sessionID,
		Aux:        aux,
	})
	if err != nil {
		t.Fatalf("VerifyElGamalCom failed: %v", err)
	}

	// Test that commitment has expected properties
	if result.Commitment == nil {
		t.Fatal("commitment is nil")
	}

	// Test Curve() accessor
	if result.Commitment.Curve() != curve.P256 {
		t.Fatalf("unexpected curve: got %v, want %v", result.Commitment.Curve(), curve.P256)
	}

	// Test String() method
	str := result.Commitment.String()
	if str == "" || str == "ECElGamalCom(nil)" || str == "ECElGamalCom(error)" {
		t.Fatalf("unexpected String() output: %s", str)
	}
	t.Logf("Commitment identifier: %s", str)
}
