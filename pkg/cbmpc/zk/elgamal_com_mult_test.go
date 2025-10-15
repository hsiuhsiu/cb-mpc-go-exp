//go:build cgo && !windows

package zk_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestElGamalComMultProveVerify tests the ElGamal commitment multiplication proof.
func TestElGamalComMultProveVerify(t *testing.T) {
	testCurve := curve.P256

	// Generate a random point Q (public key)
	qScalar, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate Q scalar: %v", err)
	}
	defer qScalar.Free()

	q, err := curve.MulGenerator(testCurve, qScalar)
	if err != nil {
		t.Fatalf("Failed to compute Q: %v", err)
	}
	defer q.Free()

	// Create commitment A with known values
	mA, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate mA: %v", err)
	}
	defer mA.Free()

	rA, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate rA: %v", err)
	}
	defer rA.Free()

	a, err := curve.MakeElGamalCom(q, mA, rA)
	if err != nil {
		t.Fatalf("Failed to create commitment A: %v", err)
	}
	defer a.Free()

	// Generate scalar b for multiplication (this is the message that B commits to)
	scalarB, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate scalar b: %v", err)
	}
	defer scalarB.Free()

	// Generate randomness for B
	rB, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate rB: %v", err)
	}
	defer rB.Free()

	// Create commitment B = commit(Q, scalarB).rand(rB) = (rB*G, scalarB*Q + rB*G)
	// This is an ElGamal commitment to the scalar scalarB with randomness rB
	b, err := curve.MakeElGamalCom(q, scalarB, rB)
	if err != nil {
		t.Fatalf("Failed to create commitment B: %v", err)
	}
	defer b.Free()

	// Generate randomness for C
	rC, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate rC: %v", err)
	}
	defer rC.Free()

	// Compute C = (scalarB * A).rerand(Q, rC)
	// In ElGamal: (L, R) * s = (s*L, s*R)
	// Then rerand adds (rC*G, rC*Q) to get C = (scalarB*A.L + rC*G, scalarB*A.R + rC*Q)
	aL, err := a.PointL()
	if err != nil {
		t.Fatalf("Failed to get A.L: %v", err)
	}
	defer aL.Free()

	aR, err := a.PointR()
	if err != nil {
		t.Fatalf("Failed to get A.R: %v", err)
	}
	defer aR.Free()

	// Compute scalarB * A
	scaledL, err := aL.Mul(scalarB)
	if err != nil {
		t.Fatalf("Failed to compute scalarB * A.L: %v", err)
	}
	defer scaledL.Free()

	scaledR, err := aR.Mul(scalarB)
	if err != nil {
		t.Fatalf("Failed to compute scalarB * A.R: %v", err)
	}
	defer scaledR.Free()

	// Add rerandomization: (rC*G, rC*Q)
	rCG, err := curve.MulGenerator(testCurve, rC)
	if err != nil {
		t.Fatalf("Failed to compute rC*G: %v", err)
	}
	defer rCG.Free()

	rCQ, err := q.Mul(rC)
	if err != nil {
		t.Fatalf("Failed to compute rC*Q: %v", err)
	}
	defer rCQ.Free()

	// C.L = scalarB*A.L + rC*G
	cL, err := scaledL.Add(rCG)
	if err != nil {
		t.Fatalf("Failed to compute C.L: %v", err)
	}
	defer cL.Free()

	// C.R = scalarB*A.R + rC*Q
	cR, err := scaledR.Add(rCQ)
	if err != nil {
		t.Fatalf("Failed to compute C.R: %v", err)
	}
	defer cR.Free()

	c, err := curve.NewECElGamalCom(cL, cR)
	if err != nil {
		t.Fatalf("Failed to create commitment C: %v", err)
	}
	defer c.Free()

	// Create a session ID
	sessionID := cbmpc.NewSessionID([]byte("test-session-elgamal-mult"))

	// Create the proof
	proof, err := zk.ProveElGamalComMult(&zk.ElGamalComMultProveParams{
		Q:         q,
		A:         a,
		B:         b,
		C:         c,
		RB:        rB,
		RC:        rC,
		ScalarB:   scalarB,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}

	// Verify the proof
	err = zk.VerifyElGamalComMult(&zk.ElGamalComMultVerifyParams{
		Proof:     proof,
		Q:         q,
		A:         a,
		B:         b,
		C:         c,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}
}
