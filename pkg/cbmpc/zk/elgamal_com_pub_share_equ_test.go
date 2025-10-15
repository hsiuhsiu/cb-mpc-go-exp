//go:build cgo && !windows

package zk_test

import (
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// TestElGamalComPubShareEquProveVerify tests the ElGamal commitment public share equality proof.
func TestElGamalComPubShareEquProveVerify(t *testing.T) {
	testCurve := curve.P256

	// Generate a random scalar r
	r, err := curve.RandomScalar(testCurve)
	if err != nil {
		t.Fatalf("Failed to generate random scalar: %v", err)
	}
	defer r.Free()

	// Compute A = r*G
	a, err := curve.MulGenerator(testCurve, r)
	if err != nil {
		t.Fatalf("Failed to compute A = r*G: %v", err)
	}
	defer a.Free()

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

	// Create ElGamal commitment B = (r*G, r*Q + r*G) where B.L = A
	// Note: For the pub_share_equ proof, the message must equal the randomness (m = r)
	// The proof shows that A = B.L and B.R - A = r*Q
	b, err := curve.MakeElGamalCom(q, r, r)
	if err != nil {
		t.Fatalf("Failed to create ElGamal commitment: %v", err)
	}
	defer b.Free()

	// Create a session ID
	sessionID := cbmpc.NewSessionID([]byte("test-session-elgamal-pub-share-equ"))

	// Create the proof
	proof, err := zk.ProveElGamalComPubShareEqu(&zk.ElGamalComPubShareEquProveParams{
		Q:         q,
		A:         a,
		B:         b,
		R:         r,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}

	// Verify the proof
	err = zk.VerifyElGamalComPubShareEqu(&zk.ElGamalComPubShareEquVerifyParams{
		Proof:     proof,
		Q:         q,
		A:         a,
		B:         b,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	// Test with wrong aux value (should fail)
	err = zk.VerifyElGamalComPubShareEqu(&zk.ElGamalComPubShareEquVerifyParams{
		Proof:     proof,
		Q:         q,
		A:         a,
		B:         b,
		SessionID: sessionID,
		Aux:       2, // Wrong aux
	})
	if err == nil {
		t.Fatal("Expected verification to fail with wrong aux, but it succeeded")
	}
}
