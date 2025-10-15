//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

func TestValidPaillierProveVerify(t *testing.T) {
	// Generate a Paillier keypair
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(12345)

	// Create proof
	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	if len(proof) == 0 {
		t.Fatal("Proof should not be empty")
	}

	// Verify proof with same Paillier instance
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Errorf("VerifyValidPaillier failed: %v", err)
	}
}

func TestValidPaillierVerifyWithPublicKeyOnly(t *testing.T) {
	// Generate a Paillier keypair
	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p1.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(67890)

	// Create proof with private key
	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	// Get public key (modulus N)
	n, err := p1.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	// Create Paillier instance with public key only
	p2, err := paillier.FromPublicKey(n)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p2.Close()

	// Verify proof with public key only
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  p2,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Errorf("VerifyValidPaillier with public key only failed: %v", err)
	}
}

func TestValidPaillierVerifyFailsWithWrongSessionID(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	sessionID1Bytes := make([]byte, 32)
	if _, err := rand.Read(sessionID1Bytes); err != nil {
		t.Fatalf("failed to generate session ID 1: %v", err)
	}
	sessionID1 := cbmpc.NewSessionID(sessionID1Bytes)

	sessionID2Bytes := make([]byte, 32)
	if _, err := rand.Read(sessionID2Bytes); err != nil {
		t.Fatalf("failed to generate session ID 2: %v", err)
	}
	sessionID2 := cbmpc.NewSessionID(sessionID2Bytes)
	aux := uint64(11111)

	// Create proof with sessionID1
	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: sessionID1,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	// Try to verify with sessionID2 (should fail)
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  p,
		SessionID: sessionID2,
		Aux:       aux,
	})
	if err == nil {
		t.Error("VerifyValidPaillier should fail with wrong session ID")
	}
}

func TestValidPaillierVerifyFailsWithWrongAux(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux1 := uint64(22222)
	aux2 := uint64(33333)

	// Create proof with aux1
	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux1,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	// Try to verify with aux2 (should fail)
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux2,
	})
	if err == nil {
		t.Error("VerifyValidPaillier should fail with wrong aux")
	}
}

func TestValidPaillierProveRequiresPrivateKey(t *testing.T) {
	// Generate a keypair to get N
	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p1.Close()

	n, err := p1.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	// Create public key only instance
	p2, err := paillier.FromPublicKey(n)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p2.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(44444)

	// Try to create proof with public key only (should fail)
	_, err = zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p2,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveValidPaillier should fail with public key only")
	}
}

func TestValidPaillierProofIsCopyable(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(55555)

	// Create proof
	proof1, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	// Copy proof ([]byte is copyable)
	proof2 := make(zk.ValidPaillierProof, len(proof1))
	copy(proof2, proof1)

	// Verify both proofs work
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof1,
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Errorf("VerifyValidPaillier with proof1 failed: %v", err)
	}

	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof2,
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Errorf("VerifyValidPaillier with proof2 failed: %v", err)
	}
}

func TestValidPaillierNilChecks(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(66666)

	// Create a valid proof first
	proof, err := zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err != nil {
		t.Fatalf("ProveValidPaillier failed: %v", err)
	}

	// Test nil params
	_, err = zk.ProveValidPaillier(nil)
	if err == nil {
		t.Error("ProveValidPaillier should fail with nil params")
	}

	err = zk.VerifyValidPaillier(nil)
	if err == nil {
		t.Error("VerifyValidPaillier should fail with nil params")
	}

	// Test nil paillier
	_, err = zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  nil,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveValidPaillier should fail with nil paillier")
	}

	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  nil,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("VerifyValidPaillier should fail with nil paillier")
	}

	// Test empty session ID
	_, err = zk.ProveValidPaillier(&zk.ValidPaillierProveParams{
		Paillier:  p,
		SessionID: cbmpc.SessionID{},
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveValidPaillier should fail with empty session ID")
	}

	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     proof,
		Paillier:  p,
		SessionID: cbmpc.SessionID{},
		Aux:       aux,
	})
	if err == nil {
		t.Error("VerifyValidPaillier should fail with empty session ID")
	}

	// Test empty proof
	err = zk.VerifyValidPaillier(&zk.ValidPaillierVerifyParams{
		Proof:     nil,
		Paillier:  p,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("VerifyValidPaillier should fail with empty proof")
	}
}
