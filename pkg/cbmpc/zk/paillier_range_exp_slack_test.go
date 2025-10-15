//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

func TestPaillierRangeExpSlackNilChecks(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	q := make([]byte, 256)
	if _, err := rand.Read(q); err != nil {
		t.Fatalf("failed to generate q: %v", err)
	}

	ciphertext := make([]byte, 256)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("failed to generate ciphertext: %v", err)
	}

	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate plaintext: %v", err)
	}

	randomness := make([]byte, 256)
	if _, err := rand.Read(randomness); err != nil {
		t.Fatalf("failed to generate randomness: %v", err)
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(11111)

	// Test nil params
	_, err = zk.ProvePaillierRangeExpSlack(nil)
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with nil params")
	}

	err = zk.VerifyPaillierRangeExpSlack(nil)
	if err == nil {
		t.Error("VerifyPaillierRangeExpSlack should fail with nil params")
	}

	// Test nil paillier
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  nil,
		Q:         q,
		C:         ciphertext,
		X:         plaintext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with nil paillier")
	}

	// Test empty q
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p,
		Q:         nil,
		C:         ciphertext,
		X:         plaintext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with empty q")
	}

	// Test empty ciphertext
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p,
		Q:         q,
		C:         nil,
		X:         plaintext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with empty ciphertext")
	}

	// Test empty plaintext
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p,
		Q:         q,
		C:         ciphertext,
		X:         nil,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with empty plaintext")
	}

	// Test empty randomness
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p,
		Q:         q,
		C:         ciphertext,
		X:         plaintext,
		R:         nil,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with empty randomness")
	}

	// Test empty session ID
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p,
		Q:         q,
		C:         ciphertext,
		X:         plaintext,
		R:         randomness,
		SessionID: cbmpc.SessionID{},
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with empty session ID")
	}
}

func TestPaillierRangeExpSlackProveRequiresPrivateKey(t *testing.T) {
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

	q := make([]byte, 256)
	if _, err := rand.Read(q); err != nil {
		t.Fatalf("failed to generate q: %v", err)
	}

	ciphertext := make([]byte, 256)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("failed to generate ciphertext: %v", err)
	}

	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("failed to generate plaintext: %v", err)
	}

	randomness := make([]byte, 256)
	if _, err := rand.Read(randomness); err != nil {
		t.Fatalf("failed to generate randomness: %v", err)
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(22222)

	// Try to create proof with public key only (should fail)
	_, err = zk.ProvePaillierRangeExpSlack(&zk.PaillierRangeExpSlackProveParams{
		Paillier:  p2,
		Q:         q,
		C:         ciphertext,
		X:         plaintext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierRangeExpSlack should fail with public key only")
	}
}
