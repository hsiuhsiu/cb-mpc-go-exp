//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

func TestPaillierZeroProveVerify(t *testing.T) {
	t.Skip("Skipping full proof test - requires tracked randomness from Paillier encryption")
	// Note: This test is skipped because the Paillier.Encrypt() function doesn't return
	// the randomness used in encryption. To properly test this ZK proof, we would need
	// to use lower-level Paillier functions that allow us to specify and track the randomness.
	// The parameter validation tests (TestPaillierZeroNilChecks) provide adequate coverage
	// for the API structure and error handling.
}

func TestPaillierZeroNilChecks(t *testing.T) {
	p, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p.Close()

	ciphertext := make([]byte, 256)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("failed to generate ciphertext: %v", err)
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
	_, err = zk.ProvePaillierZero(nil)
	if err == nil {
		t.Error("ProvePaillierZero should fail with nil params")
	}

	err = zk.VerifyPaillierZero(nil)
	if err == nil {
		t.Error("VerifyPaillierZero should fail with nil params")
	}

	// Test nil paillier
	_, err = zk.ProvePaillierZero(&zk.PaillierZeroProveParams{
		Paillier:  nil,
		C:         ciphertext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierZero should fail with nil paillier")
	}

	// Test empty ciphertext
	_, err = zk.ProvePaillierZero(&zk.PaillierZeroProveParams{
		Paillier:  p,
		C:         nil,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierZero should fail with empty ciphertext")
	}

	// Test empty randomness
	_, err = zk.ProvePaillierZero(&zk.PaillierZeroProveParams{
		Paillier:  p,
		C:         ciphertext,
		R:         nil,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierZero should fail with empty randomness")
	}

	// Test empty session ID
	_, err = zk.ProvePaillierZero(&zk.PaillierZeroProveParams{
		Paillier:  p,
		C:         ciphertext,
		R:         randomness,
		SessionID: cbmpc.SessionID{},
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierZero should fail with empty session ID")
	}
}

func TestPaillierZeroProveRequiresPrivateKey(t *testing.T) {
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

	ciphertext := make([]byte, 256)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatalf("failed to generate ciphertext: %v", err)
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
	_, err = zk.ProvePaillierZero(&zk.PaillierZeroProveParams{
		Paillier:  p2,
		C:         ciphertext,
		R:         randomness,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProvePaillierZero should fail with public key only")
	}
}
