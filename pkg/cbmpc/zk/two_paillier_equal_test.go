//go:build cgo && !windows

package zk_test

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/paillier"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

func TestTwoPaillierEqualNilChecks(t *testing.T) {
	p0, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate P0 failed: %v", err)
	}
	defer p0.Close()

	p1, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate P1 failed: %v", err)
	}
	defer p1.Close()

	q := make([]byte, 256)
	if _, err := rand.Read(q); err != nil {
		t.Fatalf("failed to generate q: %v", err)
	}

	c0 := make([]byte, 256)
	if _, err := rand.Read(c0); err != nil {
		t.Fatalf("failed to generate c0: %v", err)
	}

	c1 := make([]byte, 256)
	if _, err := rand.Read(c1); err != nil {
		t.Fatalf("failed to generate c1: %v", err)
	}

	x := make([]byte, 32)
	if _, err := rand.Read(x); err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}

	r0 := make([]byte, 256)
	if _, err := rand.Read(r0); err != nil {
		t.Fatalf("failed to generate r0: %v", err)
	}

	r1 := make([]byte, 256)
	if _, err := rand.Read(r1); err != nil {
		t.Fatalf("failed to generate r1: %v", err)
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(11111)

	// Test nil params
	_, err = zk.ProveTwoPaillierEqual(nil)
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with nil params")
	}

	err = zk.VerifyTwoPaillierEqual(nil)
	if err == nil {
		t.Error("VerifyTwoPaillierEqual should fail with nil params")
	}

	// Test empty q
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         nil,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty q")
	}

	// Test nil P0
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        nil,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with nil P0")
	}

	// Test empty c0
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        nil,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty c0")
	}

	// Test nil P1
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        nil,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with nil P1")
	}

	// Test empty c1
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        nil,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty c1")
	}

	// Test empty x
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         nil,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty x")
	}

	// Test empty r0
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        nil,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty r0")
	}

	// Test empty r1
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        nil,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty r1")
	}

	// Test empty session ID
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p0,
		C0:        c0,
		P1:        p1,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: cbmpc.SessionID{},
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with empty session ID")
	}
}

func TestTwoPaillierEqualProveRequiresPrivateKeys(t *testing.T) {
	// Generate keypairs to get N values
	p1Full, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p1Full.Close()

	n1, err := p1Full.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	p2Full, err := paillier.Generate()
	if err != nil {
		t.Fatalf("paillier.Generate failed: %v", err)
	}
	defer p2Full.Close()

	n2, err := p2Full.GetN()
	if err != nil {
		t.Fatalf("GetN failed: %v", err)
	}

	// Create public key only instances
	p1Pub, err := paillier.FromPublicKey(n1)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p1Pub.Close()

	p2Pub, err := paillier.FromPublicKey(n2)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	defer p2Pub.Close()

	q := make([]byte, 256)
	if _, err := rand.Read(q); err != nil {
		t.Fatalf("failed to generate q: %v", err)
	}

	c0 := make([]byte, 256)
	if _, err := rand.Read(c0); err != nil {
		t.Fatalf("failed to generate c0: %v", err)
	}

	c1 := make([]byte, 256)
	if _, err := rand.Read(c1); err != nil {
		t.Fatalf("failed to generate c1: %v", err)
	}

	x := make([]byte, 32)
	if _, err := rand.Read(x); err != nil {
		t.Fatalf("failed to generate x: %v", err)
	}

	r0 := make([]byte, 256)
	if _, err := rand.Read(r0); err != nil {
		t.Fatalf("failed to generate r0: %v", err)
	}

	r1 := make([]byte, 256)
	if _, err := rand.Read(r1); err != nil {
		t.Fatalf("failed to generate r1: %v", err)
	}

	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)
	aux := uint64(22222)

	// Try to create proof with P0 public key only (should fail)
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p1Pub,
		C0:        c0,
		P1:        p2Full,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with P0 public key only")
	}

	// Try to create proof with P1 public key only (should fail)
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p1Full,
		C0:        c0,
		P1:        p2Pub,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with P1 public key only")
	}

	// Try to create proof with both public keys only (should fail)
	_, err = zk.ProveTwoPaillierEqual(&zk.TwoPaillierEqualProveParams{
		Q:         q,
		P0:        p1Pub,
		C0:        c0,
		P1:        p2Pub,
		C1:        c1,
		X:         x,
		R0:        r0,
		R1:        r1,
		SessionID: sessionID,
		Aux:       aux,
	})
	if err == nil {
		t.Error("ProveTwoPaillierEqual should fail with both public keys only")
	}
}
