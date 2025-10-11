package ecdsa2p_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/ecdsa2p"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

// TestKeyBytesMutationProtection verifies that mutating the slice returned by
// Key.Bytes() does not affect the internal key state.
func TestKeyBytesMutationProtection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate key pair
	var wg sync.WaitGroup
	keys := make([]*ecdsa2p.Key, 2)
	errors := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			role := cbmpc.RoleP1
			if partyID == 1 {
				role = cbmpc.RoleP2
			}
			peer := cbmpc.RoleID(1 - partyID)
			transport := net.Ep2P(cbmpc.RoleID(partyID), peer)

			job, err := cbmpc.NewJob2P(transport, role, names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
			if err != nil {
				errors[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
	}

	defer func() { _ = keys[0].Close() }()
	defer func() { _ = keys[1].Close() }()

	// Get key bytes
	keyBytes1, err := keys[0].Bytes()
	if err != nil {
		t.Fatalf("Failed to get key bytes: %v", err)
	}

	// Make a copy of the original bytes for comparison
	originalBytes := make([]byte, len(keyBytes1))
	copy(originalBytes, keyBytes1)

	// Mutate the returned slice
	for i := range keyBytes1 {
		keyBytes1[i] = 0xFF
	}

	// Get key bytes again - should be unchanged
	keyBytes2, err := keys[0].Bytes()
	if err != nil {
		t.Fatalf("Failed to get key bytes second time: %v", err)
	}

	// Verify that the key bytes are unchanged
	if len(keyBytes2) != len(originalBytes) {
		t.Fatalf("Key bytes length changed: got %d, want %d", len(keyBytes2), len(originalBytes))
	}

	for i := range keyBytes2 {
		if keyBytes2[i] != originalBytes[i] {
			t.Fatalf("Key bytes mutated at index %d: got %02x, want %02x", i, keyBytes2[i], originalBytes[i])
		}
	}

	t.Logf("✓ Key.Bytes() is protected from mutation")
}

// TestKeyPublicKeyMutationProtection verifies that mutating the slice returned by
// Key.PublicKey() does not affect the internal key state.
func TestKeyPublicKeyMutationProtection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate key pair
	var wg sync.WaitGroup
	keys := make([]*ecdsa2p.Key, 2)
	errors := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			role := cbmpc.RoleP1
			if partyID == 1 {
				role = cbmpc.RoleP2
			}
			peer := cbmpc.RoleID(1 - partyID)
			transport := net.Ep2P(cbmpc.RoleID(partyID), peer)

			job, err := cbmpc.NewJob2P(transport, role, names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
			if err != nil {
				errors[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
	}

	defer func() { _ = keys[0].Close() }()
	defer func() { _ = keys[1].Close() }()

	// Get public key
	pubKey1, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	// Make a copy of the original bytes for comparison
	originalPubKey := make([]byte, len(pubKey1))
	copy(originalPubKey, pubKey1)

	// Mutate the returned slice
	for i := range pubKey1 {
		pubKey1[i] = 0xFF
	}

	// Get public key again - should be unchanged
	pubKey2, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key second time: %v", err)
	}

	// Verify that the public key is unchanged
	if len(pubKey2) != len(originalPubKey) {
		t.Fatalf("Public key length changed: got %d, want %d", len(pubKey2), len(originalPubKey))
	}

	for i := range pubKey2 {
		if pubKey2[i] != originalPubKey[i] {
			t.Fatalf("Public key mutated at index %d: got %02x, want %02x", i, pubKey2[i], originalPubKey[i])
		}
	}

	t.Logf("✓ Key.PublicKey() is protected from mutation")
}
