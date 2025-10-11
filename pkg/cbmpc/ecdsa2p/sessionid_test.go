package ecdsa2p_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/ecdsa2p"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

// TestSessionIDFresh tests that an empty SessionID results in a fresh session being created.
func TestSessionIDFresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys
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

	// Sign with empty SessionID (fresh session)
	message := []byte("Test message for fresh session")
	messageHash := sha256.Sum256(message)

	results := make([]*ecdsa2p.SignResult, 2)
	errors = make([]error, 2)

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

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: nil, // Fresh session
				Key:       keys[partyID],
				Message:   messageHash[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			results[partyID] = result
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign failed: %v", i, err)
		}
	}

	// Verify session IDs were generated
	if len(results[0].SessionID) == 0 {
		t.Fatal("Party 0 should have received a generated session ID")
	}
	if len(results[1].SessionID) == 0 {
		t.Fatal("Party 1 should have received a generated session ID")
	}

	t.Logf("✓ Fresh session IDs generated: party0=%d bytes, party1=%d bytes",
		len(results[0].SessionID), len(results[1].SessionID))
}

// TestSessionIDResume tests that a non-empty SessionID correctly resumes a session.
func TestSessionIDResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys
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

	// First signature with fresh session
	message1 := []byte("First message")
	messageHash1 := sha256.Sum256(message1)

	results := make([]*ecdsa2p.SignResult, 2)
	errors = make([]error, 2)

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

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: nil,
				Key:       keys[partyID],
				Message:   messageHash1[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			results[partyID] = result
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d first Sign failed: %v", i, err)
		}
	}

	// Save the session IDs
	sessionID0 := results[0].SessionID
	sessionID1 := results[1].SessionID

	if len(sessionID0) == 0 || len(sessionID1) == 0 {
		t.Fatal("Session IDs should not be empty after first signature")
	}

	// Second signature resuming with session IDs
	message2 := []byte("Second message")
	messageHash2 := sha256.Sum256(message2)

	results2 := make([]*ecdsa2p.SignResult, 2)
	errors = make([]error, 2)

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

			// Resume with previous session ID
			var sid cbmpc.SessionID
			if partyID == 0 {
				sid = sessionID0
			} else {
				sid = sessionID1
			}

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: sid, // Resume session
				Key:       keys[partyID],
				Message:   messageHash2[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			results2[partyID] = result
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d second Sign failed: %v", i, err)
		}
	}

	// Verify we got session IDs back
	if len(results2[0].SessionID) == 0 || len(results2[1].SessionID) == 0 {
		t.Fatal("Session IDs should not be empty after resumed signature")
	}

	t.Logf("✓ Session resumed successfully with provided session IDs")
	t.Logf("  Party 0: first=%s, second=%s", abbrevHex(sessionID0), abbrevHex(results2[0].SessionID))
	t.Logf("  Party 1: first=%s, second=%s", abbrevHex(sessionID1), abbrevHex(results2[1].SessionID))
}

// TestSessionIDClone tests that SessionID.Clone() creates an independent copy.
func TestSessionIDClone(t *testing.T) {
	original := cbmpc.SessionID([]byte{0x01, 0x02, 0x03, 0x04})

	// Clone the session ID
	cloned := original.Clone()

	// Verify contents are equal
	if !bytes.Equal(original, cloned) {
		t.Fatalf("Clone should have same contents: original=%x, cloned=%x", original, cloned)
	}

	// Mutate the original
	original[0] = 0xFF

	// Verify clone is unaffected
	if cloned[0] != 0x01 {
		t.Fatalf("Clone should be independent: expected 0x01, got 0x%02x", cloned[0])
	}

	t.Logf("✓ SessionID.Clone() creates independent copy")
}

// TestSessionIDCloneEmpty tests that cloning an empty SessionID returns nil.
func TestSessionIDCloneEmpty(t *testing.T) {
	var empty cbmpc.SessionID

	// Clone empty session ID
	cloned := empty.Clone()

	// Verify it's nil
	if cloned != nil {
		t.Fatalf("Clone of empty SessionID should be nil, got %v", cloned)
	}

	// Also test with explicitly nil
	var nilSID cbmpc.SessionID = nil
	clonedNil := nilSID.Clone()

	if clonedNil != nil {
		t.Fatalf("Clone of nil SessionID should be nil, got %v", clonedNil)
	}

	t.Logf("✓ Clone of empty/nil SessionID returns nil")
}

// TestSessionIDMutationSafety tests that mutating a SessionID from SignResult
// doesn't affect subsequent operations.
func TestSessionIDMutationSafety(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys
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

	// First signature
	message := []byte("Test mutation safety")
	messageHash := sha256.Sum256(message)

	results := make([]*ecdsa2p.SignResult, 2)
	errors = make([]error, 2)

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

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: nil,
				Key:       keys[partyID],
				Message:   messageHash[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			results[partyID] = result
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign failed: %v", i, err)
		}
	}

	// Save original session ID
	originalSID := make([]byte, len(results[0].SessionID))
	copy(originalSID, results[0].SessionID)

	// Mutate the returned SessionID
	for i := range results[0].SessionID {
		results[0].SessionID[i] = 0xFF
	}

	// Try to use it again - the mutation should not affect the ability to use a clone
	clonedSID := cbmpc.SessionID(originalSID)

	// Second signature using the cloned (unmutated) session ID
	message2 := []byte("Second message after mutation")
	messageHash2 := sha256.Sum256(message2)

	results2 := make([]*ecdsa2p.SignResult, 2)
	errors = make([]error, 2)

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

			// Use the cloned SID for party 0, original for party 1
			var sid cbmpc.SessionID
			if partyID == 0 {
				sid = clonedSID
			} else {
				sid = results[1].SessionID
			}

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: sid,
				Key:       keys[partyID],
				Message:   messageHash2[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			results2[partyID] = result
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d second Sign failed: %v", i, err)
		}
	}

	t.Logf("✓ SessionID mutation safety verified")
	t.Logf("  Successfully signed with cloned (unmutated) session ID")
}

// TestSessionIDIsEmpty tests the IsEmpty method.
func TestSessionIDIsEmpty(t *testing.T) {
	// Test nil SessionID
	var nilSID cbmpc.SessionID
	if !nilSID.IsEmpty() {
		t.Error("Nil SessionID should be empty")
	}

	// Test zero-length SessionID
	emptySID := cbmpc.SessionID([]byte{})
	if !emptySID.IsEmpty() {
		t.Error("Zero-length SessionID should be empty")
	}

	// Test non-empty SessionID
	nonEmpty := cbmpc.SessionID([]byte{0x01})
	if nonEmpty.IsEmpty() {
		t.Error("Non-empty SessionID should not be empty")
	}

	t.Logf("✓ SessionID.IsEmpty() works correctly")
}
