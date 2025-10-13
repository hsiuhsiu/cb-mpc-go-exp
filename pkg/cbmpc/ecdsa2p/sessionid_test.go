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
				SessionID: cbmpc.SessionID{}, // Fresh session (zero value)
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
	if results[0].SessionID.IsEmpty() {
		t.Fatal("Party 0 should have received a generated session ID")
	}
	if results[1].SessionID.IsEmpty() {
		t.Fatal("Party 1 should have received a generated session ID")
	}

	t.Logf("✓ Fresh session IDs generated: party0=%d bytes, party1=%d bytes",
		len(results[0].SessionID.Bytes()), len(results[1].SessionID.Bytes()))
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
				SessionID: cbmpc.SessionID{}, // Fresh session
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

	if sessionID0.IsEmpty() || sessionID1.IsEmpty() {
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
	if results2[0].SessionID.IsEmpty() || results2[1].SessionID.IsEmpty() {
		t.Fatal("Session IDs should not be empty after resumed signature")
	}

	t.Logf("✓ Session resumed successfully with provided session IDs")
	t.Logf("  Party 0: first=%s, second=%s", abbrevHex(sessionID0.Bytes()), abbrevHex(results2[0].SessionID.Bytes()))
	t.Logf("  Party 1: first=%s, second=%s", abbrevHex(sessionID1.Bytes()), abbrevHex(results2[1].SessionID.Bytes()))
}

// TestSessionIDBytes tests that SessionID.Bytes() returns a defensive copy.
func TestSessionIDBytes(t *testing.T) {
	original := cbmpc.NewSessionID([]byte{0x01, 0x02, 0x03, 0x04})

	// Get bytes
	bytes1 := original.Bytes()
	bytes2 := original.Bytes()

	// Verify contents are equal
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatalf("Bytes() should return same contents: bytes1=%x, bytes2=%x", bytes1, bytes2)
	}

	// Mutate bytes1
	bytes1[0] = 0xFF

	// Verify bytes2 and subsequent calls are unaffected
	bytes3 := original.Bytes()
	if bytes3[0] != 0x01 {
		t.Fatalf("Bytes() should return independent copies: expected 0x01, got 0x%02x", bytes3[0])
	}
	if bytes2[0] != 0x01 {
		t.Fatalf("Previous Bytes() call should be independent: expected 0x01, got 0x%02x", bytes2[0])
	}

	t.Logf("✓ SessionID.Bytes() returns independent defensive copies")
}

// TestSessionIDBytesEmpty tests that Bytes() on empty SessionID returns nil.
func TestSessionIDBytesEmpty(t *testing.T) {
	var empty cbmpc.SessionID

	// Get bytes from empty session ID
	bytes := empty.Bytes()

	// Verify it's nil
	if bytes != nil {
		t.Fatalf("Bytes() of empty SessionID should be nil, got %v", bytes)
	}

	t.Logf("✓ Bytes() of empty SessionID returns nil")
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
				SessionID: cbmpc.SessionID{}, // Fresh session
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

	// Save original session ID (make a copy via NewSessionID)
	originalSID := results[0].SessionID

	// Get bytes from the session ID
	sidBytes := originalSID.Bytes()

	// Mutate the bytes we got from SessionID (this should NOT affect the SessionID)
	for i := range sidBytes {
		sidBytes[i] = 0xFF
	}

	// The original SessionID should still be valid and unchanged
	unchangedBytes := originalSID.Bytes()
	if unchangedBytes[0] == 0xFF {
		t.Fatal("SessionID was affected by external mutation - immutability broken!")
	}

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

			// Use the original SID for both parties (it should be unchanged despite external byte mutation)
			var sid cbmpc.SessionID
			if partyID == 0 {
				sid = originalSID
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

	t.Logf("✓ SessionID immutability verified")
	t.Logf("  External byte mutations do not affect SessionID internal state")
	t.Logf("  Successfully used SessionID after external byte array was mutated")
}

// TestSessionIDIsEmpty tests the IsEmpty method.
func TestSessionIDIsEmpty(t *testing.T) {
	// Test zero-value SessionID
	var zeroSID cbmpc.SessionID
	if !zeroSID.IsEmpty() {
		t.Error("Zero-value SessionID should be empty")
	}

	// Test SessionID created from empty bytes
	emptySID := cbmpc.NewSessionID([]byte{})
	if !emptySID.IsEmpty() {
		t.Error("SessionID from empty bytes should be empty")
	}

	// Test SessionID created from nil
	nilSID := cbmpc.NewSessionID(nil)
	if !nilSID.IsEmpty() {
		t.Error("SessionID from nil should be empty")
	}

	// Test non-empty SessionID
	nonEmpty := cbmpc.NewSessionID([]byte{0x01})
	if nonEmpty.IsEmpty() {
		t.Error("Non-empty SessionID should not be empty")
	}

	t.Logf("✓ SessionID.IsEmpty() works correctly")
}
