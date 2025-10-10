package ecdsa2p_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/ecdsa2p"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

// abbrevHex returns an abbreviated hex string showing first 2 and last 2 bytes.
// Example: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} -> "aabb...eeff"
func abbrevHex(data []byte) string {
	if len(data) <= 4 {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:2]) + "..." + hex.EncodeToString(data[len(data)-2:])
}

// Helper to get elliptic.Curve from cbmpc.Curve
func getEllipticCurve(curve cbmpc.Curve) elliptic.Curve {
	switch curve.NID() {
	case 415: // P-256
		return elliptic.P256()
	case 715: // P-384
		return elliptic.P384()
	case 716: // P-521
		return elliptic.P521()
	case 714: // secp256k1
		return nil // secp256k1 not in standard library
	default:
		return nil
	}
}

// Helper to parse compressed EC point
func parseCompressedPublicKey(curve elliptic.Curve, compressed []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, nil
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Helper to parse DER signature
func parseDERSignature(derSig []byte) (r, s *big.Int, err error) {
	// Simple DER parser for ECDSA signature
	// Format: 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S]
	if len(derSig) < 8 || derSig[0] != 0x30 || derSig[2] != 0x02 {
		return nil, nil, nil
	}

	rLen := int(derSig[3])
	rBytes := derSig[4 : 4+rLen]
	r = new(big.Int).SetBytes(rBytes)

	sIndex := 4 + rLen
	if sIndex+2 >= len(derSig) || derSig[sIndex] != 0x02 {
		return nil, nil, nil
	}

	sLen := int(derSig[sIndex+1])
	sBytes := derSig[sIndex+2 : sIndex+2+sLen]
	s = new(big.Int).SetBytes(sBytes)

	return r, s, nil
}

// Helper to verify signature for any curve (including secp256k1)
func verifySignature(curve cbmpc.Curve, pubKeyBytes, messageHash, derSig []byte) (bool, error) {
	if curve.NID() == 714 { // secp256k1
		// Use btcd library for secp256k1
		pubKey, err := btcec.ParsePubKey(pubKeyBytes)
		if err != nil {
			return false, err
		}

		sig, err := btcecdsa.ParseDERSignature(derSig)
		if err != nil {
			return false, err
		}

		return sig.Verify(messageHash, pubKey), nil
	}

	// Use standard library for NIST curves
	ellipticCurve := getEllipticCurve(curve)
	if ellipticCurve == nil {
		return false, nil // Unsupported curve
	}

	pubKey, err := parseCompressedPublicKey(ellipticCurve, pubKeyBytes)
	if err != nil || pubKey == nil {
		return false, err
	}

	r, s, err := parseDERSignature(derSig)
	if err != nil || r == nil || s == nil {
		return false, err
	}

	return ecdsa.Verify(pubKey, messageHash, r, s), nil
}

func TestECDSA2PDKG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	curves := []cbmpc.Curve{
		cbmpc.CurveP256,
		cbmpc.CurveSecp256k1,
	}

	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			var wg sync.WaitGroup
			results := make([]*ecdsa2p.DKGResult, 2)
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
					defer func() {
						_ = job.Close()
					}()

					result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
					results[partyID] = result
					errors[partyID] = err
				}(i)
			}

			wg.Wait()

			// Check for errors
			for i, err := range errors {
				if err != nil {
					t.Fatalf("Party %d DKG failed: %v", i, err)
				}
			}

			// Verify both parties got keys
			for i, result := range results {
				if result == nil {
					t.Fatalf("Party %d got nil result", i)
				}
				if result.Key == nil {
					t.Fatalf("Party %d got nil key", i)
				}
				keyBytes, err := result.Key.Bytes()
				if err != nil {
					t.Fatalf("Party %d failed to get key bytes: %v", i, err)
				}
				if len(keyBytes) == 0 {
					t.Fatalf("Party %d got empty key", i)
				}
			}

			// Verify both parties have the same public key
			pubKey0, err := results[0].Key.PublicKey()
			if err != nil {
				t.Fatalf("Failed to get public key from party 0: %v", err)
			}
			pubKey1, err := results[1].Key.PublicKey()
			if err != nil {
				t.Fatalf("Failed to get public key from party 1: %v", err)
			}

			if string(pubKey0) != string(pubKey1) {
				t.Fatalf("Public keys don't match:\nParty 0: %x\nParty 1: %x", pubKey0, pubKey1)
			}

			// Verify curve
			curve0, err := results[0].Key.Curve()
			if err != nil {
				t.Fatalf("Failed to get curve from party 0: %v", err)
			}
			if curve0.NID() != curve.NID() {
				t.Fatalf("Curve mismatch: expected %d, got %d", curve.NID(), curve0.NID())
			}

			t.Logf("DKG successful for curve %s, public key: %s", curve.String(), abbrevHex(pubKey0))

			// Clean up keys
			for _, result := range results {
				if result != nil && result.Key != nil {
					_ = result.Key.Close()
				}
			}
		})
	}
}

func TestECDSA2PRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get initial keys
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
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	oldPubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get old public key: %v", err)
	}

	// Now perform refresh
	newKeys := make([]*ecdsa2p.Key, 2)
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
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsa2p.Refresh(ctx, job, &ecdsa2p.RefreshParams{Key: keys[partyID]})
			if err != nil {
				errors[partyID] = err
				return
			}
			newKeys[partyID] = result.NewKey
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Refresh failed: %v", i, err)
		}
	}

	// Verify public keys are the same after refresh
	newPubKey0, err := newKeys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get new public key from party 0: %v", err)
	}
	newPubKey1, err := newKeys[1].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get new public key from party 1: %v", err)
	}

	if string(newPubKey0) != string(newPubKey1) {
		t.Fatalf("New public keys don't match")
	}

	if string(oldPubKey) != string(newPubKey0) {
		t.Fatalf("Public key changed after refresh:\nOld: %s\nNew: %s", abbrevHex(oldPubKey), abbrevHex(newPubKey0))
	}

	t.Logf("Refresh successful, public key preserved: %s", abbrevHex(newPubKey0))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
	for _, key := range newKeys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveSecp256k1

	// First, perform DKG to get keys
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
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	// Now perform signing
	message := []byte("Hello, ECDSA 2P!")
	messageHash := sha256.Sum256(message)

	signatures := make([][]byte, 2)
	sessionIDs := make([][]byte, 2)
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
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
				SessionID: nil, // Can be nil for first signature
				Key:       keys[partyID],
				Message:   messageHash[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signature
	if len(signatures[0]) == 0 {
		t.Fatalf("Party 0 (P1) should receive signature but got empty")
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signature, got: %x", signatures[1])
	}

	// Verify session IDs
	if len(sessionIDs[0]) == 0 || len(sessionIDs[1]) == 0 {
		t.Fatalf("Empty session ID")
	}

	// Verify signature
	pubKeyBytes, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	valid, err := verifySignature(curve, pubKeyBytes, messageHash[:], signatures[0])
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Fatalf("Signature verification failed")
	}
	t.Logf("Signature verified successfully")

	t.Logf("Signing successful, signature: %s", abbrevHex(signatures[0]))
	t.Logf("Session ID: %s", abbrevHex(sessionIDs[0]))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PSignRefreshSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get keys
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

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	pubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	t.Logf("DKG complete, public key: %s", abbrevHex(pubKey))

	// Sign with original keys
	message1 := []byte("Message before refresh")
	messageHash1 := sha256.Sum256(message1)

	signatures := make([][]byte, 2)
	sessionIDs := make([][]byte, 2)
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
			signatures[partyID] = result.Signature
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign (before refresh) failed: %v", i, err)
		}
	}

	if len(signatures[0]) == 0 {
		t.Fatalf("Party 0 should receive signature")
	}
	t.Logf("Sign before refresh successful, signature: %s", abbrevHex(signatures[0]))

	// Verify signature before refresh
	ellipticCurve := getEllipticCurve(curve)
	if ellipticCurve != nil {
		pubKeyStd, err := parseCompressedPublicKey(ellipticCurve, pubKey)
		if err != nil || pubKeyStd == nil {
			t.Fatalf("Failed to parse public key: %v", err)
		}

		r, s, err := parseDERSignature(signatures[0])
		if err != nil || r == nil || s == nil {
			t.Fatalf("Failed to parse signature: %v", err)
		}

		if !ecdsa.Verify(pubKeyStd, messageHash1[:], r, s) {
			t.Fatalf("Signature verification failed before refresh")
		}
		t.Logf("Signature verified before refresh")
	}

	// Refresh keys
	newKeys := make([]*ecdsa2p.Key, 2)
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

			result, err := ecdsa2p.Refresh(ctx, job, &ecdsa2p.RefreshParams{Key: keys[partyID]})
			if err != nil {
				errors[partyID] = err
				return
			}
			newKeys[partyID] = result.NewKey
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Refresh failed: %v", i, err)
		}
	}

	newPubKey, err := newKeys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get new public key: %v", err)
	}

	if string(pubKey) != string(newPubKey) {
		t.Fatalf("Public key changed after refresh:\nOld: %s\nNew: %s", abbrevHex(pubKey), abbrevHex(newPubKey))
	}
	t.Logf("Refresh complete, public key preserved: %s", abbrevHex(newPubKey))

	// Sign with refreshed keys
	message2 := []byte("Message after refresh")
	messageHash2 := sha256.Sum256(message2)

	signatures = make([][]byte, 2)
	sessionIDs = make([][]byte, 2)
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
				Key:       newKeys[partyID],
				Message:   messageHash2[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign (after refresh) failed: %v", i, err)
		}
	}

	if len(signatures[0]) == 0 {
		t.Fatalf("Party 0 should receive signature after refresh")
	}
	t.Logf("Sign after refresh successful, signature: %s", abbrevHex(signatures[0]))

	// Verify signature after refresh
	if ellipticCurve != nil {
		pubKeyStd, err := parseCompressedPublicKey(ellipticCurve, newPubKey)
		if err != nil || pubKeyStd == nil {
			t.Fatalf("Failed to parse new public key: %v", err)
		}

		r, s, err := parseDERSignature(signatures[0])
		if err != nil || r == nil || s == nil {
			t.Fatalf("Failed to parse signature after refresh: %v", err)
		}

		if !ecdsa.Verify(pubKeyStd, messageHash2[:], r, s) {
			t.Fatalf("Signature verification failed after refresh")
		}
		t.Logf("Signature verified after refresh")
	}

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
	for _, key := range newKeys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PMultipleSignatures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get keys
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
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	// Sign multiple messages with session ID carryover
	messages := []string{"Message 1", "Message 2", "Message 3"}
	var sessionID []byte

	for idx, msg := range messages {
		t.Run(msg, func(t *testing.T) {
			messageHash := sha256.Sum256([]byte(msg))

			signatures := make([][]byte, 2)
			newSessionIDs := make([][]byte, 2)
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
					defer func() {
						_ = job.Close()
					}()

					result, err := ecdsa2p.Sign(ctx, job, &ecdsa2p.SignParams{
						SessionID: sessionID,
						Key:       keys[partyID],
						Message:   messageHash[:],
					})
					if err != nil {
						errors[partyID] = err
						return
					}
					signatures[partyID] = result.Signature
					newSessionIDs[partyID] = result.SessionID
				}(i)
			}

			wg.Wait()

			for i, err := range errors {
				if err != nil {
					t.Fatalf("Party %d Sign failed for message %d: %v", i, idx, err)
				}
			}

			// Only Party 0 (P1) receives the final signature
			if len(signatures[0]) == 0 {
				t.Fatalf("Party 0 (P1) should receive signature for message %d but got empty", idx)
			}
			if len(signatures[1]) != 0 {
				t.Fatalf("Party 1 (P2) should not receive signature for message %d, got: %x", idx, signatures[1])
			}

			// Verify signature
			pubKeyBytes, err := keys[0].PublicKey()
			if err != nil {
				t.Fatalf("Failed to get public key: %v", err)
			}

			valid, err := verifySignature(curve, pubKeyBytes, messageHash[:], signatures[0])
			if err != nil {
				t.Fatalf("Failed to verify signature for message %d: %v", idx, err)
			}
			if !valid {
				t.Fatalf("Signature verification failed for message %d", idx)
			}

			// Update session ID for next iteration
			sessionID = newSessionIDs[0]

			t.Logf("Message %d signed successfully: %s", idx+1, abbrevHex(signatures[0]))
		})
	}

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PSignBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get keys
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

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	// Sign batch of messages
	messages := []string{"Message 1", "Message 2", "Message 3"}
	messageHashes := make([][]byte, len(messages))
	for i, msg := range messages {
		hash := sha256.Sum256([]byte(msg))
		messageHashes[i] = hash[:]
	}

	signatureBatches := make([][][]byte, 2)
	sessionIDs := make([][]byte, 2)
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

			result, err := ecdsa2p.SignBatch(ctx, job, &ecdsa2p.SignBatchParams{
				SessionID: nil,
				Key:       keys[partyID],
				Messages:  messageHashes,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatureBatches[partyID] = result.Signatures
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d SignBatch failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signatures
	if len(signatureBatches[0]) != len(messages) {
		t.Fatalf("Party 0 should receive %d signatures but got %d", len(messages), len(signatureBatches[0]))
	}
	if len(signatureBatches[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signatures, got: %d", len(signatureBatches[1]))
	}

	// Verify all signatures
	pubKeyBytes, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	for i, sig := range signatureBatches[0] {
		valid, err := verifySignature(curve, pubKeyBytes, messageHashes[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature %d: %v", i, err)
		}
		if !valid {
			t.Fatalf("Signature verification failed for message %d", i)
		}
		t.Logf("Signature %d verified: %s", i, abbrevHex(sig))
	}

	t.Logf("Batch signing successful, %d signatures verified", len(messages))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PSignWithGlobalAbort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveSecp256k1

	// First, perform DKG to get keys
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

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	// Sign with global abort
	message := []byte("Test message with global abort")
	messageHash := sha256.Sum256(message)

	signatures := make([][]byte, 2)
	sessionIDs := make([][]byte, 2)
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

			result, err := ecdsa2p.SignWithGlobalAbort(ctx, job, &ecdsa2p.SignParams{
				SessionID: nil,
				Key:       keys[partyID],
				Message:   messageHash[:],
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d SignWithGlobalAbort failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signature
	if len(signatures[0]) == 0 {
		t.Fatalf("Party 0 (P1) should receive signature but got empty")
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signature, got: %x", signatures[1])
	}

	// Verify signature
	pubKeyBytes, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	valid, err := verifySignature(curve, pubKeyBytes, messageHash[:], signatures[0])
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Fatalf("Signature verification failed")
	}

	t.Logf("SignWithGlobalAbort successful, signature: %s", abbrevHex(signatures[0]))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSA2PSignWithGlobalAbortBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get keys
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

			result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: curve})
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

	// Sign batch with global abort
	messages := []string{"GA Message 1", "GA Message 2", "GA Message 3"}
	messageHashes := make([][]byte, len(messages))
	for i, msg := range messages {
		hash := sha256.Sum256([]byte(msg))
		messageHashes[i] = hash[:]
	}

	signatureBatches := make([][][]byte, 2)
	sessionIDs := make([][]byte, 2)
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

			result, err := ecdsa2p.SignWithGlobalAbortBatch(ctx, job, &ecdsa2p.SignBatchParams{
				SessionID: nil,
				Key:       keys[partyID],
				Messages:  messageHashes,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatureBatches[partyID] = result.Signatures
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d SignWithGlobalAbortBatch failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signatures
	if len(signatureBatches[0]) != len(messages) {
		t.Fatalf("Party 0 should receive %d signatures but got %d", len(messages), len(signatureBatches[0]))
	}
	if len(signatureBatches[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signatures, got: %d", len(signatureBatches[1]))
	}

	// Verify all signatures
	pubKeyBytes, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	for i, sig := range signatureBatches[0] {
		valid, err := verifySignature(curve, pubKeyBytes, messageHashes[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature %d: %v", i, err)
		}
		if !valid {
			t.Fatalf("Signature verification failed for message %d", i)
		}
		t.Logf("Global abort signature %d verified: %s", i, abbrevHex(sig))
	}

	t.Logf("Global abort batch signing successful, %d signatures verified", len(messages))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}
