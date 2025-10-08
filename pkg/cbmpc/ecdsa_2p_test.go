package cbmpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
)

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
			results := make([]*cbmpc.DKGResult, 2)
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

					result, err := cbmpc.DKG(ctx, job, &cbmpc.DKGParams{Curve: curve})
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
				if len(result.Key.Bytes()) == 0 {
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

			t.Logf("DKG successful for curve %s, public key: %x", curve.String(), pubKey0)
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
	keys := make([]*cbmpc.ECDSA2PKey, 2)
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

			result, err := cbmpc.DKG(ctx, job, &cbmpc.DKGParams{Curve: curve})
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
	newKeys := make([]*cbmpc.ECDSA2PKey, 2)
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

			result, err := cbmpc.Refresh(ctx, job, &cbmpc.RefreshParams{Key: keys[partyID]})
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
		t.Fatalf("Public key changed after refresh:\nOld: %x\nNew: %x", oldPubKey, newPubKey0)
	}

	t.Logf("Refresh successful, public key preserved: %x", newPubKey0)
}

func TestECDSA2PSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveSecp256k1

	// First, perform DKG to get keys
	var wg sync.WaitGroup
	keys := make([]*cbmpc.ECDSA2PKey, 2)
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

			result, err := cbmpc.DKG(ctx, job, &cbmpc.DKGParams{Curve: curve})
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

			result, err := cbmpc.Sign(ctx, job, &cbmpc.SignParams{
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

	// Verify signature using standard Go ECDSA
	// Note: secp256k1 is not in Go's standard library, so we can only verify P-256/384/521
	ellipticCurve := getEllipticCurve(curve)
	if ellipticCurve != nil {
		pubKeyBytes, err := keys[0].PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key: %v", err)
		}

		pubKey, err := parseCompressedPublicKey(ellipticCurve, pubKeyBytes)
		if err != nil || pubKey == nil {
			t.Fatalf("Failed to parse public key: %v", err)
		}

		r, s, err := parseDERSignature(signatures[0])
		if err != nil || r == nil || s == nil {
			t.Fatalf("Failed to parse signature: %v", err)
		}

		if !ecdsa.Verify(pubKey, messageHash[:], r, s) {
			t.Fatalf("Signature verification failed")
		}
		t.Logf("Signature verified successfully with standard Go ECDSA")
	} else {
		t.Logf("Skipping standard verification for secp256k1 (not in Go stdlib)")
	}

	t.Logf("Signing successful, signature: %x", signatures[0])
	t.Logf("Session ID: %x", sessionIDs[0])
}

func TestECDSA2PMultipleSignatures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}
	curve := cbmpc.CurveP256

	// First, perform DKG to get keys
	var wg sync.WaitGroup
	keys := make([]*cbmpc.ECDSA2PKey, 2)
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

			result, err := cbmpc.DKG(ctx, job, &cbmpc.DKGParams{Curve: curve})
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

					result, err := cbmpc.Sign(ctx, job, &cbmpc.SignParams{
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

			// Verify signature using standard Go ECDSA (only for supported curves)
			ellipticCurve := getEllipticCurve(curve)
			if ellipticCurve != nil {
				pubKeyBytes, err := keys[0].PublicKey()
				if err != nil {
					t.Fatalf("Failed to get public key: %v", err)
				}

				pubKey, err := parseCompressedPublicKey(ellipticCurve, pubKeyBytes)
				if err != nil || pubKey == nil {
					t.Fatalf("Failed to parse public key: %v", err)
				}

				r, s, err := parseDERSignature(signatures[0])
				if err != nil || r == nil || s == nil {
					t.Fatalf("Failed to parse signature for message %d: %v", idx, err)
				}

				if !ecdsa.Verify(pubKey, messageHash[:], r, s) {
					t.Fatalf("Signature verification failed for message %d", idx)
				}
			}

			// Update session ID for next iteration
			sessionID = newSessionIDs[0]

			t.Logf("Message %d signed successfully: %x", idx+1, signatures[0])
		})
	}
}
