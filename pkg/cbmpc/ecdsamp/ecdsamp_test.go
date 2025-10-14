package ecdsamp_test

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
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/ecdsamp"
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
	switch curve {
	case cbmpc.CurveP256:
		return elliptic.P256()
	case cbmpc.CurveP384:
		return elliptic.P384()
	case cbmpc.CurveP521:
		return elliptic.P521()
	case cbmpc.CurveSecp256k1:
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
	if curve == cbmpc.CurveSecp256k1 {
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

func TestECDSAMPDKG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()

	// Test with different party configurations
	testCases := []struct {
		name     string
		curve    cbmpc.Curve
		nParties int
	}{
		{
			name:     "P256_3parties",
			curve:    cbmpc.CurveP256,
			nParties: 3,
		},
		{
			name:     "Secp256k1_3parties",
			curve:    cbmpc.CurveSecp256k1,
			nParties: 3,
		},
		{
			name:     "P256_5parties",
			curve:    cbmpc.CurveP256,
			nParties: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up roles and names
			roles := make([]cbmpc.RoleID, tc.nParties)
			names := make([]string, tc.nParties)
			for i := 0; i < tc.nParties; i++ {
				roles[i] = cbmpc.RoleID(i)
				names[i] = "party" + string(rune('0'+i))
			}

			var wg sync.WaitGroup
			results := make([]*ecdsamp.DKGResult, tc.nParties)
			errors := make([]error, tc.nParties)

			for i := 0; i < tc.nParties; i++ {
				wg.Add(1)
				go func(partyID int) {
					defer wg.Done()

					transport := net.EpMP(roles[partyID], roles)

					job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
					if err != nil {
						errors[partyID] = err
						return
					}
					defer func() {
						_ = job.Close()
					}()

					result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: tc.curve})
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

			// Verify all parties got keys
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
				// Verify session ID
				if len(result.SessionID.Bytes()) == 0 {
					t.Fatalf("Party %d got empty session ID", i)
				}
			}

			// Verify all parties have the same public key
			pubKey0, err := results[0].Key.PublicKey()
			if err != nil {
				t.Fatalf("Failed to get public key from party 0: %v", err)
			}

			for i := 1; i < tc.nParties; i++ {
				pubKey, err := results[i].Key.PublicKey()
				if err != nil {
					t.Fatalf("Failed to get public key from party %d: %v", i, err)
				}
				if string(pubKey) != string(pubKey0) {
					t.Fatalf("Public keys don't match:\nParty 0: %x\nParty %d: %x", pubKey0, i, pubKey)
				}
			}

			// Verify curve
			curve0, err := results[0].Key.Curve()
			if err != nil {
				t.Fatalf("Failed to get curve from party 0: %v", err)
			}
			if curve0 != tc.curve {
				t.Fatalf("Curve mismatch: expected %s, got %s", tc.curve, curve0)
			}

			t.Logf("DKG successful for %d parties with curve %s, public key: %s",
				tc.nParties, tc.curve.String(), abbrevHex(pubKey0))

			// Clean up keys
			for _, result := range results {
				if result != nil && result.Key != nil {
					_ = result.Key.Close()
				}
			}
		})
	}
}

func TestECDSAMPKeySerializationRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveP256
	nParties := 3

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "party" + string(rune('0'+i))
	}

	var wg sync.WaitGroup
	keys := make([]*ecdsamp.Key, nParties)
	errors := make([]error, nParties)

	// Perform DKG
	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: curve})
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

	// Test serialization and deserialization
	for i, key := range keys {
		// Serialize
		serialized, err := key.Bytes()
		if err != nil {
			t.Fatalf("Party %d: Failed to serialize key: %v", i, err)
		}
		if len(serialized) == 0 {
			t.Fatalf("Party %d: Got empty serialized key", i)
		}

		// Get public key before deserialization
		pubKeyBefore, err := key.PublicKey()
		if err != nil {
			t.Fatalf("Party %d: Failed to get public key before deserialization: %v", i, err)
		}

		// Deserialize
		loadedKey, err := ecdsamp.LoadKey(serialized)
		if err != nil {
			t.Fatalf("Party %d: Failed to deserialize key: %v", i, err)
		}
		defer func() {
			_ = loadedKey.Close()
		}()

		// Get public key after deserialization
		pubKeyAfter, err := loadedKey.PublicKey()
		if err != nil {
			t.Fatalf("Party %d: Failed to get public key after deserialization: %v", i, err)
		}

		// Verify public keys match
		if string(pubKeyBefore) != string(pubKeyAfter) {
			t.Fatalf("Party %d: Public key mismatch after round-trip:\nBefore: %x\nAfter: %x",
				i, pubKeyBefore, pubKeyAfter)
		}

		// Verify curve
		curveBefore, err := key.Curve()
		if err != nil {
			t.Fatalf("Party %d: Failed to get curve before deserialization: %v", i, err)
		}
		curveAfter, err := loadedKey.Curve()
		if err != nil {
			t.Fatalf("Party %d: Failed to get curve after deserialization: %v", i, err)
		}
		if curveBefore != curveAfter {
			t.Fatalf("Party %d: Curve mismatch after round-trip: %s != %s",
				i, curveBefore, curveAfter)
		}

		t.Logf("Party %d: Serialization round-trip successful", i)
	}

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSAMPRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveP256
	nParties := 3

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "party" + string(rune('0'+i))
	}

	// First, perform DKG to get initial keys
	var wg sync.WaitGroup
	keys := make([]*ecdsamp.Key, nParties)
	sessionIDs := make([]cbmpc.SessionID, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: curve})
			if err != nil {
				errors[partyID] = err
				return
			}
			keys[partyID] = result.Key
			sessionIDs[partyID] = result.SessionID
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
	newKeys := make([]*ecdsamp.Key, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsamp.Refresh(ctx, job, &ecdsamp.RefreshParams{
				SessionID: sessionIDs[partyID],
				Key:       keys[partyID],
			})
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
	for i, newKey := range newKeys {
		newPubKey, err := newKey.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get new public key from party %d: %v", i, err)
		}

		if string(oldPubKey) != string(newPubKey) {
			t.Fatalf("Public key changed after refresh for party %d:\nOld: %s\nNew: %s",
				i, abbrevHex(oldPubKey), abbrevHex(newPubKey))
		}
	}

	t.Logf("Refresh successful, public key preserved: %s", abbrevHex(oldPubKey))

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

func TestECDSAMPSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveSecp256k1
	nParties := 3
	sigReceiver := 0 // Party 0 receives the signature

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "party" + string(rune('0'+i))
	}

	// First, perform DKG to get keys
	var wg sync.WaitGroup
	keys := make([]*ecdsamp.Key, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: curve})
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
	message := []byte("Hello, ECDSA MP!")
	messageHash := sha256.Sum256(message)

	signatures := make([][]byte, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := ecdsamp.Sign(ctx, job, &ecdsamp.SignParams{
				Key:         keys[partyID],
				Message:     messageHash[:],
				SigReceiver: sigReceiver,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign failed: %v", i, err)
		}
	}

	// Only Party 0 (sig_receiver) receives the final signature
	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d (sig_receiver) should receive signature but got empty", sigReceiver)
	}
	for i := 0; i < nParties; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d should not receive signature, got: %x", i, signatures[i])
		}
	}

	// Verify signature
	pubKeyBytes, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	valid, err := verifySignature(curve, pubKeyBytes, messageHash[:], signatures[sigReceiver])
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Fatalf("Signature verification failed")
	}
	t.Logf("Signature verified successfully")

	t.Logf("Signing successful, signature: %s", abbrevHex(signatures[sigReceiver]))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
}

func TestECDSAMPSignRefreshSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveP256
	nParties := 3
	sigReceiver := 0 // Party 0 receives the signature

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "party" + string(rune('0'+i))
	}

	// First, perform DKG to get keys
	var wg sync.WaitGroup
	keys := make([]*ecdsamp.Key, nParties)
	sessionIDs := make([]cbmpc.SessionID, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: curve})
			if err != nil {
				errors[partyID] = err
				return
			}
			keys[partyID] = result.Key
			sessionIDs[partyID] = result.SessionID
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

	signatures := make([][]byte, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsamp.Sign(ctx, job, &ecdsamp.SignParams{
				Key:         keys[partyID],
				Message:     messageHash1[:],
				SigReceiver: sigReceiver,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign (before refresh) failed: %v", i, err)
		}
	}

	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d should receive signature", sigReceiver)
	}
	t.Logf("Sign before refresh successful, signature: %s", abbrevHex(signatures[sigReceiver]))

	// Verify signature before refresh
	ellipticCurve := getEllipticCurve(curve)
	if ellipticCurve != nil {
		pubKeyStd, err := parseCompressedPublicKey(ellipticCurve, pubKey)
		if err != nil || pubKeyStd == nil {
			t.Fatalf("Failed to parse public key: %v", err)
		}

		r, s, err := parseDERSignature(signatures[sigReceiver])
		if err != nil || r == nil || s == nil {
			t.Fatalf("Failed to parse signature: %v", err)
		}

		if !ecdsa.Verify(pubKeyStd, messageHash1[:], r, s) {
			t.Fatalf("Signature verification failed before refresh")
		}
		t.Logf("Signature verified before refresh")
	}

	// Refresh keys
	newKeys := make([]*ecdsamp.Key, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsamp.Refresh(ctx, job, &ecdsamp.RefreshParams{
				SessionID: sessionIDs[partyID],
				Key:       keys[partyID],
			})
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

	signatures = make([][]byte, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := ecdsamp.Sign(ctx, job, &ecdsamp.SignParams{
				Key:         newKeys[partyID],
				Message:     messageHash2[:],
				SigReceiver: sigReceiver,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d Sign (after refresh) failed: %v", i, err)
		}
	}

	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d should receive signature after refresh", sigReceiver)
	}
	t.Logf("Sign after refresh successful, signature: %s", abbrevHex(signatures[sigReceiver]))

	// Verify signature after refresh
	if ellipticCurve != nil {
		pubKeyStd, err := parseCompressedPublicKey(ellipticCurve, newPubKey)
		if err != nil || pubKeyStd == nil {
			t.Fatalf("Failed to parse new public key: %v", err)
		}

		r, s, err := parseDERSignature(signatures[sigReceiver])
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
