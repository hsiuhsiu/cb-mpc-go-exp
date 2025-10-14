package schnorr2p_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/schnorr2p"
)

// TestSchnorr2PSignEdDSA tests Schnorr 2P signing with EdDSA variant (Ed25519).
func TestSchnorr2PSignEdDSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys using Schnorr 2P DKG
	var keys [2]*schnorr2p.Key
	var dkgErr [2]error
	var wg sync.WaitGroup

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
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{
				Curve: cbmpc.CurveEd25519,
			})
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	// Check for DKG errors
	for i, err := range dkgErr {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
		if keys[i] == nil {
			t.Fatalf("Party %d key is nil", i)
		}
		defer func() { _ = keys[i].Close() }()
	}

	// Verify both parties have the same public key
	pubKey0, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}
	pubKey1, err := keys[1].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 1: %v", err)
	}
	if string(pubKey0) != string(pubKey1) {
		t.Fatal("Public keys do not match")
	}

	// Sign a message
	message := []byte("Hello, Schnorr EdDSA!")

	var signatures [2][]byte
	var signErr [2]error

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
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.Sign(ctx, job, &schnorr2p.SignParams{
				Key:     keys[partyID],
				Message: message,
				Variant: schnorr2p.VariantEdDSA,
			})
			if err != nil {
				signErr[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	// Check for signing errors
	for i, err := range signErr {
		if err != nil {
			t.Fatalf("Party %d signing failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signature (same as ECDSA-2P)
	if len(signatures[0]) == 0 {
		t.Fatal("Party 0 (P1) should receive signature but got empty")
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signature, got: %x", signatures[1])
	}

	// Verify signature length (EdDSA signatures are 64 bytes)
	if len(signatures[0]) != ed25519.SignatureSize {
		t.Fatalf("Expected signature length %d, got %d", ed25519.SignatureSize, len(signatures[0]))
	}

	// Verify the signature using Ed25519 verification
	if len(pubKey0) != ed25519.PublicKeySize {
		t.Fatalf("Expected public key length %d, got %d", ed25519.PublicKeySize, len(pubKey0))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey0), message, signatures[0]) {
		t.Fatal("Ed25519 signature verification failed")
	}

	t.Log("EdDSA signature verified successfully")
}

// TestSchnorr2PSignBIP340 tests Schnorr 2P signing with BIP340 variant (secp256k1).
func TestSchnorr2PSignBIP340(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys using Schnorr 2P DKG
	var keys [2]*schnorr2p.Key
	var dkgErr [2]error
	var wg sync.WaitGroup

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
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{
				Curve: cbmpc.CurveSecp256k1,
			})
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	// Check for DKG errors
	for i, err := range dkgErr {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
		if keys[i] == nil {
			t.Fatalf("Party %d key is nil", i)
		}
		defer func() { _ = keys[i].Close() }()
	}

	// Verify both parties have the same public key
	pubKey0, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}
	pubKey1, err := keys[1].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 1: %v", err)
	}
	if string(pubKey0) != string(pubKey1) {
		t.Fatal("Public keys do not match")
	}

	// For BIP340, we need to hash the message first
	message := []byte("Hello, Schnorr BIP340!")
	hash := sha256.Sum256(message)

	var signatures [2][]byte
	var signErr [2]error

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
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.Sign(ctx, job, &schnorr2p.SignParams{
				Key:     keys[partyID],
				Message: hash[:],
				Variant: schnorr2p.VariantBIP340,
			})
			if err != nil {
				signErr[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	// Check for signing errors
	for i, err := range signErr {
		if err != nil {
			t.Fatalf("Party %d signing failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signature (same as ECDSA-2P)
	if len(signatures[0]) == 0 {
		t.Fatal("Party 0 (P1) should receive signature but got empty")
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signature, got: %x", signatures[1])
	}

	// Verify signature length (BIP340 signatures are 64 bytes)
	if len(signatures[0]) != 64 {
		t.Fatalf("Expected signature length 64, got %d", len(signatures[0]))
	}

	// Verify the BIP340 signature using btcec library
	// BIP340 uses x-only public keys (32 bytes), so we need to parse the compressed public key
	pubKeyBytes, err := btcec.ParsePubKey(pubKey0)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Parse the BIP340 signature
	sig, err := btcschnorr.ParseSignature(signatures[0])
	if err != nil {
		t.Fatalf("Failed to parse BIP340 signature: %v", err)
	}

	// Verify the signature
	if !sig.Verify(hash[:], pubKeyBytes) {
		t.Fatal("BIP340 signature verification failed")
	}

	t.Log("BIP340 signature verified successfully")
}

// TestSchnorr2PSignBatchEdDSA tests Schnorr 2P batch signing with EdDSA variant.
func TestSchnorr2PSignBatchEdDSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys using Schnorr 2P DKG
	var keys [2]*schnorr2p.Key
	var dkgErr [2]error
	var wg sync.WaitGroup

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
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{
				Curve: cbmpc.CurveEd25519,
			})
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	for i, err := range dkgErr {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
		if keys[i] == nil {
			t.Fatalf("Party %d key is nil", i)
		}
		defer func() { _ = keys[i].Close() }()
	}

	// Get public key for verification
	pubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	// Sign multiple messages
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
	}

	var signatures [2][][]byte
	var signErr [2]error

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
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.SignBatch(ctx, job, &schnorr2p.SignBatchParams{
				Key:      keys[partyID],
				Messages: messages,
				Variant:  schnorr2p.VariantEdDSA,
			})
			if err != nil {
				signErr[partyID] = err
				return
			}
			signatures[partyID] = result.Signatures
		}(i)
	}

	wg.Wait()

	for i, err := range signErr {
		if err != nil {
			t.Fatalf("Party %d batch signing failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signatures (same as ECDSA-2P)
	if len(signatures[0]) != len(messages) {
		t.Fatalf("Party 0 should receive %d signatures but got %d", len(messages), len(signatures[0]))
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signatures, got: %d", len(signatures[1]))
	}

	// Verify each signature
	for i := range messages {
		if !ed25519.Verify(ed25519.PublicKey(pubKey), messages[i], signatures[0][i]) {
			t.Fatalf("Ed25519 signature %d verification failed", i)
		}
	}

	t.Logf("Successfully signed and verified %d messages in batch", len(messages))
}

// TestSchnorr2PSignBatchBIP340 tests Schnorr 2P batch signing with BIP340 variant.
func TestSchnorr2PSignBatchBIP340(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys
	var keys [2]*schnorr2p.Key
	var dkgErr [2]error
	var wg sync.WaitGroup

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
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{
				Curve: cbmpc.CurveSecp256k1,
			})
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	for i, err := range dkgErr {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
		if keys[i] == nil {
			t.Fatalf("Party %d key is nil", i)
		}
		defer func() { _ = keys[i].Close() }()
	}

	// Get public key for verification
	pubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	// Hash messages for BIP340
	rawMessages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
	}

	messages := make([][]byte, len(rawMessages))
	for i, msg := range rawMessages {
		hash := sha256.Sum256(msg)
		messages[i] = hash[:]
	}

	var signatures [2][][]byte
	var signErr [2]error

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
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.SignBatch(ctx, job, &schnorr2p.SignBatchParams{
				Key:      keys[partyID],
				Messages: messages,
				Variant:  schnorr2p.VariantBIP340,
			})
			if err != nil {
				signErr[partyID] = err
				return
			}
			signatures[partyID] = result.Signatures
		}(i)
	}

	wg.Wait()

	for i, err := range signErr {
		if err != nil {
			t.Fatalf("Party %d batch signing failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signatures (same as ECDSA-2P)
	if len(signatures[0]) != len(messages) {
		t.Fatalf("Party 0 should receive %d signatures but got %d", len(messages), len(signatures[0]))
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signatures, got: %d", len(signatures[1]))
	}

	// Verify signature lengths (BIP340 signatures are 64 bytes)
	for i, sig := range signatures[0] {
		if len(sig) != 64 {
			t.Fatalf("Signature %d has incorrect length: expected 64, got %d", i, len(sig))
		}
	}

	// Verify the BIP340 signatures using btcec library
	pubKeyBytes, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	for i, sigBytes := range signatures[0] {
		sig, err := btcschnorr.ParseSignature(sigBytes)
		if err != nil {
			t.Fatalf("Failed to parse BIP340 signature %d: %v", i, err)
		}

		if !sig.Verify(messages[i], pubKeyBytes) {
			t.Fatalf("BIP340 signature %d verification failed", i)
		}
	}

	t.Logf("Successfully signed and verified %d messages in batch with BIP340", len(messages))
}

// TestSchnorr2PSignWithRandomMessage tests signing with a random message.
func TestSchnorr2PSignWithRandomMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	net := mocknet.New()
	names := [2]string{"party1", "party2"}

	// Generate keys
	var keys [2]*schnorr2p.Key
	var dkgErr [2]error
	var wg sync.WaitGroup

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
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.DKG(ctx, job, &schnorr2p.DKGParams{
				Curve: cbmpc.CurveEd25519,
			})
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			keys[partyID] = result.Key
		}(i)
	}

	wg.Wait()

	for i, err := range dkgErr {
		if err != nil {
			t.Fatalf("Party %d DKG failed: %v", i, err)
		}
		defer func() { _ = keys[i].Close() }()
	}

	// Create random message
	message := make([]byte, 100)
	if _, err := rand.Read(message); err != nil {
		t.Fatalf("Failed to generate random message: %v", err)
	}

	pubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	var signatures [2][]byte
	var signErr [2]error

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
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorr2p.Sign(ctx, job, &schnorr2p.SignParams{
				Key:     keys[partyID],
				Message: message,
				Variant: schnorr2p.VariantEdDSA,
			})
			if err != nil {
				signErr[partyID] = err
				return
			}
			signatures[partyID] = result.Signature
		}(i)
	}

	wg.Wait()

	for i, err := range signErr {
		if err != nil {
			t.Fatalf("Party %d signing failed: %v", i, err)
		}
	}

	// Only Party 0 (P1) receives the final signature
	if len(signatures[0]) == 0 {
		t.Fatal("Party 0 (P1) should receive signature but got empty")
	}
	if len(signatures[1]) != 0 {
		t.Fatalf("Party 1 (P2) should not receive signature, got: %x", signatures[1])
	}

	// Verify the signature
	if !ed25519.Verify(ed25519.PublicKey(pubKey), message, signatures[0]) {
		t.Fatal("Ed25519 signature verification failed for random message")
	}

	t.Log("Successfully signed and verified random message")
}
