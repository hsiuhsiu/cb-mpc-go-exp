package schnorrmp_test

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
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/schnorrmp"
)

// TestSchnorrMPSignEdDSA tests Schnorr MP signing with EdDSA variant (Ed25519).
func TestSchnorrMPSignEdDSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Generate keys using Schnorr MP DKG
	var keys [3]*schnorrmp.Key
	var dkgErr [3]error
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
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

	// Verify all parties have the same public key
	pubKey0, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}
	for i := 1; i < 3; i++ {
		pubKey, err := keys[i].PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey0) != string(pubKey) {
			t.Fatal("Public keys do not match")
		}
	}

	// Sign a message (party 0 will receive the signature)
	message := []byte("Hello, Schnorr MP EdDSA!")
	sigReceiver := 0

	var signatures [3][]byte
	var signErr [3]error

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.Sign(ctx, job, &schnorrmp.SignParams{
				Key:         keys[partyID],
				Message:     message,
				SigReceiver: sigReceiver,
				Variant:     schnorrmp.VariantEdDSA,
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

	// Only the designated receiver (party 0) should receive the signature
	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d (receiver) should receive signature but got empty", sigReceiver)
	}
	for i := 0; i < 3; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d (non-receiver) should not receive signature, got: %x", i, signatures[i])
		}
	}

	// Verify signature length (EdDSA signatures are 64 bytes)
	if len(signatures[sigReceiver]) != ed25519.SignatureSize {
		t.Fatalf("Expected signature length %d, got %d", ed25519.SignatureSize, len(signatures[sigReceiver]))
	}

	// Verify the signature using Ed25519 verification
	if len(pubKey0) != ed25519.PublicKeySize {
		t.Fatalf("Expected public key length %d, got %d", ed25519.PublicKeySize, len(pubKey0))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey0), message, signatures[sigReceiver]) {
		t.Fatal("Ed25519 signature verification failed")
	}

	t.Log("EdDSA signature verified successfully")
}

// TestSchnorrMPSignBIP340 tests Schnorr MP signing with BIP340 variant (secp256k1).
func TestSchnorrMPSignBIP340(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Generate keys using Schnorr MP DKG
	var keys [3]*schnorrmp.Key
	var dkgErr [3]error
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
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

	// Verify all parties have the same public key
	pubKey0, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}
	for i := 1; i < 3; i++ {
		pubKey, err := keys[i].PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey0) != string(pubKey) {
			t.Fatal("Public keys do not match")
		}
	}

	// For BIP340, we need to hash the message first
	message := []byte("Hello, Schnorr MP BIP340!")
	hash := sha256.Sum256(message)
	sigReceiver := 1 // Party 1 will receive the signature

	var signatures [3][]byte
	var signErr [3]error

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.Sign(ctx, job, &schnorrmp.SignParams{
				Key:         keys[partyID],
				Message:     hash[:],
				SigReceiver: sigReceiver,
				Variant:     schnorrmp.VariantBIP340,
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

	// Only the designated receiver should receive the signature
	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d (receiver) should receive signature but got empty", sigReceiver)
	}
	for i := 0; i < 3; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d (non-receiver) should not receive signature, got: %x", i, signatures[i])
		}
	}

	// Verify signature length (BIP340 signatures are 64 bytes)
	if len(signatures[sigReceiver]) != 64 {
		t.Fatalf("Expected signature length 64, got %d", len(signatures[sigReceiver]))
	}

	// Verify the BIP340 signature using btcec library
	pubKeyBytes, err := btcec.ParsePubKey(pubKey0)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	// Parse the BIP340 signature
	sig, err := btcschnorr.ParseSignature(signatures[sigReceiver])
	if err != nil {
		t.Fatalf("Failed to parse BIP340 signature: %v", err)
	}

	// Verify the signature
	if !sig.Verify(hash[:], pubKeyBytes) {
		t.Fatal("BIP340 signature verification failed")
	}

	t.Log("BIP340 signature verified successfully")
}

// TestSchnorrMPSignBatchEdDSA tests Schnorr MP batch signing with EdDSA variant.
func TestSchnorrMPSignBatchEdDSA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Generate keys using Schnorr MP DKG
	var keys [3]*schnorrmp.Key
	var dkgErr [3]error
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
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

	// Sign multiple messages (party 2 will receive the signatures)
	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte("Message 3"),
	}
	sigReceiver := 2

	var signatures [3][][]byte
	var signErr [3]error

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.SignBatch(ctx, job, &schnorrmp.SignBatchParams{
				Key:         keys[partyID],
				Messages:    messages,
				SigReceiver: sigReceiver,
				Variant:     schnorrmp.VariantEdDSA,
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

	// Only the designated receiver should receive signatures
	if len(signatures[sigReceiver]) != len(messages) {
		t.Fatalf("Party %d (receiver) should receive %d signatures but got %d", sigReceiver, len(messages), len(signatures[sigReceiver]))
	}
	for i := 0; i < 3; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d (non-receiver) should not receive signatures, got: %d", i, len(signatures[i]))
		}
	}

	// Verify each signature
	for i := range messages {
		if !ed25519.Verify(ed25519.PublicKey(pubKey), messages[i], signatures[sigReceiver][i]) {
			t.Fatalf("Ed25519 signature %d verification failed", i)
		}
	}

	t.Logf("Successfully signed and verified %d messages in batch", len(messages))
}

// TestSchnorrMPSignBatchBIP340 tests Schnorr MP batch signing with BIP340 variant.
func TestSchnorrMPSignBatchBIP340(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Generate keys using Schnorr MP DKG
	var keys [3]*schnorrmp.Key
	var dkgErr [3]error
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
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

	sigReceiver := 0

	var signatures [3][][]byte
	var signErr [3]error

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.SignBatch(ctx, job, &schnorrmp.SignBatchParams{
				Key:         keys[partyID],
				Messages:    messages,
				SigReceiver: sigReceiver,
				Variant:     schnorrmp.VariantBIP340,
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

	// Only the designated receiver should receive signatures
	if len(signatures[sigReceiver]) != len(messages) {
		t.Fatalf("Party %d (receiver) should receive %d signatures but got %d", sigReceiver, len(messages), len(signatures[sigReceiver]))
	}
	for i := 0; i < 3; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d (non-receiver) should not receive signatures, got: %d", i, len(signatures[i]))
		}
	}

	// Verify signature lengths (BIP340 signatures are 64 bytes)
	for i, sig := range signatures[sigReceiver] {
		if len(sig) != 64 {
			t.Fatalf("Signature %d has incorrect length: expected 64, got %d", i, len(sig))
		}
	}

	// Verify the BIP340 signatures using btcec library
	pubKeyBytes, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	for i, sigBytes := range signatures[sigReceiver] {
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

// TestSchnorrMPSignWithRandomMessage tests signing with a random message.
func TestSchnorrMPSignWithRandomMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	net := mocknet.New()
	roles := []cbmpc.RoleID{0, 1, 2}
	names := []string{"p1", "p2", "p3"}

	// Generate keys using Schnorr MP DKG
	var keys [3]*schnorrmp.Key
	var dkgErr [3]error
	var wg sync.WaitGroup

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				dkgErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{
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

	sigReceiver := 1

	var signatures [3][]byte
	var signErr [3]error

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(cbmpc.RoleID(partyID), roles)
			job, err := cbmpc.NewJobMP(transport, cbmpc.RoleID(partyID), names)
			if err != nil {
				signErr[partyID] = err
				return
			}
			defer func() { _ = job.Close() }()

			result, err := schnorrmp.Sign(ctx, job, &schnorrmp.SignParams{
				Key:         keys[partyID],
				Message:     message,
				SigReceiver: sigReceiver,
				Variant:     schnorrmp.VariantEdDSA,
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

	// Only the designated receiver should receive the signature
	if len(signatures[sigReceiver]) == 0 {
		t.Fatalf("Party %d (receiver) should receive signature but got empty", sigReceiver)
	}
	for i := 0; i < 3; i++ {
		if i != sigReceiver && len(signatures[i]) != 0 {
			t.Fatalf("Party %d (non-receiver) should not receive signature, got: %x", i, signatures[i])
		}
	}

	// Verify the signature
	if !ed25519.Verify(ed25519.PublicKey(pubKey), message, signatures[sigReceiver]) {
		t.Fatal("Ed25519 signature verification failed for random message")
	}

	t.Log("Successfully signed and verified random message")
}
