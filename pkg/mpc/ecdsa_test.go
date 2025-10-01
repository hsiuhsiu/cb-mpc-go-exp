package mpc

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func TestECDSA2PC_KeyGen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test with SECP256R1 (P-256) which has proper Go support
	ecdsa := NewECDSA2PC(SECP256R1)

	// Create mock network for 2 parties
	sessions := NewMockNetwork(2)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	// Run keygen in parallel
	type keyGenResult struct {
		key KeyShare
		err error
	}

	results := make(chan keyGenResult, 2)

	// Party 0
	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[0])
		results <- keyGenResult{key, err}
	}()

	// Party 1
	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[1])
		results <- keyGenResult{key, err}
	}()

	// Collect results
	var key0, key1 KeyShare
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("KeyGen failed: %v", result.err)
		}
		if i == 0 {
			key0 = result.key
		} else {
			key1 = result.key
		}
	}

	defer key0.Close()
	defer key1.Close()

	// Verify both parties have the same public key
	pubKey0, err := key0.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key 0: %v", err)
	}

	pubKey1, err := key1.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key 1: %v", err)
	}

	if len(pubKey0) == 0 || len(pubKey1) == 0 {
		t.Fatal("Public keys are empty")
	}

	if !bytesEqual(pubKey0, pubKey1) {
		t.Fatal("Public keys don't match between parties")
	}

	// Verify curve
	if key0.Curve() != SECP256R1 {
		t.Errorf("Expected curve SECP256R1, got %v", key0.Curve())
	}

	// Verify roles are different
	ecdsa0 := key0.(*ECDSA2PKey)
	ecdsa1 := key1.(*ECDSA2PKey)

	if ecdsa0.GetRole() == ecdsa1.GetRole() {
		t.Error("Both parties have the same role")
	}

	if ecdsa0.GetRole() < 0 || ecdsa0.GetRole() > 1 {
		t.Errorf("Invalid role for party 0: %d", ecdsa0.GetRole())
	}

	if ecdsa1.GetRole() < 0 || ecdsa1.GetRole() > 1 {
		t.Errorf("Invalid role for party 1: %d", ecdsa1.GetRole())
	}
}

func TestECDSA2PC_SignAndVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate keys first
	ecdsa := NewECDSA2PC(SECP256R1)
	sessions := NewMockNetwork(2)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	// Generate keys
	var key0, key1 KeyShare
	type keyGenResult struct {
		key KeyShare
		err error
	}

	results := make(chan keyGenResult, 2)

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[0])
		results <- keyGenResult{key, err}
	}()

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[1])
		results <- keyGenResult{key, err}
	}()

	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("KeyGen failed: %v", result.err)
		}
		if i == 0 {
			key0 = result.key
		} else {
			key1 = result.key
		}
	}

	defer key0.Close()
	defer key1.Close()

	// Test message
	message := []byte("Hello, MPC ECDSA!")

	// Create new sessions for signing
	signSessions := NewMockNetwork(2)
	defer func() {
		for _, s := range signSessions {
			s.Close()
		}
	}()

	// Sign in parallel
	type signResult struct {
		signature []byte
		err       error
		party     int
	}

	signResults := make(chan signResult, 2)

	go func() {
		sig, err := key0.(*ECDSA2PKey).Sign(ctx, signSessions[0], message)
		signResults <- signResult{sig, err, 0}
	}()

	go func() {
		sig, err := key1.(*ECDSA2PKey).Sign(ctx, signSessions[1], message)
		signResults <- signResult{sig, err, 1}
	}()

	// Collect signatures
	var sig0, sig1 []byte
	for i := 0; i < 2; i++ {
		result := <-signResults
		if result.err != nil {
			t.Fatalf("Sign failed for party %d: %v", result.party, result.err)
		}
		if result.party == 0 {
			sig0 = result.signature
		} else {
			sig1 = result.signature
		}
	}

	// In 2PC ECDSA, only Party 0 (role 0) gets the signature
	if len(sig0) == 0 {
		t.Fatal("Party 0 should have received the signature")
	}

	// Party 1 (role 1) typically gets an empty signature in 2PC ECDSA
	if len(sig1) != 0 {
		t.Logf("Note: Party 1 unexpectedly received a signature of length %d", len(sig1))
	}

	// Verify signature
	err := key0.(*ECDSA2PKey).VerifySignature(message, sig0)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	// Verify signature with wrong message should fail
	wrongMessage := []byte("Wrong message")
	err = key0.(*ECDSA2PKey).VerifySignature(wrongMessage, sig0)
	if err == nil {
		t.Error("Signature verification should have failed for wrong message")
	}
}

func TestECDSA2PC_Refresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate initial keys
	ecdsa := NewECDSA2PC(SECP256R1)
	sessions := NewMockNetwork(2)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	var key0, key1 KeyShare
	type keyGenResult struct {
		key KeyShare
		err error
	}

	results := make(chan keyGenResult, 2)

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[0])
		results <- keyGenResult{key, err}
	}()

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[1])
		results <- keyGenResult{key, err}
	}()

	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("KeyGen failed: %v", result.err)
		}
		if i == 0 {
			key0 = result.key
		} else {
			key1 = result.key
		}
	}

	defer key0.Close()
	defer key1.Close()

	// Get original public key
	originalPubKey, err := key0.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get original public key: %v", err)
	}

	// Refresh keys
	refreshSessions := NewMockNetwork(2)
	defer func() {
		for _, s := range refreshSessions {
			s.Close()
		}
	}()

	type refreshResult struct {
		key KeyShare
		err error
	}

	refreshResults := make(chan refreshResult, 2)

	go func() {
		newKey, err := key0.(*ECDSA2PKey).Refresh(ctx, refreshSessions[0])
		refreshResults <- refreshResult{newKey, err}
	}()

	go func() {
		newKey, err := key1.(*ECDSA2PKey).Refresh(ctx, refreshSessions[1])
		refreshResults <- refreshResult{newKey, err}
	}()

	var newKey0, newKey1 KeyShare
	for i := 0; i < 2; i++ {
		result := <-refreshResults
		if result.err != nil {
			t.Fatalf("Refresh failed: %v", result.err)
		}
		if i == 0 {
			newKey0 = result.key
		} else {
			newKey1 = result.key
		}
	}

	defer newKey0.Close()
	defer newKey1.Close()

	// Verify public key is the same
	newPubKey, err := newKey0.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get refreshed public key: %v", err)
	}

	if !bytesEqual(originalPubKey, newPubKey) {
		t.Error("Public key changed after refresh")
	}

	// Verify we can still sign with refreshed keys
	message := []byte("Test with refreshed keys")

	signSessions := NewMockNetwork(2)
	defer func() {
		for _, s := range signSessions {
			s.Close()
		}
	}()

	type signResult struct {
		signature []byte
		err       error
		party     int
	}

	signResults := make(chan signResult, 2)

	go func() {
		sig, err := newKey0.(*ECDSA2PKey).Sign(ctx, signSessions[0], message)
		signResults <- signResult{sig, err, 0}
	}()

	go func() {
		sig, err := newKey1.(*ECDSA2PKey).Sign(ctx, signSessions[1], message)
		signResults <- signResult{sig, err, 1}
	}()

	var sig0, sig1 []byte
	for i := 0; i < 2; i++ {
		result := <-signResults
		if result.err != nil {
			t.Fatalf("Sign with refreshed keys failed for party %d: %v", result.party, result.err)
		}
		if result.party == 0 {
			sig0 = result.signature
		} else {
			sig1 = result.signature
		}
	}

	// In 2PC ECDSA, only Party 0 (role 0) gets the signature
	if len(sig0) == 0 {
		t.Fatal("Party 0 should have received the signature with refreshed keys")
	}

	// Party 1 gets empty signature - this is expected in 2PC ECDSA
	if len(sig1) != 0 {
		t.Logf("Note: Party 1 unexpectedly received a signature of length %d with refreshed keys", len(sig1))
	}

	// Verify signature with refreshed key
	err = newKey0.(*ECDSA2PKey).VerifySignature(message, sig0)
	if err != nil {
		t.Fatalf("Signature verification with refreshed key failed: %v", err)
	}
}

func TestECDSA2PC_InvalidInput(t *testing.T) {
	ecdsa := NewECDSA2PC(SECP256R1)

	// Test nil context
	_, err := ecdsa.KeyGen(nil, nil)
	if err == nil {
		t.Error("Expected error for nil context")
	}

	// Test nil session
	ctx := context.Background()
	_, err = ecdsa.KeyGen(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil session")
	}

	// Test wrong party count
	sessions := NewMockNetwork(3) // 3 parties instead of 2
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	_, err = ecdsa.KeyGen(ctx, sessions[0])
	if err == nil {
		t.Error("Expected error for wrong party count")
	}
}

func TestECDSA2PC_ContextCancellation(t *testing.T) {
	ecdsa := NewECDSA2PC(SECP256R1)
	sessions := NewMockNetwork(2)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := ecdsa.KeyGen(ctx, sessions[0])
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestECDSA2PC_ConcurrentSigning(t *testing.T) {
	// Test multiple concurrent signing operations
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate keys
	ecdsa := NewECDSA2PC(SECP256R1)
	sessions := NewMockNetwork(2)
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	var key0, key1 KeyShare
	type keyGenResult struct {
		key KeyShare
		err error
	}

	results := make(chan keyGenResult, 2)

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[0])
		results <- keyGenResult{key, err}
	}()

	go func() {
		key, err := ecdsa.KeyGen(ctx, sessions[1])
		results <- keyGenResult{key, err}
	}()

	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("KeyGen failed: %v", result.err)
		}
		if i == 0 {
			key0 = result.key
		} else {
			key1 = result.key
		}
	}

	defer key0.Close()
	defer key1.Close()

	// Perform multiple signing operations concurrently
	numSigns := 5
	type signOp struct {
		message []byte
		index   int
	}

	signOps := make([]signOp, numSigns)
	for i := 0; i < numSigns; i++ {
		message := make([]byte, 32)
		rand.Read(message)
		signOps[i] = signOp{message, i}
	}

	// Create separate networks for each signing operation
	networks := make([][]*MockSession, numSigns)
	for i := 0; i < numSigns; i++ {
		networks[i] = NewMockNetwork(2)
		defer func(sessions []*MockSession) {
			for _, s := range sessions {
				s.Close()
			}
		}(networks[i])
	}

	type signResult struct {
		signature []byte
		index     int
		err       error
	}

	signResults := make(chan signResult, numSigns*2)

	// Start all signing operations
	for i, op := range signOps {
		go func(op signOp, netIdx int) {
			sig, err := key0.(*ECDSA2PKey).Sign(ctx, networks[netIdx][0], op.message)
			signResults <- signResult{sig, op.index, err}
		}(op, i)

		go func(op signOp, netIdx int) {
			sig, err := key1.(*ECDSA2PKey).Sign(ctx, networks[netIdx][1], op.message)
			signResults <- signResult{sig, op.index, err}
		}(op, i)
	}

	// Collect and verify results
	signatures := make(map[int][][]byte)
	for i := 0; i < numSigns*2; i++ {
		result := <-signResults
		if result.err != nil {
			t.Fatalf("Concurrent sign %d failed: %v", result.index, result.err)
		}

		if signatures[result.index] == nil {
			signatures[result.index] = make([][]byte, 0, 2)
		}
		signatures[result.index] = append(signatures[result.index], result.signature)
	}

	// Verify all signatures
	for i, op := range signOps {
		sigs := signatures[i]
		if len(sigs) != 2 {
			t.Fatalf("Expected 2 signatures for operation %d, got %d", i, len(sigs))
		}

		// In 2PC ECDSA, Party 0 gets the signature, Party 1 gets empty
		var validSig []byte
		if len(sigs[0]) > 0 {
			validSig = sigs[0]
		} else if len(sigs[1]) > 0 {
			validSig = sigs[1]
		} else {
			t.Errorf("No valid signature found for operation %d", i)
			continue
		}

		// Verify signature
		err := key0.(*ECDSA2PKey).VerifySignature(op.message, validSig)
		if err != nil {
			t.Errorf("Signature verification failed for operation %d: %v", i, err)
		}
	}
}
