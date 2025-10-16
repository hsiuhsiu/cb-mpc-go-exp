//go:build cgo && !windows

package pve_test

import (
	"context"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	ac "github.com/coinbase/cb-mpc-go/pkg/cbmpc/accessstructure"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/testkem"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

// TestPVEACEncryptSimpleThreshold tests PVE-AC encryption with a simple 2-of-3 threshold.
func TestPVEACEncryptSimpleThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Create a 2-of-3 threshold AC structure
	acExpr := ac.Threshold(2,
		ac.Leaf("alice"),
		ac.Leaf("bob"),
		ac.Leaf("charlie"),
	)

	// Compile access structure
	structure, err := ac.Compile(acExpr)
	if err != nil {
		t.Fatalf("Failed to compile AC: %v", err)
	}

	// Get actual paths from AC structure using dynamic discovery
	paths, err := backend.ACListLeafPaths(structure)
	if err != nil {
		t.Fatalf("Failed to list leaf paths: %v", err)
	}

	// Generate key pairs for each path
	pathToEK := make(map[string][]byte)
	for _, path := range paths {
		_, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair for %s: %v", path, err)
		}
		pathToEK[path] = ek
	}

	// Create scalars to encrypt (one per party)
	scalars := make([][]byte, len(paths))
	for i := 0; i < len(paths); i++ {
		x, err := curve.NewScalarFromString("12345678901234567890")
		if err != nil {
			t.Fatalf("Failed to create scalar %d: %v", i, err)
		}
		scalars[i] = x.Bytes
		x.Free()
	}

	// Test parameters
	crv := cbmpc.CurveP256
	label := []byte("test-ac-label")

	// Encrypt
	encryptResult, err := pveInstance.ACEncrypt(ctx, &pve.ACEncryptParams{
		AC:       structure,
		PathToEK: pathToEK,
		Label:    label,
		Curve:    crv,
		Scalars:  scalars,
	})
	if err != nil {
		t.Fatalf("ACEncrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext
	if len(ct) == 0 {
		t.Fatal("ACCiphertext is empty")
	}

	// Verify we got bytes back
	ctBytes := ct.Bytes()
	if len(ctBytes) == 0 {
		t.Fatal("ACCiphertext.Bytes() returned empty slice")
	}
}

// TestPVEACEncryptComplexNested tests PVE-AC encryption with a complex nested policy.
func TestPVEACEncryptComplexNested(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Create a complex nested policy:
	// Requires alice AND (bob OR (2-of-3: charlie, dave, eve))
	acExpr := ac.And(
		ac.Leaf("alice"),
		ac.Or(
			ac.Leaf("bob"),
			ac.Threshold(2,
				ac.Leaf("charlie"),
				ac.Leaf("dave"),
				ac.Leaf("eve"),
			),
		),
	)

	// Compile AC
	structure, err := ac.Compile(acExpr)
	if err != nil {
		t.Fatalf("Failed to compile AC: %v", err)
	}

	// Get actual paths from AC structure using dynamic discovery
	paths, err := backend.ACListLeafPaths(structure)
	if err != nil {
		t.Fatalf("Failed to list leaf paths: %v", err)
	}

	t.Logf("Complex nested - discovered %d paths: %v", len(paths), paths)

	// Generate key pairs for each path
	pathToEK := make(map[string][]byte)
	for _, path := range paths {
		_, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair for %s: %v", path, err)
		}
		pathToEK[path] = ek
	}

	// Create scalars (one per party)
	scalars := make([][]byte, len(paths))
	for i := 0; i < len(paths); i++ {
		x, err := curve.NewScalarFromString("99999999999999999999")
		if err != nil {
			t.Fatalf("Failed to create scalar %d: %v", i, err)
		}
		scalars[i] = x.Bytes
		x.Free()
	}

	// Test parameters
	crv := cbmpc.CurveSecp256k1
	label := []byte("complex-ac-label")

	// Encrypt
	encryptResult, err := pveInstance.ACEncrypt(ctx, &pve.ACEncryptParams{
		AC:       structure,
		PathToEK: pathToEK,
		Label:    label,
		Curve:    crv,
		Scalars:  scalars,
	})
	if err != nil {
		t.Fatalf("ACEncrypt failed: %v", err)
	}

	if len(encryptResult.Ciphertext) == 0 {
		t.Fatal("ACCiphertext is empty")
	}
}

// TestPVEACEncryptSimpleAnd tests PVE-AC encryption with a simple AND gate.
func TestPVEACEncryptSimpleAnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Simple AND: both alice AND bob required
	acExpr := ac.And(
		ac.Leaf("alice"),
		ac.Leaf("bob"),
	)

	structure, err := ac.Compile(acExpr)
	if err != nil {
		t.Fatalf("Failed to compile AC: %v", err)
	}

	// Get actual paths from AC structure using dynamic discovery
	paths, err := backend.ACListLeafPaths(structure)
	if err != nil {
		t.Fatalf("Failed to list leaf paths: %v", err)
	}

	// Generate key pairs for each path
	pathToEK := make(map[string][]byte)
	for _, path := range paths {
		_, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair for %s: %v", path, err)
		}
		pathToEK[path] = ek
	}

	// Create scalars
	scalars := make([][]byte, len(paths))
	for i := 0; i < len(paths); i++ {
		x, err := curve.NewScalarFromString("42")
		if err != nil {
			t.Fatalf("Failed to create scalar %d: %v", i, err)
		}
		scalars[i] = x.Bytes
		x.Free()
	}

	// Encrypt
	encryptResult, err := pveInstance.ACEncrypt(ctx, &pve.ACEncryptParams{
		AC:       structure,
		PathToEK: pathToEK,
		Label:    []byte("and-test"),
		Curve:    cbmpc.CurveP256,
		Scalars:  scalars,
	})
	if err != nil {
		t.Fatalf("ACEncrypt failed: %v", err)
	}

	if len(encryptResult.Ciphertext) == 0 {
		t.Fatal("ACCiphertext is empty")
	}
}

// TestPVEACDecryptAggregate tests PVE-AC party-decrypt and aggregate workflow:
// encrypt → party-decrypt (multiple parties) → aggregate
func TestPVEACDecryptAggregate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Set up ToyRSAKEM
	kem := testkem.NewToyRSAKEM(2048)

	// Create PVE instance
	pveInstance, err := pve.New(kem)
	if err != nil {
		t.Fatalf("Failed to create PVE instance: %v", err)
	}

	// Create a 2-of-3 threshold AC structure
	acExpr := ac.Threshold(2,
		ac.Leaf("alice"),
		ac.Leaf("bob"),
		ac.Leaf("charlie"),
	)

	structure, err := ac.Compile(acExpr)
	if err != nil {
		t.Fatalf("Failed to compile AC: %v", err)
	}

	// Get paths from AC
	paths, err := backend.ACListLeafPaths(structure)
	if err != nil {
		t.Fatalf("Failed to list leaf paths: %v", err)
	}
	t.Logf("Paths: %v", paths)

	// Generate key pairs for each path
	type KeyPair struct {
		DK any
		EK []byte
	}
	pathToKeys := make(map[string]*KeyPair)
	pathToEK := make(map[string][]byte)

	for _, path := range paths {
		skRef, ek, err := kem.Generate()
		if err != nil {
			t.Fatalf("Failed to generate key pair for %s: %v", path, err)
		}
		dkHandle, err := kem.NewPrivateKeyHandle(skRef)
		if err != nil {
			t.Fatalf("Failed to create private key handle for %s: %v", path, err)
		}
		pathToKeys[path] = &KeyPair{DK: dkHandle, EK: ek}
		pathToEK[path] = ek
	}

	// Create scalars to encrypt (one per party)
	crv := cbmpc.CurveP256
	scalars := make([][]byte, len(paths))

	// Create unique scalars for each party (use curve size for proper padding)
	// Use large non-zero values to avoid infinity points (Q = x*G)
	scalarStrings := []string{"123456789012345", "987654321098765", "555555555555555"}
	for i := 0; i < len(paths); i++ {
		x, err := curve.NewScalarFromString(scalarStrings[i])
		if err != nil {
			t.Fatalf("Failed to create scalar %d: %v", i, err)
		}
		// Use BytesPadded to ensure fixed-size scalar representation for the curve
		scalars[i] = x.BytesPadded(crv)
		x.Free()
	}

	label := []byte("test-ac-label")

	// Step 1: Encrypt
	encryptResult, err := pveInstance.ACEncrypt(ctx, &pve.ACEncryptParams{
		AC:       structure,
		PathToEK: pathToEK,
		Label:    label,
		Curve:    crv,
		Scalars:  scalars,
	})
	if err != nil {
		t.Fatalf("ACEncrypt failed: %v", err)
	}

	ct := encryptResult.Ciphertext
	if len(ct) == 0 {
		t.Fatal("ACCiphertext is empty")
	}
	t.Logf("Encrypted ciphertext: %d bytes", len(ct))

	// Debug: Verify that encryption created valid Q points (not infinity)
	// by checking if we can compute Q = x*G for each scalar
	for i, scalar := range scalars {
		x, err := curve.NewScalarFromBytes(scalar)
		if err != nil {
			t.Fatalf("Failed to recreate scalar %d: %v", i, err)
		}
		Q, err := curve.MulGenerator(crv, x)
		if err != nil {
			t.Fatalf("Failed to compute Q = x*G for scalar %d: %v", i, err)
		}
		Qbytes, err := Q.Bytes()
		if err != nil {
			t.Fatalf("Failed to get Q bytes for scalar %d: %v", i, err)
		}
		t.Logf("Scalar %d: Q point is %d bytes (not infinity)", i, len(Qbytes))
		Q.Free()
		x.Free()
	}

	// Step 2: Party decrypt (we'll use alice and bob to form a quorum)
	// For a 2-of-3 threshold, we need 2 parties to decrypt
	t.Log("Step 2: Party decrypting...")
	// Use the first two paths from the AC structure
	quorumPaths := paths[:2]
	rowIndex := 0 // Decrypt the first row

	quorumPathToShare := make(map[string][]byte)
	for _, fullPath := range quorumPaths {
		kp := pathToKeys[fullPath]
		if kp == nil {
			t.Fatalf("No key pair for path %s", fullPath)
		}

		// Strip leading "/" from path - C++ party_decrypt_row uses list_leaf_names() which
		// returns names without the "/" prefix (e.g., "alice" not "/alice")
		path := fullPath
		if len(path) > 0 && path[0] == '/' {
			path = path[1:]
		}

		shareResult, err := pveInstance.ACPartyDecryptRow(ctx, &pve.ACPartyDecryptRowParams{
			AC:         structure,
			RowIndex:   rowIndex,
			Path:       path,
			DK:         kp.DK,
			Ciphertext: ct,
			Label:      label,
		})
		if err != nil {
			t.Fatalf("ACPartyDecryptRow failed for %s: %v", path, err)
		}

		quorumPathToShare[path] = shareResult.Share
		t.Logf("Party %s decrypted share: %d bytes", path, len(shareResult.Share))
	}

	// Step 3: Aggregate to restore (without verification)
	t.Log("Step 3: Aggregating to restore...")
	aggregateResult, err := pveInstance.ACAggregateToRestoreRow(ctx, &pve.ACAggregateToRestoreRowParams{
		AC:                structure,
		RowIndex:          rowIndex,
		Label:             label,
		QuorumPathToShare: quorumPathToShare,
		Ciphertext:        ct,
		AllPathToEK:       nil, // Skip verification during aggregation
	})
	if err != nil {
		t.Fatalf("ACAggregateToRestoreRow failed: %v", err)
	}

	restoredScalars := aggregateResult.Scalars
	if len(restoredScalars) == 0 {
		t.Fatal("No scalars restored")
	}
	t.Logf("Restored %d scalars", len(restoredScalars))

	// Verify restored scalars match original
	if len(restoredScalars) != len(scalars) {
		t.Fatalf("Restored scalar count mismatch: got %d, want %d", len(restoredScalars), len(scalars))
	}

	for i := range restoredScalars {
		// Create Scalar objects for comparison using Equal method
		// This handles byte-length differences (e.g., C++ may strip leading zeros)
		origScalar, err := curve.NewScalarFromBytes(scalars[i])
		if err != nil {
			t.Fatalf("Failed to create original scalar %d: %v", i, err)
		}
		defer origScalar.Free()

		restoredScalar, err := curve.NewScalarFromBytes(restoredScalars[i])
		if err != nil {
			t.Fatalf("Failed to create restored scalar %d: %v", i, err)
		}
		defer restoredScalar.Free()

		if !origScalar.Equal(restoredScalar) {
			t.Errorf("Restored scalar %d does not match original\n  original:  %d bytes: %x\n  restored:  %d bytes: %x",
				i, len(scalars[i]), scalars[i], len(restoredScalars[i]), restoredScalars[i])
		}
	}

	t.Log("All scalars restored correctly!")
}
