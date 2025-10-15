//go:build cgo && !windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

func main() {
	var (
		party           = flag.String("party", "p1", "party name (p1 or p2)")
		pointHex        = flag.String("point", "", "public point Q (hex) - for p2 only")
		sessionIDHex    = flag.String("sessionid", "", "session ID (hex) - for p2 only")
		validProofHex   = flag.String("valid-proof", "", "valid proof bytes (hex) - for p2 only")
		invalidProofHex = flag.String("invalid-proof", "", "invalid proof bytes (hex) - for p2 only")
	)
	flag.Parse()

	switch *party {
	case "p1":
		runProver()
	case "p2":
		runVerifier(*pointHex, *sessionIDHex, *validProofHex, *invalidProofHex)
	default:
		log.Fatalf("unknown party %q, must be p1 or p2", *party)
	}
}

// runProver demonstrates P1 generating proofs (both valid and invalid)
func runProver() {
	fmt.Println("=== Party 1 (Prover) ===\n")

	// Generate a random exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		log.Fatalf("generate random exponent: %v", err)
	}
	defer exponent.Free()

	// Compute Q = w*G (public point)
	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		log.Fatalf("compute Q = w*G: %v", err)
	}
	defer point.Free()

	qBytes, err := point.Bytes()
	if err != nil {
		log.Fatalf("get point bytes: %v", err)
	}

	wBytes := exponent.Bytes
	fmt.Printf("Generated secret exponent w: %s\n", hex.EncodeToString(wBytes[:8]))
	fmt.Printf("Computed public point Q = w*G: %s...\n\n", hex.EncodeToString(qBytes[:16]))

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		log.Fatalf("generate session ID: %v", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Example 1: Generate valid proof (P1 has the correct exponent)
	fmt.Println("--- Example 1: Valid Proof ---")
	fmt.Println("P1 generates proof with correct exponent w")

	// Proof is returned as bytes - no Close() needed
	proof1, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1, // party ID
	})
	if err != nil {
		log.Fatalf("generate valid proof: %v", err)
	}

	// Proof is already serialized bytes, ready for transmission or storage
	fmt.Printf("Generated valid proof (%d bytes)\n", len(proof1))
	fmt.Printf("Proof bytes: %s...\n", hex.EncodeToString(proof1[:32]))
	fmt.Printf("Point Q: %s\n", hex.EncodeToString(qBytes))
	fmt.Printf("SessionID: %s\n\n", hex.EncodeToString(sessionIDBytes))

	// Example 2: Generate invalid proof (P1 uses wrong exponent)
	fmt.Println("--- Example 2: Invalid Proof (Wrong Exponent) ---")
	fmt.Println("P1 generates proof with WRONG exponent (should be rejected by P2)")

	// Generate a different random exponent (wrong one!)
	wrongExponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		log.Fatalf("generate wrong exponent: %v", err)
	}
	defer wrongExponent.Free()

	wrongWBytes := wrongExponent.Bytes
	fmt.Printf("Using wrong exponent: %s (instead of correct %s)\n",
		hex.EncodeToString(wrongWBytes[:8]),
		hex.EncodeToString(wBytes[:8]))

	proof2, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point, // Same public point Q
		Exponent:  wrongExponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		log.Fatalf("generate invalid proof: %v", err)
	}

	fmt.Printf("Generated invalid proof (%d bytes)\n", len(proof2))
	fmt.Printf("Proof bytes: %s...\n\n", hex.EncodeToString(proof2[:32]))

	// Save data for P2 to verify
	fmt.Println("=== Data for P2 (Verifier) ===")
	fmt.Printf("Point Q: %s\n", hex.EncodeToString(qBytes))
	fmt.Printf("SessionID: %s\n", hex.EncodeToString(sessionIDBytes))
	fmt.Printf("Valid proof: %s\n", hex.EncodeToString(proof1))
	fmt.Printf("Invalid proof: %s\n", hex.EncodeToString(proof2))
}

// runVerifier demonstrates P2 verifying proofs from P1
func runVerifier(pointHex, sessionIDHex, validProofHex, invalidProofHex string) {
	fmt.Println("=== Party 2 (Verifier) ===\n")

	// In a real scenario, these would be received from P1
	// For demonstration, we'll use values passed via command line flags

	if pointHex == "" || sessionIDHex == "" || validProofHex == "" || invalidProofHex == "" {
		fmt.Println("Verifier requires data from prover. Run with flags:")
		fmt.Println("  --point <hex>")
		fmt.Println("  --sessionid <hex>")
		fmt.Println("  --valid-proof <hex>")
		fmt.Println("  --invalid-proof <hex>")
		fmt.Println("\nFor a quick demo, run the prover first and copy the output data.")
		return
	}

	qBytes, err := hex.DecodeString(pointHex)
	if err != nil {
		log.Fatalf("decode point: %v", err)
	}

	sessionIDBytes, err := hex.DecodeString(sessionIDHex)
	if err != nil {
		log.Fatalf("decode session ID: %v", err)
	}

	validProofBytes, err := hex.DecodeString(validProofHex)
	if err != nil {
		log.Fatalf("decode valid proof: %v", err)
	}

	invalidProofBytes, err := hex.DecodeString(invalidProofHex)
	if err != nil {
		log.Fatalf("decode invalid proof: %v", err)
	}

	fmt.Printf("Received public point Q: %s...\n", hex.EncodeToString(qBytes[:16]))
	fmt.Printf("Received session ID: %s...\n\n", hex.EncodeToString(sessionIDBytes[:16]))

	// Create point from bytes
	point, err := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
	if err != nil {
		log.Fatalf("create point: %v", err)
	}
	defer point.Free()

	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Verify Example 1: Valid proof
	// Proof bytes are already in the right format - just use them directly
	fmt.Println("--- Verifying Example 1: Valid Proof ---")

	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     zk.DLProof(validProofBytes),
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		fmt.Printf("❌ Verification FAILED (unexpected): %v\n\n", err)
	} else {
		fmt.Printf("✓ Verification SUCCEEDED (expected)\n\n")
	}

	// Verify Example 2: Invalid proof
	fmt.Println("--- Verifying Example 2: Invalid Proof ---")

	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     zk.DLProof(invalidProofBytes),
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		fmt.Printf("✓ Verification FAILED (expected): %v\n\n", err)
	} else {
		fmt.Printf("❌ Verification SUCCEEDED (unexpected)\n\n")
	}

	fmt.Println("=== Verification Complete ===")
}

// demonstration runs both prover and verifier in-process for easy demonstration
func demonstration() error {
	fmt.Println("=== ZK UC_DL Proof Demonstration ===\n")

	// Generate a random exponent w
	exponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return fmt.Errorf("generate random exponent: %w", err)
	}
	defer exponent.Free()

	// Compute Q = w*G (public point)
	point, err := curve.MulGenerator(curve.P256, exponent)
	if err != nil {
		return fmt.Errorf("compute Q = w*G: %w", err)
	}
	defer point.Free()

	qBytes, err := point.Bytes()
	if err != nil {
		return fmt.Errorf("get point bytes: %w", err)
	}

	wBytes := exponent.Bytes
	fmt.Println("Setup:")
	fmt.Printf("  Secret exponent w: %s...\n", hex.EncodeToString(wBytes[:8]))
	fmt.Printf("  Public point Q = w*G: %s...\n\n", hex.EncodeToString(qBytes[:16]))

	// Create session ID
	sessionIDBytes := make([]byte, 32)
	if _, err := rand.Read(sessionIDBytes); err != nil {
		return fmt.Errorf("generate session ID: %w", err)
	}
	sessionID := cbmpc.NewSessionID(sessionIDBytes)

	// Example 1: P1 generates valid proof
	fmt.Println("--- Example 1: Valid Proof ---")
	fmt.Println("P1: Generating proof with correct exponent w")

	proof1, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  exponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("generate valid proof: %w", err)
	}

	fmt.Printf("P1: Generated proof (%d bytes)\n", len(proof1))

	// P1 stores and retrieves the proof (proof is just bytes, can be stored anywhere)
	fmt.Println("P1: Storing proof...")
	storedProof := make([]byte, len(proof1))
	copy(storedProof, proof1)
	fmt.Println("P1: Retrieved proof from storage")

	// P1 sends proof to P2
	fmt.Println("P1: Sending proof to P2...")

	// P2 verifies the proof
	fmt.Println("P2: Verifying proof...")
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     storedProof,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		fmt.Printf("P2: ❌ Verification FAILED (unexpected): %v\n\n", err)
	} else {
		fmt.Println("P2: ✓ Verification SUCCEEDED (expected)\n")
	}

	// Example 2: P1 generates invalid proof (wrong exponent)
	fmt.Println("--- Example 2: Invalid Proof (Wrong Exponent) ---")
	fmt.Println("P1: Generating proof with WRONG exponent")

	wrongExponent, err := curve.RandomScalar(curve.P256)
	if err != nil {
		return fmt.Errorf("generate wrong exponent: %w", err)
	}
	defer wrongExponent.Free()

	proof2, err := zk.ProveDL(&zk.DLProveParams{
		Point:     point,
		Exponent:  wrongExponent,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		return fmt.Errorf("generate invalid proof: %w", err)
	}

	fmt.Printf("P1: Generated proof with wrong exponent (%d bytes)\n", len(proof2))

	// P1 stores and retrieves the proof
	fmt.Println("P1: Storing proof...")
	storedProof2 := make([]byte, len(proof2))
	copy(storedProof2, proof2)
	fmt.Println("P1: Retrieved proof from storage")

	// P1 sends proof to P2
	fmt.Println("P1: Sending proof to P2...")

	// P2 verifies the proof
	fmt.Println("P2: Verifying proof...")
	err = zk.VerifyDL(&zk.DLVerifyParams{
		Proof:     storedProof2,
		Point:     point,
		SessionID: sessionID,
		Aux:       1,
	})
	if err != nil {
		fmt.Printf("P2: ✓ Verification FAILED (expected): %v\n\n", err)
	} else {
		fmt.Println("P2: ❌ Verification SUCCEEDED (unexpected)\n")
	}

	fmt.Println("=== Demonstration Complete ===")
	return nil
}
