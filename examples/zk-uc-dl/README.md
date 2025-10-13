# ZK UC_DL Proof Example

This example demonstrates the use of Zero-Knowledge Universally Composable Discrete Logarithm (UC_DL) proofs between two parties.

## Overview

The UC_DL protocol allows a prover (P1) to convince a verifier (P2) that they know the discrete logarithm `w` of a public point `Q = w*G`, without revealing `w` itself.

## Scenario

- **P1 (Prover)**: Has a secret exponent `w` and knows the public point `Q = w*G`
- **P2 (Verifier)**: Knows the public point `Q` but not the secret `w`

P1 generates a zero-knowledge proof that they know `w`, stores the proof, retrieves it, and sends it to P2. P2 verifies the proof.

## Two Examples

### Example 1: Valid Proof (Accepted)
P1 generates a proof using the **correct** exponent `w` that corresponds to the public point `Q`. P2's verification succeeds.

### Example 2: Invalid Proof (Rejected)
P1 generates a proof using a **wrong** exponent (different from the actual `w`). P2's verification fails, demonstrating the security of the protocol.

## Running the Example

### Quick Demo (In-Process)

The simplest way to see the demonstration is to run the prover, which will output all the necessary data:

```bash
go run examples/zk-uc-dl/main.go --party p1
```

This will:
1. Generate a random secret exponent `w`
2. Compute public point `Q = w*G`
3. Generate a valid proof with correct exponent
4. Generate an invalid proof with wrong exponent
5. Output all data needed for verification

The output will look like:
```
=== Party 1 (Prover) ===

Generated secret exponent w: 1a2b3c4d...
Computed public point Q = w*G: 02abcdef...

--- Example 1: Valid Proof ---
P1 generates proof with correct exponent w
Generated valid proof (2315 bytes)
Proof bytes: 0a1b2c3d...
Point Q: 02abcdef...
SessionID: 4e5f6071...

--- Example 2: Invalid Proof (Wrong Exponent) ---
P1 generates proof with WRONG exponent (should be rejected by P2)
Using wrong exponent: 9f8e7d6c (instead of correct 1a2b3c4d)
Generated invalid proof (2315 bytes)
Proof bytes: f1e2d3c4...

=== Data for P2 (Verifier) ===
Point Q: 02abcdef...
SessionID: 4e5f6071...
Valid proof: 0a1b2c3d...
Invalid proof: f1e2d3c4...
```

### Two-Party Demo (Separate Processes)

To run P1 and P2 as separate processes:

1. **Run the prover (P1)**:
```bash
go run examples/zk-uc-dl/main.go --party p1
```

Copy the output data (Point Q, SessionID, Valid proof, Invalid proof).

2. **Run the verifier (P2)** with the data from P1:
```bash
go run examples/zk-uc-dl/main.go --party p2 \
  --point <POINT_HEX> \
  --sessionid <SESSION_ID_HEX> \
  --valid-proof <VALID_PROOF_HEX> \
  --invalid-proof <INVALID_PROOF_HEX>
```

P2 will verify both proofs and show:
- ✓ Valid proof verification succeeds (expected)
- ✓ Invalid proof verification fails (expected)

## What This Demonstrates

1. **Proof Generation**: P1 can generate a ZK proof of knowledge of discrete logarithm
2. **Serialization**: Proofs can be stored as bytes and later retrieved
3. **Verification**: P2 can verify proofs without knowing the secret exponent
4. **Security**: Invalid proofs (using wrong exponent) are correctly rejected

## Key API Usage

### Prover Side (P1)

```go
// Create point and exponent
point, _ := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
exponent, _ := curve.NewScalarFromBytes(wBytes)

// Generate proof
proof, _ := zk.Prove(&zk.DLProveParams{
    Point:     point,
    Exponent:  exponent,
    SessionID: sessionID,
    Aux:       1,
})

// Serialize for storage/transmission
proofBytes, _ := proof.Bytes()

// Later: restore from storage
restoredProof, _ := zk.LoadDLProof(proofBytes)
```

### Verifier Side (P2)

```go
// Create point (same as P1)
point, _ := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)

// Deserialize proof received from P1
proof, _ := zk.LoadDLProof(proofBytes)

// Verify
err := zk.Verify(&zk.DLVerifyParams{
    Proof:     proof,
    Point:     point,
    SessionID: sessionID,
    Aux:       1,
})
if err != nil {
    // Verification failed - invalid proof
} else {
    // Verification succeeded - valid proof
}
```

## Protocol Details

The UC_DL protocol uses the Fischlin transform to achieve universally composable security with parameters:
- **t = 32**: Number of challenges
- **l = 4**: Challenge length in bits
- **r = 9**: Number of random coins

This results in proof sizes around 2315 bytes for P-256 curve.

## See Also

- [pkg/cbmpc/zk/uc_dl.go](../../pkg/cbmpc/zk/uc_dl.go) - Public API implementation
- [pkg/cbmpc/zk/uc_dl_test.go](../../pkg/cbmpc/zk/uc_dl_test.go) - Unit tests
- [cb-mpc/src/cbmpc/zk/zk_ec.h](../../cb-mpc/src/cbmpc/zk/zk_ec.h) - Underlying C++ protocol
