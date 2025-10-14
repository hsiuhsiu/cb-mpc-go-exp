# ZK Proofs Package

This package provides zero-knowledge proof protocols for use in secure multi-party computation.

## Available Protocols

- **UC_DL**: Universally composable discrete logarithm proof (single point)
- **UC_Batch_DL**: Batch discrete logarithm proof (multiple points)
- **DH**: Diffie-Hellman proof

## UC_DL - Universally Composable Discrete Logarithm Proof

The UC_DL protocol is a non-interactive zero-knowledge proof (NIZK) that proves knowledge of a discrete logarithm. Specifically, given a public curve point `Q = w*G` on an elliptic curve, the prover can demonstrate knowledge of the secret exponent `w` without revealing it.

### Features

- **Non-interactive**: Single-message proof (no back-and-forth communication)
- **UC-secure**: Universally composable in the random oracle model
- **Fischlin transform**: Uses the Fischlin transformation for security
- **Type-safe**: Uses proper curve types (`curve.Point`, `curve.Scalar`, `SessionID`)
- **Value semantics**: Proofs are `[]byte` - no resource management needed

### Usage

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Create curve point Q and scalar exponent w
point, _ := curve.NewPointFromBytes(cbmpc.CurveP256, qBytes)
defer point.Free()

exponent, _ := curve.NewScalarFromBytes(wBytes)
defer exponent.Free()

sessionID := cbmpc.NewSessionID(sessionIDBytes)

// Generate proof (returns []byte, no Close() needed)
proof, err := zk.ProveDL(&zk.DLProveParams{
    Point:     point,        // The public point Q = w*G
    Exponent:  exponent,     // The secret discrete log w
    SessionID: sessionID,    // 32-byte session identifier
    Aux:       partyID,      // Auxiliary data (e.g., party ID)
})
if err != nil {
    return err
}
// Proof is just []byte - no Close() needed
// Can serialize, pass to other goroutines, store, etc.

// Verify proof
err = zk.VerifyDL(&zk.DLVerifyParams{
    Proof:     proof,        // Just pass the []byte directly
    Point:     point,
    SessionID: sessionID,
    Aux:       partyID,
})
```

## UC_Batch_DL - Batch Discrete Logarithm Proof

Proves knowledge of multiple discrete logarithms efficiently in a single proof.

### Usage

```go
// Generate proof for multiple points
proof, err := zk.ProveBatchDL(&zk.BatchDLProveParams{
    Points:    []*curve.Point{point1, point2, point3},
    Exponents: []*curve.Scalar{exp1, exp2, exp3},
    SessionID: sessionID,
    Aux:       partyID,
})

// Verify batch proof
err = zk.VerifyBatchDL(&zk.BatchDLVerifyParams{
    Proof:     proof,
    Points:    []*curve.Point{point1, point2, point3},
    SessionID: sessionID,
    Aux:       partyID,
})
```

## DH - Diffie-Hellman Proof

Proves that three points Q, A, B satisfy the Diffie-Hellman relation: B = w*A where Q = w*G.

### Usage

```go
// Generate DH proof
proof, err := zk.ProveDH(&zk.DHProveParams{
    Q:         pointQ,      // Q = w*G
    A:         pointA,      // Public point A
    B:         pointB,      // B = w*A
    Exponent:  scalar,      // Secret w
    SessionID: sessionID,
    Aux:       partyID,
})

// Verify DH proof
err = zk.VerifyDH(&zk.DHVerifyParams{
    Proof:     proof,
    Q:         pointQ,
    A:         pointA,
    B:         pointB,
    SessionID: sessionID,
    Aux:       partyID,
})
```

### Type Safety

The API uses proper cryptographic types:

- **`Point`** (`*curve.Point`): Represents a curve point, encapsulating both the curve and point data
- **`Exponent`** (`*curve.Scalar`): Represents the discrete logarithm (witness), providing constant-time operations
- **`SessionID`** (`cbmpc.SessionID`): Immutable session identifier with defensive copying
- **Curve**: Implicitly determined from the `Point` type

This design prevents common mistakes like:
- Mixing curves (the point already knows its curve)
- Using non-constant-time operations on secrets (scalars use constant-time C++ bn_t)
- Accidental mutation of session IDs (defensive copying)

### Memory Management

**Proofs** are value types (`[]byte`) and require no resource management:
- No `Close()` method
- No finalizers
- Can be freely copied, serialized, and passed across goroutines
- Safe to store in structs or return from functions

**Points and Scalars** must be freed with `Free()` when no longer needed:
- Use `defer point.Free()` immediately after creation
- Use `defer scalar.Free()` immediately after creation

### Security Parameters

The default Fischlin parameters are:
- `t = 32`: Number of bits for the Fischlin challenge
- `l = 4`: Number of parallel executions
- `r = 9`: Repetition factor

These provide strong security guarantees in the UC model.

## References

- See `cb-mpc/src/cbmpc/zk/zk_ec.h` for the C++ implementation details
- Fischlin, M. (2005). "Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors"
