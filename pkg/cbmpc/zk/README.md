# ZK Proofs Package

This package provides zero-knowledge proof protocols for use in secure multi-party computation.

## UC_DL - Universally Composable Discrete Logarithm Proof

The UC_DL protocol is a non-interactive zero-knowledge proof (NIZK) that proves knowledge of a discrete logarithm. Specifically, given a public curve point `Q = w*G` on an elliptic curve, the prover can demonstrate knowledge of the secret exponent `w` without revealing it.

### Features

- **Non-interactive**: Single-message proof (no back-and-forth communication)
- **UC-secure**: Universally composable in the random oracle model
- **Fischlin transform**: Uses the Fischlin transformation for security
- **Type-safe**: Uses proper curve types (`curve.Point`, `curve.Scalar`, `SessionID`)

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

// Generate proof
proof, err := zk.Prove(&zk.DLProveParams{
    Point:     point,        // The public point Q = w*G
    Exponent:  exponent,     // The secret discrete log w
    SessionID: sessionID,    // 32-byte session identifier
    Aux:       partyID,      // Auxiliary data (e.g., party ID)
})
if err != nil {
    return err
}
defer proof.Close()

// Verify proof
err = zk.Verify(&zk.DLVerifyParams{
    Proof:     proof,
    Point:     point,
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

### Serialization

Proofs can be serialized for transmission or storage:

```go
// Serialize
proofBytes, err := proof.Bytes()

// Deserialize
proof2, err := zk.LoadDLProof(proofBytes)
defer proof2.Close()
```

### Memory Management

Proofs must be explicitly freed with `Close()` when no longer needed. A finalizer is set as a safety net, but relying on it may cause resource leaks. Best practice is to use `defer proof.Close()` immediately after creating or loading a proof.

The same applies to `curve.Point` and `curve.Scalar` types.

### Security Parameters

The default Fischlin parameters are:
- `t = 32`: Number of bits for the Fischlin challenge
- `l = 4`: Number of parallel executions
- `r = 9`: Repetition factor

These provide strong security guarantees in the UC model.

## Future Protocols

This package will be extended with additional ZK protocols:
- Batch DL proofs (multiple discrete logs in one proof)
- Diffie-Hellman proofs
- Paillier encryption proofs
- And more...

## References

- See `cb-mpc/src/cbmpc/zk/zk_ec.h` for the C++ implementation details
- Fischlin, M. (2005). "Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors"
