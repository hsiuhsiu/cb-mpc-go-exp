# ZK Proofs Package

This package provides zero-knowledge proof protocols for use in secure multi-party computation.

## Available Protocols

- **UC_DL**: Universally composable discrete logarithm proof (single point)
- **UC_Batch_DL**: Batch discrete logarithm proof (multiple points)
- **UC_ElGamal_Com**: ElGamal commitment proof (proves knowledge of commitment opening)
- **DH**: Diffie-Hellman proof
- **ElGamal_Com_PubShare_Equ**: Proves equality of public share in ElGamal commitment
- **ElGamal_Com_Mult**: Proves multiplicative relationship between ElGamal commitments
- **UC_ElGamal_Com_Mult_Private_Scalar**: UC-secure multiplication with private scalar

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

## UC_ElGamal_Com - ElGamal Commitment Proof

The UC_ElGamal_Com protocol is a non-interactive zero-knowledge proof that proves knowledge of the opening of an ElGamal commitment. Specifically, given an ElGamal commitment `UV = (L, R)` where `L = r*G` and `R = x*Q + r*G`, the prover demonstrates knowledge of both the secret value `x` and the randomness `r` without revealing them.

### What is an ElGamal Commitment?

An ElGamal commitment is a cryptographic commitment scheme based on the Diffie-Hellman problem:
- **Commitment**: `UV = (L, R)` where `L = r*G` and `R = x*Q + r*G`
- **Q**: Base point (public key)
- **x**: Secret value (the committed value)
- **r**: Secret randomness (blinding factor)
- **G**: Curve generator point

The commitment is:
- **Hiding**: Without knowing `r`, the commitment reveals no information about `x`
- **Binding**: The prover cannot change `x` after committing without being detected

### Usage

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Generate base point Q
qScalar, _ := curve.RandomScalar(curve.P256)
defer qScalar.Free()

qPoint, _ := curve.MulGenerator(curve.P256, qScalar)
defer qPoint.Free()

// Secret value x and randomness r
x, _ := curve.RandomScalar(curve.P256)
defer x.Free()

r, _ := curve.RandomScalar(curve.P256)
defer r.Free()

// Create ElGamal commitment UV = (r*G, x*Q + r*G)
commitment, _ := curve.MakeElGamalCom(qPoint, x, r)
defer commitment.Free()

// Create session ID
sessionID := cbmpc.NewSessionID(sessionIDBytes)

// Generate proof of knowledge of x and r
proof, _ := zk.ProveElGamalCom(&zk.ElGamalComProveParams{
    BasePoint:  qPoint,
    Commitment: commitment,
    X:          x,
    R:          r,
    SessionID:  sessionID,
    Aux:        partyID,
})
// Proof is just []byte - no Close() needed

// Verify the proof (anyone can verify)
err := zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
    Proof:      proof,
    BasePoint:  qPoint,
    Commitment: commitment,
    SessionID:  sessionID,
    Aux:        partyID,
})
// err == nil means verification succeeded
```

### Convenience Function

For convenience, you can create a commitment and proof in one step:

```go
// Create commitment + proof in one call
result, _ := zk.MakeElGamalComWithProof(qPoint, x, r, sessionID, partyID)
defer result.Commitment.Free()

// result.Commitment is the ElGamal commitment
// result.Proof is the ZK proof ([]byte)

// Verify as usual
err := zk.VerifyElGamalCom(&zk.ElGamalComVerifyParams{
    Proof:      result.Proof,
    BasePoint:  qPoint,
    Commitment: result.Commitment,
    SessionID:  sessionID,
    Aux:        partyID,
})
```

### Use Cases

ElGamal commitment proofs are commonly used in:
- **Secure multi-party computation**: Parties commit to their inputs and prove correctness
- **Threshold signatures**: Proving knowledge of secret shares without revealing them
- **Verifiable secret sharing**: Ensuring shares are correctly distributed
- **Anonymous credentials**: Committing to attributes while preserving privacy

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

## ElGamal_Com_PubShare_Equ - ElGamal Commitment Public Share Equality Proof

The ElGamal_Com_PubShare_Equ protocol proves that the public share (L component) of an ElGamal commitment equals a given public point. Specifically, it proves that `A = r*G` where `B.L = r*G` for an ElGamal commitment `B = (L, R)`.

### What does this prove?

Given:
- Point `A = r*G` (public)
- ElGamal commitment `B = (L, R)` where `L = r*G` and `R = m*Q + r*G` (public)
- Secret randomness `r` (witness)

The proof demonstrates that `A` and `B.L` use the same randomness `r`, without revealing `r`.

### Usage

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Generate randomness r
r, _ := curve.RandomScalar(curve.P256)
defer r.Free()

// Compute A = r*G
a, _ := curve.MulGenerator(curve.P256, r)
defer a.Free()

// Create ElGamal commitment B = (r*G, m*Q + r*G)
// where B.L = A
q, _ := /* base point Q */
m, _ := curve.RandomScalar(curve.P256)
defer m.Free()

b, _ := curve.MakeElGamalCom(q, m, r)
defer b.Free()

sessionID := cbmpc.NewSessionID(sessionIDBytes)

// Generate proof that A = B.L (same randomness r)
proof, _ := zk.ProveElGamalComPubShareEqu(&zk.ElGamalComPubShareEquProveParams{
    Q:         q,
    A:         a,
    B:         b,
    R:         r,
    SessionID: sessionID,
    Aux:       partyID,
})

// Verify the proof
err := zk.VerifyElGamalComPubShareEqu(&zk.ElGamalComPubShareEquVerifyParams{
    Proof:     proof,
    Q:         q,
    A:         a,
    B:         b,
    SessionID: sessionID,
    Aux:       partyID,
})
```

### Use Cases

- **Proving consistent randomness**: Demonstrating that multiple commitments use the same blinding factor
- **Verifiable re-randomization**: Proving a commitment was correctly re-randomized
- **Threshold protocols**: Ensuring shares use consistent randomness

## ElGamal_Com_Mult - ElGamal Commitment Multiplication Proof

The ElGamal_Com_Mult protocol proves a multiplicative relationship between ElGamal commitments. Specifically, it proves that `C = b * A` where `b` is a secret scalar and `A, B, C` are ElGamal commitments.

### What does this prove?

Given:
- ElGamal commitments `A`, `B`, `C` (public)
- Secret scalar `b` (witness)
- Randomness `r_B`, `r_C` (witnesses)

The proof demonstrates that commitment `C` is the scalar multiplication of commitment `A` by `b`, without revealing `b`, `r_B`, or `r_C`.

### Usage

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Create commitment A
q, _ := /* base point Q */
mA, _ := curve.RandomScalar(curve.P256)
defer mA.Free()

rA, _ := curve.RandomScalar(curve.P256)
defer rA.Free()

a, _ := curve.MakeElGamalCom(q, mA, rA)
defer a.Free()

// Create commitment B
mB, _ := curve.RandomScalar(curve.P256)
defer mB.Free()

rB, _ := curve.RandomScalar(curve.P256)
defer rB.Free()

b, _ := curve.MakeElGamalCom(q, mB, rB)
defer b.Free()

// Scalar multiplier
scalarB, _ := curve.RandomScalar(curve.P256)
defer scalarB.Free()

// Compute C = scalarB * A
// (multiply both L and R components)
aL, _ := a.PointL()
defer aL.Free()
aR, _ := a.PointR()
defer aR.Free()

cL, _ := aL.Mul(scalarB)
defer cL.Free()
cR, _ := aR.Mul(scalarB)
defer cR.Free()

c, _ := curve.NewECElGamalCom(cL, cR)
defer c.Free()

rC, _ := curve.RandomScalar(curve.P256)
defer rC.Free()

sessionID := cbmpc.NewSessionID(sessionIDBytes)

// Generate proof that C = scalarB * A
proof, _ := zk.ProveElGamalComMult(&zk.ElGamalComMultProveParams{
    Q:         q,
    A:         a,
    B:         b,
    C:         c,
    RB:        rB,
    RC:        rC,
    ScalarB:   scalarB,
    SessionID: sessionID,
    Aux:       partyID,
})

// Verify the proof
err := zk.VerifyElGamalComMult(&zk.ElGamalComMultVerifyParams{
    Proof:     proof,
    Q:         q,
    A:         a,
    B:         b,
    C:         c,
    SessionID: sessionID,
    Aux:       partyID,
})
```

### Use Cases

- **Homomorphic operations**: Proving correctness of encrypted computations
- **Threshold signatures**: Proving share multiplications are correct
- **Secure computation**: Verifying encrypted intermediate values

## UC_ElGamal_Com_Mult_Private_Scalar - UC-Secure ElGamal Commitment Multiplication with Private Scalar

The UC_ElGamal_Com_Mult_Private_Scalar protocol is a universally composable proof that `eB = c * eA` where `c` is a secret scalar and `eA`, `eB` are ElGamal commitments. This provides the strongest security guarantees (UC-security).

### What does this prove?

Given:
- Base point `E` (public)
- ElGamal commitments `eA`, `eB` (public)
- Secret scalar `c` (witness)
- Randomness `r0` (witness)

The proof demonstrates that `eB` is `c` times `eA`, without revealing `c` or `r0`, with universally composable security.

### Features

- **UC-secure**: Provides universal composability guarantees
- **Fischlin transform**: Uses optimized Fischlin parameters (t=19, l=7, r=12)
- **Prover optimization**: Includes optimizations from the specification
- **Verifier optimization**: Includes verifier-side optimizations

### Usage

```go
import (
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/zk"
)

// Generate base point E
eScalar, _ := curve.RandomScalar(curve.P256)
defer eScalar.Free()

e, _ := curve.MulGenerator(curve.P256, eScalar)
defer e.Free()

// Create commitment eA
mA, _ := curve.RandomScalar(curve.P256)
defer mA.Free()

rA, _ := curve.RandomScalar(curve.P256)
defer rA.Free()

ea, _ := curve.MakeElGamalCom(e, mA, rA)
defer ea.Free()

// Secret scalar c
c, _ := curve.RandomScalar(curve.P256)
defer c.Free()

// Compute eB = c * eA
eaL, _ := ea.PointL()
defer eaL.Free()
eaR, _ := ea.PointR()
defer eaR.Free()

ebL, _ := eaL.Mul(c)
defer ebL.Free()
ebR, _ := eaR.Mul(c)
defer ebR.Free()

eb, _ := curve.NewECElGamalCom(ebL, ebR)
defer eb.Free()

// Randomness for eB
r0, _ := curve.RandomScalar(curve.P256)
defer r0.Free()

sessionID := cbmpc.NewSessionID(sessionIDBytes)

// Generate UC-secure proof
proof, _ := zk.ProveUCElGamalComMultPrivateScalar(&zk.UCElGamalComMultPrivateScalarProveParams{
    E:         e,
    EA:        ea,
    EB:        eb,
    R0:        r0,
    C:         c,
    SessionID: sessionID,
    Aux:       partyID,
})

// Verify the proof
err := zk.VerifyUCElGamalComMultPrivateScalar(&zk.UCElGamalComMultPrivateScalarVerifyParams{
    Proof:     proof,
    E:         e,
    EA:        ea,
    EB:        eb,
    SessionID: sessionID,
    Aux:       partyID,
})
```

### Use Cases

- **Threshold cryptography**: UC-secure share operations
- **Secure multi-party computation**: Composable encrypted computations
- **Privacy-preserving protocols**: When UC security is required

### Security Parameters

This protocol uses optimized Fischlin parameters:
- `t = 19`: Challenge bits
- `l = 7`: Parallel executions
- `r = 12`: Repetition factor

## References

- See `cb-mpc/src/cbmpc/zk/zk_ec.h` for UC_DL, UC_Batch_DL, and DH implementation details
- See `cb-mpc/src/cbmpc/zk/zk_elgamal_com.h` for all ElGamal commitment proof implementations
- Fischlin, M. (2005). "Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors"
