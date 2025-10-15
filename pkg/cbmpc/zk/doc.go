// Package zk provides zero-knowledge proof protocols.
//
// This package contains non-interactive zero-knowledge proofs (NIZKs) for various statements
// used in secure multi-party computation protocols. All proofs are UC (universally composable)
// secure when used with appropriate parameters.
//
// # Available Proofs
//
//   - UC-DL: Proves knowledge of discrete log (Q = w*G)
//   - UC-Batch-DL: Batch proof for multiple discrete logs
//   - DH: Proves Diffie-Hellman relation (B = w*A where Q = w*G)
//   - UC-ElGamal-Com: Proves correct ElGamal commitment opening
//   - ElGamal-Com-PubShare-Equ: Proves equality of public share in ElGamal commitment
//   - ElGamal-Com-Mult: Proves multiplicative relationship between ElGamal commitments
//   - UC-ElGamal-Com-Mult-Private-Scalar: UC-secure multiplication with private scalar
//
// # Usage
//
// All proofs are value types ([]byte) requiring no cleanup:
//
//	// Generate discrete log proof
//	proof, err := zk.ProveDL(&zk.DLProveParams{
//	    Point:     Q,
//	    Exponent:  w,
//	    SessionID: sessionID,
//	    Aux:       partyID,
//	})
//
//	// Verify proof
//	err = zk.VerifyDL(&zk.DLVerifyParams{
//	    Proof:     proof,
//	    Point:     Q,
//	    SessionID: sessionID,
//	    Aux:       partyID,
//	})
//
// See pkg/cbmpc/zk/README.md for detailed protocol documentation and examples.
package zk
