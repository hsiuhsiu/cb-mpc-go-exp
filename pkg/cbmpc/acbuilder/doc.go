// Package acbuilder provides a DSL for constructing access control structures.
//
// Access Control (AC) structures define flexible policies for secret sharing
// using combinations of AND, OR, and Threshold gates. These structures are
// used with PVE-AC (Publicly Verifiable Encryption with Access Control) to
// encrypt secrets that can only be decrypted by parties satisfying the policy.
//
// # Building Access Structures
//
// The package provides four expression types:
//   - Leaf(name): A party identified by name
//   - And(children...): Requires ALL children to satisfy the policy
//   - Or(children...): Requires ANY child to satisfy the policy
//   - Threshold(k, children...): Requires k of n children to satisfy the policy
//
// # Compilation
//
// The Compile function builds the expression tree in C++ and returns
// serialized bytes that can be used with PVE-AC operations:
//
//	ac, err := acbuilder.Compile(expr)
//
// All validation (duplicate names, invalid thresholds, etc.) is performed
// in the C++ layer. The Go DSL is purely a builder.
//
// # Usage Example
//
//	import "github.com/coinbase/cb-mpc-go/pkg/cbmpc/acbuilder"
//
//	// Simple 2-of-3 threshold
//	simple := acbuilder.Threshold(2,
//	    acbuilder.Leaf("alice"),
//	    acbuilder.Leaf("bob"),
//	    acbuilder.Leaf("charlie"),
//	)
//	ac, _ := acbuilder.Compile(simple)
//
//	// Complex nested policy:
//	// Requires alice AND (bob OR (2-of-3: charlie, dave, eve))
//	complex := acbuilder.And(
//	    acbuilder.Leaf("alice"),
//	    acbuilder.Or(
//	        acbuilder.Leaf("bob"),
//	        acbuilder.Threshold(2,
//	            acbuilder.Leaf("charlie"),
//	            acbuilder.Leaf("dave"),
//	            acbuilder.Leaf("eve"),
//	        ),
//	    ),
//	)
//	ac2, _ := acbuilder.Compile(complex)
//
// # Path Names
//
// Party names in Leaf() nodes must:
//   - Be non-empty
//   - Match the keys used in PVE-AC encryption/decryption maps
//   - Be unique within the tree (enforced by C++ validation)
//
// Paths are hierarchical strings like "alice", "or1/bob", "or1/threshold2/charlie".
// The caller is responsible for using consistent names across operations.
//
// # Debugging
//
// The String() method returns a summary of the AC structure:
//
//	str, _ := ac.String()  // e.g., "AC with 3 leaves: [/alice /bob /charlie]"
//
// See cb-mpc/src/cbmpc/crypto/secret_sharing.h for access structure implementation.
package acbuilder
