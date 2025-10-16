//go:build cgo && !windows

package accessstructure

import (
	"errors"
	"fmt"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// AccessStructure represents a serialized access control structure (ss::ac_t).
// It defines policies for secret sharing using combinations of AND, OR, and Threshold gates.
type AccessStructure []byte

// Expr represents an access control expression node.
type Expr interface {
	isExpr()
}

// leaf is a leaf node representing a single party.
type leaf struct {
	name string
}

func (leaf) isExpr() {}

// andExpr is an AND gate requiring all children.
type andExpr struct {
	children []Expr
}

func (andExpr) isExpr() {}

// orExpr is an OR gate requiring any child.
type orExpr struct {
	children []Expr
}

func (orExpr) isExpr() {}

// thresholdExpr is a threshold gate requiring k of n children.
type thresholdExpr struct {
	k        int
	children []Expr
}

func (thresholdExpr) isExpr() {}

// Leaf creates a leaf node with the given party name.
func Leaf(name string) Expr {
	return leaf{name: name}
}

// And creates an AND gate requiring all children to satisfy the policy.
func And(children ...Expr) Expr {
	return andExpr{children: children}
}

// Or creates an OR gate requiring any child to satisfy the policy.
func Or(children ...Expr) Expr {
	return orExpr{children: children}
}

// Threshold creates a threshold gate requiring k of n children to satisfy the policy.
func Threshold(k int, children ...Expr) Expr {
	return thresholdExpr{k: k, children: children}
}

// Compile builds an access control structure from the expression tree and returns
// the serialized bytes. All C++ node allocation and deallocation is handled internally.
// See cb-mpc/src/cbmpc/crypto/secret_sharing.h for semantics and validation rules.
func Compile(e Expr) (AccessStructure, error) {
	if e == nil {
		return nil, errors.New("nil expression")
	}

	// Build the node tree
	node, err := buildNode(e)
	if err != nil {
		return nil, err
	}
	defer backend.ACNodeFree(node)

	// Serialize to bytes
	bytes, err := backend.ACSerialize(node)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return AccessStructure(bytes), nil
}

// buildNode recursively constructs C++ AC nodes from the expression tree.
func buildNode(e Expr) (backend.ACNode, error) {
	switch expr := e.(type) {
	case leaf:
		if expr.name == "" {
			return nil, errors.New("empty leaf name")
		}
		return backend.ACLeaf([]byte(expr.name))

	case andExpr:
		if len(expr.children) == 0 {
			return nil, errors.New("AND gate requires at least one child")
		}
		nodes := make([]backend.ACNode, len(expr.children))
		for i, child := range expr.children {
			node, err := buildNode(child)
			if err != nil {
				// Clean up already-built nodes
				for j := 0; j < i; j++ {
					backend.ACNodeFree(nodes[j])
				}
				return nil, err
			}
			nodes[i] = node
		}
		// Build AND node (this takes ownership of children, so we don't free them)
		return backend.ACAnd(nodes)

	case orExpr:
		if len(expr.children) == 0 {
			return nil, errors.New("OR gate requires at least one child")
		}
		nodes := make([]backend.ACNode, len(expr.children))
		for i, child := range expr.children {
			node, err := buildNode(child)
			if err != nil {
				// Clean up already-built nodes
				for j := 0; j < i; j++ {
					backend.ACNodeFree(nodes[j])
				}
				return nil, err
			}
			nodes[i] = node
		}
		// Build OR node (this takes ownership of children, so we don't free them)
		return backend.ACOr(nodes)

	case thresholdExpr:
		if len(expr.children) == 0 {
			return nil, errors.New("Threshold gate requires at least one child")
		}
		if expr.k <= 0 {
			return nil, fmt.Errorf("threshold k must be positive, got %d", expr.k)
		}
		if expr.k > len(expr.children) {
			return nil, fmt.Errorf("threshold k (%d) cannot exceed number of children (%d)", expr.k, len(expr.children))
		}
		nodes := make([]backend.ACNode, len(expr.children))
		for i, child := range expr.children {
			node, err := buildNode(child)
			if err != nil {
				// Clean up already-built nodes
				for j := 0; j < i; j++ {
					backend.ACNodeFree(nodes[j])
				}
				return nil, err
			}
			nodes[i] = node
		}
		// Build Threshold node (this takes ownership of children, so we don't free them)
		return backend.ACThreshold(expr.k, nodes)

	default:
		return nil, errors.New("unknown expression type")
	}
}

// String returns a canonicalized string representation of the access control structure.
// This is useful for debugging and logging.
func (s AccessStructure) String() (string, error) {
	if len(s) == 0 {
		return "", errors.New("empty AccessStructure")
	}
	str, err := backend.ACToString(s)
	if err != nil {
		return "", cbmpc.RemapError(err)
	}
	return str, nil
}
