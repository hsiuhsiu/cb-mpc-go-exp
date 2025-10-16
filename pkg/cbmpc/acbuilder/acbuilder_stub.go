//go:build !cgo || windows

package acbuilder

import "errors"

// AC represents a serialized access control structure.
type AC []byte

// Expr represents an access control expression node.
type Expr interface {
	isExpr()
}

type leaf struct{ name string }
type andExpr struct{ children []Expr }
type orExpr struct{ children []Expr }
type thresholdExpr struct {
	k        int
	children []Expr
}

func (leaf) isExpr()          {}
func (andExpr) isExpr()       {}
func (orExpr) isExpr()        {}
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

// Compile returns an error indicating CGO is required.
func Compile(e Expr) (AC, error) {
	return nil, errors.New("AC builder requires CGO")
}

// String returns an error indicating CGO is required.
func (ac AC) String() (string, error) {
	return "", errors.New("AC builder requires CGO")
}
