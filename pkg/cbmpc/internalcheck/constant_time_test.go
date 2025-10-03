package internalcheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestNoDirectByteComparison(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedName,
	}

	pkgs, err := packages.Load(cfg, "github.com/coinbase/cb-mpc-go/pkg/cbmpc")
	if err != nil {
		t.Fatalf("load package: %v", err)
	}

	var findings []string

	for _, pkg := range pkgs {
		for fileIdx, file := range pkg.Syntax {
			fset := pkg.Fset
			typesInfo := pkg.TypesInfo

			ast.Inspect(file, func(n ast.Node) bool {
				be, ok := n.(*ast.BinaryExpr)
				if !ok {
					return true
				}

				if be.Op != token.EQL && be.Op != token.NEQ {
					return true
				}

				left := typesInfo.TypeOf(be.X)
				right := typesInfo.TypeOf(be.Y)

				if isByteSlice(left) && isByteSlice(right) {
					pos := fset.Position(be.Pos())
					findings = append(findings, fmt.Sprintf("%s: avoid == on byte slices; use crypto/subtle", pos))
				}

				return true
			})

			// Ensure file set is used even if there are no findings to avoid unused variable
			_ = fileIdx
		}
	}

	if len(findings) > 0 {
		t.Fatalf("constant-time policy violation:\n%s", strings.Join(findings, "\n"))
	}
}

func isByteSlice(typ types.Type) bool {
	if typ == nil {
		return false
	}

	switch tt := typ.(type) {
	case *types.Slice:
		return isByte(tt.Elem())
	case *types.Pointer:
		return isByteSlice(tt.Elem())
	case *types.Named:
		return isByteSlice(tt.Underlying())
	case *types.Array:
		return isByte(tt.Elem())
	default:
		return false
	}
}

func isByte(t types.Type) bool {
	basic, ok := t.(*types.Basic)
	return ok && basic.Kind() == types.Byte
}
