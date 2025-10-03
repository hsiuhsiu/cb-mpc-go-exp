package internalcheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestNoHexFormatting(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedName,
	}

	pkgs, err := packages.Load(cfg, "github.com/coinbase/cb-mpc-go/pkg/cbmpc")
	if err != nil {
		t.Fatalf("load package: %v", err)
	}

	var findings []string

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			fset := pkg.Fset
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				obj := pkg.TypesInfo.Uses[selector.Sel]
				if obj == nil || obj.Pkg() == nil {
					return true
				}

				pkgPath := obj.Pkg().Path()
				name := obj.Name()

				formatIdx, ok := formatIndex(pkgPath, name)
				if !ok || len(call.Args) <= formatIdx {
					return true
				}

				lit, ok := call.Args[formatIdx].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}

				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}

				if containsHexVerb(value) {
					pos := fset.Position(lit.Pos())
					findings = append(findings, fmt.Sprintf("%s: avoid %%x formatting of secrets", pos))
				}

				return true
			})
		}
	}

	if len(findings) > 0 {
		t.Fatalf("secret logging policy violation:\n%s", strings.Join(findings, "\n"))
	}
}

func formatIndex(pkgPath, name string) (int, bool) {
	switch pkgPath {
	case "fmt":
		switch name {
		case "Errorf", "Printf", "Sprintf":
			return 0, true
		case "Fprintf":
			return 1, true
		}
	case "log":
		switch name {
		case "Printf", "Fatalf", "Panicf":
			return 0, true
		}
	}
	return 0, false
}

func containsHexVerb(s string) bool {
	return strings.Contains(s, "%x") || strings.Contains(s, "%X")
}
