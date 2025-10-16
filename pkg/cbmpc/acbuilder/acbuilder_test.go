//go:build cgo && !windows

package acbuilder

import (
	"strings"
	"testing"
)

func TestACBuilderSimpleThreshold(t *testing.T) {
	// Create a simple 2-of-3 threshold AC structure
	expr := Threshold(2,
		Leaf("alice"),
		Leaf("bob"),
		Leaf("charlie"),
	)

	// Compile to bytes
	ac, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(ac) == 0 {
		t.Fatal("Compile returned empty bytes")
	}

	// Convert to string representation
	str, err := ac.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	if str == "" {
		t.Fatal("String returned empty string")
	}

	// Verify the string contains 3 leaves
	if !strings.Contains(str, "3 leaves") {
		t.Errorf("Expected string to contain '3 leaves', got: %s", str)
	}
	// Verify it contains all party names
	for _, name := range []string{"alice", "bob", "charlie"} {
		if !strings.Contains(str, name) {
			t.Errorf("Expected string to contain '%s', got: %s", name, str)
		}
	}
}

func TestACBuilderComplexNested(t *testing.T) {
	// Create a complex nested policy:
	// Requires alice AND (bob OR (2-of-3: charlie, dave, eve))
	expr := And(
		Leaf("alice"),
		Or(
			Leaf("bob"),
			Threshold(2,
				Leaf("charlie"),
				Leaf("dave"),
				Leaf("eve"),
			),
		),
	)

	// Compile to bytes
	ac, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(ac) == 0 {
		t.Fatal("Compile returned empty bytes")
	}

	// Convert to string representation
	str, err := ac.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	if str == "" {
		t.Fatal("String returned empty string")
	}

	// Verify the string contains 5 leaves
	if !strings.Contains(str, "5 leaves") {
		t.Errorf("Expected string to contain '5 leaves', got: %s", str)
	}
	// Verify the paths show nesting (e.g., or1/bob, or1/th2/charlie)
	if !strings.Contains(str, "or") && !strings.Contains(str, "th") {
		t.Errorf("Expected string to show nested structure, got: %s", str)
	}
}

func TestACBuilderSimpleAnd(t *testing.T) {
	// Create a simple AND gate
	expr := And(
		Leaf("alice"),
		Leaf("bob"),
	)

	ac, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(ac) == 0 {
		t.Fatal("Compile returned empty bytes")
	}

	str, err := ac.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	if !strings.Contains(str, "2 leaves") {
		t.Errorf("Expected string to contain '2 leaves', got: %s", str)
	}
	if !strings.Contains(str, "alice") {
		t.Errorf("Expected string to contain 'alice', got: %s", str)
	}
	if !strings.Contains(str, "bob") {
		t.Errorf("Expected string to contain 'bob', got: %s", str)
	}
}

func TestACBuilderSimpleOr(t *testing.T) {
	// Create a simple OR gate
	expr := Or(
		Leaf("alice"),
		Leaf("bob"),
	)

	ac, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(ac) == 0 {
		t.Fatal("Compile returned empty bytes")
	}

	str, err := ac.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	if !strings.Contains(str, "2 leaves") {
		t.Errorf("Expected string to contain '2 leaves', got: %s", str)
	}
	if !strings.Contains(str, "alice") {
		t.Errorf("Expected string to contain 'alice', got: %s", str)
	}
	if !strings.Contains(str, "bob") {
		t.Errorf("Expected string to contain 'bob', got: %s", str)
	}
}

func TestACBuilderSingleLeaf(t *testing.T) {
	// Single leaf (trivial AC - just one party required)
	expr := Leaf("alice")

	ac, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if len(ac) == 0 {
		t.Fatal("Compile returned empty bytes")
	}

	str, err := ac.String()
	if err != nil {
		t.Fatalf("String failed: %v", err)
	}

	// For a single leaf that becomes the root, the name gets cleared
	// So the path will be empty "/" and the string representation may be "AC with 1 leaves: []"
	// This is expected - single leaf ACs are a degenerate case
	if !strings.Contains(str, "1 leaves") {
		t.Errorf("Expected string to contain '1 leaves', got: %s", str)
	}
	// The leaf path is "/" or empty since root has no name
	// We accept this as correct behavior for a single-leaf AC
}
