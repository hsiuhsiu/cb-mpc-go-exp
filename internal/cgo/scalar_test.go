package cgo

import (
	"bytes"
	"testing"
)

func TestCurveFromNID(t *testing.T) {
	// Test SECP256K1 (NID 714)
	curve, err := CurveFromNID(714)
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	// Get order
	order := curve.Order()
	if len(order) == 0 {
		t.Error("Curve order is empty")
	}
	t.Logf("SECP256K1 order length: %d bytes", len(order))
}

func TestBNFromInt64(t *testing.T) {
	bn := BNFromInt64(42)
	defer bn.Free()

	bytes := bn.ToBytes()
	if len(bytes) == 0 {
		t.Error("BN ToBytes returned empty")
	}

	// Check value
	if len(bytes) != 1 || bytes[0] != 42 {
		t.Errorf("BN value = %v, want [42]", bytes)
	}
}

func TestBNFromBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	bn, err := BNFromBytes(data)
	if err != nil {
		t.Fatalf("BNFromBytes failed: %v", err)
	}
	defer bn.Free()

	result := bn.ToBytes()
	if !bytes.Equal(result, data) {
		t.Errorf("BN round-trip failed: got %v, want %v", result, data)
	}
}

func TestBNAdd(t *testing.T) {
	a := BNFromInt64(10)
	defer a.Free()

	b := BNFromInt64(32)
	defer b.Free()

	c := a.Add(b)
	defer c.Free()

	result := c.ToBytes()
	if len(result) != 1 || result[0] != 42 {
		t.Errorf("10 + 32 = %v, want [42]", result)
	}
}

func TestBNSub(t *testing.T) {
	a := BNFromInt64(50)
	defer a.Free()

	b := BNFromInt64(8)
	defer b.Free()

	c := a.Sub(b)
	defer c.Free()

	result := c.ToBytes()
	if len(result) != 1 || result[0] != 42 {
		t.Errorf("50 - 8 = %v, want [42]", result)
	}
}

func TestBNMul(t *testing.T) {
	a := BNFromInt64(6)
	defer a.Free()

	b := BNFromInt64(7)
	defer b.Free()

	c := a.Mul(b)
	defer c.Free()

	result := c.ToBytes()
	if len(result) != 1 || result[0] != 42 {
		t.Errorf("6 * 7 = %v, want [42]", result)
	}
}

func TestBNIsZero(t *testing.T) {
	zero := BNFromInt64(0)
	defer zero.Free()

	if !zero.IsZero() {
		t.Error("BNFromInt64(0) should be zero")
	}

	nonZero := BNFromInt64(42)
	defer nonZero.Free()

	if nonZero.IsZero() {
		t.Error("BNFromInt64(42) should not be zero")
	}
}

func TestBNEqual(t *testing.T) {
	a := BNFromInt64(42)
	defer a.Free()

	b := BNFromInt64(42)
	defer b.Free()

	c := BNFromInt64(43)
	defer c.Free()

	if !a.Equal(b) {
		t.Error("42 should equal 42")
	}

	if a.Equal(c) {
		t.Error("42 should not equal 43")
	}
}

func TestBNModular(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	a := BNFromInt64(10)
	defer a.Free()

	b := BNFromInt64(20)
	defer b.Free()

	// Test modular addition
	c := a.AddMod(b, curve)
	defer c.Free()

	result := c.ToBytes()
	if len(result) == 0 {
		t.Error("AddMod returned empty result")
	}
	t.Logf("10 + 20 mod order = %x", result)
}

func TestCurveRandomScalar(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	s1 := curve.RandomScalar()
	s2 := curve.RandomScalar()

	if len(s1) == 0 {
		t.Error("RandomScalar returned empty")
	}

	if bytes.Equal(s1, s2) {
		t.Error("Two random scalars should not be equal")
	}

	t.Logf("Random scalar: %x", s1)
}

func TestPointOperations(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	// Get generator
	g := curve.Generator()
	defer g.Free()

	if g.IsInfinity() {
		t.Error("Generator should not be infinity")
	}

	// Serialize
	gBytes := g.ToBytes()
	if len(gBytes) == 0 {
		t.Error("Generator ToBytes returned empty")
	}
	t.Logf("Generator: %x", gBytes)

	// Deserialize
	g2, err := PointFromBytes(curve, gBytes)
	if err != nil {
		t.Fatalf("PointFromBytes failed: %v", err)
	}
	defer g2.Free()

	if !g.Equal(g2) {
		t.Error("Round-trip point serialization failed")
	}
}

func TestPointMulGenerator(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	// Create scalar
	scalar := BNFromInt64(2)
	defer scalar.Free()

	// Multiply generator by 2
	point := MulGenerator(curve, scalar)
	defer point.Free()

	if point.IsInfinity() {
		t.Error("2 * G should not be infinity")
	}

	pointBytes := point.ToBytes()
	t.Logf("2 * G = %x", pointBytes)
}

func TestPointAddition(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	g := curve.Generator()
	defer g.Free()

	// G + G should equal 2*G
	gPlusG := g.Add(g)
	defer gPlusG.Free()

	scalar2 := BNFromInt64(2)
	defer scalar2.Free()

	twoG := MulGenerator(curve, scalar2)
	defer twoG.Free()

	if !gPlusG.Equal(twoG) {
		t.Error("G + G should equal 2 * G")
	}
}

func TestPointCoordinates(t *testing.T) {
	curve, err := CurveFromNID(714) // SECP256K1
	if err != nil {
		t.Fatalf("CurveFromNID failed: %v", err)
	}
	defer curve.Free()

	g := curve.Generator()
	defer g.Free()

	x := g.GetX()
	y := g.GetY()

	if len(x) == 0 || len(y) == 0 {
		t.Error("Generator coordinates should not be empty")
	}

	t.Logf("Generator X: %x", x)
	t.Logf("Generator Y: %x", y)
}
