package mpc

import (
	"encoding/hex"
	"testing"
)

func TestNewScalar(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	s := NewScalar(data)

	if s == nil {
		t.Fatal("NewScalar returned nil")
	}

	// Check immutability - modifying original should not affect scalar
	data[0] = 0xFF
	if s.data[0] != 0x01 {
		t.Error("Scalar is not immutable")
	}
}

func TestScalarBytes(t *testing.T) {
	data := []byte{0xAB, 0xCD, 0xEF}
	s := NewScalar(data)

	result := s.Bytes()
	if len(result) != len(data) {
		t.Errorf("Bytes() length = %d, want %d", len(result), len(data))
	}

	// Check immutability - modifying result should not affect scalar
	result[0] = 0x00
	if s.data[0] != 0xAB {
		t.Error("Bytes() does not return a copy")
	}
}

func TestScalarString(t *testing.T) {
	data := []byte{0x01, 0x23, 0x45}
	s := NewScalar(data)

	expected := "012345"
	if s.String() != expected {
		t.Errorf("String() = %s, want %s", s.String(), expected)
	}
}

func TestScalarEqual(t *testing.T) {
	s1 := NewScalar([]byte{0x01, 0x02, 0x03})
	s2 := NewScalar([]byte{0x01, 0x02, 0x03})
	s3 := NewScalar([]byte{0x01, 0x02, 0x04})

	if !s1.Equal(s2) {
		t.Error("Equal scalars are not equal")
	}

	if s1.Equal(s3) {
		t.Error("Different scalars are equal")
	}
}

func TestScalarIsZero(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		isZero bool
	}{
		{"single zero byte", []byte{0x00}, true},
		{"multiple zero bytes", []byte{0x00, 0x00, 0x00}, true},
		{"non-zero", []byte{0x00, 0x00, 0x01}, false},
		{"all non-zero", []byte{0x01, 0x02, 0x03}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScalar(tt.data)
			if s.IsZero() != tt.isZero {
				t.Errorf("IsZero() = %v, want %v", s.IsZero(), tt.isZero)
			}
		})
	}
}

func TestPointFromBytes(t *testing.T) {
	// Test with dummy point data
	data, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	point, err := PointFromBytes(data, SECP256K1)
	if err != nil {
		t.Fatalf("PointFromBytes failed: %v", err)
	}

	if point.Curve() != SECP256K1 {
		t.Errorf("Curve() = %v, want %v", point.Curve(), SECP256K1)
	}

	// Test immutability
	data[0] = 0xFF
	if point.data[0] != 0x02 {
		t.Error("Point is not immutable")
	}
}

func TestPointFromBytesEmpty(t *testing.T) {
	_, err := PointFromBytes([]byte{}, SECP256K1)
	if err == nil {
		t.Error("PointFromBytes should fail with empty data")
	}
}

func TestPointBytes(t *testing.T) {
	data, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	point, _ := PointFromBytes(data, SECP256K1)
	result := point.Bytes()

	if len(result) != len(data) {
		t.Errorf("Bytes() length = %d, want %d", len(result), len(data))
	}

	// Test immutability
	result[0] = 0xFF
	if point.data[0] != 0x02 {
		t.Error("Bytes() does not return a copy")
	}
}

func TestPointAddDifferentCurves(t *testing.T) {
	data, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	p1, _ := PointFromBytes(data, SECP256K1)
	p2, _ := PointFromBytes(data, SECP256R1)

	_, err := p1.Add(p2)
	if err == nil {
		t.Error("Add should fail for points from different curves")
	}
}

func TestPointSubDifferentCurves(t *testing.T) {
	data, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	p1, _ := PointFromBytes(data, SECP256K1)
	p2, _ := PointFromBytes(data, SECP256R1)

	_, err := p1.Sub(p2)
	if err == nil {
		t.Error("Sub should fail for points from different curves")
	}
}
