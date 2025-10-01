package cgo

// #include "scalar.h"
// #cgo CXXFLAGS: -I${SRCDIR}/../../cb-mpc/src
import "C"
import (
	"fmt"
)

// ============ Curve Operations ============

// CurveHandle is an opaque handle to an ecurve_t
type CurveHandle C.curve_handle_t

// CurveFromNID creates a curve handle from an OpenSSL NID
func CurveFromNID(nid int) (CurveHandle, error) {
	handle := C.curve_from_nid(C.int(nid))
	if handle.ptr == nil {
		return CurveHandle{}, fmt.Errorf("invalid curve NID: %d", nid)
	}
	return CurveHandle(handle), nil
}

// Free releases the curve handle
func (h CurveHandle) Free() {
	C.curve_free(C.curve_handle_t(h))
}

// Order returns the curve order as bytes
func (h CurveHandle) Order() []byte {
	cmem := C.curve_order(C.curve_handle_t(h))
	return cmemToBytes(cmem)
}

// RandomScalar generates a random scalar mod curve order
func (h CurveHandle) RandomScalar() []byte {
	cmem := C.curve_random_scalar(C.curve_handle_t(h))
	return cmemToBytes(cmem)
}

// Generator returns the generator point
func (h CurveHandle) Generator() PointHandle {
	handle := C.curve_generator(C.curve_handle_t(h))
	return PointHandle(handle)
}

// ============ Scalar (BN) Operations ============

// BNHandle is an opaque handle to a bn_t
type BNHandle C.bn_handle_t

// BNFromInt64 creates a scalar from an int64
func BNFromInt64(value int64) BNHandle {
	handle := C.bn_from_int64(C.int64_t(value))
	return BNHandle(handle)
}

// BNFromBytes creates a scalar from big-endian bytes
func BNFromBytes(data []byte) (BNHandle, error) {
	if len(data) == 0 {
		return BNHandle{}, fmt.Errorf("empty data")
	}
	cmem := bytesToCmem(data)
	handle := C.bn_from_bytes(cmem)
	if handle.ptr == nil {
		return BNHandle{}, fmt.Errorf("failed to create scalar from bytes")
	}
	return BNHandle(handle), nil
}

// ToBytes converts scalar to big-endian bytes
func (h BNHandle) ToBytes() []byte {
	cmem := C.bn_to_bytes(C.bn_handle_t(h))
	return cmemToBytes(cmem)
}

// Free releases the scalar handle
func (h BNHandle) Free() {
	C.bn_free(C.bn_handle_t(h))
}

// Add returns a + b
func (h BNHandle) Add(other BNHandle) BNHandle {
	result := C.bn_add(C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// Sub returns a - b
func (h BNHandle) Sub(other BNHandle) BNHandle {
	result := C.bn_sub(C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// Mul returns a * b
func (h BNHandle) Mul(other BNHandle) BNHandle {
	result := C.bn_mul(C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// Neg returns -a
func (h BNHandle) Neg() BNHandle {
	result := C.bn_neg(C.bn_handle_t(h))
	return BNHandle(result)
}

// AddMod returns (a + b) mod curve.Order()
func (h BNHandle) AddMod(other BNHandle, curve CurveHandle) BNHandle {
	result := C.bn_add_mod(C.curve_handle_t(curve), C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// SubMod returns (a - b) mod curve.Order()
func (h BNHandle) SubMod(other BNHandle, curve CurveHandle) BNHandle {
	result := C.bn_sub_mod(C.curve_handle_t(curve), C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// MulMod returns (a * b) mod curve.Order()
func (h BNHandle) MulMod(other BNHandle, curve CurveHandle) BNHandle {
	result := C.bn_mul_mod(C.curve_handle_t(curve), C.bn_handle_t(h), C.bn_handle_t(other))
	return BNHandle(result)
}

// InvMod returns a^-1 mod curve.Order()
func (h BNHandle) InvMod(curve CurveHandle) (BNHandle, error) {
	result := C.bn_inv_mod(C.curve_handle_t(curve), C.bn_handle_t(h))
	if result.ptr == nil {
		return BNHandle{}, fmt.Errorf("failed to invert scalar")
	}
	return BNHandle(result), nil
}

// IsZero returns true if the scalar is zero
func (h BNHandle) IsZero() bool {
	return C.bn_is_zero(C.bn_handle_t(h)) != 0
}

// Equal returns true if two scalars are equal
func (h BNHandle) Equal(other BNHandle) bool {
	return C.bn_equal(C.bn_handle_t(h), C.bn_handle_t(other)) != 0
}

// ============ Point Operations ============

// PointHandle is an opaque handle to an ecc_point_t
type PointHandle C.point_handle_t

// PointFromBytes creates a point from bytes
func PointFromBytes(curve CurveHandle, data []byte) (PointHandle, error) {
	if len(data) == 0 {
		return PointHandle{}, fmt.Errorf("empty data")
	}
	cmem := bytesToCmem(data)
	handle := C.point_from_bytes(C.curve_handle_t(curve), cmem)
	if handle.ptr == nil {
		return PointHandle{}, fmt.Errorf("failed to create point from bytes")
	}
	return PointHandle(handle), nil
}

// ToBytes converts point to bytes
func (h PointHandle) ToBytes() []byte {
	cmem := C.point_to_bytes(C.point_handle_t(h))
	return cmemToBytes(cmem)
}

// Free releases the point handle
func (h PointHandle) Free() {
	C.point_free(C.point_handle_t(h))
}

// Add returns a + b
func (h PointHandle) Add(other PointHandle) PointHandle {
	result := C.point_add(C.point_handle_t(h), C.point_handle_t(other))
	return PointHandle(result)
}

// Sub returns a - b
func (h PointHandle) Sub(other PointHandle) PointHandle {
	result := C.point_sub(C.point_handle_t(h), C.point_handle_t(other))
	return PointHandle(result)
}

// Neg returns -a
func (h PointHandle) Neg() PointHandle {
	result := C.point_neg(C.point_handle_t(h))
	return PointHandle(result)
}

// Mul returns scalar * point
func (h PointHandle) Mul(scalar BNHandle) PointHandle {
	result := C.point_mul(C.point_handle_t(h), C.bn_handle_t(scalar))
	return PointHandle(result)
}

// MulGenerator returns scalar * G
func MulGenerator(curve CurveHandle, scalar BNHandle) PointHandle {
	result := C.point_mul_generator(C.curve_handle_t(curve), C.bn_handle_t(scalar))
	return PointHandle(result)
}

// GetX returns the X coordinate
func (h PointHandle) GetX() []byte {
	cmem := C.point_get_x(C.point_handle_t(h))
	return cmemToBytes(cmem)
}

// GetY returns the Y coordinate
func (h PointHandle) GetY() []byte {
	cmem := C.point_get_y(C.point_handle_t(h))
	return cmemToBytes(cmem)
}

// IsInfinity returns true if the point is infinity
func (h PointHandle) IsInfinity() bool {
	return C.point_is_infinity(C.point_handle_t(h)) != 0
}

// Equal returns true if two points are equal
func (h PointHandle) Equal(other PointHandle) bool {
	return C.point_equal(C.point_handle_t(h), C.point_handle_t(other)) != 0
}

// ============ Helper Functions ============
// Note: bytesToCmem and cmemToBytes are defined in binding.go
