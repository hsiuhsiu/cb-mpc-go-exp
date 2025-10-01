#ifndef CB_MPC_GO_SCALAR_H
#define CB_MPC_GO_SCALAR_H

#ifdef __cplusplus
#include <cbmpc/core/cmem.h>
extern "C" {
#else
// For C code, declare cmem_t
typedef struct tag_cmem_t {
    unsigned char* data;
    int size;
} cmem_t;
#endif

#include <stdint.h>
#include <stdlib.h>

// Opaque handle to bn_t (bignum)
typedef struct {
    void* ptr;
} bn_handle_t;

// Opaque handle to ecc_point_t
typedef struct {
    void* ptr;
} point_handle_t;

// Opaque handle to ecurve_t
typedef struct {
    void* ptr;
} curve_handle_t;

// ============ Curve Operations ============

// Create curve handle from OpenSSL NID
curve_handle_t curve_from_nid(int nid);

// Free curve handle
void curve_free(curve_handle_t handle);

// Get curve order as bytes
cmem_t curve_order(curve_handle_t handle);

// Generate random scalar mod curve order
cmem_t curve_random_scalar(curve_handle_t handle);

// Get generator point
point_handle_t curve_generator(curve_handle_t handle);

// ============ Scalar (bn_t) Operations ============

// Create scalar from int64
bn_handle_t bn_from_int64(int64_t value);

// Create scalar from bytes (big-endian)
bn_handle_t bn_from_bytes(cmem_t data);

// Convert scalar to bytes (big-endian)
cmem_t bn_to_bytes(bn_handle_t handle);

// Free scalar
void bn_free(bn_handle_t handle);

// Scalar arithmetic (arbitrary precision)
bn_handle_t bn_add(bn_handle_t a, bn_handle_t b);
bn_handle_t bn_sub(bn_handle_t a, bn_handle_t b);
bn_handle_t bn_mul(bn_handle_t a, bn_handle_t b);
bn_handle_t bn_neg(bn_handle_t a);

// Modular arithmetic (mod curve order)
bn_handle_t bn_add_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b);
bn_handle_t bn_sub_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b);
bn_handle_t bn_mul_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b);
bn_handle_t bn_inv_mod(curve_handle_t curve, bn_handle_t a);

// Comparison
int bn_is_zero(bn_handle_t handle);
int bn_equal(bn_handle_t a, bn_handle_t b);

// ============ Point (ecc_point_t) Operations ============

// Create point from bytes
point_handle_t point_from_bytes(curve_handle_t curve, cmem_t data);

// Convert point to bytes
cmem_t point_to_bytes(point_handle_t handle);

// Free point
void point_free(point_handle_t handle);

// Point arithmetic
point_handle_t point_add(point_handle_t a, point_handle_t b);
point_handle_t point_sub(point_handle_t a, point_handle_t b);
point_handle_t point_neg(point_handle_t p);
point_handle_t point_mul(point_handle_t p, bn_handle_t scalar);

// Multiply generator by scalar (optimized)
point_handle_t point_mul_generator(curve_handle_t curve, bn_handle_t scalar);

// Get coordinates
cmem_t point_get_x(point_handle_t handle);
cmem_t point_get_y(point_handle_t handle);

// Comparison
int point_is_infinity(point_handle_t handle);
int point_equal(point_handle_t a, point_handle_t b);

#ifdef __cplusplus
}
#endif

#endif // CB_MPC_GO_SCALAR_H
