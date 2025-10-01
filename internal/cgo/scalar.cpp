#include "scalar.h"
#include <cbmpc/crypto/base.h>
#include <cbmpc/crypto/base_bn.h>
#include <cbmpc/crypto/base_ecc.h>
#include <cbmpc/core/buf.h>
#include <cstring>

using namespace coinbase;
using namespace coinbase::crypto;

// Helper to allocate memory that Go will free
static cmem_t alloc_cmem(const buf_t& buf) {
    cmem_t result;
    result.size = buf.size();
    result.data = (uint8_t*)malloc(result.size);
    if (result.data) {
        memcpy(result.data, buf.data(), result.size);
    }
    return result;
}

// ============ Curve Operations ============

extern "C" curve_handle_t curve_from_nid(int nid) {
    curve_handle_t handle = {nullptr};
    try {
        ecurve_t* curve = new ecurve_t(ecurve_t::find(nid));
        if (curve->valid()) {
            handle.ptr = curve;
        } else {
            delete curve;
        }
    } catch (...) {
        // Return null handle
    }
    return handle;
}

extern "C" void curve_free(curve_handle_t handle) {
    if (handle.ptr) {
        delete (ecurve_t*)handle.ptr;
    }
}

extern "C" cmem_t curve_order(curve_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        ecurve_t* curve = (ecurve_t*)handle.ptr;
        const mod_t& order = curve->order();
        buf_t buf = order.value().to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" cmem_t curve_random_scalar(curve_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        ecurve_t* curve = (ecurve_t*)handle.ptr;
        bn_t scalar = curve->get_random_value();
        buf_t buf = scalar.to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" point_handle_t curve_generator(curve_handle_t handle) {
    point_handle_t result = {nullptr};
    if (!handle.ptr) return result;

    try {
        ecurve_t* curve = (ecurve_t*)handle.ptr;
        ecc_point_t* point = new ecc_point_t(curve->generator());
        result.ptr = point;
    } catch (...) {
        // Return null
    }
    return result;
}

// ============ Scalar (bn_t) Operations ============

extern "C" bn_handle_t bn_from_int64(int64_t value) {
    bn_handle_t handle = {nullptr};
    try {
        bn_t* bn = new bn_t();
        bn->set_int64(value);
        handle.ptr = bn;
    } catch (...) {
        // Return null
    }
    return handle;
}

extern "C" bn_handle_t bn_from_bytes(cmem_t data) {
    bn_handle_t handle = {nullptr};
    if (!data.data || data.size <= 0) return handle;

    try {
        mem_t mem(data.data, data.size);
        bn_t* bn = new bn_t(mem);
        handle.ptr = bn;
    } catch (...) {
        // Return null
    }
    return handle;
}

extern "C" cmem_t bn_to_bytes(bn_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        bn_t* bn = (bn_t*)handle.ptr;
        buf_t buf = bn->to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" void bn_free(bn_handle_t handle) {
    if (handle.ptr) {
        delete (bn_t*)handle.ptr;
    }
}

extern "C" bn_handle_t bn_add(bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!a.ptr || !b.ptr) return result;

    try {
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(*bn_a + *bn_b);
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_sub(bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!a.ptr || !b.ptr) return result;

    try {
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(*bn_a - *bn_b);
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_mul(bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!a.ptr || !b.ptr) return result;

    try {
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(*bn_a * *bn_b);
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_neg(bn_handle_t a) {
    bn_handle_t result = {nullptr};
    if (!a.ptr) return result;

    try {
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_result = new bn_t(bn_a->neg());
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_add_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!curve.ptr || !a.ptr || !b.ptr) return result;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        const mod_t& mod = ec->order();
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(mod.add(*bn_a, *bn_b));
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_sub_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!curve.ptr || !a.ptr || !b.ptr) return result;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        const mod_t& mod = ec->order();
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(mod.sub(*bn_a, *bn_b));
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_mul_mod(curve_handle_t curve, bn_handle_t a, bn_handle_t b) {
    bn_handle_t result = {nullptr};
    if (!curve.ptr || !a.ptr || !b.ptr) return result;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        const mod_t& mod = ec->order();
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        bn_t* bn_result = new bn_t(mod.mul(*bn_a, *bn_b));
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" bn_handle_t bn_inv_mod(curve_handle_t curve, bn_handle_t a) {
    bn_handle_t result = {nullptr};
    if (!curve.ptr || !a.ptr) return result;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        const mod_t& mod = ec->order();
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_result = new bn_t(mod.inv(*bn_a));
        result.ptr = bn_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" int bn_is_zero(bn_handle_t handle) {
    if (!handle.ptr) return 0;
    try {
        bn_t* bn = (bn_t*)handle.ptr;
        return bn->is_zero() ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

extern "C" int bn_equal(bn_handle_t a, bn_handle_t b) {
    if (!a.ptr || !b.ptr) return 0;
    try {
        bn_t* bn_a = (bn_t*)a.ptr;
        bn_t* bn_b = (bn_t*)b.ptr;
        return (*bn_a == *bn_b) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

// ============ Point (ecc_point_t) Operations ============

extern "C" point_handle_t point_from_bytes(curve_handle_t curve, cmem_t data) {
    point_handle_t handle = {nullptr};
    if (!curve.ptr || !data.data || data.size <= 0) return handle;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        mem_t mem(data.data, data.size);
        ecc_point_t* point = new ecc_point_t(*ec);
        error_t err = point->from_bin(*ec, mem);
        if (err) {
            delete point;
            return handle;
        }
        handle.ptr = point;
    } catch (...) {
        // Return null
    }
    return handle;
}

extern "C" cmem_t point_to_bytes(point_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        ecc_point_t* point = (ecc_point_t*)handle.ptr;
        buf_t buf = point->to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" void point_free(point_handle_t handle) {
    if (handle.ptr) {
        delete (ecc_point_t*)handle.ptr;
    }
}

extern "C" point_handle_t point_add(point_handle_t a, point_handle_t b) {
    point_handle_t result = {nullptr};
    if (!a.ptr || !b.ptr) return result;

    try {
        ecc_point_t* pt_a = (ecc_point_t*)a.ptr;
        ecc_point_t* pt_b = (ecc_point_t*)b.ptr;
        ecc_point_t* pt_result = new ecc_point_t(*pt_a + *pt_b);
        result.ptr = pt_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" point_handle_t point_sub(point_handle_t a, point_handle_t b) {
    point_handle_t result = {nullptr};
    if (!a.ptr || !b.ptr) return result;

    try {
        ecc_point_t* pt_a = (ecc_point_t*)a.ptr;
        ecc_point_t* pt_b = (ecc_point_t*)b.ptr;
        ecc_point_t* pt_result = new ecc_point_t(*pt_a - *pt_b);
        result.ptr = pt_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" point_handle_t point_neg(point_handle_t p) {
    point_handle_t result = {nullptr};
    if (!p.ptr) return result;

    try {
        ecc_point_t* pt = (ecc_point_t*)p.ptr;
        ecc_point_t* pt_result = new ecc_point_t(-(*pt));
        result.ptr = pt_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" point_handle_t point_mul(point_handle_t p, bn_handle_t scalar) {
    point_handle_t result = {nullptr};
    if (!p.ptr || !scalar.ptr) return result;

    try {
        ecc_point_t* pt = (ecc_point_t*)p.ptr;
        bn_t* bn_scalar = (bn_t*)scalar.ptr;
        ecc_point_t* pt_result = new ecc_point_t(ecc_point_t::mul(*pt, *bn_scalar));
        result.ptr = pt_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" point_handle_t point_mul_generator(curve_handle_t curve, bn_handle_t scalar) {
    point_handle_t result = {nullptr};
    if (!curve.ptr || !scalar.ptr) return result;

    try {
        ecurve_t* ec = (ecurve_t*)curve.ptr;
        bn_t* bn_scalar = (bn_t*)scalar.ptr;
        ecc_point_t* pt_result = new ecc_point_t(ec->mul_to_generator(*bn_scalar));
        result.ptr = pt_result;
    } catch (...) {
        // Return null
    }
    return result;
}

extern "C" cmem_t point_get_x(point_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        ecc_point_t* point = (ecc_point_t*)handle.ptr;
        bn_t x, y;
        point->get_coordinates(x, y);
        buf_t buf = x.to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" cmem_t point_get_y(point_handle_t handle) {
    cmem_t result = {nullptr, 0};
    if (!handle.ptr) return result;

    try {
        ecc_point_t* point = (ecc_point_t*)handle.ptr;
        bn_t x, y;
        point->get_coordinates(x, y);
        buf_t buf = y.to_bin();
        result = alloc_cmem(buf);
    } catch (...) {
        // Return empty
    }
    return result;
}

extern "C" int point_is_infinity(point_handle_t handle) {
    if (!handle.ptr) return 0;
    try {
        ecc_point_t* point = (ecc_point_t*)handle.ptr;
        return point->is_infinity() ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

extern "C" int point_equal(point_handle_t a, point_handle_t b) {
    if (!a.ptr || !b.ptr) return 0;
    try {
        ecc_point_t* pt_a = (ecc_point_t*)a.ptr;
        ecc_point_t* pt_b = (ecc_point_t*)b.ptr;
        return (*pt_a == *pt_b) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}
