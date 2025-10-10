#include "cbmpc/crypto/pki_ffi.h"

// Forward declarations of Go-exported functions
extern int go_ffi_kem_encap(cmem_t ek_bytes, cmem_t rho, cmem_t* kem_ct_out, cmem_t* kem_ss_out);
extern int go_ffi_kem_decap(const void* dk_handle, cmem_t kem_ct, cmem_t* kem_ss_out);
extern int go_ffi_kem_dk_to_ek(const void* dk_handle, cmem_t* ek_bytes_out);

// Strong symbols that override the weak symbols in C++
// These bridge C++ calls to Go implementations

ffi_kem_encap_fn get_ffi_kem_encap_fn(void) {
    return go_ffi_kem_encap;
}

ffi_kem_decap_fn get_ffi_kem_decap_fn(void) {
    return go_ffi_kem_decap;
}

ffi_kem_dk_to_ek_fn get_ffi_kem_dk_to_ek_fn(void) {
    return go_ffi_kem_dk_to_ek;
}
