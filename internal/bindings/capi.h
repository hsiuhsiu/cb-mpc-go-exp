#pragma once
#include <stddef.h>
#include <stdint.h>

#include "cbmpc/core/cmem.h"
#include "ctypes.h"
#include "cjob.h"

#ifdef __cplusplus
extern "C" {
#endif

int cbmpc_agree_random_2p(cbmpc_job2p *j, int bitlen, cmem_t *out);
int cbmpc_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out);
int cbmpc_weak_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out);
int cbmpc_multi_pairwise_agree_random(cbmpc_jobmp *j, int bitlen, cmems_t *out);

// ECDSA 2P protocols
// All functions return a key that must be freed with cbmpc_ecdsa2p_key_free.

// Perform 2-party ECDSA distributed key generation.
int cbmpc_ecdsa2p_dkg(cbmpc_job2p *j, int curve_nid, cbmpc_ecdsa2p_key **key_out);

// Refresh an ECDSA 2P key (re-randomize shares while preserving public key).
int cbmpc_ecdsa2p_refresh(cbmpc_job2p *j, const cbmpc_ecdsa2p_key *key_in, cbmpc_ecdsa2p_key **key_out);

// Sign a message with an ECDSA 2P key.
int cbmpc_ecdsa2p_sign(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmem_t msg, cmem_t *sid_out, cmem_t *sig_out);

// Sign multiple messages with an ECDSA 2P key (batch mode).
int cbmpc_ecdsa2p_sign_batch(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmems_t msgs, cmem_t *sid_out, cmems_t *sigs_out);

// Sign a message with an ECDSA 2P key using global abort mode.
// Returns E_ECDSA_2P_BIT_LEAK if signature verification fails (indicates potential key leak).
int cbmpc_ecdsa2p_sign_with_global_abort(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmem_t msg, cmem_t *sid_out, cmem_t *sig_out);

// Sign multiple messages with an ECDSA 2P key using global abort mode (batch mode).
// Returns E_ECDSA_2P_BIT_LEAK if signature verification fails (indicates potential key leak).
int cbmpc_ecdsa2p_sign_with_global_abort_batch(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmems_t msgs, cmem_t *sid_out, cmems_t *sigs_out);

// PVE (Publicly Verifiable Encryption) functions
// Encrypt a scalar x with respect to a curve, producing a PVE ciphertext.
// ek_bytes: serialized public encryption key bytes.
int cbmpc_pve_encrypt(cmem_t ek_bytes, cmem_t label, int curve_nid, cmem_t x_bytes, cmem_t *pve_ct_out);

// Verify a PVE ciphertext against a public key Q and label.
// ek_bytes: serialized public encryption key bytes.
int cbmpc_pve_verify(cmem_t ek_bytes, cmem_t pve_ct, cmem_t Q_bytes, cmem_t label);

// Decrypt a PVE ciphertext to recover the scalar x.
// dk_handle: opaque pointer to the decryption key (managed by Go KEM).
// ek_bytes: serialized public encryption key bytes.
int cbmpc_pve_decrypt(const void *dk_handle, cmem_t ek_bytes, cmem_t pve_ct, cmem_t label, int curve_nid, cmem_t *x_bytes_out);

// Extract public key Q from a PVE ciphertext.
int cbmpc_pve_get_Q(cmem_t pve_ct, cmem_t *Q_bytes_out);

// Extract label from a PVE ciphertext.
int cbmpc_pve_get_label(cmem_t pve_ct, cmem_t *label_out);

// Scalar operations (wraps C++ bn_t)
// Create a scalar from bytes (big-endian).
int cbmpc_scalar_from_bytes(cmem_t bytes, cmem_t *scalar_out);

// Create a scalar from a decimal string.
int cbmpc_scalar_from_string(const char *str, cmem_t *scalar_out);

// Serialize a scalar to bytes (big-endian).
int cbmpc_scalar_to_bytes(cmem_t scalar, cmem_t *bytes_out);

// Free a scalar.
void cbmpc_scalar_free(cmem_t scalar);

// ECC Point operations (wraps C++ ecc_point_t)
// These allow working with curve points directly without serialization overhead.

// Opaque pointer to ecc_point_t (C++ type).
typedef void* cbmpc_ecc_point;

// Create a new ECC point from compressed binary format.
// Returns a pointer to ecc_point_t that must be freed with cbmpc_ecc_point_free.
int cbmpc_ecc_point_from_bytes(int curve_nid, cmem_t bytes, cbmpc_ecc_point *point_out);

// Serialize an ECC point to compressed binary format.
int cbmpc_ecc_point_to_bytes(cbmpc_ecc_point point, cmem_t *bytes_out);

// Free an ECC point.
void cbmpc_ecc_point_free(cbmpc_ecc_point point);

// Get the curve NID for an ECC point.
int cbmpc_ecc_point_get_curve_nid(cbmpc_ecc_point point);

// PVE operations using ecc_point_t directly (more efficient)
// Extract public key Q from a PVE ciphertext as an ecc_point_t.
// Returns a borrowed reference - do NOT free the returned point.
// The point is valid as long as the ciphertext is valid.
int cbmpc_pve_get_Q_point(cmem_t pve_ct, cbmpc_ecc_point *Q_point_out);

// Verify a PVE ciphertext against a public key Q (as ecc_point_t) and label.
int cbmpc_pve_verify_with_point(cmem_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point Q_point, cmem_t label);

#ifdef __cplusplus
}
#endif
