#pragma once
#include <stddef.h>
#include <stdint.h>

#include "cbmpc/core/cmem.h"
#include "ctypes.h"
#include "cjob.h"

#ifdef __cplusplus
extern "C" {
#endif

// Minimal error code definitions mirrored from cb-mpc C++ headers for use in C FFI.
// Values are negative 32-bit equivalents of 0xff.. style codes to fit in C int via cgo.
#define CBMPC_SUCCESS 0
#define CBMPC_E_BADARG (-16711678)      // 0xff010002
#define CBMPC_E_NOT_SUPPORTED (-16711675) // 0xff010005
#define CBMPC_E_NOT_FOUND (-16711674)   // 0xff010006
#define CBMPC_E_CRYPTO (-16515071)      // 0xff040001

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

// ECDSA MP protocols
// All functions return a key that must be freed with cbmpc_ecdsamp_key_free.

// Perform multi-party ECDSA distributed key generation.
int cbmpc_ecdsamp_dkg(cbmpc_jobmp *j, int curve_nid, cbmpc_ecdsamp_key **key_out, cmem_t *sid_out);

// Refresh an ECDSA MP key (re-randomize shares while preserving public key).
// sid_in: input session ID (can be empty to generate new one)
// sid_out: output session ID (updated or newly generated)
int cbmpc_ecdsamp_refresh(cbmpc_jobmp *j, cmem_t sid_in, const cbmpc_ecdsamp_key *key_in, cmem_t *sid_out, cbmpc_ecdsamp_key **key_out);

// Sign a message with an ECDSA MP key.
// Only the party with party_idx == sig_receiver will receive the final signature.
int cbmpc_ecdsamp_sign(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmem_t msg, int sig_receiver, cmem_t *sig_out);

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

// Get the curve for an ECC point (returns curve enum value, not NID).
int cbmpc_ecc_point_get_curve(cbmpc_ecc_point point);

// Curve operations
// Generate a random scalar for a given curve (returns bytes in big-endian format).
int cbmpc_curve_random_scalar(int curve_nid, cmem_t *scalar_out);

// Get the generator point for a given curve.
// Returns a NEW point that must be freed with cbmpc_ecc_point_free.
int cbmpc_curve_get_generator(int curve_nid, cbmpc_ecc_point *generator_out);

// Multiply a scalar by the generator: result = scalar * G
// scalar_bytes: big-endian scalar bytes
// Returns a NEW point that must be freed with cbmpc_ecc_point_free.
int cbmpc_curve_mul_generator(int curve_nid, cmem_t scalar_bytes, cbmpc_ecc_point *point_out);

// Multiply a scalar by a point: result = scalar * point
// scalar_bytes: big-endian scalar bytes
// Returns a NEW point that must be freed with cbmpc_ecc_point_free.
int cbmpc_ecc_point_mul(cbmpc_ecc_point point, cmem_t scalar_bytes, cbmpc_ecc_point *result_out);

// PVE operations using ecc_point_t directly (more efficient)
// Extract public key Q from a PVE ciphertext as an ecc_point_t.
// Returns a borrowed reference - do NOT free the returned point.
// The point is valid as long as the ciphertext is valid.
int cbmpc_pve_get_Q_point(cmem_t pve_ct, cbmpc_ecc_point *Q_point_out);

// Verify a PVE ciphertext against a public key Q (as ecc_point_t) and label.
int cbmpc_pve_verify_with_point(cmem_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point Q_point, cmem_t label);

// KEM context (thread-local) management for FFI policy
// These APIs allow Go to set a per-thread opaque handle that the Go FFI
// callbacks can retrieve to locate the correct KEM implementation.
// Note: The handle must NOT be a Go pointer. Use backend.RegisterHandle to
// obtain a CGO-safe opaque handle value.
void cbmpc_set_kem_tls(const void *handle);
void cbmpc_clear_kem_tls(void);
const void *cbmpc_get_kem_tls(void);

// Schnorr 2P protocols
// Schnorr 2P key type (wraps eckey::key_share_2p_t, same underlying type as ECDSA 2P but kept separate).
// All functions return a key that must be freed with cbmpc_schnorr2p_key_free.

// Schnorr variant enum (EdDSA or BIP340).
#define CBMPC_SCHNORR_VARIANT_EDDSA 0
#define CBMPC_SCHNORR_VARIANT_BIP340 1

// Perform 2-party Schnorr distributed key generation.
int cbmpc_schnorr2p_dkg(cbmpc_job2p *j, int curve_nid, cbmpc_schnorr2p_key **key_out);

// Free a Schnorr 2P key.
void cbmpc_schnorr2p_key_free(cbmpc_schnorr2p_key *key);

// Serialize a Schnorr 2P key to bytes.
int cbmpc_schnorr2p_key_serialize(const cbmpc_schnorr2p_key *key, cmem_t *out);

// Deserialize bytes into a Schnorr 2P key.
int cbmpc_schnorr2p_key_deserialize(cmem_t serialized, cbmpc_schnorr2p_key **key_out);

// Get the public key from a Schnorr 2P key (compressed format).
int cbmpc_schnorr2p_key_get_public_key(const cbmpc_schnorr2p_key *key, cmem_t *out);

// Get the curve NID from a Schnorr 2P key.
int cbmpc_schnorr2p_key_get_curve(const cbmpc_schnorr2p_key *key, int *curve_nid_out);

// Sign a message with a Schnorr 2P key.
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorr2p_sign(cbmpc_job2p *j, const cbmpc_schnorr2p_key *key, cmem_t msg, int variant, cmem_t *sig_out);

// Sign multiple messages with a Schnorr 2P key (batch mode).
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorr2p_sign_batch(cbmpc_job2p *j, const cbmpc_schnorr2p_key *key, cmems_t msgs, int variant, cmems_t *sigs_out);

// Schnorr MP protocols
// Schnorr MP uses the same key type as ECDSA MP (eckey::key_share_mp_t).
// Use cbmpc_ecdsamp_dkg and cbmpc_ecdsamp_refresh for key management.

// Sign a message with a Schnorr MP key.
// Only the party with party_idx == sig_receiver will receive the final signature.
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorrmp_sign(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmem_t msg, int sig_receiver, int variant, cmem_t *sig_out);

// Sign multiple messages with a Schnorr MP key (batch mode).
// Only the party with party_idx == sig_receiver will receive the final signatures.
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorrmp_sign_batch(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmems_t msgs, int sig_receiver, int variant, cmems_t *sigs_out);

// EC ElGamal Commitment operations (coinbase::crypto namespace)
// Opaque pointer to ec_elgamal_commitment_t (C++ type).
typedef void* cbmpc_ec_elgamal_commitment;

// Create a new EC ElGamal commitment from two points (L and R).
// Returns a pointer to ec_elgamal_commitment_t that must be freed with cbmpc_ec_elgamal_commitment_free.
int cbmpc_ec_elgamal_commitment_new(cbmpc_ecc_point point_L, cbmpc_ecc_point point_R, cbmpc_ec_elgamal_commitment *commitment_out);

// Serialize an EC ElGamal commitment to bytes.
int cbmpc_ec_elgamal_commitment_to_bytes(cbmpc_ec_elgamal_commitment commitment, cmem_t *bytes_out);

// Deserialize bytes into an EC ElGamal commitment.
int cbmpc_ec_elgamal_commitment_from_bytes(int curve_nid, cmem_t bytes, cbmpc_ec_elgamal_commitment *commitment_out);

// Get the L point from a commitment (returns a NEW point that must be freed).
int cbmpc_ec_elgamal_commitment_get_L(cbmpc_ec_elgamal_commitment commitment, cbmpc_ecc_point *point_L_out);

// Get the R point from a commitment (returns a NEW point that must be freed).
int cbmpc_ec_elgamal_commitment_get_R(cbmpc_ec_elgamal_commitment commitment, cbmpc_ecc_point *point_R_out);

// Free an EC ElGamal commitment.
void cbmpc_ec_elgamal_commitment_free(cbmpc_ec_elgamal_commitment commitment);

// Create an EC ElGamal commitment using make_commitment: UV = (r*G, m*P + r*G)
// P: the public key point, m: the message scalar, r: the randomness scalar
// Returns a pointer to ec_elgamal_commitment_t that must be freed with cbmpc_ec_elgamal_commitment_free.
int cbmpc_ec_elgamal_commitment_make(cbmpc_ecc_point P, cmem_t m, cmem_t r, cbmpc_ec_elgamal_commitment *commitment_out);

// ZK proof operations (coinbase::zk namespace)
// UC_DL proof - universally composable discrete log proof

// Create UC_DL proof for proving knowledge of w such that Q = w*G
// Q_point: the public key point, w: the secret scalar (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_uc_dl_prove(cbmpc_ecc_point Q_point, cmem_t w, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a UC_DL proof
// proof: serialized proof bytes
// Q_point: the public key point to verify against
int cbmpc_uc_dl_verify(cmem_t proof, cbmpc_ecc_point Q_point, cmem_t session_id, uint64_t aux);

// UC_Batch_DL proof - batch universally composable discrete log proof
// Proves knowledge of multiple discrete logarithms Q[i] = w[i]*G

// Create UC_Batch_DL proof for proving knowledge of multiple w's such that Q[i] = w[i]*G
// Q_points: array of ECC point handles (cbmpc_ecc_point*)
// Q_count: number of points
// w_scalars: array of secret scalars/witnesses (serialized as cmems_t)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_uc_batch_dl_prove(cbmpc_ecc_point *Q_points, int Q_count, cmems_t w_scalars, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a UC_Batch_DL proof
// proof: serialized proof bytes
// Q_points: array of ECC point handles to verify against (cbmpc_ecc_point*)
// Q_count: number of points
int cbmpc_uc_batch_dl_verify(cmem_t proof, cbmpc_ecc_point *Q_points, int Q_count, cmem_t session_id, uint64_t aux);

// DH proof - Diffie-Hellman proof
// Proves knowledge of w such that A = w*G and B = w*Q (same discrete log for two different bases)

// Create DH proof for proving B = w*Q where A = w*G
// Q_point: the base point, A_point: w*G, B_point: w*Q
// w: the secret scalar (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_dh_prove(cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ecc_point B_point, cmem_t w, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a DH proof
// proof: serialized proof bytes
// Q_point, A_point, B_point: the points to verify against
int cbmpc_dh_verify(cmem_t proof, cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ecc_point B_point, cmem_t session_id, uint64_t aux);

// UC_ElGamalCom proof - universally composable ElGamal commitment proof
// Proves knowledge of discrete log and randomness for an ElGamal commitment

// Create UC_ElGamalCom proof for proving knowledge of x and r such that UV = (r*G, x*Q + r*G)
// Q_point: the public base point
// UV_commitment: the ElGamal commitment (L, R) where L = r*G and R = x*Q + r*G
// x: the secret value (witness)
// r: the secret randomness (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_uc_elgamal_com_prove(cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment UV_commitment, cmem_t x, cmem_t r, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a UC_ElGamalCom proof
// proof: serialized proof bytes
// Q_point: the public base point
// UV_commitment: the ElGamal commitment to verify against
int cbmpc_uc_elgamal_com_verify(cmem_t proof, cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment UV_commitment, cmem_t session_id, uint64_t aux);

#ifdef __cplusplus
}
#endif
