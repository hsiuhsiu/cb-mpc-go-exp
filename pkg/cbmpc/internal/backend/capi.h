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

// Perform multi-party ECDSA threshold DKG with access control.
// ac_bytes: serialized access control structure
// quorum_party_indices: array of party indices forming the quorum
// quorum_count: number of parties in quorum
int cbmpc_ecdsamp_threshold_dkg(cbmpc_jobmp *j, int curve_nid, cmem_t ac_bytes, const int *quorum_party_indices, int quorum_count, cbmpc_ecdsamp_key **key_out, cmem_t *sid_out);

// Refresh an ECDSA MP key using threshold refresh with access control.
// ac_bytes: serialized access control structure
// quorum_party_indices: array of party indices forming the quorum
// quorum_count: number of parties in quorum
// sid_in: input session ID (can be empty to generate new one)
// sid_out: output session ID (updated or newly generated)
int cbmpc_ecdsamp_threshold_refresh(cbmpc_jobmp *j, int curve_nid, cmem_t ac_bytes, const int *quorum_party_indices, int quorum_count, cmem_t sid_in, const cbmpc_ecdsamp_key *key_in, cmem_t *sid_out, cbmpc_ecdsamp_key **key_out);

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

// Add two points: result = point_a + point_b
// Returns a NEW point that must be freed with cbmpc_ecc_point_free.
int cbmpc_ecc_point_add(cbmpc_ecc_point point_a, cbmpc_ecc_point point_b, cbmpc_ecc_point *result_out);

// Scalar arithmetic operations
// Add two scalars: result = scalar_a + scalar_b (mod curve_order)
// scalar_a_bytes, scalar_b_bytes: big-endian scalar bytes
// Returns result scalar bytes (big-endian).
int cbmpc_scalar_add(cmem_t scalar_a_bytes, cmem_t scalar_b_bytes, int curve_nid, cmem_t *result_out);

// PVE operations using ecc_point_t directly (more efficient)
// Extract public key Q from a PVE ciphertext as an ecc_point_t.
// Returns a borrowed reference - do NOT free the returned point.
// The point is valid as long as the ciphertext is valid.
int cbmpc_pve_get_Q_point(cmem_t pve_ct, cbmpc_ecc_point *Q_point_out);

// Verify a PVE ciphertext against a public key Q (as ecc_point_t) and label.
int cbmpc_pve_verify_with_point(cmem_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point Q_point, cmem_t label);

// PVE Batch operations - encrypt/verify/decrypt multiple scalars in a single operation
// Encrypt multiple scalars x[] with respect to a curve, producing a batch PVE ciphertext.
// x_scalars: cmems_t containing serialized scalars (one per value to encrypt).
int cbmpc_pve_batch_encrypt(cmem_t ek_bytes, cmem_t label, int curve_nid, cmems_t x_scalars, cmem_t *pve_ct_out);

// Verify a batch PVE ciphertext against multiple public key points Q[] and label.
// Q_points: array of ECC point handles (cbmpc_ecc_point*), Q_count: number of points.
int cbmpc_pve_batch_verify(cmem_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point *Q_points, int Q_count, cmem_t label);

// Decrypt a batch PVE ciphertext to recover multiple scalars x[].
// Returns cmems_t containing the decrypted scalar bytes.
int cbmpc_pve_batch_decrypt(const void *dk_handle, cmem_t ek_bytes, cmem_t pve_ct, cmem_t label, int curve_nid, cmems_t *x_scalars_out);

// Access Control (AC) builder - opaque node handles for constructing AC trees
// Opaque pointer to ac_owned_t node (C++ type).
typedef void* cbmpc_ac_node;

// Create a leaf node with the given party name.
// Returns a new node that must be freed with cbmpc_ac_node_free.
int cbmpc_ac_leaf(cmem_t name, cbmpc_ac_node *node_out);

// Create an AND node with the given children.
// Takes ownership of children nodes - caller should NOT free them after this call.
// Returns a new node that must be freed with cbmpc_ac_node_free.
int cbmpc_ac_and(cbmpc_ac_node *children, int count, cbmpc_ac_node *node_out);

// Create an OR node with the given children.
// Takes ownership of children nodes - caller should NOT free them after this call.
// Returns a new node that must be freed with cbmpc_ac_node_free.
int cbmpc_ac_or(cbmpc_ac_node *children, int count, cbmpc_ac_node *node_out);

// Create a Threshold node requiring k of n children.
// Takes ownership of children nodes - caller should NOT free them after this call.
// Returns a new node that must be freed with cbmpc_ac_node_free.
int cbmpc_ac_threshold(int k, cbmpc_ac_node *children, int count, cbmpc_ac_node *node_out);

// Serialize an AC node tree to bytes.
// Returns serialized ac_owned_t bytes.
int cbmpc_ac_serialize(cbmpc_ac_node node, cmem_t *bytes_out);

// Convert an AC to a canonical string representation (for debugging).
// ac_bytes: serialized AC bytes.
int cbmpc_ac_to_string(cmem_t ac_bytes, cmem_t *str_out);

// Get list of leaf paths from an AC structure.
// ac_bytes: serialized AC bytes.
// Returns cmems_t containing leaf path strings (UTF-8).
int cbmpc_ac_list_leaf_paths(cmem_t ac_bytes, cmems_t *paths_out);

// Free an AC node (and its entire subtree if it's a parent node).
void cbmpc_ac_node_free(cbmpc_ac_node node);

// PVE-AC operations - Publicly Verifiable Encryption with Access Control
// These operations use serialized AC structures and path->key mappings.

// Encrypt scalars with AC policy.
// ac_bytes: serialized AC structure
// paths: cmems_t containing party path names (UTF-8 strings)
// ek_bytes: cmems_t containing encryption keys corresponding to paths (same order)
// label: encryption label
// curve_nid: elliptic curve NID
// x_scalars: cmems_t containing scalars to encrypt
// Returns serialized ACCiphertext bytes.
int cbmpc_pve_ac_encrypt(cmem_t ac_bytes, cmems_t paths, cmems_t ek_bytes, cmem_t label, int curve_nid, cmems_t x_scalars, cmem_t *pve_ct_out);

// Verify an AC ciphertext against public key points.
// ac_bytes: serialized AC structure
// paths: cmems_t containing party path names
// ek_bytes: cmems_t containing encryption keys corresponding to paths
// pve_ct: serialized ACCiphertext
// Q_points: array of ECC point handles (cbmpc_ecc_point*)
// Q_count: number of points
// label: encryption label (must match encryption)
int cbmpc_pve_ac_verify(cmem_t ac_bytes, cmems_t paths, cmems_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point *Q_points, int Q_count, cmem_t label);

// Party decrypts one row to produce a share.
// ac_bytes: serialized AC structure
// row_index: which scalar to decrypt (0-based)
// path: party path name (UTF-8 string)
// dk_handle: opaque pointer to the decryption key
// pve_ct: serialized ACCiphertext
// label: encryption label (must match encryption)
// Returns scalar share bytes.
int cbmpc_pve_ac_party_decrypt_row(cmem_t ac_bytes, int row_index, cmem_t path, const void *dk_handle, cmem_t pve_ct, cmem_t label, cmem_t *share_out);

// Aggregate quorum shares to restore the original scalars for a row.
// ac_bytes: serialized AC structure
// row_index: which scalar to restore (0-based)
// label: encryption label (must match encryption)
// quorum_paths: cmems_t containing party paths that form a quorum
// quorum_shares: cmems_t containing corresponding scalar shares
// pve_ct: serialized ACCiphertext
// all_paths: cmems_t containing all party paths (optional, for verification)
// all_eks: cmems_t containing all encryption keys (optional, for verification)
// Returns cmems_t containing the restored scalar bytes.
int cbmpc_pve_ac_aggregate_to_restore_row(cmem_t ac_bytes, int row_index, cmem_t label, cmems_t quorum_paths, cmems_t quorum_shares, cmem_t pve_ct, cmems_t all_paths, cmems_t all_eks, cmems_t *x_out);

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

// Perform multi-party Schnorr distributed key generation.
// Uses coinbase::mpc::schnorrmp::dkg wrapper.
int cbmpc_schnorrmp_dkg(cbmpc_jobmp *j, int curve_nid, cbmpc_ecdsamp_key **key_out, cmem_t *sid_out);

// Refresh a Schnorr MP key (re-randomize shares while preserving public key).
// Uses coinbase::mpc::schnorrmp::refresh wrapper.
// sid_in: input session ID (can be empty to generate new one)
// sid_out: output session ID (updated or newly generated)
int cbmpc_schnorrmp_refresh(cbmpc_jobmp *j, cmem_t sid_in, const cbmpc_ecdsamp_key *key_in, cmem_t *sid_out, cbmpc_ecdsamp_key **key_out);

// Sign a message with a Schnorr MP key.
// Only the party with party_idx == sig_receiver will receive the final signature.
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorrmp_sign(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmem_t msg, int sig_receiver, int variant, cmem_t *sig_out);

// Sign multiple messages with a Schnorr MP key (batch mode).
// Only the party with party_idx == sig_receiver will receive the final signatures.
// variant: CBMPC_SCHNORR_VARIANT_EDDSA or CBMPC_SCHNORR_VARIANT_BIP340
int cbmpc_schnorrmp_sign_batch(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmems_t msgs, int sig_receiver, int variant, cmems_t *sigs_out);

// Perform multi-party Schnorr threshold DKG with access control.
// Uses coinbase::mpc::schnorrmp::threshold_dkg wrapper.
// ac_bytes: serialized access control structure
// quorum_party_indices: array of party indices forming the quorum
// quorum_count: number of parties in quorum
int cbmpc_schnorrmp_threshold_dkg(cbmpc_jobmp *j, int curve_nid, cmem_t ac_bytes, const int *quorum_party_indices, int quorum_count, cbmpc_ecdsamp_key **key_out, cmem_t *sid_out);

// Refresh a Schnorr MP key using threshold refresh with access control.
// Uses coinbase::mpc::schnorrmp::threshold_refresh wrapper.
// ac_bytes: serialized access control structure
// quorum_party_indices: array of party indices forming the quorum
// quorum_count: number of parties in quorum
// sid_in: input session ID (can be empty to generate new one)
// sid_out: output session ID (updated or newly generated)
int cbmpc_schnorrmp_threshold_refresh(cbmpc_jobmp *j, int curve_nid, cmem_t ac_bytes, const int *quorum_party_indices, int quorum_count, cmem_t sid_in, const cbmpc_ecdsamp_key *key_in, cmem_t *sid_out, cbmpc_ecdsamp_key **key_out);

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

// ElGamalCom_PubShare_Equ proof - proves equality of public share in ElGamal commitment
// Proves that A and the public share of B are equal: A = r*G where B.L = r*G

// Create ElGamalCom_PubShare_Equ proof
// Q_point: the base point Q
// A_point: the public point A = r*G
// B_commitment: the ElGamal commitment B where B.L should equal A
// r: the secret randomness (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_elgamal_com_pub_share_equ_prove(cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ec_elgamal_commitment B_commitment, cmem_t r, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify an ElGamalCom_PubShare_Equ proof
// proof: serialized proof bytes
// Q_point, A_point: the points to verify against
// B_commitment: the ElGamal commitment to verify against
int cbmpc_elgamal_com_pub_share_equ_verify(cmem_t proof, cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ec_elgamal_commitment B_commitment, cmem_t session_id, uint64_t aux);

// ElGamalCom_Mult proof - proves multiplicative relationship between ElGamal commitments
// Proves that C = b * A (scalar multiplication of commitment A by secret scalar b)

// Create ElGamalCom_Mult proof
// Q_point: the base point Q
// A_commitment: the ElGamal commitment A
// B_commitment: the ElGamal commitment B
// C_commitment: the ElGamal commitment C (should be b * A)
// r_B: randomness for commitment B (witness)
// r_C: randomness for commitment C (witness)
// b: the secret scalar multiplier (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_elgamal_com_mult_prove(cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment A_commitment, cbmpc_ec_elgamal_commitment B_commitment, cbmpc_ec_elgamal_commitment C_commitment, cmem_t r_B, cmem_t r_C, cmem_t b, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify an ElGamalCom_Mult proof
// proof: serialized proof bytes
// Q_point: the base point
// A_commitment, B_commitment, C_commitment: the ElGamal commitments to verify against
int cbmpc_elgamal_com_mult_verify(cmem_t proof, cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment A_commitment, cbmpc_ec_elgamal_commitment B_commitment, cbmpc_ec_elgamal_commitment C_commitment, cmem_t session_id, uint64_t aux);

// UC_ElGamalCom_Mult_Private_Scalar proof - UC version of multiplication with private scalar
// Proves that eB = c * eA with universally composable security

// Create UC_ElGamalCom_Mult_Private_Scalar proof
// E_point: the base point E
// eA_commitment: the ElGamal commitment eA
// eB_commitment: the ElGamal commitment eB (should be c * eA)
// r0: the randomness for eB (witness)
// c: the secret scalar multiplier (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_uc_elgamal_com_mult_private_scalar_prove(cbmpc_ecc_point E_point, cbmpc_ec_elgamal_commitment eA_commitment, cbmpc_ec_elgamal_commitment eB_commitment, cmem_t r0, cmem_t c, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a UC_ElGamalCom_Mult_Private_Scalar proof
// proof: serialized proof bytes
// E_point: the base point
// eA_commitment, eB_commitment: the ElGamal commitments to verify against
int cbmpc_uc_elgamal_com_mult_private_scalar_verify(cmem_t proof, cbmpc_ecc_point E_point, cbmpc_ec_elgamal_commitment eA_commitment, cbmpc_ec_elgamal_commitment eB_commitment, cmem_t session_id, uint64_t aux);

// Valid_Paillier proof - proves that a Paillier key is valid (no small factors)
// This is a non-interactive zero-knowledge proof of Paillier key validity.

// Create Valid_Paillier proof for proving that a Paillier key is well-formed
// paillier: the Paillier instance (must have private key for proving)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_valid_paillier_prove(cbmpc_paillier paillier, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a Valid_Paillier proof
// proof: serialized proof bytes
// paillier: the Paillier instance to verify against (public key only)
// session_id: session identifier (must match the one used in Prove)
// aux: auxiliary data (must match the one used in Prove)
int cbmpc_valid_paillier_verify(cmem_t proof, cbmpc_paillier paillier, cmem_t session_id, uint64_t aux);

// Paillier_Zero proof - proves that a Paillier ciphertext encrypts zero
// This is a non-interactive zero-knowledge proof that c is an encryption of 0.

// Create Paillier_Zero proof for proving that c encrypts zero
// paillier: the Paillier instance (must have private key for proving)
// c: the ciphertext (as bytes)
// r: the randomness used to encrypt (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_paillier_zero_prove(cbmpc_paillier paillier, cmem_t c, cmem_t r, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a Paillier_Zero proof
// proof: serialized proof bytes
// paillier: the Paillier instance (public key only)
// c: the ciphertext to verify encrypts zero
// session_id: session identifier (must match the one used in Prove)
// aux: auxiliary data (must match the one used in Prove)
int cbmpc_paillier_zero_verify(cmem_t proof, cbmpc_paillier paillier, cmem_t c, cmem_t session_id, uint64_t aux);

// Two_Paillier_Equal proof - proves two Paillier ciphertexts encrypt the same plaintext
// This proves that c0 (under P0) and c1 (under P1) encrypt the same value x.

// Create Two_Paillier_Equal proof
// q: the modulus (as bytes)
// P0, P1: two Paillier instances (must have private keys for proving)
// c0, c1: the two ciphertexts (as bytes)
// x: the plaintext value (witness)
// r0, r1: the randomness used for c0 and c1 (witnesses)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_two_paillier_equal_prove(cmem_t q, cbmpc_paillier P0, cmem_t c0, cbmpc_paillier P1, cmem_t c1, cmem_t x, cmem_t r0, cmem_t r1, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a Two_Paillier_Equal proof
// proof: serialized proof bytes
// q: the modulus (as bytes)
// P0, P1: two Paillier instances (public keys only)
// c0, c1: the two ciphertexts to verify encrypt the same value
// session_id: session identifier (must match the one used in Prove)
// aux: auxiliary data (must match the one used in Prove)
int cbmpc_two_paillier_equal_verify(cmem_t proof, cmem_t q, cbmpc_paillier P0, cmem_t c0, cbmpc_paillier P1, cmem_t c1, cmem_t session_id, uint64_t aux);

// Paillier_Range_Exp_Slack proof - proves a Paillier ciphertext encrypts a value in range
// This proves that c encrypts a value x within the valid range with some slack.

// Create Paillier_Range_Exp_Slack proof
// paillier: the Paillier instance (must have private key for proving)
// q: the modulus (as bytes)
// c: the ciphertext (as bytes)
// x: the plaintext value (witness)
// r: the randomness used to encrypt (witness)
// session_id: session identifier for security, aux: auxiliary data
// Returns serialized proof bytes.
int cbmpc_paillier_range_exp_slack_prove(cbmpc_paillier paillier, cmem_t q, cmem_t c, cmem_t x, cmem_t r, cmem_t session_id, uint64_t aux, cmem_t *proof_out);

// Verify a Paillier_Range_Exp_Slack proof
// proof: serialized proof bytes
// paillier: the Paillier instance (public key only)
// q: the modulus (as bytes)
// c: the ciphertext to verify
// session_id: session identifier (must match the one used in Prove)
// aux: auxiliary data (must match the one used in Prove)
int cbmpc_paillier_range_exp_slack_verify(cmem_t proof, cbmpc_paillier paillier, cmem_t q, cmem_t c, cmem_t session_id, uint64_t aux);

#ifdef __cplusplus
}
#endif
