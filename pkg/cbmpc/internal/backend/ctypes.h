#ifndef CBMPC_CTYPES_H
#define CBMPC_CTYPES_H

#include <stddef.h>
#include <stdint.h>

#include "cbmpc/core/cmem.h"

#ifdef __cplusplus
extern "C" {
#endif

// ECDSA 2P key - opaque handle to C++ key_t object
// Memory management: Keys returned by cbmpc_ecdsa2p_* functions must be freed with cbmpc_ecdsa2p_key_free.
typedef struct cbmpc_ecdsa2p_key {
  void *opaque;  // Opaque pointer to coinbase::mpc::ecdsa2pc::key_t
} cbmpc_ecdsa2p_key;

// Free an ECDSA 2P key. The key pointer must not be used after calling this function.
void cbmpc_ecdsa2p_key_free(cbmpc_ecdsa2p_key *key);

// Get the public key from an ECDSA 2P key (compressed EC point).
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_ecdsa2p_key_get_public_key(const cbmpc_ecdsa2p_key *key, cmem_t *out);

// Get the curve from an ECDSA 2P key (returns curve enum value, not NID).
int cbmpc_ecdsa2p_key_get_curve(const cbmpc_ecdsa2p_key *key, int *curve);

// Serialize an ECDSA 2P key to bytes for persistent storage or network transmission.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_ecdsa2p_key_serialize(const cbmpc_ecdsa2p_key *key, cmem_t *out);

// Deserialize an ECDSA 2P key from bytes.
// The returned key must be freed with cbmpc_ecdsa2p_key_free.
int cbmpc_ecdsa2p_key_deserialize(cmem_t serialized, cbmpc_ecdsa2p_key **key);

// ECDSA MP key - opaque handle to C++ key_t object
// Memory management: Keys returned by cbmpc_ecdsamp_* functions must be freed with cbmpc_ecdsamp_key_free.
typedef struct cbmpc_ecdsamp_key {
  void *opaque;  // Opaque pointer to coinbase::mpc::ecdsampc::key_t
} cbmpc_ecdsamp_key;

// Free an ECDSA MP key. The key pointer must not be used after calling this function.
void cbmpc_ecdsamp_key_free(cbmpc_ecdsamp_key *key);

// Get the public key from an ECDSA MP key (compressed EC point).
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_ecdsamp_key_get_public_key(const cbmpc_ecdsamp_key *key, cmem_t *out);

// Get the curve from an ECDSA MP key (returns curve enum value, not NID).
int cbmpc_ecdsamp_key_get_curve(const cbmpc_ecdsamp_key *key, int *curve);

// Serialize an ECDSA MP key to bytes for persistent storage or network transmission.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_ecdsamp_key_serialize(const cbmpc_ecdsamp_key *key, cmem_t *out);

// Deserialize an ECDSA MP key from bytes.
// The returned key must be freed with cbmpc_ecdsamp_key_free.
int cbmpc_ecdsamp_key_deserialize(cmem_t serialized, cbmpc_ecdsamp_key **key);

// Schnorr 2P key - opaque handle to C++ key_t object (eckey::key_share_2p_t)
// Memory management: Keys returned by cbmpc_schnorr2p_* functions must be freed with cbmpc_schnorr2p_key_free.
typedef struct cbmpc_schnorr2p_key {
  void *opaque;  // Opaque pointer to coinbase::mpc::eckey::key_share_2p_t
} cbmpc_schnorr2p_key;

// Paillier cryptosystem - opaque handle to C++ paillier_t object
// Memory management: Paillier instances returned by cbmpc_paillier_* functions must be freed with cbmpc_paillier_free.
typedef void *cbmpc_paillier;

// Generate a new Paillier keypair (2048-bit modulus).
// The returned paillier instance must be freed with cbmpc_paillier_free.
int cbmpc_paillier_generate(cbmpc_paillier *paillier_out);

// Create a Paillier instance from a public key (modulus N only).
// The returned paillier instance must be freed with cbmpc_paillier_free.
int cbmpc_paillier_create_pub(cmem_t N, cbmpc_paillier *paillier_out);

// Create a Paillier instance from a private key (modulus N and factors p, q).
// The returned paillier instance must be freed with cbmpc_paillier_free.
int cbmpc_paillier_create_prv(cmem_t N, cmem_t p, cmem_t q, cbmpc_paillier *paillier_out);

// Free a Paillier instance. The paillier pointer must not be used after calling this function.
void cbmpc_paillier_free(cbmpc_paillier paillier);

// Check if the Paillier instance has a private key.
// Returns 1 if private key is present, 0 otherwise.
int cbmpc_paillier_has_private_key(cbmpc_paillier paillier);

// Get the modulus N from a Paillier instance.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_get_N(cbmpc_paillier paillier, cmem_t *out);

// Encrypt a plaintext value with the Paillier cryptosystem.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_encrypt(cbmpc_paillier paillier, cmem_t plaintext, cmem_t *ciphertext_out);

// Decrypt a ciphertext value with the Paillier cryptosystem (requires private key).
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_decrypt(cbmpc_paillier paillier, cmem_t ciphertext, cmem_t *plaintext_out);

// Add two Paillier ciphertexts homomorphically.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_add_ciphers(cbmpc_paillier paillier, cmem_t c1, cmem_t c2, cmem_t *result_out);

// Multiply a Paillier ciphertext by a scalar homomorphically.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_mul_scalar(cbmpc_paillier paillier, cmem_t ciphertext, cmem_t scalar, cmem_t *result_out);

// Verify that a ciphertext is well-formed for this Paillier instance.
int cbmpc_paillier_verify_cipher(cbmpc_paillier paillier, cmem_t ciphertext);

// Serialize a Paillier instance to bytes for persistent storage or network transmission.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_paillier_serialize(cbmpc_paillier paillier, cmem_t *out);

// Deserialize a Paillier instance from bytes.
// The returned paillier instance must be freed with cbmpc_paillier_free.
int cbmpc_paillier_deserialize(cmem_t serialized, cbmpc_paillier *paillier_out);

#ifdef __cplusplus
}
#endif

#endif  // CBMPC_CTYPES_H
