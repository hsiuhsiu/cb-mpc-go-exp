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

#ifdef __cplusplus
}
#endif

#endif  // CBMPC_CTYPES_H
