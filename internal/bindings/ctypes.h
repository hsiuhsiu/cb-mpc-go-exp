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

// Get the curve NID from an ECDSA 2P key.
int cbmpc_ecdsa2p_key_get_curve_nid(const cbmpc_ecdsa2p_key *key, int *nid);

// Serialize an ECDSA 2P key to bytes for persistent storage or network transmission.
// The returned cmem_t is allocated and must be freed by the caller.
int cbmpc_ecdsa2p_key_serialize(const cbmpc_ecdsa2p_key *key, cmem_t *out);

// Deserialize an ECDSA 2P key from bytes.
// The returned key must be freed with cbmpc_ecdsa2p_key_free.
int cbmpc_ecdsa2p_key_deserialize(cmem_t serialized, cbmpc_ecdsa2p_key **key);

#ifdef __cplusplus
}
#endif

#endif  // CBMPC_CTYPES_H
