#pragma once

#include <stdint.h>

#include "binding.h"

#ifdef __cplusplus
extern "C" {
#endif

// ECDSA 2PC key handle
typedef struct {
    void* opaque;
} ecdsa_2p_key_t;

// ECDSA 2PC key generation
// Returns 0 on success, error code on failure
int ecdsa_2p_keygen(session_t* session, int curve_code, ecdsa_2p_key_t* key);

// ECDSA 2PC signing
// Returns 0 on success, error code on failure
int ecdsa_2p_sign(session_t* session, ecdsa_2p_key_t* key, const uint8_t* message_hash, size_t hash_len, uint8_t** signature, size_t* sig_len);

// ECDSA 2PC key refresh
// Returns 0 on success, error code on failure
int ecdsa_2p_refresh(session_t* session, ecdsa_2p_key_t* old_key, ecdsa_2p_key_t* new_key);

// Key accessors
int ecdsa_2p_key_get_role(ecdsa_2p_key_t* key);
int ecdsa_2p_key_get_curve_code(ecdsa_2p_key_t* key);
int ecdsa_2p_key_get_public_key(ecdsa_2p_key_t* key, uint8_t** pubkey, size_t* pubkey_len);
int ecdsa_2p_key_get_private_share(ecdsa_2p_key_t* key, uint8_t** share, size_t* share_len);

// Memory management
void ecdsa_2p_key_free(ecdsa_2p_key_t* key);
void ecdsa_2p_free_buffer(uint8_t* buffer);

#ifdef __cplusplus
}
#endif