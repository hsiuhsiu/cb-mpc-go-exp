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

#ifdef __cplusplus
}
#endif
