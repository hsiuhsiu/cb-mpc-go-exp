#pragma once

#include <stdint.h>
#include <cbmpc/core/cmem.h>
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

// Two-party agree random protocol
// Both parties agree on a random value of bitLen bits
int mpc_agree_random(job_2p_ref* job, int bit_len, cmem_t* out);

// Multi-party agree random protocol
// All parties agree on a random value of bitLen bits
int mpc_multi_agree_random(job_mp_ref* job, int bit_len, cmem_t* out);

#ifdef __cplusplus
}
#endif
