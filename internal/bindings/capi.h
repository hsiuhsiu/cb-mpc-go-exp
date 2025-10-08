#pragma once
#include <stddef.h>
#include <stdint.h>

#include "cbmpc/core/cmem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t cbmpc_role_id;

typedef struct cbmpc_go_transport {
  void *ctx;
  int (*send)(void *ctx, cbmpc_role_id to, uint8_t *ptr, size_t len);
  int (*receive)(void *ctx, cbmpc_role_id from, cmem_t *out);
  int (*receive_all)(void *ctx, cbmpc_role_id *from, size_t n, cmem_t *outs);
} cbmpc_go_transport;

int cbmpc_go_send(void *ctx, uint32_t to, uint8_t *ptr, size_t len);
int cbmpc_go_receive(void *ctx, uint32_t from, cmem_t *out);
int cbmpc_go_receive_all(void *ctx, uint32_t *from, size_t n, cmem_t *outs);

cbmpc_go_transport cbmpc_make_go_transport(void *ctx);

typedef struct cbmpc_job2p cbmpc_job2p;
typedef struct cbmpc_jobmp cbmpc_jobmp;

cbmpc_job2p *cbmpc_job2p_new(const cbmpc_go_transport *t,
                             cbmpc_role_id self,
                             const char *const *names);
void cbmpc_job2p_free(cbmpc_job2p *j);

cbmpc_jobmp *cbmpc_jobmp_new(const cbmpc_go_transport *t,
                             cbmpc_role_id self,
                             size_t n_parties,
                             const char *const *names);
void cbmpc_jobmp_free(cbmpc_jobmp *j);

int cbmpc_agree_random_2p(cbmpc_job2p *j, int bitlen, cmem_t *out);
int cbmpc_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out);
int cbmpc_weak_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out);
int cbmpc_multi_pairwise_agree_random(cbmpc_jobmp *j, int bitlen, cmems_t *out);

#ifdef __cplusplus
}
#endif
