#include "agree_random.h"
#include <cbmpc/protocol/agree_random.h>
#include <cbmpc/protocol/mpc_job_session.h>
#include <cbmpc/crypto/base.h>
#include <iostream>

using namespace coinbase;
using namespace coinbase::mpc;

namespace {
constexpr int SUCCESS_CODE = 0;
constexpr int ERROR_CODE = -1;
constexpr int PARAM_ERROR_CODE = -2;
}

#define VALIDATE_JOB_2P(job) \
  do { \
    if (!job || !job->opaque) { \
      return PARAM_ERROR_CODE; \
    } \
  } while (0)

#define VALIDATE_JOB_MP(job) \
  do { \
    if (!job || !job->opaque) { \
      return PARAM_ERROR_CODE; \
    } \
  } while (0)

#define GET_JOB_2P(job) static_cast<job_2p_t*>(job->opaque)
#define GET_JOB_MP(job) static_cast<job_mp_t*>(job->opaque)

extern "C" {

int mpc_agree_random(job_2p_ref* job, int bit_len, cmem_t* out) {
  if (!job || !job->opaque || !out) return PARAM_ERROR_CODE;
  if (bit_len <= 0) return PARAM_ERROR_CODE;

  try {
    job_2p_t* j = GET_JOB_2P(job);
    buf_t out_buf;
    error_t err = agree_random(*j, bit_len, out_buf);

    if (err) return static_cast<int>(err);

    *out = out_buf.to_cmem();
    return SUCCESS_CODE;

  } catch (const std::exception& e) {
    std::cerr << "Error in mpc_agree_random: " << e.what() << std::endl;
    return ERROR_CODE;
  }
}

int mpc_multi_agree_random(job_mp_ref* job, int bit_len, cmem_t* out) {
  if (!job || !job->opaque || !out) return PARAM_ERROR_CODE;
  if (bit_len <= 0) return PARAM_ERROR_CODE;

  try {
    job_mp_t* j = GET_JOB_MP(job);
    buf_t out_buf;
    error_t err = multi_agree_random(*j, bit_len, out_buf);

    if (err) return static_cast<int>(err);

    *out = out_buf.to_cmem();
    return SUCCESS_CODE;

  } catch (const std::exception& e) {
    std::cerr << "Error in mpc_multi_agree_random: " << e.what() << std::endl;
    return ERROR_CODE;
  }
}

}  // extern "C"
