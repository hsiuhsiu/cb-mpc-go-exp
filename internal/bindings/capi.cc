#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "capi.h"

#include "cbmpc/core/buf.h"
#include "cbmpc/core/convert.h"
#include "cbmpc/core/error.h"
#include "cbmpc/crypto/base_ecc.h"
#include "cbmpc/protocol/agree_random.h"
#include "cbmpc/protocol/ecdsa_2p.h"
#include "cbmpc/protocol/mpc_job.h"

namespace {

using coinbase::buf_t;
using coinbase::mem_t;
using coinbase::mpc::job_2p_t;
using coinbase::mpc::job_mp_t;

// Allocate and copy data to a new cmem_t that the caller owns.
// The caller is responsible for freeing this memory.
static inline cmem_t alloc_and_copy(const uint8_t *src, size_t n) {
  uint8_t *p = nullptr;
  if (n > 0) {
    p = static_cast<uint8_t *>(std::malloc(n));
    if (!p) {
      cmem_t v{};
      v.data = nullptr;
      v.size = 0;
      return v;
    }
    if (src) std::memcpy(p, src, n);
  }
  cmem_t view{};
  view.data = p;
  view.size = static_cast<int>(n);
  return view;
}

// Allocate and copy a vector of buf_t to a new cmems_t that the caller owns.
// The caller is responsible for freeing this memory.
static inline cmems_t alloc_and_copy_vector(const std::vector<buf_t> &vec) {
  cmems_t result{};
  if (vec.empty()) {
    result.data = nullptr;
    result.sizes = nullptr;
    result.count = 0;
    return result;
  }

  size_t n = vec.size();

  // Calculate total size needed for all data
  size_t total_size = 0;
  for (const auto &buf : vec) {
    total_size += static_cast<size_t>(buf.size());
  }

  // If all buffers are empty (e.g., P2 in ECDSA 2P), return empty result
  if (total_size == 0) {
    result.data = nullptr;
    result.sizes = nullptr;
    result.count = 0;
    return result;
  }

  // Allocate contiguous buffer for all data
  uint8_t *data = static_cast<uint8_t *>(std::malloc(total_size));
  if (!data) {
    result.data = nullptr;
    result.sizes = nullptr;
    result.count = 0;
    return result;
  }

  // Allocate array for sizes
  int *sizes = static_cast<int *>(std::malloc(n * sizeof(int)));
  if (!sizes) {
    std::free(data);
    result.data = nullptr;
    result.sizes = nullptr;
    result.count = 0;
    return result;
  }

  // Copy data and record sizes
  size_t offset = 0;
  for (size_t i = 0; i < n; ++i) {
    sizes[i] = static_cast<int>(vec[i].size());
    if (vec[i].size() > 0 && vec[i].data()) {
      std::memcpy(data + offset, vec[i].data(), vec[i].size());
      offset += vec[i].size();
    }
  }

  result.data = data;
  result.sizes = sizes;
  result.count = static_cast<int>(n);
  return result;
}

struct go_job2p {
  std::shared_ptr<coinbase::mpc::data_transport_interface_t> transport;
  std::unique_ptr<job_2p_t> job;
  std::vector<cbmpc_role_id> roles;
};

struct go_jobmp {
  std::shared_ptr<coinbase::mpc::data_transport_interface_t> transport;
  std::unique_ptr<job_mp_t> job;
  std::vector<cbmpc_role_id> roles;
};

}  // namespace

extern "C" {

int cbmpc_agree_random_2p(cbmpc_job2p *j, int bitlen, cmem_t *out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  buf_t result;
  error_t rv = coinbase::mpc::agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}

int cbmpc_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  buf_t result;
  error_t rv = coinbase::mpc::multi_agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}

int cbmpc_weak_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  buf_t result;
  error_t rv = coinbase::mpc::weak_multi_agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}

int cbmpc_multi_pairwise_agree_random(cbmpc_jobmp *j, int bitlen, cmems_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  std::vector<buf_t> result;
  error_t rv = coinbase::mpc::multi_pairwise_agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    return rv;
  }
  *out = alloc_and_copy_vector(result);
  return 0;
}

// Helper function to find ecurve_t by NID
static inline coinbase::crypto::ecurve_t find_curve_by_nid(int nid) {
  return coinbase::crypto::ecurve_t::find(nid);
}

// ECDSA 2P DKG
int cbmpc_ecdsa2p_dkg(cbmpc_job2p *j, int curve_nid, cbmpc_ecdsa2p_key **key_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key_out) return E_BADARG;

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  auto key = std::make_unique<coinbase::mpc::ecdsa2pc::key_t>();
  error_t rv = coinbase::mpc::ecdsa2pc::dkg(*wrapper->job, curve, *key);
  if (rv != SUCCESS) return rv;

  auto key_wrapper = new cbmpc_ecdsa2p_key;
  key_wrapper->opaque = key.release();
  *key_out = key_wrapper;
  return 0;
}

// ECDSA 2P Refresh
int cbmpc_ecdsa2p_refresh(cbmpc_job2p *j, const cbmpc_ecdsa2p_key *key_in, cbmpc_ecdsa2p_key **key_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key_in || !key_in->opaque || !key_out) return E_BADARG;

  const auto *old_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key_in->opaque);

  auto new_key = std::make_unique<coinbase::mpc::ecdsa2pc::key_t>();
  error_t rv = coinbase::mpc::ecdsa2pc::refresh(*wrapper->job, *old_key, *new_key);
  if (rv != SUCCESS) return rv;

  auto key_wrapper = new cbmpc_ecdsa2p_key;
  key_wrapper->opaque = new_key.release();
  *key_out = key_wrapper;
  return 0;
}

// ECDSA 2P Sign
int cbmpc_ecdsa2p_sign(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmem_t msg, cmem_t *sid_out, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque ||
      !msg.data || msg.size <= 0 || !sid_out || !sig_out) return E_BADARG;

  const auto *signing_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);

  // Create mutable sid
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  // Sign
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  error_t rv = coinbase::mpc::ecdsa2pc::sign(*wrapper->job, sid, *signing_key, msg_mem, signature);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  if (!sig_out->data && signature.size() > 0) {
    coinbase::secure_bzero(sid_out->data, sid_out->size);
    coinbase::cgo_free(sid_out->data);
    sid_out->data = nullptr;
    sid_out->size = 0;
    return E_BADARG;
  }

  return 0;
}

// ECDSA 2P Sign Batch
int cbmpc_ecdsa2p_sign_batch(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmems_t msgs, cmem_t *sid_out, cmems_t *sigs_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque || !sid_out || !sigs_out) return E_BADARG;
  if (msgs.count <= 0 || !msgs.data || !msgs.sizes) return E_BADARG;

  const auto *signing_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);

  // Create mutable sid
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  // Convert cmems_t to std::vector<mem_t>
  std::vector<mem_t> msg_vec;
  msg_vec.reserve(msgs.count);
  size_t offset = 0;
  for (int i = 0; i < msgs.count; ++i) {
    int size = msgs.sizes[i];
    if (size > 0) {
      msg_vec.emplace_back(msgs.data + offset, size);
      offset += size;
    } else {
      msg_vec.emplace_back(nullptr, 0);
    }
  }

  // Sign batch
  std::vector<buf_t> signatures;
  error_t rv = coinbase::mpc::ecdsa2pc::sign_batch(*wrapper->job, sid, *signing_key, msg_vec, signatures);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  *sigs_out = alloc_and_copy_vector(signatures);
  // Note: sigs_out->data can be nullptr if all signatures are empty (total_size=0)
  // This is normal for P2, so we don't check for allocation failure here

  return 0;
}

// ECDSA 2P Sign with Global Abort
int cbmpc_ecdsa2p_sign_with_global_abort(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmem_t msg, cmem_t *sid_out, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque ||
      !msg.data || msg.size <= 0 || !sid_out || !sig_out) return E_BADARG;

  const auto *signing_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);

  // Create mutable sid
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  // Sign with global abort
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  error_t rv = coinbase::mpc::ecdsa2pc::sign_with_global_abort(*wrapper->job, sid, *signing_key, msg_mem, signature);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  if (!sig_out->data && signature.size() > 0) {
    coinbase::secure_bzero(sid_out->data, sid_out->size);
    coinbase::cgo_free(sid_out->data);
    sid_out->data = nullptr;
    sid_out->size = 0;
    return E_BADARG;
  }

  return 0;
}

// ECDSA 2P Sign with Global Abort Batch
int cbmpc_ecdsa2p_sign_with_global_abort_batch(cbmpc_job2p *j, cmem_t sid_in, const cbmpc_ecdsa2p_key *key, cmems_t msgs, cmem_t *sid_out, cmems_t *sigs_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque || !sid_out || !sigs_out) return E_BADARG;
  if (msgs.count <= 0 || !msgs.data || !msgs.sizes) return E_BADARG;

  const auto *signing_key = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);

  // Create mutable sid
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  // Convert cmems_t to std::vector<mem_t>
  std::vector<mem_t> msg_vec;
  msg_vec.reserve(msgs.count);
  size_t offset = 0;
  for (int i = 0; i < msgs.count; ++i) {
    int size = msgs.sizes[i];
    if (size > 0) {
      msg_vec.emplace_back(msgs.data + offset, size);
      offset += size;
    } else {
      msg_vec.emplace_back(nullptr, 0);
    }
  }

  // Sign batch with global abort
  std::vector<buf_t> signatures;
  error_t rv = coinbase::mpc::ecdsa2pc::sign_with_global_abort_batch(*wrapper->job, sid, *signing_key, msg_vec, signatures);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  *sigs_out = alloc_and_copy_vector(signatures);
  // Note: sigs_out->data can be nullptr if all signatures are empty (total_size=0)
  // This is normal for P2, so we don't check for allocation failure here

  return 0;
}

}  // extern "C"
