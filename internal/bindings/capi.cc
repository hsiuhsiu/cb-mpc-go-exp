#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
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

extern "C" {
int cbmpc_go_send(void *ctx, cbmpc_role_id to, uint8_t *ptr, size_t len);
int cbmpc_go_receive(void *ctx, cbmpc_role_id from, cmem_t *out);
int cbmpc_go_receive_all(void *ctx, cbmpc_role_id *from, size_t n, cmem_t *outs);
cbmpc_go_transport cbmpc_make_go_transport(void *ctx);
}

namespace {

using coinbase::buf_t;
using coinbase::mem_t;
using coinbase::mpc::job_2p_t;
using coinbase::mpc::job_mp_t;
using coinbase::mpc::party_idx_t;
using coinbase::mpc::party_t;

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

static inline void free_cmem_view(cmem_t &view) {
  if (view.data && view.size > 0) {
    coinbase::secure_bzero(view.data, view.size);
  }
  coinbase::cgo_free(view.data);
  view.data = nullptr;
  view.size = 0;
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

  // Allocate contiguous buffer for all data
  uint8_t *data = nullptr;
  if (total_size > 0) {
    data = static_cast<uint8_t *>(std::malloc(total_size));
    if (!data) {
      result.data = nullptr;
      result.sizes = nullptr;
      result.count = 0;
      return result;
    }
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

class go_transport_base : public coinbase::mpc::data_transport_interface_t {
 public:
  go_transport_base(const cbmpc_go_transport *table, std::vector<cbmpc_role_id> mapping)
      : vtable(*table), index_to_role(std::move(mapping)) {}

  error_t send(party_idx_t receiver, mem_t msg) override {
    if (!vtable.send) return E_NET_GENERAL;
    auto role = role_for(receiver);
    if (!role.has_value()) return E_BADARG;
    size_t len = static_cast<size_t>(msg.size);
    uint8_t *ptr = reinterpret_cast<uint8_t *>(msg.data);
    int rc = vtable.send(vtable.ctx, *role, ptr, len);
    return rc == 0 ? SUCCESS : E_NET_GENERAL;
  }

  error_t receive(party_idx_t sender, buf_t &msg) override {
    if (!vtable.receive) return E_NET_GENERAL;
    auto role = role_for(sender);
    if (!role.has_value()) return E_BADARG;
    cmem_t out{};
    int rc = vtable.receive(vtable.ctx, *role, &out);
    if (rc != 0) {
      free_cmem_view(out);
      return E_NET_GENERAL;
    }
    msg = buf_t(out.data, out.size);
    free_cmem_view(out);
    return SUCCESS;
  }

 protected:
  const cbmpc_go_transport vtable;
  const std::vector<cbmpc_role_id> index_to_role;

  std::optional<cbmpc_role_id> role_for(party_idx_t idx) const {
    if (idx < 0) return std::nullopt;
    auto uidx = static_cast<size_t>(idx);
    if (uidx >= index_to_role.size()) return std::nullopt;
    return index_to_role[uidx];
  }
};

class go_transport_2p : public go_transport_base {
 public:
  using go_transport_base::go_transport_base;

  error_t receive_all(const std::vector<party_idx_t> &senders, std::vector<buf_t> &message) override {
    if (senders.size() != 1) return E_BADARG;
    message.resize(1);
    return go_transport_base::receive(senders[0], message[0]);
  }
};

class go_transport_mp : public go_transport_base {
 public:
  using go_transport_base::go_transport_base;

  error_t receive_all(const std::vector<party_idx_t> &senders, std::vector<buf_t> &message) override {
    if (!vtable.receive_all) return E_NET_GENERAL;
    size_t n = senders.size();
    message.resize(n);
    if (n == 0) return SUCCESS;
    std::vector<cbmpc_role_id> roles(n);
    for (size_t i = 0; i < n; ++i) {
      auto role = role_for(senders[i]);
      if (!role.has_value()) return E_BADARG;
      roles[i] = *role;
    }
    std::vector<cmem_t> outs(n);
    int rc = vtable.receive_all(vtable.ctx, roles.data(), n, outs.data());
    if (rc != 0) {
      for (auto &view : outs) free_cmem_view(view);
      return E_NET_GENERAL;
    }
    for (size_t i = 0; i < n; ++i) {
      message[i] = buf_t(outs[i].data, outs[i].size);
      free_cmem_view(outs[i]);
    }
    return SUCCESS;
  }
};

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

cbmpc_go_transport cbmpc_make_go_transport(void *ctx) {
  cbmpc_go_transport t;
  t.ctx = ctx;
  t.send = cbmpc_go_send;
  t.receive = cbmpc_go_receive;
  t.receive_all = cbmpc_go_receive_all;
  return t;
}

cbmpc_job2p *cbmpc_job2p_new(const cbmpc_go_transport *t,
                             cbmpc_role_id self,
                             const char *const *names) {
  if (!t || !names) return nullptr;
  if (self > 1) return nullptr;
  if (!names[0] || !names[1]) return nullptr;

  std::vector<cbmpc_role_id> roles{0, 1};
  auto transport = std::make_shared<go_transport_2p>(t, roles);

  party_t party = (self == 0) ? party_t::p1 : party_t::p2;
  auto job = std::make_unique<job_2p_t>(party, std::string(names[0]), std::string(names[1]), transport);

  auto wrapper = std::make_unique<go_job2p>();
  wrapper->transport = std::move(transport);
  wrapper->job = std::move(job);
  wrapper->roles = std::move(roles);
  return reinterpret_cast<cbmpc_job2p *>(wrapper.release());
}

void cbmpc_job2p_free(cbmpc_job2p *j) {
  delete reinterpret_cast<go_job2p *>(j);
}

cbmpc_jobmp *cbmpc_jobmp_new(const cbmpc_go_transport *t,
                             cbmpc_role_id self,
                             size_t n_parties,
                             const char *const *names) {
  if (!t || !names) return nullptr;
  if (n_parties < 2) return nullptr;
  if (self >= n_parties) return nullptr;

  std::vector<cbmpc_role_id> roles(n_parties);
  std::vector<coinbase::crypto::pname_t> pname;
  pname.reserve(n_parties);
  for (size_t i = 0; i < n_parties; ++i) {
    if (!names[i]) return nullptr;
    roles[i] = static_cast<cbmpc_role_id>(i);
    pname.emplace_back(names[i]);
  }

  auto transport = std::make_shared<go_transport_mp>(t, roles);
  auto job = std::make_unique<job_mp_t>(static_cast<int>(self), pname, transport);

  auto wrapper = std::make_unique<go_jobmp>();
  wrapper->transport = std::move(transport);
  wrapper->job = std::move(job);
  wrapper->roles = std::move(roles);
  return reinterpret_cast<cbmpc_jobmp *>(wrapper.release());
}

void cbmpc_jobmp_free(cbmpc_jobmp *j) {
  delete reinterpret_cast<go_jobmp *>(j);
}

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

// Helper to serialize ECDSA 2P key manually
static buf_t serialize_ecdsa2p_key(const coinbase::mpc::ecdsa2pc::key_t& key) {
  // Calculate size
  coinbase::converter_t size_calc(true);
  uint32_t role_val = static_cast<uint32_t>(key.role);
  int curve_nid = key.curve.get_openssl_code();
  buf_t Q_bin = key.Q.to_compressed_bin();
  buf_t x_share_bin = key.x_share.to_bin();
  buf_t c_key_bin = key.c_key.to_bin();

  // Make a mutable copy of paillier for serialization
  coinbase::crypto::paillier_t paillier_copy = key.paillier;

  size_calc.convert(role_val);
  size_calc.convert(curve_nid);
  size_calc.convert(Q_bin);
  size_calc.convert(x_share_bin);
  size_calc.convert(c_key_bin);
  paillier_copy.convert(size_calc);

  if (size_calc.is_error()) return buf_t();

  // Allocate and write
  buf_t result(size_calc.get_size());
  coinbase::converter_t writer(result.data());
  paillier_copy = key.paillier;

  writer.convert(role_val);
  writer.convert(curve_nid);
  writer.convert(Q_bin);
  writer.convert(x_share_bin);
  writer.convert(c_key_bin);
  paillier_copy.convert(writer);

  if (writer.is_error()) return buf_t();
  return result;
}

// Helper to deserialize ECDSA 2P key manually
static error_t deserialize_ecdsa2p_key(mem_t serialized, coinbase::mpc::ecdsa2pc::key_t& key) {
  coinbase::converter_t reader(serialized);

  uint32_t role_val = 0;
  int curve_nid = 0;
  buf_t Q_bin, x_share_bin, c_key_bin;

  reader.convert(role_val);
  reader.convert(curve_nid);
  reader.convert(Q_bin);
  reader.convert(x_share_bin);
  reader.convert(c_key_bin);
  key.paillier.convert(reader);

  if (reader.is_error()) return E_CRYPTO;

  key.role = static_cast<party_t>(role_val);
  key.curve = find_curve_by_nid(curve_nid);
  if (!key.curve) return E_BADARG;

  if (key.Q.from_bin(key.curve, mem_t(Q_bin.data(), Q_bin.size())) != SUCCESS) return E_CRYPTO;
  key.x_share = bn_t::from_bin(mem_t(x_share_bin.data(), x_share_bin.size()));
  key.c_key = bn_t::from_bin(mem_t(c_key_bin.data(), c_key_bin.size()));

  return SUCCESS;
}

// ECDSA 2P key serialization
int cbmpc_ecdsa2p_key_serialize(const void *key, cmem_t *out) {
  if (!key || !out) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key);
  buf_t serialized = serialize_ecdsa2p_key(*k);
  if (serialized.size() == 0) return E_CRYPTO;

  *out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));
  if (!out->data && serialized.size() > 0) return E_BADARG;

  return 0;
}

// ECDSA 2P key deserialization
int cbmpc_ecdsa2p_key_deserialize(cmem_t serialized, void **key) {
  if (!serialized.data || serialized.size <= 0 || !key) return E_BADARG;

  auto k = std::make_unique<coinbase::mpc::ecdsa2pc::key_t>();
  error_t rv = deserialize_ecdsa2p_key(mem_t(serialized.data, serialized.size), *k);
  if (rv != SUCCESS) return rv;

  *key = k.release();
  return 0;
}

// Free ECDSA 2P key
void cbmpc_ecdsa2p_key_free(void *key) {
  delete static_cast<coinbase::mpc::ecdsa2pc::key_t *>(key);
}

// Get public key from serialized ECDSA 2P key
int cbmpc_ecdsa2p_key_get_public_key(cmem_t serialized_key, cmem_t *out) {
  if (!serialized_key.data || serialized_key.size <= 0 || !out) return E_BADARG;

  coinbase::mpc::ecdsa2pc::key_t key;
  error_t rv = deserialize_ecdsa2p_key(mem_t(serialized_key.data, serialized_key.size), key);
  if (rv != SUCCESS) return rv;

  buf_t pub_key_buf = key.Q.to_compressed_bin();
  *out = alloc_and_copy(pub_key_buf.data(), static_cast<size_t>(pub_key_buf.size()));
  if (!out->data && pub_key_buf.size() > 0) return E_BADARG;

  return 0;
}

// Get curve NID from serialized ECDSA 2P key
int cbmpc_ecdsa2p_key_get_curve_nid(cmem_t serialized_key, int *nid) {
  if (!serialized_key.data || serialized_key.size <= 0 || !nid) return E_BADARG;

  coinbase::mpc::ecdsa2pc::key_t key;
  error_t rv = deserialize_ecdsa2p_key(mem_t(serialized_key.data, serialized_key.size), key);
  if (rv != SUCCESS) return rv;

  *nid = key.curve.get_openssl_code();
  return 0;
}

// ECDSA 2P DKG
int cbmpc_ecdsa2p_dkg(cbmpc_job2p *j, int curve_nid, cmem_t *key_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key_out) return E_BADARG;

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  coinbase::mpc::ecdsa2pc::key_t key;
  error_t rv = coinbase::mpc::ecdsa2pc::dkg(*wrapper->job, curve, key);
  if (rv != SUCCESS) {
    return rv;
  }

  // Serialize key
  return cbmpc_ecdsa2p_key_serialize(&key, key_out);
}

// ECDSA 2P Refresh
int cbmpc_ecdsa2p_refresh(cbmpc_job2p *j, cmem_t key_in, cmem_t *key_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key_in.data || key_in.size <= 0 || !key_out) return E_BADARG;

  // Deserialize input key
  coinbase::mpc::ecdsa2pc::key_t old_key;
  error_t rv = deserialize_ecdsa2p_key(mem_t(key_in.data, key_in.size), old_key);
  if (rv != SUCCESS) return rv;

  // Refresh
  coinbase::mpc::ecdsa2pc::key_t new_key;
  rv = coinbase::mpc::ecdsa2pc::refresh(*wrapper->job, old_key, new_key);
  if (rv != SUCCESS) return rv;

  // Serialize new key
  buf_t serialized = serialize_ecdsa2p_key(new_key);
  if (serialized.size() == 0) return E_CRYPTO;

  *key_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));
  if (!key_out->data && serialized.size() > 0) return E_BADARG;

  return 0;
}

// ECDSA 2P Sign
int cbmpc_ecdsa2p_sign(cbmpc_job2p *j, cmem_t sid_in, cmem_t key, cmem_t msg, cmem_t *sid_out, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key.data || key.size <= 0 ||
      !msg.data || msg.size <= 0 || !sid_out || !sig_out) return E_BADARG;

  // Deserialize key
  coinbase::mpc::ecdsa2pc::key_t signing_key;
  error_t rv = deserialize_ecdsa2p_key(mem_t(key.data, key.size), signing_key);
  if (rv != SUCCESS) return rv;

  // Create mutable sid
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  // Sign
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  rv = coinbase::mpc::ecdsa2pc::sign(*wrapper->job, sid, signing_key, msg_mem, signature);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  if (!sig_out->data && signature.size() > 0) {
    free_cmem_view(*sid_out);
    return E_BADARG;
  }

  return 0;
}

}  // extern "C"
