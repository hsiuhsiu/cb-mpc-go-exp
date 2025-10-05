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
#include "cbmpc/core/error.h"
#include "cbmpc/protocol/agree_random.h"
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

thread_local std::vector<std::pair<void *, size_t>> g_scratch;

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
  g_scratch.emplace_back(p, n);
  cmem_t view{};
  view.data = p;
  view.size = static_cast<int>(n);
  return view;
}

static inline void scratch_free_all() {
  for (auto &kv : g_scratch) {
    if (kv.first && kv.second) {
      coinbase::secure_bzero(static_cast<uint8_t *>(kv.first), static_cast<int>(kv.second));
    }
    std::free(kv.first);
  }
  g_scratch.clear();
}

static inline void free_cmem_view(cmem_t &view) {
  if (view.data && view.size > 0) {
    coinbase::secure_bzero(view.data, view.size);
  }
  coinbase::cgo_free(view.data);
  view.data = nullptr;
  view.size = 0;
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

void cbmpc_last_call_scratch_free(void) { scratch_free_all(); }

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
  scratch_free_all();
  buf_t result;
  error_t rv = coinbase::mpc::agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    scratch_free_all();
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}

int cbmpc_multi_agree_random(cbmpc_jobmp *j, int bitlen, cmem_t *out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !out) return E_BADARG;
  scratch_free_all();
  buf_t result;
  error_t rv = coinbase::mpc::multi_agree_random(*wrapper->job, bitlen, result);
  if (rv != SUCCESS) {
    scratch_free_all();
    return rv;
  }
  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  return 0;
}

}  // extern "C"
