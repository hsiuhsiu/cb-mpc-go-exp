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
#include "cbmpc/crypto/base_pki.h"
#include "cbmpc/crypto/elgamal.h"
#include "cbmpc/protocol/agree_random.h"
#include "cbmpc/protocol/ecdsa_2p.h"
#include "cbmpc/protocol/ecdsa_mp.h"
#include "cbmpc/protocol/mpc_job.h"
#include "cbmpc/protocol/pve.h"
#include "cbmpc/protocol/pve_base.h"
#include "cbmpc/protocol/schnorr_2p.h"
#include "cbmpc/protocol/schnorr_mp.h"
#include "cbmpc/zk/zk_ec.h"
#include "cbmpc/zk/zk_elgamal_com.h"

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

// Curve enum values matching backend.Curve in Go
enum {
  CURVE_UNKNOWN = 0,
  CURVE_P256 = 1,
  CURVE_P384 = 2,
  CURVE_P521 = 3,
  CURVE_SECP256K1 = 4,
  CURVE_ED25519 = 5
};

// Helper function to convert NID to Curve enum
static inline int nid_to_curve_enum(int nid) {
  switch (nid) {
    case 415:  // NID_X9_62_prime256v1
      return CURVE_P256;
    case 715:  // NID_secp384r1
      return CURVE_P384;
    case 716:  // NID_secp521r1
      return CURVE_P521;
    case 714:  // NID_secp256k1
      return CURVE_SECP256K1;
    case 1087: // NID_ED25519
      return CURVE_ED25519;
    default:
      return CURVE_UNKNOWN;
  }
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

// ============================================================
// ECDSA MP protocols
// ============================================================

// ECDSA MP DKG
int cbmpc_ecdsamp_dkg(cbmpc_jobmp *j, int curve_nid, cbmpc_ecdsamp_key **key_out, cmem_t *sid_out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !key_out || !sid_out) return E_BADARG;

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  auto key = std::make_unique<coinbase::mpc::ecdsampc::key_t>();
  buf_t sid;
  error_t rv = coinbase::mpc::ecdsampc::dkg(*wrapper->job, curve, *key, sid);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  auto key_wrapper = new cbmpc_ecdsamp_key;
  key_wrapper->opaque = key.release();
  *key_out = key_wrapper;
  return 0;
}

// ECDSA MP Refresh
int cbmpc_ecdsamp_refresh(cbmpc_jobmp *j, cmem_t sid_in, const cbmpc_ecdsamp_key *key_in, cmem_t *sid_out, cbmpc_ecdsamp_key **key_out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !key_in || !key_in->opaque || !sid_out || !key_out) return E_BADARG;

  // Copy the old key so we can pass a mutable reference to refresh
  auto old_key_copy = *static_cast<const coinbase::mpc::ecdsampc::key_t *>(key_in->opaque);

  // Create mutable sid buffer (can be empty to generate new one)
  buf_t sid;
  if (sid_in.data && sid_in.size > 0) {
    sid = buf_t(sid_in.data, sid_in.size);
  }

  auto new_key = std::make_unique<coinbase::mpc::ecdsampc::key_t>();
  error_t rv = coinbase::mpc::ecdsampc::refresh(*wrapper->job, sid, old_key_copy, *new_key);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sid_out = alloc_and_copy(sid.data(), static_cast<size_t>(sid.size()));
  if (!sid_out->data && sid.size() > 0) return E_BADARG;

  auto key_wrapper = new cbmpc_ecdsamp_key;
  key_wrapper->opaque = new_key.release();
  *key_out = key_wrapper;
  return 0;
}

// ECDSA MP Sign
int cbmpc_ecdsamp_sign(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmem_t msg, int sig_receiver, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque ||
      !msg.data || msg.size <= 0 || !sig_out) return E_BADARG;

  // Copy the key so we can pass a mutable reference to sign
  auto signing_key_copy = *static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);

  // Sign
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  error_t rv = coinbase::mpc::ecdsampc::sign(*wrapper->job, signing_key_copy, msg_mem, sig_receiver, signature);
  if (rv != SUCCESS) return rv;

  // Copy output (signature may be empty for non-receiver parties)
  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  return 0;
}

// PVE Encrypt
int cbmpc_pve_encrypt(cmem_t ek_bytes, cmem_t label, int curve_nid, cmem_t x_bytes, cmem_t *pve_ct_out) {
  if (!ek_bytes.data || ek_bytes.size <= 0 || !label.data || label.size <= 0 || !x_bytes.data || x_bytes.size <= 0 || !pve_ct_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Deserialize scalar x from bytes
  coinbase::crypto::bn_t x = coinbase::crypto::bn_t::from_bin(mem_t(x_bytes.data, x_bytes.size));

  // Create PVE ciphertext using FFI KEM policy
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::kem_pve_base_pke<coinbase::crypto::kem_policy_ffi_t>());

  // Construct ffi_kem_ek_t from the EK bytes
  // ffi_kem_ek_t is just a buf_t
  coinbase::crypto::ffi_kem_ek_t ek(ek_bytes.data, static_cast<size_t>(ek_bytes.size));

  pve.encrypt(&ek, mem_t(label.data, label.size), curve, x);

  // Serialize the PVE ciphertext
  buf_t pve_serialized = coinbase::ser(pve);
  *pve_ct_out = alloc_and_copy(pve_serialized.data(), static_cast<size_t>(pve_serialized.size()));

  return 0;
}

// PVE Verify
int cbmpc_pve_verify(cmem_t ek_bytes, cmem_t pve_ct, cmem_t Q_bytes, cmem_t label) {
  if (!ek_bytes.data || ek_bytes.size <= 0 || !pve_ct.data || pve_ct.size <= 0 || !Q_bytes.data || Q_bytes.size <= 0 || !label.data || label.size <= 0) {
    return E_BADARG;
  }

  // Deserialize PVE ciphertext
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::kem_pve_base_pke<coinbase::crypto::kem_policy_ffi_t>());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), pve);
  if (rv != SUCCESS) return rv;

  // Get curve from the stored Q point
  const auto& stored_Q = pve.get_Q();
  auto curve = stored_Q.get_curve();

  // Deserialize Q from bytes
  coinbase::crypto::ecc_point_t Q;
  rv = Q.from_oct(curve, mem_t(Q_bytes.data, Q_bytes.size));
  if (rv != SUCCESS) return rv;

  // Construct ffi_kem_ek_t from the EK bytes
  coinbase::crypto::ffi_kem_ek_t ek(ek_bytes.data, static_cast<size_t>(ek_bytes.size));

  // Verify
  rv = pve.verify(&ek, Q, mem_t(label.data, label.size));
  return rv;
}

// PVE Decrypt
int cbmpc_pve_decrypt(const void *dk_handle, cmem_t ek_bytes, cmem_t pve_ct, cmem_t label, int curve_nid, cmem_t *x_bytes_out) {
  if (!dk_handle || !ek_bytes.data || ek_bytes.size <= 0 || !pve_ct.data || pve_ct.size <= 0 || !label.data || label.size <= 0 || !x_bytes_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Deserialize PVE ciphertext
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::kem_pve_base_pke<coinbase::crypto::kem_policy_ffi_t>());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), pve);
  if (rv != SUCCESS) return rv;

  // The dk_handle is an opaque Go pointer that will be passed to FFI callbacks.
  // We need to wrap it in an ffi_kem_dk_t struct.
  coinbase::crypto::ffi_kem_dk_t dk(const_cast<void*>(dk_handle));

  // Construct ffi_kem_ek_t from the EK bytes
  coinbase::crypto::ffi_kem_ek_t ek(ek_bytes.data, static_cast<size_t>(ek_bytes.size));

  // Decrypt
  coinbase::crypto::bn_t x;
  rv = pve.decrypt(&dk, &ek, mem_t(label.data, label.size), curve, x);
  if (rv != SUCCESS) return rv;

  // Serialize x to bytes
  buf_t x_serialized = x.to_bin();
  *x_bytes_out = alloc_and_copy(x_serialized.data(), static_cast<size_t>(x_serialized.size()));

  return 0;
}

// PVE Get Q
int cbmpc_pve_get_Q(cmem_t pve_ct, cmem_t *Q_bytes_out) {
  if (!pve_ct.data || pve_ct.size <= 0 || !Q_bytes_out) {
    return E_BADARG;
  }

  // Deserialize PVE ciphertext (using unified PKE as placeholder since we only need Q)
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::pve_base_pke_unified());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), pve);
  if (rv != SUCCESS) return rv;

  // Get Q and serialize to bytes
  const auto& Q = pve.get_Q();
  buf_t Q_serialized = Q.to_oct();
  *Q_bytes_out = alloc_and_copy(Q_serialized.data(), static_cast<size_t>(Q_serialized.size()));

  return 0;
}

// PVE Get Label
int cbmpc_pve_get_label(cmem_t pve_ct, cmem_t *label_out) {
  if (!pve_ct.data || pve_ct.size <= 0 || !label_out) {
    return E_BADARG;
  }

  // Deserialize PVE ciphertext (using unified PKE as placeholder since we only need label)
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::pve_base_pke_unified());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), pve);
  if (rv != SUCCESS) return rv;

  // Get label
  const auto& label = pve.get_Label();
  *label_out = alloc_and_copy(label.data(), static_cast<size_t>(label.size()));

  return 0;
}

// Scalar operations - wrapping bn_t
int cbmpc_scalar_from_bytes(cmem_t bytes, cmem_t *scalar_out) {
  if (!bytes.data || bytes.size <= 0 || !scalar_out) {
    return E_BADARG;
  }

  // Create bn_t from bytes
  auto bn = std::make_unique<coinbase::crypto::bn_t>();
  *bn = coinbase::crypto::bn_t::from_bin(mem_t(bytes.data, bytes.size));

  // Return pointer to bn_t as cmem_t (opaque handle)
  scalar_out->data = reinterpret_cast<uint8_t*>(bn.release());
  scalar_out->size = 0; // Size of 0 indicates this is an opaque pointer
  return 0;
}

int cbmpc_scalar_from_string(const char *str, cmem_t *scalar_out) {
  if (!str || !scalar_out) {
    return E_BADARG;
  }

  // Create bn_t from decimal string
  auto bn = std::make_unique<coinbase::crypto::bn_t>();
  *bn = coinbase::crypto::bn_t::from_string(str);

  // Return pointer to bn_t as cmem_t (opaque handle)
  scalar_out->data = reinterpret_cast<uint8_t*>(bn.release());
  scalar_out->size = 0; // Size of 0 indicates this is an opaque pointer
  return 0;
}

int cbmpc_scalar_to_bytes(cmem_t scalar, cmem_t *bytes_out) {
  if (!scalar.data || !bytes_out) {
    return E_BADARG;
  }

  // Cast to bn_t pointer
  const auto* bn = reinterpret_cast<const coinbase::crypto::bn_t*>(scalar.data);

  // Serialize to bytes
  buf_t bytes = bn->to_bin();
  *bytes_out = alloc_and_copy(bytes.data(), static_cast<size_t>(bytes.size()));

  return 0;
}

void cbmpc_scalar_free(cmem_t scalar) {
  if (scalar.data) {
    auto* bn = reinterpret_cast<coinbase::crypto::bn_t*>(scalar.data);
    delete bn;
  }
}

// ECC Point operations - wrapping ecc_point_t
int cbmpc_ecc_point_from_bytes(int curve_nid, cmem_t bytes, cbmpc_ecc_point *point_out) {
  if (!bytes.data || bytes.size <= 0 || !point_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Create ecc_point_t from compressed bytes
  auto point = std::make_unique<coinbase::crypto::ecc_point_t>();
  error_t rv = point->from_oct(curve, mem_t(bytes.data, bytes.size));
  if (rv != SUCCESS) return rv;

  *point_out = reinterpret_cast<cbmpc_ecc_point>(point.release());
  return 0;
}

int cbmpc_ecc_point_to_bytes(cbmpc_ecc_point point, cmem_t *bytes_out) {
  if (!point || !bytes_out) {
    return E_BADARG;
  }

  const auto* ecc_point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(point);

  // Serialize to compressed format
  buf_t bytes = ecc_point->to_oct();
  *bytes_out = alloc_and_copy(bytes.data(), static_cast<size_t>(bytes.size()));

  return 0;
}

void cbmpc_ecc_point_free(cbmpc_ecc_point point) {
  if (point) {
    auto* ecc_point = reinterpret_cast<coinbase::crypto::ecc_point_t*>(point);
    delete ecc_point;
  }
}

int cbmpc_ecc_point_get_curve(cbmpc_ecc_point point) {
  if (!point) return CURVE_UNKNOWN;
  const auto* ecc_point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(point);
  auto curve = ecc_point->get_curve();
  if (!curve) return CURVE_UNKNOWN;
  int nid = curve.get_openssl_code();
  return nid_to_curve_enum(nid);
}

// Curve operations
int cbmpc_curve_random_scalar(int curve_nid, cmem_t *scalar_out) {
  if (!scalar_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Generate random scalar using curve's get_random_value
  coinbase::crypto::bn_t random_scalar = curve.get_random_value();

  // Serialize to bytes (big-endian)
  buf_t scalar_bytes = random_scalar.to_bin();
  *scalar_out = alloc_and_copy(scalar_bytes.data(), static_cast<size_t>(scalar_bytes.size()));

  return 0;
}

int cbmpc_curve_get_generator(int curve_nid, cbmpc_ecc_point *generator_out) {
  if (!generator_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Get generator point from curve
  const auto& gen = curve.generator();

  // Create a copy of the generator point
  auto point_copy = std::make_unique<coinbase::crypto::ecc_point_t>(gen);

  *generator_out = reinterpret_cast<cbmpc_ecc_point>(point_copy.release());
  return 0;
}

int cbmpc_curve_mul_generator(int curve_nid, cmem_t scalar_bytes, cbmpc_ecc_point *point_out) {
  if (!scalar_bytes.data || scalar_bytes.size <= 0 || !point_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Deserialize scalar from bytes
  coinbase::crypto::bn_t scalar = coinbase::crypto::bn_t::from_bin(mem_t(scalar_bytes.data, scalar_bytes.size));

  // Multiply generator by scalar: result = scalar * G
  coinbase::crypto::ecc_point_t result = curve.mul_to_generator(scalar);

  // Return as new point (caller must free)
  auto point_ptr = std::make_unique<coinbase::crypto::ecc_point_t>(std::move(result));
  *point_out = reinterpret_cast<cbmpc_ecc_point>(point_ptr.release());

  return 0;
}

int cbmpc_ecc_point_mul(cbmpc_ecc_point point, cmem_t scalar_bytes, cbmpc_ecc_point *result_out) {
  if (!point || !scalar_bytes.data || scalar_bytes.size <= 0 || !result_out) {
    return E_BADARG;
  }

  const auto* ecc_point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(point);

  // Deserialize scalar from bytes
  coinbase::crypto::bn_t scalar = coinbase::crypto::bn_t::from_bin(mem_t(scalar_bytes.data, scalar_bytes.size));

  // Multiply point by scalar: result = scalar * point
  // Using the operator* overload from base_ecc.h
  coinbase::crypto::ecc_point_t result = scalar * (*ecc_point);

  // Return as new point (caller must free)
  auto result_ptr = std::make_unique<coinbase::crypto::ecc_point_t>(std::move(result));
  *result_out = reinterpret_cast<cbmpc_ecc_point>(result_ptr.release());

  return 0;
}

// PVE operations using ecc_point_t directly
int cbmpc_pve_get_Q_point(cmem_t pve_ct, cbmpc_ecc_point *Q_point_out) {
  if (!pve_ct.data || pve_ct.size <= 0 || !Q_point_out) {
    return E_BADARG;
  }

  // Deserialize PVE ciphertext (using unified PKE as placeholder since we only need Q)
  auto pve_ptr = std::make_unique<coinbase::mpc::ec_pve_t>(coinbase::mpc::pve_base_pke_unified());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), *pve_ptr);
  if (rv != SUCCESS) return rv;

  // Get Q reference and create a new copy
  const auto& Q = pve_ptr->get_Q();
  auto point_copy = std::make_unique<coinbase::crypto::ecc_point_t>(Q);

  *Q_point_out = reinterpret_cast<cbmpc_ecc_point>(point_copy.release());
  return 0;
}

int cbmpc_pve_verify_with_point(cmem_t ek_bytes, cmem_t pve_ct, cbmpc_ecc_point Q_point, cmem_t label) {
  if (!ek_bytes.data || ek_bytes.size <= 0 || !pve_ct.data || pve_ct.size <= 0 || !Q_point || !label.data || label.size <= 0) {
    return E_BADARG;
  }

  // Deserialize PVE ciphertext
  coinbase::mpc::ec_pve_t pve(coinbase::mpc::kem_pve_base_pke<coinbase::crypto::kem_policy_ffi_t>());
  error_t rv = coinbase::deser(mem_t(pve_ct.data, pve_ct.size), pve);
  if (rv != SUCCESS) return rv;

  // Cast to ecc_point_t
  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);

  // Construct ffi_kem_ek_t from the EK bytes
  coinbase::crypto::ffi_kem_ek_t ek(ek_bytes.data, static_cast<size_t>(ek_bytes.size));

  // Verify using the ecc_point_t directly
  rv = pve.verify(&ek, *Q, mem_t(label.data, label.size));
  return rv;
}

// =====================
// Thread-local KEM handle for FFI policy context
// =====================

static thread_local const void* g_cbmpc_kem_tls = nullptr;

void cbmpc_set_kem_tls(const void *handle) {
  g_cbmpc_kem_tls = handle;
}

void cbmpc_clear_kem_tls(void) {
  g_cbmpc_kem_tls = nullptr;
}

const void *cbmpc_get_kem_tls(void) {
  return g_cbmpc_kem_tls;
}

// =====================
// EC ElGamal Commitment Operations
// =====================

// Create EC ElGamal commitment from two points
int cbmpc_ec_elgamal_commitment_new(cbmpc_ecc_point point_L, cbmpc_ecc_point point_R, cbmpc_ec_elgamal_commitment *commitment_out) {
  if (!point_L || !point_R || !commitment_out) {
    return E_BADARG;
  }

  const auto* L = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(point_L);
  const auto* R = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(point_R);

  // Create commitment from two points
  auto commitment = std::make_unique<coinbase::crypto::ec_elgamal_commitment_t>(*L, *R);

  *commitment_out = reinterpret_cast<cbmpc_ec_elgamal_commitment>(commitment.release());
  return 0;
}

// Serialize EC ElGamal commitment to bytes
int cbmpc_ec_elgamal_commitment_to_bytes(cbmpc_ec_elgamal_commitment commitment, cmem_t *bytes_out) {
  if (!commitment || !bytes_out) {
    return E_BADARG;
  }

  const auto* elg_commitment = reinterpret_cast<const coinbase::crypto::ec_elgamal_commitment_t*>(commitment);

  // Serialize using converter_t
  buf_t serialized = coinbase::ser(*elg_commitment);
  *bytes_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));

  return 0;
}

// Deserialize bytes into EC ElGamal commitment
int cbmpc_ec_elgamal_commitment_from_bytes(int curve_nid, cmem_t bytes, cbmpc_ec_elgamal_commitment *commitment_out) {
  if (!bytes.data || bytes.size <= 0 || !commitment_out) {
    return E_BADARG;
  }

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  auto commitment = std::make_unique<coinbase::crypto::ec_elgamal_commitment_t>();

  // Deserialize using converter_t
  error_t rv = coinbase::deser(mem_t(bytes.data, bytes.size), *commitment);
  if (rv != SUCCESS) return rv;

  // Verify curve consistency
  rv = commitment->check_curve(curve);
  if (rv != SUCCESS) return rv;

  *commitment_out = reinterpret_cast<cbmpc_ec_elgamal_commitment>(commitment.release());
  return 0;
}

// Get the L point from commitment (returns a NEW point)
int cbmpc_ec_elgamal_commitment_get_L(cbmpc_ec_elgamal_commitment commitment, cbmpc_ecc_point *point_L_out) {
  if (!commitment || !point_L_out) {
    return E_BADARG;
  }

  const auto* elg_commitment = reinterpret_cast<const coinbase::crypto::ec_elgamal_commitment_t*>(commitment);

  // Create a copy of the L point
  auto point_copy = std::make_unique<coinbase::crypto::ecc_point_t>(elg_commitment->L);

  *point_L_out = reinterpret_cast<cbmpc_ecc_point>(point_copy.release());
  return 0;
}

// Get the R point from commitment (returns a NEW point)
int cbmpc_ec_elgamal_commitment_get_R(cbmpc_ec_elgamal_commitment commitment, cbmpc_ecc_point *point_R_out) {
  if (!commitment || !point_R_out) {
    return E_BADARG;
  }

  const auto* elg_commitment = reinterpret_cast<const coinbase::crypto::ec_elgamal_commitment_t*>(commitment);

  // Create a copy of the R point
  auto point_copy = std::make_unique<coinbase::crypto::ecc_point_t>(elg_commitment->R);

  *point_R_out = reinterpret_cast<cbmpc_ecc_point>(point_copy.release());
  return 0;
}

// Free an EC ElGamal commitment
void cbmpc_ec_elgamal_commitment_free(cbmpc_ec_elgamal_commitment commitment) {
  if (commitment) {
    auto* elg_commitment = reinterpret_cast<coinbase::crypto::ec_elgamal_commitment_t*>(commitment);
    delete elg_commitment;
  }
}

// Create EC ElGamal commitment using make_commitment
int cbmpc_ec_elgamal_commitment_make(cbmpc_ecc_point P, cmem_t m, cmem_t r, cbmpc_ec_elgamal_commitment *commitment_out) {
  if (!P || !m.data || m.size <= 0 || !r.data || r.size <= 0 || !commitment_out) {
    return E_BADARG;
  }

  const auto* P_point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(P);

  // Deserialize scalars m and r from bytes
  coinbase::crypto::bn_t m_bn = coinbase::crypto::bn_t::from_bin(mem_t(m.data, m.size));
  coinbase::crypto::bn_t r_bn = coinbase::crypto::bn_t::from_bin(mem_t(r.data, r.size));

  // Create commitment using make_commitment: UV = (r*G, m*P + r*G)
  auto commitment = std::make_unique<coinbase::crypto::ec_elgamal_commitment_t>(
    coinbase::crypto::ec_elgamal_commitment_t::make_commitment(*P_point, m_bn, r_bn)
  );

  *commitment_out = reinterpret_cast<cbmpc_ec_elgamal_commitment>(commitment.release());
  return 0;
}

// =====================
// ZK Proof Operations - UC_DL
// =====================

// UC_DL Prove
int cbmpc_uc_dl_prove(cbmpc_ecc_point Q_point, cmem_t w, cmem_t session_id, uint64_t aux, cmem_t *proof_out) {
  if (!Q_point || !w.data || w.size <= 0 || !session_id.data || session_id.size <= 0 || !proof_out) {
    return E_BADARG;
  }

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);

  // Deserialize scalar w from bytes
  coinbase::crypto::bn_t w_bn = coinbase::crypto::bn_t::from_bin(mem_t(w.data, w.size));

  // Create proof
  coinbase::zk::uc_dl_t proof;
  proof.prove(*Q, w_bn, mem_t(session_id.data, session_id.size), aux);

  // Serialize proof to bytes and return
  buf_t serialized = coinbase::ser(proof);
  *proof_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));

  return 0;
}

// UC_DL Verify
int cbmpc_uc_dl_verify(cmem_t proof_bytes, cbmpc_ecc_point Q_point, cmem_t session_id, uint64_t aux) {
  if (!proof_bytes.data || proof_bytes.size <= 0 || !Q_point || !session_id.data || session_id.size <= 0) {
    return E_BADARG;
  }

  // Deserialize proof from bytes
  coinbase::zk::uc_dl_t proof;
  error_t rv = coinbase::deser(mem_t(proof_bytes.data, proof_bytes.size), proof);
  if (rv != SUCCESS) return rv;

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);

  // Verify
  rv = proof.verify(*Q, mem_t(session_id.data, session_id.size), aux);
  return rv;
}

// =====================
// ZK Proof Operations - UC_Batch_DL
// =====================

// UC_Batch_DL Prove
int cbmpc_uc_batch_dl_prove(cbmpc_ecc_point *Q_points, int Q_count, cmems_t w_scalars, cmem_t session_id, uint64_t aux, cmem_t *proof_out) {
  if (!Q_points || Q_count <= 0 ||
      !w_scalars.data || w_scalars.count <= 0 || !w_scalars.sizes ||
      !session_id.data || session_id.size <= 0 || !proof_out) {
    return E_BADARG;
  }

  // Check counts match
  if (Q_count != w_scalars.count) {
    return E_BADARG;
  }

  // Convert Q_points from cbmpc_ecc_point* to std::vector<ecc_point_t>
  std::vector<coinbase::crypto::ecc_point_t> Q_vec;
  Q_vec.reserve(Q_count);
  for (int i = 0; i < Q_count; ++i) {
    if (!Q_points[i]) return E_BADARG;
    const auto* point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_points[i]);
    Q_vec.push_back(*point);
  }

  // Convert w_scalars from cmems_t to std::vector<bn_t>
  std::vector<coinbase::crypto::bn_t> w_vec;
  w_vec.reserve(w_scalars.count);
  size_t w_offset = 0;
  for (int i = 0; i < w_scalars.count; ++i) {
    int size = w_scalars.sizes[i];
    if (size <= 0) return E_BADARG;

    // Deserialize bn_t from bytes
    coinbase::crypto::bn_t scalar = coinbase::crypto::bn_t::from_bin(mem_t(w_scalars.data + w_offset, size));
    w_vec.push_back(std::move(scalar));
    w_offset += size;
  }

  // Create proof
  coinbase::zk::uc_batch_dl_t proof;
  proof.prove(Q_vec, w_vec, mem_t(session_id.data, session_id.size), aux);

  // Serialize proof to bytes and return
  buf_t serialized = coinbase::ser(proof);
  *proof_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));

  return 0;
}

// UC_Batch_DL Verify
int cbmpc_uc_batch_dl_verify(cmem_t proof_bytes, cbmpc_ecc_point *Q_points, int Q_count, cmem_t session_id, uint64_t aux) {
  if (!proof_bytes.data || proof_bytes.size <= 0 ||
      !Q_points || Q_count <= 0 ||
      !session_id.data || session_id.size <= 0) {
    return E_BADARG;
  }

  // Deserialize proof from bytes
  coinbase::zk::uc_batch_dl_t proof;
  error_t rv = coinbase::deser(mem_t(proof_bytes.data, proof_bytes.size), proof);
  if (rv != SUCCESS) return rv;

  // Convert Q_points from cbmpc_ecc_point* to std::vector<ecc_point_t>
  std::vector<coinbase::crypto::ecc_point_t> Q_vec;
  Q_vec.reserve(Q_count);
  for (int i = 0; i < Q_count; ++i) {
    if (!Q_points[i]) return E_BADARG;
    const auto* point = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_points[i]);
    Q_vec.push_back(*point);
  }

  // Verify
  rv = proof.verify(Q_vec, mem_t(session_id.data, session_id.size), aux);
  return rv;
}

// =====================
// ZK Proof Operations - DH
// =====================

// DH Prove
int cbmpc_dh_prove(cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ecc_point B_point, cmem_t w, cmem_t session_id, uint64_t aux, cmem_t *proof_out) {
  if (!Q_point || !A_point || !B_point ||
      !w.data || w.size <= 0 ||
      !session_id.data || session_id.size <= 0 || !proof_out) {
    return E_BADARG;
  }

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);
  const auto* A = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(A_point);
  const auto* B = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(B_point);

  // Deserialize scalar w from bytes
  coinbase::crypto::bn_t w_bn = coinbase::crypto::bn_t::from_bin(mem_t(w.data, w.size));

  // Create proof
  coinbase::zk::dh_t proof;
  proof.prove(*Q, *A, *B, w_bn, mem_t(session_id.data, session_id.size), aux);

  // Serialize proof to bytes and return
  buf_t serialized = coinbase::ser(proof);
  *proof_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));

  return 0;
}

// DH Verify
int cbmpc_dh_verify(cmem_t proof_bytes, cbmpc_ecc_point Q_point, cbmpc_ecc_point A_point, cbmpc_ecc_point B_point, cmem_t session_id, uint64_t aux) {
  if (!proof_bytes.data || proof_bytes.size <= 0 ||
      !Q_point || !A_point || !B_point ||
      !session_id.data || session_id.size <= 0) {
    return E_BADARG;
  }

  // Deserialize proof from bytes
  coinbase::zk::dh_t proof;
  error_t rv = coinbase::deser(mem_t(proof_bytes.data, proof_bytes.size), proof);
  if (rv != SUCCESS) return rv;

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);
  const auto* A = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(A_point);
  const auto* B = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(B_point);

  // Verify
  rv = proof.verify(*Q, *A, *B, mem_t(session_id.data, session_id.size), aux);
  return rv;
}

// ============================================================
// Schnorr 2P protocols
// ============================================================

// Helper function to convert variant enum to C++ variant_e
static inline coinbase::mpc::schnorr2p::variant_e int_to_schnorr_variant(int variant) {
  switch (variant) {
    case CBMPC_SCHNORR_VARIANT_EDDSA:
      return coinbase::mpc::schnorr2p::variant_e::EdDSA;
    case CBMPC_SCHNORR_VARIANT_BIP340:
      return coinbase::mpc::schnorr2p::variant_e::BIP340;
    default:
      return coinbase::mpc::schnorr2p::variant_e::EdDSA;  // Default fallback
  }
}

// Schnorr 2P DKG
int cbmpc_schnorr2p_dkg(cbmpc_job2p *j, int curve_nid, cbmpc_schnorr2p_key **key_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key_out) return E_BADARG;

  auto curve = find_curve_by_nid(curve_nid);
  if (!curve) return E_BADARG;

  // Schnorr 2P uses eckey::key_share_2p_t
  auto key = std::make_unique<coinbase::mpc::eckey::key_share_2p_t>();
  buf_t sid;
  error_t rv = coinbase::mpc::eckey::key_share_2p_t::dkg(*wrapper->job, curve, *key, sid);
  if (rv != SUCCESS) return rv;

  auto key_wrapper = new cbmpc_schnorr2p_key;
  key_wrapper->opaque = key.release();
  *key_out = key_wrapper;
  return 0;
}

// Free a Schnorr 2P key
void cbmpc_schnorr2p_key_free(cbmpc_schnorr2p_key *key) {
  if (key && key->opaque) {
    auto* cpp_key = static_cast<coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);
    delete cpp_key;
    delete key;
  }
}

// Serialize a Schnorr 2P key (eckey::key_share_2p_t)
int cbmpc_schnorr2p_key_serialize(const cbmpc_schnorr2p_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto* cpp_key = static_cast<const coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);

  // Manual serialization: role (uint32), curve_nid (int), Q (bytes), x_share (bytes)
  uint32_t role_val = static_cast<uint32_t>(cpp_key->role);
  int curve_nid = cpp_key->curve.get_openssl_code();
  buf_t Q_bin = cpp_key->Q.to_oct();
  buf_t x_share_bin = cpp_key->x_share.to_bin();

  // Calculate size
  coinbase::converter_t size_calc(true);
  size_calc.convert(role_val);
  size_calc.convert(curve_nid);
  size_calc.convert(Q_bin);
  size_calc.convert(x_share_bin);
  if (size_calc.is_error()) return E_CRYPTO;

  // Allocate and write
  buf_t result(size_calc.get_size());
  coinbase::converter_t writer(result.data());
  writer.convert(role_val);
  writer.convert(curve_nid);
  writer.convert(Q_bin);
  writer.convert(x_share_bin);
  if (writer.is_error()) return E_CRYPTO;

  *out = alloc_and_copy(result.data(), static_cast<size_t>(result.size()));
  if (!out->data && result.size() > 0) return E_BADARG;

  return 0;
}

// Deserialize a Schnorr 2P key (eckey::key_share_2p_t)
int cbmpc_schnorr2p_key_deserialize(cmem_t serialized, cbmpc_schnorr2p_key **key_out) {
  if (!serialized.data || serialized.size <= 0 || !key_out) return E_BADARG;

  auto key = std::make_unique<coinbase::mpc::eckey::key_share_2p_t>();

  // Manual deserialization
  coinbase::converter_t reader(mem_t(serialized.data, serialized.size));
  uint32_t role_val;
  int curve_nid;
  buf_t Q_bin, x_share_bin;

  reader.convert(role_val);
  reader.convert(curve_nid);
  reader.convert(Q_bin);
  reader.convert(x_share_bin);
  if (reader.is_error()) return E_CRYPTO;

  // Reconstruct key
  key->role = static_cast<coinbase::mpc::party_t>(role_val);
  key->curve = find_curve_by_nid(curve_nid);
  if (!key->curve) return E_BADARG;

  error_t rv = key->Q.from_oct(key->curve, mem_t(Q_bin.data(), Q_bin.size()));
  if (rv != SUCCESS) return rv;

  key->x_share = coinbase::crypto::bn_t::from_bin(mem_t(x_share_bin.data(), x_share_bin.size()));

  auto key_wrapper = new cbmpc_schnorr2p_key;
  key_wrapper->opaque = key.release();
  *key_out = key_wrapper;
  return 0;
}

// Get public key from Schnorr 2P key
int cbmpc_schnorr2p_key_get_public_key(const cbmpc_schnorr2p_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto* cpp_key = static_cast<const coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);

  // Serialize public key point Q to compressed format
  buf_t Q_bytes = cpp_key->Q.to_oct();
  *out = alloc_and_copy(Q_bytes.data(), static_cast<size_t>(Q_bytes.size()));

  return 0;
}

// Get curve from Schnorr 2P key
int cbmpc_schnorr2p_key_get_curve(const cbmpc_schnorr2p_key *key, int *curve_nid_out) {
  if (!key || !key->opaque || !curve_nid_out) return E_BADARG;

  const auto* cpp_key = static_cast<const coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);

  // Get OpenSSL NID from curve
  *curve_nid_out = cpp_key->curve.get_openssl_code();

  return 0;
}

// Schnorr 2P Sign
int cbmpc_schnorr2p_sign(cbmpc_job2p *j, const cbmpc_schnorr2p_key *key, cmem_t msg, int variant, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque ||
      !msg.data || msg.size <= 0 || !sig_out) return E_BADARG;

  // Copy the key so we can pass a mutable reference to sign
  // (Schnorr 2P protocol may modify the key during signing)
  auto signing_key_copy = *static_cast<const coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);

  // Convert variant
  auto cpp_variant = int_to_schnorr_variant(variant);

  // Sign
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  error_t rv = coinbase::mpc::schnorr2p::sign(*wrapper->job, signing_key_copy, msg_mem, signature, cpp_variant);
  if (rv != SUCCESS) return rv;

  // Copy output
  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  if (!sig_out->data && signature.size() > 0) {
    return E_BADARG;
  }

  return 0;
}

// Schnorr 2P Sign Batch
int cbmpc_schnorr2p_sign_batch(cbmpc_job2p *j, const cbmpc_schnorr2p_key *key, cmems_t msgs, int variant, cmems_t *sigs_out) {
  auto wrapper = reinterpret_cast<go_job2p *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque || !sigs_out) return E_BADARG;
  if (msgs.count <= 0 || !msgs.data || !msgs.sizes) return E_BADARG;

  // Copy the key so we can pass a mutable reference to sign_batch
  // (Schnorr 2P protocol may modify the key during signing)
  auto signing_key_copy = *static_cast<const coinbase::mpc::eckey::key_share_2p_t*>(key->opaque);

  // Convert variant
  auto cpp_variant = int_to_schnorr_variant(variant);

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
  error_t rv = coinbase::mpc::schnorr2p::sign_batch(*wrapper->job, signing_key_copy, msg_vec, signatures, cpp_variant);
  if (rv != SUCCESS) return rv;

  // Copy outputs
  *sigs_out = alloc_and_copy_vector(signatures);
  // Note: sigs_out->data can be nullptr if all signatures are empty (total_size=0)
  // This is normal for P2, so we don't check for allocation failure here

  return 0;
}

// ============================================================
// Schnorr MP protocols
// ============================================================

// Helper function to convert variant enum to C++ variant_e for Schnorr MP
static inline coinbase::mpc::schnorrmp::variant_e int_to_schnorrmp_variant(int variant) {
  switch (variant) {
    case CBMPC_SCHNORR_VARIANT_EDDSA:
      return coinbase::mpc::schnorrmp::variant_e::EdDSA;
    case CBMPC_SCHNORR_VARIANT_BIP340:
      return coinbase::mpc::schnorrmp::variant_e::BIP340;
    default:
      return coinbase::mpc::schnorrmp::variant_e::EdDSA;  // Default fallback
  }
}

// Schnorr MP Sign
int cbmpc_schnorrmp_sign(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmem_t msg, int sig_receiver, int variant, cmem_t *sig_out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque ||
      !msg.data || msg.size <= 0 || !sig_out) return E_BADARG;

  // Copy the key so we can pass a mutable reference to sign
  auto signing_key_copy = *static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);

  // Convert variant
  auto cpp_variant = int_to_schnorrmp_variant(variant);

  // Sign
  buf_t signature;
  mem_t msg_mem(msg.data, msg.size);
  error_t rv = coinbase::mpc::schnorrmp::sign(*wrapper->job, signing_key_copy, msg_mem, sig_receiver, signature, cpp_variant);
  if (rv != SUCCESS) return rv;

  // Copy output (signature may be empty for non-receiver parties)
  *sig_out = alloc_and_copy(signature.data(), static_cast<size_t>(signature.size()));
  return 0;
}

// Schnorr MP Sign Batch
int cbmpc_schnorrmp_sign_batch(cbmpc_jobmp *j, const cbmpc_ecdsamp_key *key, cmems_t msgs, int sig_receiver, int variant, cmems_t *sigs_out) {
  auto wrapper = reinterpret_cast<go_jobmp *>(j);
  if (!wrapper || !wrapper->job || !key || !key->opaque || !sigs_out) return E_BADARG;
  if (msgs.count <= 0 || !msgs.data || !msgs.sizes) return E_BADARG;

  // Copy the key so we can pass a mutable reference to sign_batch
  auto signing_key_copy = *static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);

  // Convert variant
  auto cpp_variant = int_to_schnorrmp_variant(variant);

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
  error_t rv = coinbase::mpc::schnorrmp::sign_batch(*wrapper->job, signing_key_copy, msg_vec, sig_receiver, signatures, cpp_variant);
  if (rv != SUCCESS) return rv;

  // Copy outputs (signatures may be empty for non-receiver parties)
  *sigs_out = alloc_and_copy_vector(signatures);
  return 0;
}

// =====================
// ZK Proof Operations - UC_ElGamalCom
// =====================

// UC_ElGamalCom Prove
int cbmpc_uc_elgamal_com_prove(cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment UV_commitment, cmem_t x, cmem_t r, cmem_t session_id, uint64_t aux, cmem_t *proof_out) {
  if (!Q_point || !UV_commitment ||
      !x.data || x.size <= 0 ||
      !r.data || r.size <= 0 ||
      !session_id.data || session_id.size <= 0 || !proof_out) {
    return E_BADARG;
  }

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);
  const auto* UV = reinterpret_cast<const coinbase::crypto::ec_elgamal_commitment_t*>(UV_commitment);

  // Deserialize scalars x and r from bytes
  coinbase::crypto::bn_t x_bn = coinbase::crypto::bn_t::from_bin(mem_t(x.data, x.size));
  coinbase::crypto::bn_t r_bn = coinbase::crypto::bn_t::from_bin(mem_t(r.data, r.size));

  // Create proof
  coinbase::zk::uc_elgamal_com_t proof;
  proof.prove(*Q, *UV, x_bn, r_bn, mem_t(session_id.data, session_id.size), aux);

  // Serialize proof to bytes and return
  buf_t serialized = coinbase::ser(proof);
  *proof_out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));

  return 0;
}

// UC_ElGamalCom Verify
int cbmpc_uc_elgamal_com_verify(cmem_t proof_bytes, cbmpc_ecc_point Q_point, cbmpc_ec_elgamal_commitment UV_commitment, cmem_t session_id, uint64_t aux) {
  if (!proof_bytes.data || proof_bytes.size <= 0 ||
      !Q_point || !UV_commitment ||
      !session_id.data || session_id.size <= 0) {
    return E_BADARG;
  }

  // Deserialize proof from bytes
  coinbase::zk::uc_elgamal_com_t proof;
  error_t rv = coinbase::deser(mem_t(proof_bytes.data, proof_bytes.size), proof);
  if (rv != SUCCESS) return rv;

  const auto* Q = reinterpret_cast<const coinbase::crypto::ecc_point_t*>(Q_point);
  const auto* UV = reinterpret_cast<const coinbase::crypto::ec_elgamal_commitment_t*>(UV_commitment);

  // Verify
  rv = proof.verify(*Q, *UV, mem_t(session_id.data, session_id.size), aux);
  return rv;
}

}  // extern "C"
