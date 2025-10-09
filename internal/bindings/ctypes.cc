#include "ctypes.h"

#include <cstring>
#include <memory>
#include <utility>

#include "cbmpc/core/buf.h"
#include "cbmpc/core/convert.h"
#include "cbmpc/core/error.h"
#include "cbmpc/crypto/base_ecc.h"
#include "cbmpc/protocol/ecdsa_2p.h"

namespace {

using coinbase::buf_t;
using coinbase::mem_t;
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

}  // namespace

extern "C" {

// Free ECDSA 2P key
void cbmpc_ecdsa2p_key_free(cbmpc_ecdsa2p_key *key) {
  if (!key) return;
  delete static_cast<coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);
  delete key;
}

// Get public key from ECDSA 2P key
int cbmpc_ecdsa2p_key_get_public_key(const cbmpc_ecdsa2p_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);
  buf_t pub_key_buf = k->Q.to_compressed_bin();
  *out = alloc_and_copy(pub_key_buf.data(), static_cast<size_t>(pub_key_buf.size()));
  if (!out->data && pub_key_buf.size() > 0) return E_BADARG;

  return 0;
}

// Get curve NID from ECDSA 2P key
int cbmpc_ecdsa2p_key_get_curve_nid(const cbmpc_ecdsa2p_key *key, int *nid) {
  if (!key || !key->opaque || !nid) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);
  *nid = k->curve.get_openssl_code();
  return 0;
}

// Serialize an ECDSA 2P key
int cbmpc_ecdsa2p_key_serialize(const cbmpc_ecdsa2p_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);
  buf_t serialized = serialize_ecdsa2p_key(*k);
  if (serialized.size() == 0) return E_CRYPTO;

  *out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));
  if (!out->data && serialized.size() > 0) return E_BADARG;

  return 0;
}

// Deserialize an ECDSA 2P key
int cbmpc_ecdsa2p_key_deserialize(cmem_t serialized, cbmpc_ecdsa2p_key **key) {
  if (!serialized.data || serialized.size <= 0 || !key) return E_BADARG;

  auto k = std::make_unique<coinbase::mpc::ecdsa2pc::key_t>();
  error_t rv = deserialize_ecdsa2p_key(mem_t(serialized.data, serialized.size), *k);
  if (rv != SUCCESS) return rv;

  auto wrapper = new cbmpc_ecdsa2p_key;
  wrapper->opaque = k.release();
  *key = wrapper;
  return 0;
}

}  // extern "C"
