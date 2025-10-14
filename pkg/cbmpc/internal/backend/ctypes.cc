#include "ctypes.h"

#include <cstring>
#include <memory>
#include <utility>

#include "cbmpc/core/buf.h"
#include "cbmpc/core/convert.h"
#include "cbmpc/core/error.h"
#include "cbmpc/crypto/base_ecc.h"
#include "cbmpc/protocol/ecdsa_2p.h"
#include "cbmpc/protocol/ecdsa_mp.h"

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

// Helper to serialize ECDSA MP key manually (similar to ECDSA 2P)
static buf_t serialize_ecdsamp_key(const coinbase::mpc::ecdsampc::key_t& key) {
  // Calculate size
  coinbase::converter_t size_calc(true);
  int curve_nid = key.curve.get_openssl_code();
  buf_t Q_bin = key.Q.to_compressed_bin();
  buf_t x_share_bin = key.x_share.to_bin();

  // Serialize Qis map (party_name -> ecc_point_t)
  uint32_t qis_count = static_cast<uint32_t>(key.Qis.size());
  std::vector<buf_t> qis_names;
  std::vector<buf_t> qis_points;
  for (const auto& [name, point] : key.Qis) {
    qis_names.push_back(buf_t(mem_t(reinterpret_cast<const uint8_t*>(name.data()), name.size())));
    qis_points.push_back(point.to_compressed_bin());
  }

  // Serialize party_name as a buffer
  buf_t party_name_buf(mem_t(reinterpret_cast<const uint8_t*>(key.party_name.data()), key.party_name.size()));

  size_calc.convert(curve_nid);
  size_calc.convert(Q_bin);
  size_calc.convert(x_share_bin);
  size_calc.convert(party_name_buf);
  size_calc.convert(qis_count);
  for (size_t i = 0; i < qis_names.size(); i++) {
    buf_t name_copy = qis_names[i];
    size_calc.convert(name_copy);
  }
  for (size_t i = 0; i < qis_points.size(); i++) {
    buf_t point_copy = qis_points[i];
    size_calc.convert(point_copy);
  }

  if (size_calc.is_error()) return buf_t();

  // Allocate and write
  buf_t result(size_calc.get_size());
  coinbase::converter_t writer(result.data());

  // Recreate party_name_buf for writer
  buf_t party_name_buf_writer(mem_t(reinterpret_cast<const uint8_t*>(key.party_name.data()), key.party_name.size()));

  writer.convert(curve_nid);
  writer.convert(Q_bin);
  writer.convert(x_share_bin);
  writer.convert(party_name_buf_writer);
  writer.convert(qis_count);
  for (size_t i = 0; i < qis_names.size(); i++) {
    buf_t name_copy = qis_names[i];
    writer.convert(name_copy);
  }
  for (size_t i = 0; i < qis_points.size(); i++) {
    buf_t point_copy = qis_points[i];
    writer.convert(point_copy);
  }

  if (writer.is_error()) return buf_t();
  return result;
}

// Helper to deserialize ECDSA MP key manually
static error_t deserialize_ecdsamp_key(mem_t serialized, coinbase::mpc::ecdsampc::key_t& key) {
  coinbase::converter_t reader(serialized);

  int curve_nid = 0;
  buf_t Q_bin, x_share_bin, party_name_buf;
  uint32_t qis_count = 0;

  reader.convert(curve_nid);
  reader.convert(Q_bin);
  reader.convert(x_share_bin);
  reader.convert(party_name_buf);
  reader.convert(qis_count);

  if (reader.is_error()) return E_CRYPTO;

  key.curve = find_curve_by_nid(curve_nid);
  if (!key.curve) return E_BADARG;

  if (key.Q.from_bin(key.curve, mem_t(Q_bin.data(), Q_bin.size())) != SUCCESS) return E_CRYPTO;
  key.x_share = coinbase::crypto::bn_t::from_bin(mem_t(x_share_bin.data(), x_share_bin.size()));

  // Convert party_name_buf to string
  key.party_name = coinbase::crypto::pname_t(reinterpret_cast<const char*>(party_name_buf.data()), party_name_buf.size());

  // Deserialize Qis map
  key.Qis.clear();
  std::vector<coinbase::crypto::pname_t> names;
  for (uint32_t i = 0; i < qis_count; i++) {
    buf_t name_buf;
    reader.convert(name_buf);
    if (reader.is_error()) return E_CRYPTO;

    coinbase::crypto::pname_t pname(reinterpret_cast<const char*>(name_buf.data()), name_buf.size());
    names.push_back(pname);
    key.Qis[pname] = coinbase::crypto::ecc_point_t();
  }

  for (size_t i = 0; i < names.size(); i++) {
    buf_t point_buf;
    reader.convert(point_buf);
    if (reader.is_error()) return E_CRYPTO;

    if (key.Qis[names[i]].from_bin(key.curve, mem_t(point_buf.data(), point_buf.size())) != SUCCESS) return E_CRYPTO;
  }

  if (reader.is_error()) return E_CRYPTO;
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

// Get curve enum from ECDSA 2P key (converts NID to Curve enum)
int cbmpc_ecdsa2p_key_get_curve(const cbmpc_ecdsa2p_key *key, int *curve) {
  if (!key || !key->opaque || !curve) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsa2pc::key_t *>(key->opaque);
  int nid = k->curve.get_openssl_code();
  *curve = nid_to_curve_enum(nid);
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

// ============================================================
// ECDSA MP key management functions
// ============================================================

// Free ECDSA MP key
void cbmpc_ecdsamp_key_free(cbmpc_ecdsamp_key *key) {
  if (!key) return;
  delete static_cast<coinbase::mpc::ecdsampc::key_t *>(key->opaque);
  delete key;
}

// Get public key from ECDSA MP key
int cbmpc_ecdsamp_key_get_public_key(const cbmpc_ecdsamp_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);
  buf_t pub_key_buf = k->Q.to_compressed_bin();
  *out = alloc_and_copy(pub_key_buf.data(), static_cast<size_t>(pub_key_buf.size()));
  if (!out->data && pub_key_buf.size() > 0) return E_BADARG;

  return 0;
}

// Get curve enum from ECDSA MP key (converts NID to Curve enum)
int cbmpc_ecdsamp_key_get_curve(const cbmpc_ecdsamp_key *key, int *curve) {
  if (!key || !key->opaque || !curve) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);
  int nid = k->curve.get_openssl_code();
  *curve = nid_to_curve_enum(nid);
  return 0;
}

// Serialize an ECDSA MP key
int cbmpc_ecdsamp_key_serialize(const cbmpc_ecdsamp_key *key, cmem_t *out) {
  if (!key || !key->opaque || !out) return E_BADARG;

  const auto *k = static_cast<const coinbase::mpc::ecdsampc::key_t *>(key->opaque);
  buf_t serialized = serialize_ecdsamp_key(*k);
  if (serialized.size() == 0) return E_CRYPTO;

  *out = alloc_and_copy(serialized.data(), static_cast<size_t>(serialized.size()));
  if (!out->data && serialized.size() > 0) return E_BADARG;

  return 0;
}

// Deserialize an ECDSA MP key
int cbmpc_ecdsamp_key_deserialize(cmem_t serialized, cbmpc_ecdsamp_key **key) {
  if (!serialized.data || serialized.size <= 0 || !key) return E_BADARG;

  auto k = std::make_unique<coinbase::mpc::ecdsampc::key_t>();
  error_t rv = deserialize_ecdsamp_key(mem_t(serialized.data, serialized.size), *k);
  if (rv != SUCCESS) return rv;

  auto wrapper = new cbmpc_ecdsamp_key;
  wrapper->opaque = k.release();
  *key = wrapper;
  return 0;
}

}  // extern "C"
