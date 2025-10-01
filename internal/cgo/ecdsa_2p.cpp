#include "ecdsa_2p.h"

#include <memory>
#include <vector>
#include <cstring>

#include <cbmpc/core/buf.h>
#include <cbmpc/crypto/base.h>
#include <cbmpc/protocol/ecdsa_2p.h>
#include <cbmpc/protocol/mpc_job_session.h>

using namespace coinbase;
using namespace coinbase::mpc;

// Internal key wrapper
struct ecdsa_2p_key_internal {
    ecdsa2pc::key_t cpp_key;
};

extern "C" {

int ecdsa_2p_keygen(session_t* session, int curve_code, ecdsa_2p_key_t* key) {
    if (!session || !key) return PARAM_ERROR_CODE;

    try {
        // Create job_2p_ref for the C++ job
        job_2p_ref cJob;

        // Create party names (P1, P2)
        const char* party_names[] = {"P1", "P2"};

        // Create job_2p using the existing function
        job_2p_ref* jobPtr = new_job_2p(session->data_transport_callbacks,
                                       session->session_data,
                                       session->my_index,
                                       party_names, 2);
        if (!jobPtr) return MEMORY_ERROR_CODE;

        // Cast to job_2p_t for C++ use
        job_2p_t* cppJob = static_cast<job_2p_t*>(jobPtr->opaque);
        if (!cppJob) {
            free_job_2p(jobPtr);
            return PARAM_ERROR_CODE;
        }

        // Find curve
        ecurve_t curve = ecurve_t::find(curve_code);

        // Create key
        auto* internal_key = new ecdsa_2p_key_internal();

        // Run DKG
        error_t err = ecdsa2pc::dkg(*cppJob, curve, internal_key->cpp_key);
        if (err) {
            delete internal_key;
            free_job_2p(jobPtr);
            return static_cast<int>(err);
        }

        key->opaque = internal_key;
        free_job_2p(jobPtr);
        return SUCCESS_CODE;

    } catch (...) {
        return UNKNOWN_ERROR_CODE;
    }
}

int ecdsa_2p_sign(session_t* session, ecdsa_2p_key_t* key, const uint8_t* message_hash, size_t hash_len, uint8_t** signature, size_t* sig_len) {
    if (!session || !key || !key->opaque || !message_hash || !signature || !sig_len) {
        return PARAM_ERROR_CODE;
    }

    try {
        // Create party names (P1, P2)
        const char* party_names[] = {"P1", "P2"};

        // Create job_2p using the existing function
        job_2p_ref* jobPtr = new_job_2p(session->data_transport_callbacks,
                                       session->session_data,
                                       session->my_index,
                                       party_names, 2);
        if (!jobPtr) return MEMORY_ERROR_CODE;

        // Cast to job_2p_t for C++ use
        job_2p_t* cppJob = static_cast<job_2p_t*>(jobPtr->opaque);
        if (!cppJob) {
            free_job_2p(jobPtr);
            return PARAM_ERROR_CODE;
        }

        auto* internal_key = static_cast<ecdsa_2p_key_internal*>(key->opaque);

        // Create message vector for batch signing
        std::vector<mem_t> messages;
        messages.emplace_back(message_hash, hash_len);

        // Create session ID (empty for now)
        buf_t sid;

        // Sign using batch API with global abort
        std::vector<buf_t> signatures;
        error_t err = ecdsa2pc::sign_with_global_abort_batch(*cppJob, sid, internal_key->cpp_key, messages, signatures);
        if (err) {
            free_job_2p(jobPtr);
            return static_cast<int>(err);
        }

        if (signatures.empty()) {
            free_job_2p(jobPtr);
            return UNKNOWN_ERROR_CODE;
        }

        // Allocate output buffer
        *sig_len = signatures[0].size();
        *signature = static_cast<uint8_t*>(malloc(*sig_len));
        if (!*signature) {
            free_job_2p(jobPtr);
            return MEMORY_ERROR_CODE;
        }

        memcpy(*signature, signatures[0].data(), *sig_len);
        free_job_2p(jobPtr);
        return SUCCESS_CODE;

    } catch (...) {
        return UNKNOWN_ERROR_CODE;
    }
}

int ecdsa_2p_refresh(session_t* session, ecdsa_2p_key_t* old_key, ecdsa_2p_key_t* new_key) {
    if (!session || !old_key || !old_key->opaque || !new_key) {
        return PARAM_ERROR_CODE;
    }

    try {
        // Create party names (P1, P2)
        const char* party_names[] = {"P1", "P2"};

        // Create job_2p using the existing function
        job_2p_ref* jobPtr = new_job_2p(session->data_transport_callbacks,
                                       session->session_data,
                                       session->my_index,
                                       party_names, 2);
        if (!jobPtr) return MEMORY_ERROR_CODE;

        // Cast to job_2p_t for C++ use
        job_2p_t* cppJob = static_cast<job_2p_t*>(jobPtr->opaque);
        if (!cppJob) {
            free_job_2p(jobPtr);
            return PARAM_ERROR_CODE;
        }

        auto* old_internal = static_cast<ecdsa_2p_key_internal*>(old_key->opaque);
        auto* new_internal = new ecdsa_2p_key_internal();

        // Refresh key
        error_t err = ecdsa2pc::refresh(*cppJob, old_internal->cpp_key, new_internal->cpp_key);
        if (err) {
            delete new_internal;
            free_job_2p(jobPtr);
            return static_cast<int>(err);
        }

        new_key->opaque = new_internal;
        free_job_2p(jobPtr);
        return SUCCESS_CODE;

    } catch (...) {
        return UNKNOWN_ERROR_CODE;
    }
}

int ecdsa_2p_key_get_role(ecdsa_2p_key_t* key) {
    if (!key || !key->opaque) return -1;

    auto* internal_key = static_cast<ecdsa_2p_key_internal*>(key->opaque);
    return static_cast<int>(internal_key->cpp_key.role);
}

int ecdsa_2p_key_get_curve_code(ecdsa_2p_key_t* key) {
    if (!key || !key->opaque) return -1;

    auto* internal_key = static_cast<ecdsa_2p_key_internal*>(key->opaque);
    return internal_key->cpp_key.curve.get_openssl_code();
}

int ecdsa_2p_key_get_public_key(ecdsa_2p_key_t* key, uint8_t** pubkey, size_t* pubkey_len) {
    if (!key || !key->opaque || !pubkey || !pubkey_len) return PARAM_ERROR_CODE;

    try {
        auto* internal_key = static_cast<ecdsa_2p_key_internal*>(key->opaque);

        // Serialize public key point Q - use default to_bin() without arguments
        buf_t pubkey_buf = internal_key->cpp_key.Q.to_bin();

        *pubkey_len = pubkey_buf.size();
        *pubkey = static_cast<uint8_t*>(malloc(*pubkey_len));
        if (!*pubkey) return MEMORY_ERROR_CODE;

        memcpy(*pubkey, pubkey_buf.data(), *pubkey_len);
        return SUCCESS_CODE;

    } catch (...) {
        return UNKNOWN_ERROR_CODE;
    }
}

int ecdsa_2p_key_get_private_share(ecdsa_2p_key_t* key, uint8_t** share, size_t* share_len) {
    if (!key || !key->opaque || !share || !share_len) return PARAM_ERROR_CODE;

    try {
        auto* internal_key = static_cast<ecdsa_2p_key_internal*>(key->opaque);

        // Serialize private key share with proper size calculation
        int bin_size = std::max(internal_key->cpp_key.x_share.get_bin_size(), internal_key->cpp_key.curve.order().get_bin_size());
        buf_t share_buf = internal_key->cpp_key.x_share.to_bin(bin_size);

        *share_len = share_buf.size();
        *share = static_cast<uint8_t*>(malloc(*share_len));
        if (!*share) return MEMORY_ERROR_CODE;

        memcpy(*share, share_buf.data(), *share_len);
        return SUCCESS_CODE;

    } catch (...) {
        return UNKNOWN_ERROR_CODE;
    }
}

void ecdsa_2p_key_free(ecdsa_2p_key_t* key) {
    if (key && key->opaque) {
        delete static_cast<ecdsa_2p_key_internal*>(key->opaque);
        key->opaque = nullptr;
    }
}

void ecdsa_2p_free_buffer(uint8_t* buffer) {
    if (buffer) {
        free(buffer);
    }
}

} // extern "C"