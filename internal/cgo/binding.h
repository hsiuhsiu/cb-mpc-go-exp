#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <cbmpc/core/cmem.h>
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

// Common error codes
#define SUCCESS_CODE 0
#define UNKNOWN_ERROR_CODE 1
#define PARAM_ERROR_CODE 2
#define MEMORY_ERROR_CODE 3
#define INVALID_STATE_CODE 4

// Session structure for MPC operations
typedef struct session_t {
    void* session_data;
    int my_index;
    int party_count;
    data_transport_callbacks_t* data_transport_callbacks;
} session_t;

#ifdef __cplusplus
}
#endif