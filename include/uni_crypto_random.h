// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

#pragma once


#ifdef __cplusplus
extern "C" {
#endif

//
// Includes
//

// stdlib
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// uni.crypto
#include "uni_crypto_export.h"



//
// Functions
//

UNI_CRYPTO_EXPORT bool uni_crypto_random_fill(uint8_t* data, size_t data_len);

#ifdef __cplusplus
} /* extern "C" */
#endif
