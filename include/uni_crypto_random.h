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

/**
 * @brief Fills a buffer with cryptographically secure random bytes from the backend DRBG.
 * @param data Output buffer (not NULL).
 * @param data_len Number of bytes to generate (any size; large requests are served in DRBG-sized chunks).
 * @return true on success; false for a NULL buffer, a zero length, or an entropy source / DRBG failure.
 */
UNI_CRYPTO_EXPORT bool uni_crypto_random_fill(uint8_t* data, size_t data_len);

#ifdef __cplusplus
} /* extern "C" */
#endif
