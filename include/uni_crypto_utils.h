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
#include <stddef.h>
#include <stdint.h>



//
// Functions
//

/**
 * @brief Constant-time comparison of two byte buffers of equal length.
 *
 * @return
 *  0  - buffers are equal
 *  1  - buffers differ
 * -1  - invalid arguments (NULL with non-zero length)
 */
int uni_crypto_utils_compare(const void* a, const void* b, size_t len);

/**
 * @brief Overwrite the memory region pointed by ptr with zeros.
 *
 * @arg ptr pointer to memory (may be NULL for no-op)
 * @arg len number of bytes to zeroize
 */
void uni_crypto_utils_zeroize(void* ptr, size_t len);

#ifdef __cplusplus
} /* extern "C" */
#endif
