// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <stddef.h>
#include <stdint.h>

// mbedtls
#include <mbedtls/platform_util.h>

// uni.crypto
#include "uni_crypto_utils.h"



//
// Implementation
//

int uni_crypto_utils_compare(const void* a, const void* b, size_t len)
{
    if (len > 0 && (!a || !b)) {
        return -1;
    }
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;

    /* Constant-time compare: accumulate XOR of all bytes */
    uint32_t diff = 0u;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint32_t)(pa[i] ^ pb[i]);
    }
    /* Return 0 if equal, 1 if different */
    return (diff == 0u) ? 0 : 1;
}


void uni_crypto_utils_zeroize(void* ptr, size_t len)
{
    if (ptr && len > 0) {
        mbedtls_platform_zeroize(ptr, len);
    }
}
