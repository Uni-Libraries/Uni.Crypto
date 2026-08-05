// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "uni_crypto_export.h"

typedef enum {
    UNI_CRYPTO_HASH_ALG_INVALID = 0,
    UNI_CRYPTO_HASH_ALG_SHA256  = 1,
    UNI_CRYPTO_HASH_ALG_SHA224  = 2,
    UNI_CRYPTO_HASH_ALG_SHA1    = 3
} uni_crypto_hash_algorithm;

#define UNI_CRYPTO_HASH_SUCCESS     0
#define UNI_CRYPTO_HASH_EINVAL     (-1)
#define UNI_CRYPTO_HASH_EALGO      (-2)
#define UNI_CRYPTO_HASH_EINTERNAL  (-3)
#define UNI_CRYPTO_HASH_EBUFFER    (-4)

UNI_CRYPTO_EXPORT int uni_crypto_hash_compute(uni_crypto_hash_algorithm alg,
                                               const void* data,
                                               size_t data_len,
                                               uint8_t* out_digest,
                                               size_t out_digest_len);

UNI_CRYPTO_EXPORT size_t uni_crypto_hash_digest_size(uni_crypto_hash_algorithm alg);

#ifdef __cplusplus
} /* extern "C" */
#endif
