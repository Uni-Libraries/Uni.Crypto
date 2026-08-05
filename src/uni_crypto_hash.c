// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#include <mbedtls/md.h>

#include "uni_crypto_hash.h"

static mbedtls_md_type_t uni__hash_map_alg(uni_crypto_hash_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_HASH_ALG_SHA256: return MBEDTLS_MD_SHA256;
        case UNI_CRYPTO_HASH_ALG_SHA224: return MBEDTLS_MD_SHA224;
        case UNI_CRYPTO_HASH_ALG_SHA1:   return MBEDTLS_MD_SHA1;
        default:                         return MBEDTLS_MD_NONE;
    }
}

int uni_crypto_hash_compute(uni_crypto_hash_algorithm alg,
                            const void* data,
                            size_t data_len,
                            uint8_t* out_digest,
                            size_t out_digest_len) {
    if ((data_len > 0u && data == NULL) || out_digest == NULL) {
        return UNI_CRYPTO_HASH_EINVAL;
    }

    size_t digest_size = uni_crypto_hash_digest_size(alg);
    if (digest_size == 0u) {
        return UNI_CRYPTO_HASH_EALGO;
    }
    if (out_digest_len < digest_size) {
        return UNI_CRYPTO_HASH_EBUFFER;
    }

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(uni__hash_map_alg(alg));
    if (info == NULL) {
        return UNI_CRYPTO_HASH_EALGO;
    }

    return mbedtls_md(info, (const unsigned char*)data, data_len, out_digest) == 0
        ? UNI_CRYPTO_HASH_SUCCESS
        : UNI_CRYPTO_HASH_EINTERNAL;
}

size_t uni_crypto_hash_digest_size(uni_crypto_hash_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_HASH_ALG_SHA256: return 32u;
        case UNI_CRYPTO_HASH_ALG_SHA224: return 28u;
        case UNI_CRYPTO_HASH_ALG_SHA1:   return 20u;
        default:                         return 0u;
    }
}
