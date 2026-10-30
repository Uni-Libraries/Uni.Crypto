// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#include <stdbool.h>
#include <stdlib.h>

#include <mbedtls/md.h>

#include "uni_crypto_hash.h"

struct uni_crypto_hash_context {
    mbedtls_md_context_t md_ctx;
    uni_crypto_hash_algorithm alg;
    bool finalized;
};

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

uni_crypto_hash_context* uni_crypto_hash_create(uni_crypto_hash_algorithm alg) {
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(uni__hash_map_alg(alg));
    if (info == NULL) {
        return NULL;
    }
    uni_crypto_hash_context* ctx = calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    mbedtls_md_init(&ctx->md_ctx);
    ctx->alg = alg;
    if (mbedtls_md_setup(&ctx->md_ctx, info, 0) != 0 || mbedtls_md_starts(&ctx->md_ctx) != 0) {
        uni_crypto_hash_free(ctx);
        return NULL;
    }
    return ctx;
}

int uni_crypto_hash_update(uni_crypto_hash_context* ctx, const void* data, size_t data_len) {
    if (ctx == NULL || ctx->finalized || (data_len > 0u && data == NULL)) {
        return UNI_CRYPTO_HASH_EINVAL;
    }
    return mbedtls_md_update(&ctx->md_ctx, (const unsigned char*)data, data_len) == 0
        ? UNI_CRYPTO_HASH_SUCCESS
        : UNI_CRYPTO_HASH_EINTERNAL;
}

int uni_crypto_hash_final(uni_crypto_hash_context* ctx, uint8_t* out_digest, size_t out_digest_len) {
    if (ctx == NULL || ctx->finalized || out_digest == NULL) {
        return UNI_CRYPTO_HASH_EINVAL;
    }
    if (out_digest_len < uni_crypto_hash_digest_size(ctx->alg)) {
        return UNI_CRYPTO_HASH_EBUFFER;
    }
    ctx->finalized = true;
    return mbedtls_md_finish(&ctx->md_ctx, out_digest) == 0
        ? UNI_CRYPTO_HASH_SUCCESS
        : UNI_CRYPTO_HASH_EINTERNAL;
}

void uni_crypto_hash_free(uni_crypto_hash_context* ctx) {
    if (ctx == NULL) {
        return;
    }
    mbedtls_md_free(&ctx->md_ctx);
    free(ctx);
}
