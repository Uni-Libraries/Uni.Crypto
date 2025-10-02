// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// mbedtls
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

// uni.crypto
#include "uni_crypto_hmac.h"
#include "uni_crypto_utils.h"



//
// Private Structs
//

struct uni_crypto_hmac_context {
    const mbedtls_md_info_t* md_info;
    mbedtls_md_context_t md_ctx;
    uni_crypto_hmac_algorithm alg;
    bool initialized;

    /**
     * true if allocated via uni_crypto_hmac_create(), false if static
     */
    bool owns_memory;
};
_Static_assert(UNI_CRYPTO_HMAC_CONTEXT_SIZE >= sizeof(struct uni_crypto_hmac_context), "UNI_CRYPTO_HMAC_CONTEXT_SIZE too small for uni_crypto_hmac_context");



//
// Private Functions
//

static mbedtls_md_type_t uni__map_alg(uni_crypto_hmac_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_HMAC_ALG_SHA256: return MBEDTLS_MD_SHA256;
        case UNI_CRYPTO_HMAC_ALG_SHA1:   return MBEDTLS_MD_SHA1;
        default:                         return MBEDTLS_MD_NONE;
    }
}


/* Reinitialize/clear internal state safely */
static void uni__ctx_reset_storage(uni_crypto_hmac_context* ctx) {
    if (!ctx) return;
    /* Free any allocated backend state */
    if (ctx->initialized) {
        mbedtls_md_free(&ctx->md_ctx);
    } else {
        /* If not initialized, md_ctx may still be zero; ensure consistent state */
    }
    /* Zeroize the entire struct content including md_ctx and metadata */
    uni_crypto_utils_zeroize(ctx, sizeof(*ctx));
}



//
// Public
//

uni_crypto_hmac_context* uni_crypto_hmac_create(void) {
    uni_crypto_hmac_context* ctx = (uni_crypto_hmac_context*)calloc(1u, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    /* md_ctx must be initialized before any mbedtls operation */
    mbedtls_md_init(&ctx->md_ctx);
    ctx->initialized = false;
    ctx->owns_memory = true;
    ctx->alg = UNI_CRYPTO_HMAC_ALG_INVALID;
    ctx->md_info = NULL;
    return ctx;
}


int uni_crypto_hmac_context_create_static(void* buffer, size_t buffer_len, uni_crypto_hmac_context** out_ctx) {
    if (!buffer || !out_ctx) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (buffer_len < (size_t)UNI_CRYPTO_HMAC_CONTEXT_SIZE) {
        return UNI_CRYPTO_HMAC_EBUFFER;
    }
    /* Alignment check for safety */
    size_t align = _Alignof(struct uni_crypto_hmac_context);
    if (((uintptr_t)buffer) % align != 0u) {
        return UNI_CRYPTO_HMAC_EBUFFER;
    }

    uni_crypto_hmac_context* ctx = (uni_crypto_hmac_context*)buffer;
    /* Ensure full zero-initialization and backend init */
    uni_crypto_utils_zeroize(ctx, sizeof(*ctx));
    mbedtls_md_init(&ctx->md_ctx);
    ctx->initialized = false;
    ctx->owns_memory = false;
    ctx->alg = UNI_CRYPTO_HMAC_ALG_INVALID;
    ctx->md_info = NULL;

    *out_ctx = ctx;
    return UNI_CRYPTO_HMAC_SUCCESS;
}


void uni_crypto_hmac_free(uni_crypto_hmac_context* ctx) {
    if (!ctx) return;
    int should_free = ctx->owns_memory;
    /* Free backend and zeroize structure */
    if (ctx->initialized) {
        mbedtls_md_free(&ctx->md_ctx);
    }
    /* Zeroize entire context including embedded mbedtls_md_context_t */
    uni_crypto_utils_zeroize(ctx, sizeof(*ctx));
    if (should_free) {
        free(ctx);
    }
}


int uni_crypto_hmac_init(uni_crypto_hmac_context* ctx,
                         uni_crypto_hmac_algorithm alg,
                         const uint8_t* key,
                         size_t key_len) {
    if (!ctx) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if ((key_len > 0u) && (key == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }

    /* If re-initializing an existing context, free prior state first */
    if (ctx->initialized) {
        mbedtls_md_free(&ctx->md_ctx);
        /* Re-initialize the backend context before reuse (required by mbedTLS) */
        mbedtls_md_init(&ctx->md_ctx);
        ctx->initialized = 0;
        ctx->alg = UNI_CRYPTO_HMAC_ALG_INVALID;
        ctx->md_info = NULL;
    } else {
        mbedtls_md_init(&ctx->md_ctx);
    }

    mbedtls_md_type_t md_type = uni__map_alg(alg);
    if (md_type == MBEDTLS_MD_NONE) {
        return UNI_CRYPTO_HMAC_EALGO;
    }

    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(md_type);
    if (!info) {
        return UNI_CRYPTO_HMAC_EALGO;
    }

    int rc = mbedtls_md_setup(&ctx->md_ctx, info, 1 /* HMAC enabled */);
    if (rc != 0) {
        /* Zeroize any partial state, restore to clean */
        mbedtls_md_free(&ctx->md_ctx);
        uni_crypto_utils_zeroize(&ctx->md_ctx, sizeof(ctx->md_ctx));
        return UNI_CRYPTO_HMAC_EINTERNAL;
    }

    rc = mbedtls_md_hmac_starts(&ctx->md_ctx, key, key_len);
    if (rc != 0) {
        mbedtls_md_free(&ctx->md_ctx);
        uni_crypto_utils_zeroize(&ctx->md_ctx, sizeof(ctx->md_ctx));
        return UNI_CRYPTO_HMAC_EINTERNAL;
    }

    ctx->initialized = true;
    ctx->alg = alg;
    ctx->md_info = info;
    return UNI_CRYPTO_HMAC_SUCCESS;
}


int uni_crypto_hmac_update(uni_crypto_hmac_context* ctx,
                           const void* data,
                           size_t data_len) {
    if (!ctx) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (!ctx->initialized) {
        return UNI_CRYPTO_HMAC_ESTATE;
    }
    if ((data_len > 0u) && (data == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (data_len == 0u) {
        return UNI_CRYPTO_HMAC_SUCCESS; /* No-op */
    }
    int rc = mbedtls_md_hmac_update(&ctx->md_ctx, (const unsigned char*)data, data_len);
    if (rc != 0) {
        return UNI_CRYPTO_HMAC_EINTERNAL;
    }
    return UNI_CRYPTO_HMAC_SUCCESS;
}

int uni_crypto_hmac_final(uni_crypto_hmac_context* ctx,
                          uint8_t* out_tag,
                          size_t out_tag_len) {
    if (!ctx || !out_tag) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (!ctx->initialized) {
        return UNI_CRYPTO_HMAC_ESTATE;
    }
    size_t need = uni_crypto_hmac_digest_size(ctx->alg);
    if (out_tag_len < need || need == 0u) {
        return UNI_CRYPTO_HMAC_EBUFFER;
    }

    int rc = mbedtls_md_hmac_finish(&ctx->md_ctx, out_tag);
    if (rc != 0) {
        return UNI_CRYPTO_HMAC_EINTERNAL;
    }
    return UNI_CRYPTO_HMAC_SUCCESS;
}

int uni_crypto_hmac_reset(uni_crypto_hmac_context* ctx) {
    if (!ctx) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (!ctx->initialized) {
        return UNI_CRYPTO_HMAC_ESTATE;
    }
    int rc = mbedtls_md_hmac_reset(&ctx->md_ctx);
    if (rc != 0) {
        return UNI_CRYPTO_HMAC_EINTERNAL;
    }
    return UNI_CRYPTO_HMAC_SUCCESS;
}

int uni_crypto_hmac_compute(uni_crypto_hmac_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const void* data, size_t data_len,
                            uint8_t* out_tag, size_t out_tag_len) {
    if ((key_len > 0u) && (key == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if ((data_len > 0u) && (data == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (!out_tag) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }

    size_t need = uni_crypto_hmac_digest_size(alg);
    if (need == 0u) {
        return UNI_CRYPTO_HMAC_EALGO;
    }
    if (out_tag_len < need) {
        return UNI_CRYPTO_HMAC_EBUFFER;
    }

    /* Use a local context (no heap) */
    uni_crypto_hmac_context ctx_local;
    /* Ensure full zero-initialization */
    uni_crypto_utils_zeroize(&ctx_local, sizeof(ctx_local));
    mbedtls_md_init(&ctx_local.md_ctx);

    int rc = uni_crypto_hmac_init(&ctx_local, alg, key, key_len);
    if (rc != UNI_CRYPTO_HMAC_SUCCESS) {
        /* ctx_local.md_ctx already cleaned by init on error path */
        uni_crypto_utils_zeroize(&ctx_local, sizeof(ctx_local));
        return rc;
    }

    if (data_len > 0u) {
        rc = uni_crypto_hmac_update(&ctx_local, data, data_len);
        if (rc != UNI_CRYPTO_HMAC_SUCCESS) {
            uni__ctx_reset_storage(&ctx_local);
            return rc;
        }
    }

    rc = uni_crypto_hmac_final(&ctx_local, out_tag, out_tag_len);
    /* Reset and zeroize local context memory */
    uni__ctx_reset_storage(&ctx_local);
    return rc;
}


int uni_crypto_hmac_verify(uni_crypto_hmac_algorithm alg,
                           const uint8_t* key, size_t key_len,
                           const void* data, size_t data_len,
                           const uint8_t* expected_tag, size_t expected_tag_len) {
    if (!expected_tag) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if (expected_tag_len == 0u) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if ((key_len > 0u) && (key == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }
    if ((data_len > 0u) && (data == NULL)) {
        return UNI_CRYPTO_HMAC_EINVAL;
    }

    size_t full = uni_crypto_hmac_digest_size(alg);
    if (full == 0u) {
        return UNI_CRYPTO_HMAC_EALGO;
    }
    if (expected_tag_len > full) {
        return UNI_CRYPTO_HMAC_EBUFFER;
    }

    /* Compute full-length tag, compare first expected_tag_len bytes */
    uint8_t tag_buf[64];
    if (full > sizeof(tag_buf)) {
        return UNI_CRYPTO_HMAC_EALGO; /* Unsupported digest larger than our buffer */
    }

    int rc = uni_crypto_hmac_compute(alg, key, key_len, data, data_len, tag_buf, full);
    if (rc != UNI_CRYPTO_HMAC_SUCCESS) {
        uni_crypto_utils_zeroize(tag_buf, sizeof(tag_buf));
        return rc;
    }

    bool equal = uni_crypto_utils_compare(tag_buf, expected_tag, expected_tag_len) == 0;
    /* Zeroize temporary buffer */
    uni_crypto_utils_zeroize(tag_buf, sizeof(tag_buf));

    if (!equal) {
        return UNI_CRYPTO_HMAC_EVERIFY;
    }
    return UNI_CRYPTO_HMAC_SUCCESS;
}

size_t uni_crypto_hmac_digest_size(uni_crypto_hmac_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_HMAC_ALG_SHA256: return 32u;
        case UNI_CRYPTO_HMAC_ALG_SHA1:   return 20u;
        default:                         return 0u;
    }
}

size_t uni_crypto_hmac_block_size(uni_crypto_hmac_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_HMAC_ALG_SHA256: return 64u;
        case UNI_CRYPTO_HMAC_ALG_SHA1:   return 64u;
        default:                         return 0u;
    }
}
