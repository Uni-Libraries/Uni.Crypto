// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// mbetls
#include <mbedtls/gcm.h>
#include <mbedtls/ccm.h>

// uni.crypto
#include "uni_crypto_aead.h"
#include "uni_crypto_utils.h"


//
// Private
//

static int _uni_crypto_aead_map_mbedtls_errcode(int rc) {
    int result = UNI_CRYPTO_AEAD_EINTERNAL;
    switch(rc){
        case 0:
            result = UNI_CRYPTO_AEAD_SUCCESS;
            break;
        case MBEDTLS_ERR_GCM_AUTH_FAILED:
        case MBEDTLS_ERR_CCM_AUTH_FAILED:
            result = UNI_CRYPTO_AEAD_EVERIFY;
            break;
        default:
            break;
    }

    return result;
}


static int _uni_crypto_aead_validate_input(const uint8_t* nonce, size_t nonce_len,
                                           const uint8_t* aad, size_t aad_len,
                                           size_t tag_len) {
    if ((!nonce && nonce_len > 0) || (!aad && aad_len > 0)) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (tag_len == 0) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    return UNI_CRYPTO_AEAD_SUCCESS;
}


/* Marks a keyed context; a zero-initialized or freed context never carries it. */
#define UNI_CRYPTO_AEAD_CTX_MAGIC 0x55414541u /* "UAEA" */

/* State behind the opaque storage of uni_crypto_aead_ctx. */
typedef struct {
    uint32_t magic;
    uni_crypto_aead_algorithm alg;
    union {
        mbedtls_gcm_context gcm;
        mbedtls_ccm_context ccm;
    } backend;
} uni_crypto_aead_ctx_state;

_Static_assert(sizeof(uni_crypto_aead_ctx_state) <= UNI_CRYPTO_AEAD_CTX_SIZE,
               "UNI_CRYPTO_AEAD_CTX_SIZE is too small for the configured mbedTLS GCM/CCM context");
_Static_assert(_Alignof(uni_crypto_aead_ctx_state) <= _Alignof(uni_crypto_aead_ctx),
               "uni_crypto_aead_ctx storage is under-aligned for the backend state");

static uni_crypto_aead_ctx_state* _uni_crypto_aead_state(uni_crypto_aead_ctx* ctx) {
    return (uni_crypto_aead_ctx_state*)(void*)ctx->opaque.bytes;
}

/* CCM length limit guard: q = 15 - nonce_len, max payload < 2^(8*q). */
static int _uni_crypto_aead_ccm_check_lengths(size_t nonce_len, size_t payload_len) {
    size_t q = (nonce_len <= 15u) ? (size_t)(15u - nonce_len) : 0u;
    if (q < 2u || q > 8u) {
        return UNI_CRYPTO_AEAD_EINTERNAL; /* invalid nonce length for CCM */
    }
    if (q < 8u) {
        unsigned int bits = (unsigned int)(8u * q);
        uint64_t max_len64 = (bits >= 64u) ? UINT64_MAX : (1ULL << bits);
        if ((uint64_t)payload_len >= max_len64) {
            return UNI_CRYPTO_AEAD_ELIMIT;
        }
    }
    return UNI_CRYPTO_AEAD_SUCCESS;
}



//
// Public
//

size_t uni_crypto_aead_recommended_nonce_len(uni_crypto_aead_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM: return 12u; /* NIST SP 800-38D */
        case UNI_CRYPTO_AEAD_ALG_AES_CCM: return 13u; /* Common choice; CCM permits 7..13 */
        default: return 0u;
    }
}


size_t uni_crypto_aead_max_tag_len(uni_crypto_aead_algorithm alg) {
    switch (alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM: return 16u;
        case UNI_CRYPTO_AEAD_ALG_AES_CCM: return 16u;
        default: return 0u;
    }
}


int uni_crypto_aead_ctx_init(uni_crypto_aead_ctx* ctx, uni_crypto_aead_algorithm alg, const uint8_t* key, size_t key_len)
{
    if (!ctx || !key || key_len == 0u) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }

    uni_crypto_aead_ctx_state* st = _uni_crypto_aead_state(ctx);
    uni_crypto_utils_zeroize(st, sizeof(*st));

    int rc = 0;
    switch (alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM:
            mbedtls_gcm_init(&st->backend.gcm);
            rc = mbedtls_gcm_setkey(&st->backend.gcm, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) {
                mbedtls_gcm_free(&st->backend.gcm);
            }
            break;
        case UNI_CRYPTO_AEAD_ALG_AES_CCM:
            mbedtls_ccm_init(&st->backend.ccm);
            rc = mbedtls_ccm_setkey(&st->backend.ccm, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) {
                mbedtls_ccm_free(&st->backend.ccm);
            }
            break;
        default:
            return UNI_CRYPTO_AEAD_EALGO;
    }
    if (rc != 0) {
        uni_crypto_utils_zeroize(st, sizeof(*st));
        return UNI_CRYPTO_AEAD_EALGO;
    }

    st->alg = alg;
    st->magic = UNI_CRYPTO_AEAD_CTX_MAGIC;
    return UNI_CRYPTO_AEAD_SUCCESS;
}


void uni_crypto_aead_ctx_free(uni_crypto_aead_ctx* ctx)
{
    if (!ctx) {
        return;
    }
    uni_crypto_aead_ctx_state* st = _uni_crypto_aead_state(ctx);
    if (st->magic == UNI_CRYPTO_AEAD_CTX_MAGIC) {
        if (st->alg == UNI_CRYPTO_AEAD_ALG_AES_GCM) {
            mbedtls_gcm_free(&st->backend.gcm);
        } else if (st->alg == UNI_CRYPTO_AEAD_ALG_AES_CCM) {
            mbedtls_ccm_free(&st->backend.ccm);
        }
    }
    uni_crypto_utils_zeroize(st, sizeof(*st));
}


int uni_crypto_aead_ctx_encrypt(uni_crypto_aead_ctx* ctx,
                                const uint8_t* nonce, size_t nonce_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* plaintext, size_t plaintext_len,
                                uint8_t* ciphertext_out,
                                uint8_t* tag_out, size_t tag_len)
{
    if (!ctx || _uni_crypto_aead_state(ctx)->magic != UNI_CRYPTO_AEAD_CTX_MAGIC) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if ((plaintext_len > 0 && (!plaintext || !ciphertext_out)) ||
        (plaintext_len == 0 && (plaintext && !ciphertext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!tag_out) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    int vrc = _uni_crypto_aead_validate_input(nonce, nonce_len, aad, aad_len, tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
        return vrc;
    }

    uni_crypto_aead_ctx_state* st = _uni_crypto_aead_state(ctx);
    const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
    int rc = 0;
    switch (st->alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM:
            rc = mbedtls_gcm_crypt_and_tag(&st->backend.gcm,
                                           MBEDTLS_GCM_ENCRYPT,
                                           plaintext_len,
                                           nonce, nonce_len,
                                           aad_ptr, aad_len,
                                           plaintext, ciphertext_out,
                                           tag_len, tag_out);
            break;
        case UNI_CRYPTO_AEAD_ALG_AES_CCM:
            vrc = _uni_crypto_aead_ccm_check_lengths(nonce_len, plaintext_len);
            if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
                return vrc;
            }
            rc = mbedtls_ccm_encrypt_and_tag(&st->backend.ccm,
                                             plaintext_len,
                                             nonce, nonce_len,
                                             aad_ptr, aad_len,
                                             plaintext,
                                             ciphertext_out,
                                             tag_out, tag_len);
            break;
        default:
            return UNI_CRYPTO_AEAD_EALGO;
    }
    return (rc == 0) ? UNI_CRYPTO_AEAD_SUCCESS : UNI_CRYPTO_AEAD_EINTERNAL;
}


int uni_crypto_aead_ctx_decrypt(uni_crypto_aead_ctx* ctx,
                                const uint8_t* nonce, size_t nonce_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ciphertext, size_t ciphertext_len,
                                const uint8_t* expected_tag, size_t expected_tag_len,
                                uint8_t* plaintext_out)
{
    if (!ctx || _uni_crypto_aead_state(ctx)->magic != UNI_CRYPTO_AEAD_CTX_MAGIC) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if ((ciphertext_len > 0 && (!ciphertext || !plaintext_out)) ||
        (ciphertext_len == 0 && (ciphertext && !plaintext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!expected_tag || expected_tag_len == 0) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    int vrc = _uni_crypto_aead_validate_input(nonce, nonce_len, aad, aad_len, expected_tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
        return vrc;
    }

    uni_crypto_aead_ctx_state* st = _uni_crypto_aead_state(ctx);
    const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
    int rc = 0;
    switch (st->alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM:
            /* Enforce 16-byte tag for GCM in this API; shorter tags are treated as authentication failure. */
            if (expected_tag_len != 16u) {
                return UNI_CRYPTO_AEAD_EVERIFY;
            }
            /* Allocation-free decrypt: backend may write to plaintext_out before final tag check.
             * On authentication failure (EVERIFY), plaintext_out contents are unspecified and must not be used. */
            rc = mbedtls_gcm_auth_decrypt(&st->backend.gcm,
                                          ciphertext_len,
                                          nonce, nonce_len,
                                          aad_ptr, aad_len,
                                          expected_tag, expected_tag_len,
                                          ciphertext,
                                          plaintext_out);
            break;
        case UNI_CRYPTO_AEAD_ALG_AES_CCM:
            vrc = _uni_crypto_aead_ccm_check_lengths(nonce_len, ciphertext_len);
            if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
                return vrc;
            }
            rc = mbedtls_ccm_auth_decrypt(&st->backend.ccm,
                                          ciphertext_len,
                                          nonce, nonce_len,
                                          aad_ptr, aad_len,
                                          ciphertext,
                                          plaintext_out,
                                          expected_tag, expected_tag_len);
            break;
        default:
            return UNI_CRYPTO_AEAD_EALGO;
    }
    return _uni_crypto_aead_map_mbedtls_errcode(rc);
}


/* The one-shot functions key a temporary context; their argument checks run before keying so that the
 * error codes for invalid arguments do not depend on the key. */

int uni_crypto_aead_encrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* ciphertext_out,
                            uint8_t* tag_out, size_t tag_len)
{
    if ((plaintext_len > 0 && (!plaintext || !ciphertext_out)) ||
        (plaintext_len == 0 && (plaintext && !ciphertext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!tag_out || (!key && key_len > 0)) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    int vrc = _uni_crypto_aead_validate_input(nonce, nonce_len, aad, aad_len, tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
        return vrc;
    }
    if (alg != UNI_CRYPTO_AEAD_ALG_AES_GCM && alg != UNI_CRYPTO_AEAD_ALG_AES_CCM) {
        return UNI_CRYPTO_AEAD_EALGO;
    }
    if (key_len == 0u) {
        return UNI_CRYPTO_AEAD_EALGO; /* no valid AES key length */
    }

    uni_crypto_aead_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    int rc = uni_crypto_aead_ctx_init(&ctx, alg, key, key_len);
    if (rc == UNI_CRYPTO_AEAD_SUCCESS) {
        rc = uni_crypto_aead_ctx_encrypt(&ctx, nonce, nonce_len, aad, aad_len, plaintext, plaintext_len, ciphertext_out, tag_out, tag_len);
    }
    uni_crypto_aead_ctx_free(&ctx);
    return rc;
}

int uni_crypto_aead_decrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* expected_tag, size_t expected_tag_len,
                            uint8_t* plaintext_out)
{
    if ((ciphertext_len > 0 && (!ciphertext || !plaintext_out)) ||
        (ciphertext_len == 0 && (ciphertext && !plaintext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!expected_tag || expected_tag_len == 0 || (!key && key_len > 0)) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    int vrc = _uni_crypto_aead_validate_input(nonce, nonce_len, aad, aad_len, expected_tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
        return vrc;
    }
    if (alg != UNI_CRYPTO_AEAD_ALG_AES_GCM && alg != UNI_CRYPTO_AEAD_ALG_AES_CCM) {
        return UNI_CRYPTO_AEAD_EALGO;
    }
    if (key_len == 0u) {
        return UNI_CRYPTO_AEAD_EALGO; /* no valid AES key length */
    }

    uni_crypto_aead_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    int rc = uni_crypto_aead_ctx_init(&ctx, alg, key, key_len);
    if (rc == UNI_CRYPTO_AEAD_SUCCESS) {
        rc = uni_crypto_aead_ctx_decrypt(&ctx, nonce, nonce_len, aad, aad_len, ciphertext, ciphertext_len, expected_tag, expected_tag_len,
                                         plaintext_out);
    }
    uni_crypto_aead_ctx_free(&ctx);
    return rc;
}
