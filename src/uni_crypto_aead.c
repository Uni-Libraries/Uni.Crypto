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


static int _uni_crypto_aead_validate_input(const uint8_t* key, size_t key_len,
                                       const uint8_t* nonce, size_t nonce_len,
                                       const uint8_t* aad, size_t aad_len,
                                       size_t tag_len) {
    if ((!key && key_len > 0) || (!nonce && nonce_len > 0) || (!aad && aad_len > 0)) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (tag_len == 0) {
        return UNI_CRYPTO_AEAD_EINVAL;
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


int uni_crypto_aead_encrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* ciphertext_out,
                            uint8_t* tag_out, size_t tag_len)
{
    /* Parameter validation */
    if ((plaintext_len > 0 && (!plaintext || !ciphertext_out)) ||
        (plaintext_len == 0 && (plaintext && !ciphertext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!tag_out) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }

    int vrc = _uni_crypto_aead_validate_input(key, key_len, nonce, nonce_len, aad, aad_len, tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) {
        return vrc;
    }

    switch (alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM:
        {
            mbedtls_gcm_context ctx;
            mbedtls_gcm_init(&ctx);

            int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) { mbedtls_gcm_free(&ctx); return UNI_CRYPTO_AEAD_EALGO; }

            const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
            rc = mbedtls_gcm_crypt_and_tag(&ctx,
                                           MBEDTLS_GCM_ENCRYPT,
                                           plaintext_len,
                                           nonce, nonce_len,
                                           aad_ptr, aad_len,
                                           plaintext, ciphertext_out,
                                           tag_len, tag_out);

            mbedtls_gcm_free(&ctx);
            return (rc == 0) ? UNI_CRYPTO_AEAD_SUCCESS : UNI_CRYPTO_AEAD_EINTERNAL;
        }

        case UNI_CRYPTO_AEAD_ALG_AES_CCM:
        {
            mbedtls_ccm_context ctx;
            mbedtls_ccm_init(&ctx);

            int rc = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) { mbedtls_ccm_free(&ctx); return UNI_CRYPTO_AEAD_EALGO; }
            
            /* CCM length limit guard: q = 15 - nonce_len, max payload < 2^(8*q).
             * When payload exceeds this per-parameter bound, return ELIMIT instead of backend error. */
            size_t q = (nonce_len <= 15u) ? (size_t)(15u - nonce_len) : 0u;
            if (q < 2u || q > 8u) {
                mbedtls_ccm_free(&ctx);
                return UNI_CRYPTO_AEAD_EINTERNAL; /* invalid nonce length for CCM */
            }
            if (q < 8u) {
                unsigned int bits = (unsigned int)(8u * q);
                uint64_t max_len64 = (bits >= 64u) ? UINT64_MAX : (1ULL << bits);
                if ((uint64_t)plaintext_len >= max_len64) {
                    mbedtls_ccm_free(&ctx);
                    return UNI_CRYPTO_AEAD_ELIMIT;
                }
            }
            const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
            rc = mbedtls_ccm_encrypt_and_tag(&ctx,
                                             plaintext_len,
                                             nonce, nonce_len,
                                             aad_ptr, aad_len,
                                             plaintext,
                                             ciphertext_out,
                                             tag_out, tag_len);
            
            mbedtls_ccm_free(&ctx);
            return (rc == 0) ? UNI_CRYPTO_AEAD_SUCCESS : UNI_CRYPTO_AEAD_EINTERNAL;
        }
        default:
            return UNI_CRYPTO_AEAD_EALGO;
    }
}

int uni_crypto_aead_decrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* expected_tag, size_t expected_tag_len,
                            uint8_t* plaintext_out)
{
    /* Parameter validation */
    if ((ciphertext_len > 0 && (!ciphertext || !plaintext_out)) ||
        (ciphertext_len == 0 && (ciphertext && !plaintext_out))) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    if (!expected_tag || expected_tag_len == 0) {
        return UNI_CRYPTO_AEAD_EINVAL;
    }
    int vrc = _uni_crypto_aead_validate_input(key, key_len, nonce, nonce_len, aad, aad_len, expected_tag_len);
    if (vrc != UNI_CRYPTO_AEAD_SUCCESS) return vrc;

    switch (alg) {
        case UNI_CRYPTO_AEAD_ALG_AES_GCM:
        {
            mbedtls_gcm_context ctx;
            mbedtls_gcm_init(&ctx);

            int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) { mbedtls_gcm_free(&ctx); return UNI_CRYPTO_AEAD_EALGO; }

            /* Enforce 16-byte tag for GCM in this API; shorter tags are treated as authentication failure. */
            if (expected_tag_len != 16u) {
                mbedtls_gcm_free(&ctx);
                return UNI_CRYPTO_AEAD_EVERIFY;
            }

            const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
 
            /* Allocation-free decrypt: backend may write to plaintext_out before final tag check.
             * On authentication failure (EVERIFY), plaintext_out contents are unspecified and must not be used. */
            rc = mbedtls_gcm_auth_decrypt(&ctx,
                                          ciphertext_len,
                                          nonce, nonce_len,
                                          aad_ptr, aad_len,
                                          expected_tag, expected_tag_len,
                                          ciphertext,
                                          plaintext_out);
 
            mbedtls_gcm_free(&ctx);
            return _uni_crypto_aead_map_mbedtls_errcode(rc);
        }

        case UNI_CRYPTO_AEAD_ALG_AES_CCM:
        {
            mbedtls_ccm_context ctx;
            mbedtls_ccm_init(&ctx);

            int rc = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8u));
            if (rc != 0) { mbedtls_ccm_free(&ctx); return UNI_CRYPTO_AEAD_EALGO; }
            
            /* CCM length limit guard: q = 15 - nonce_len, max payload < 2^(8*q).
             * When payload exceeds this per-parameter bound, return ELIMIT instead of backend error. */
            size_t q = (nonce_len <= 15u) ? (size_t)(15u - nonce_len) : 0u;
            if (q < 2u || q > 8u) {
                mbedtls_ccm_free(&ctx);
                return UNI_CRYPTO_AEAD_EINTERNAL; /* invalid nonce length for CCM */
            }
            if (q < 8u) {
                unsigned int bits = (unsigned int)(8u * q);
                uint64_t max_len64 = (bits >= 64u) ? UINT64_MAX : (1ULL << bits);
                if ((uint64_t)ciphertext_len >= max_len64) {
                    mbedtls_ccm_free(&ctx);
                    return UNI_CRYPTO_AEAD_ELIMIT;
                }
            }
            const uint8_t* aad_ptr = (aad_len > 0) ? aad : (const uint8_t*)"";
 
            /* Allocation-free decrypt: backend may write to plaintext_out before final tag check.
             * On authentication failure (EVERIFY), plaintext_out contents are unspecified and must not be used. */
            rc = mbedtls_ccm_auth_decrypt(&ctx,
                                          ciphertext_len,
                                          nonce, nonce_len,
                                          aad_ptr, aad_len,
                                          ciphertext,
                                          plaintext_out,
                                          expected_tag, expected_tag_len);
 
            mbedtls_ccm_free(&ctx);
            return _uni_crypto_aead_map_mbedtls_errcode(rc);
        }

        default:
            return UNI_CRYPTO_AEAD_EALGO;
    }
}