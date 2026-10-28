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

// uni.crypto
#include "uni_crypto_export.h"


//
// Enums
//

/**
 * @brief Supported AEAD algorithms.
 */
typedef enum {
    UNI_CRYPTO_AEAD_ALG_INVALID = 0,
    UNI_CRYPTO_AEAD_ALG_AES_GCM = 1,
    UNI_CRYPTO_AEAD_ALG_AES_CCM = 2
} uni_crypto_aead_algorithm;

/**
 * @brief AEAD error codes.
 */
typedef enum {
    UNI_CRYPTO_AEAD_SUCCESS = 0,   /**< Operation successful. */
    UNI_CRYPTO_AEAD_EINVAL = -1,   /**< Invalid argument (NULL pointer, bad length, etc.). */
    UNI_CRYPTO_AEAD_EALGO = -2,    /**< Unsupported or invalid algorithm. */
    UNI_CRYPTO_AEAD_EBUFFER = -3,  /**< Output buffer too small. */
    UNI_CRYPTO_AEAD_EVERIFY = -4,  /**< Authentication or tag verification failed. */
    UNI_CRYPTO_AEAD_EINTERNAL = -5,/**< Internal or backend error. */
    UNI_CRYPTO_AEAD_ELIMIT = -6    /**< Message length exceeds algorithm or parameter limits (e.g., CCM L field). */
} uni_crypto_aead_status;



//
// Typedefs
//

/**
 * @brief Size in bytes of the storage reserved for a keyed AEAD context.
 *
 * The implementation checks at compile time that the backend state fits; a backend configured with very large
 * GCM tables (MBEDTLS_GCM_LARGE_TABLE) needs this value raised.
 */
#define UNI_CRYPTO_AEAD_CTX_SIZE (1024u)

/**
 * @brief Keyed AEAD context: the AES key schedule (and GCM hash tables) computed once by uni_crypto_aead_ctx_init()
 * and reused for every message.
 *
 * The one-shot functions uni_crypto_aead_encrypt() / uni_crypto_aead_decrypt() derive the key schedule on every call;
 * a context removes that cost for protocols that protect many messages with one key (e.g. SDLS frames).
 *
 * Lifetime: zero-initialize (or uni_crypto_aead_ctx_free()) -> uni_crypto_aead_ctx_init() -> any number of
 * uni_crypto_aead_ctx_encrypt() / uni_crypto_aead_ctx_decrypt() -> uni_crypto_aead_ctx_free(). The context may live
 * in static or automatic storage; the backend may allocate internally during init, released by free.
 *
 * Thread-safety: a context must not be used concurrently by multiple threads.
 */
typedef struct uni_crypto_aead_ctx {
    union {
        uint64_t align_u64;
        void* align_ptr;
        long double align_ld;
        unsigned char bytes[UNI_CRYPTO_AEAD_CTX_SIZE];
    } opaque; /**< Implementation state; do not access. */
} uni_crypto_aead_ctx;



//
// Functions
//

/**
 * @brief Encrypts plaintext using the selected AEAD algorithm.
 * @details Produces ciphertext_out with the same length as plaintext and writes the authentication tag to tag_out.
 * Buffers may alias when permitted by the backend (ciphertext_out may equal plaintext).
 * @param alg AEAD algorithm (AES-GCM or AES-CCM).
 * @param key Pointer to the secret key buffer.
 * @param key_len Length of the secret key in bytes (AES-128/192/256 as supported by the backend).
 * @param nonce Pointer to the IV/nonce buffer.
 * @param nonce_len Length of the IV/nonce in bytes.
 * @param aad Pointer to the associated data buffer (may be NULL when aad_len is 0).
 * @param aad_len Length of the associated data in bytes.
 * @param plaintext Pointer to the plaintext buffer (may be NULL when plaintext_len is 0).
 * @param plaintext_len Length of the plaintext in bytes.
 * @param ciphertext_out Pointer to the output ciphertext buffer (same size as plaintext; may be NULL when plaintext_len is 0).
 * @param tag_out Pointer to the output authentication tag buffer.
 * @param tag_len Requested authentication tag length in bytes (e.g., 16 for GCM, 8/12/16 for CCM).
 * @return UNI_CRYPTO_AEAD_SUCCESS on success or a negative error code on failure.
 */
UNI_CRYPTO_EXPORT int uni_crypto_aead_encrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* ciphertext_out,
                            uint8_t* tag_out, size_t tag_len);

/**
 * @brief Decrypts ciphertext and verifies the supplied authentication tag.
 * @details Returns UNI_CRYPTO_AEAD_SUCCESS when the computed tag matches expected_tag. The backend operates allocation-free and may write into plaintext_out before final verification. On authentication failure UNI_CRYPTO_AEAD_EVERIFY is returned and plaintext_out must be discarded. For AES-GCM the expected_tag_len must be 16; shorter tags are rejected with UNI_CRYPTO_AEAD_EVERIFY.
 * @param alg AEAD algorithm (AES-GCM or AES-CCM).
 * @param key Pointer to the secret key buffer.
 * @param key_len Length of the secret key in bytes.
 * @param nonce Pointer to the IV/nonce buffer.
 * @param nonce_len Length of the IV/nonce in bytes.
 * @param aad Pointer to the associated data buffer (may be NULL when aad_len is 0).
 * @param aad_len Length of the associated data in bytes.
 * @param ciphertext Pointer to the ciphertext buffer (may be NULL when ciphertext_len is 0).
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param expected_tag Pointer to the authentication tag to verify.
 * @param expected_tag_len Length of the expected authentication tag in bytes.
 * @param plaintext_out Pointer to the output plaintext buffer (same size as ciphertext; may be NULL when ciphertext_len is 0).
 * @return UNI_CRYPTO_AEAD_SUCCESS on success or a negative error code on failure.
 */
UNI_CRYPTO_EXPORT int uni_crypto_aead_decrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* expected_tag, size_t expected_tag_len,
                            uint8_t* plaintext_out);

/**
 * @brief Keys an AEAD context.
 * @details Computes the AES key schedule once. The key bytes are not retained by the context.
 * @param ctx Context in zero-initialized or freed state (initializing an already keyed context leaks its backend state).
 * @param alg AEAD algorithm (AES-GCM or AES-CCM).
 * @param key Secret key (16, 24 or 32 bytes).
 * @param key_len Key length in bytes.
 * @return UNI_CRYPTO_AEAD_SUCCESS, UNI_CRYPTO_AEAD_EINVAL for NULL arguments, UNI_CRYPTO_AEAD_EALGO for an unsupported
 *         algorithm or key length. On failure the context is left in the freed state.
 */
UNI_CRYPTO_EXPORT int uni_crypto_aead_ctx_init(uni_crypto_aead_ctx* ctx, uni_crypto_aead_algorithm alg, const uint8_t* key, size_t key_len);

/**
 * @brief Encrypts with a keyed context; same contract and results as uni_crypto_aead_encrypt().
 * @details ciphertext_out may be equal to plaintext (in-place encryption); partial overlap is not allowed.
 * @return UNI_CRYPTO_AEAD_SUCCESS, or UNI_CRYPTO_AEAD_EINVAL when the context is not keyed or arguments are invalid,
 *         or another negative error code.
 */
UNI_CRYPTO_EXPORT int uni_crypto_aead_ctx_encrypt(uni_crypto_aead_ctx* ctx,
                                                  const uint8_t* nonce, size_t nonce_len,
                                                  const uint8_t* aad, size_t aad_len,
                                                  const uint8_t* plaintext, size_t plaintext_len,
                                                  uint8_t* ciphertext_out,
                                                  uint8_t* tag_out, size_t tag_len);

/**
 * @brief Decrypts and verifies with a keyed context; same contract and results as uni_crypto_aead_decrypt().
 * @details plaintext_out may be equal to ciphertext (in-place decryption); partial overlap is not allowed. On
 *          UNI_CRYPTO_AEAD_EVERIFY the contents of plaintext_out are unspecified and must be discarded.
 */
UNI_CRYPTO_EXPORT int uni_crypto_aead_ctx_decrypt(uni_crypto_aead_ctx* ctx,
                                                  const uint8_t* nonce, size_t nonce_len,
                                                  const uint8_t* aad, size_t aad_len,
                                                  const uint8_t* ciphertext, size_t ciphertext_len,
                                                  const uint8_t* expected_tag, size_t expected_tag_len,
                                                  uint8_t* plaintext_out);

/**
 * @brief Releases backend resources and zeroizes the key schedule.
 * @param ctx Context to free; NULL and already freed or zero-initialized contexts are allowed (no-op).
 */
UNI_CRYPTO_EXPORT void uni_crypto_aead_ctx_free(uni_crypto_aead_ctx* ctx);

/**
 * @brief Helper utilities for AEAD configuration.
 */

/**
 * @brief Returns the recommended nonce length for an algorithm.
 * @param alg AEAD algorithm identifier.
 * @return Recommended nonce length in bytes, or 0 if unspecified.
 */
UNI_CRYPTO_EXPORT size_t uni_crypto_aead_recommended_nonce_len(uni_crypto_aead_algorithm alg);

/**
 * @brief Returns the maximum tag length for an algorithm.
 * @param alg AEAD algorithm identifier.
 * @return Maximum authentication tag length in bytes, or 0 if the algorithm is invalid.
 */
UNI_CRYPTO_EXPORT size_t uni_crypto_aead_max_tag_len(uni_crypto_aead_algorithm alg);

#ifdef __cplusplus
} /* extern "C" */
#endif
