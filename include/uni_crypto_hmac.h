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
// Typedefs
//

/**
 * @brief Opaque HMAC context object.
 *
 * Lifetime:
 *  - allocate with uni_crypto_hmac_create()
 *  - initialize with uni_crypto_hmac_init() or uni_crypto_hmac_context_init_static()
 *  - use update/final/reset
 *  - release with uni_crypto_hmac_free().
 *
 * Thread-safety:
 *  - A context must not be used concurrently by multiple threads.
 */
typedef struct uni_crypto_hmac_context uni_crypto_hmac_context;



//
// Enums
//

/**
 * @brief Supported HMAC algorithms (maps to underlying hash functions).
 */
typedef enum {
    UNI_CRYPTO_HMAC_ALG_INVALID = 0,  /*!< Invalid/unspecified algorithm */
    UNI_CRYPTO_HMAC_ALG_SHA256  = 1,  /*!< HMAC over SHA-256 */
    UNI_CRYPTO_HMAC_ALG_SHA1    = 2   /*!< HMAC over SHA-1 */
} uni_crypto_hmac_algorithm;



//
// Defines
//

/**
 * Error codes
 */
#define UNI_CRYPTO_HMAC_SUCCESS     0    /*!< Operation completed successfully */
#define UNI_CRYPTO_HMAC_EINVAL     (-1)  /*!< Invalid argument (NULL pointer, bad length, etc.) */
#define UNI_CRYPTO_HMAC_ESTATE     (-2)  /*!< Invalid state (e.g., context not initialized) */
#define UNI_CRYPTO_HMAC_EALGO      (-3)  /*!< Unsupported or invalid algorithm */
#define UNI_CRYPTO_HMAC_EINTERNAL  (-4)  /*!< Internal/backend error */
#define UNI_CRYPTO_HMAC_EBUFFER    (-5)  /*!< Output buffer too small */
#define UNI_CRYPTO_HMAC_EVERIFY    (-6)  /*!< Verification failed (constant-time compare mismatch) */

/**
 * @brief Size in bytes required to store an HMAC context in user-provided memory.
 */
#define UNI_CRYPTO_HMAC_CONTEXT_SIZE  (40u)



//
// Functions
//

/**
 * @brief Initialize a context object in caller-provided memory.
 *
 * @param[in]  buffer      Pointer to user-provided memory.
 * @param[in]  buffer_len  Size of the provided memory in bytes. Must be
 *                         at least UNI_CRYPTO_HMAC_CONTEXT_SIZE.
 * @param[out] out_ctx     On success, receives a pointer to the context view
 *                         within the provided buffer (not NULL).
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success.
 * @retval UNI_CRYPTO_HMAC_EINVAL  If buffer or out_ctx is NULL.
 * @retval UNI_CRYPTO_HMAC_EBUFFER If buffer_len is too small.
 *
 * Notes:
 *  - After this call, the context is constructed but not keyed. You must call
 *    uni_crypto_hmac_init(ctx, alg, key, key_len) before update/final/reset.
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_context_create_static(void* buffer, size_t buffer_len, uni_crypto_hmac_context** out_ctx);

/**
 * @brief Allocate a new HMAC context.
 *
 * @return Non-NULL pointer on success; NULL on allocation failure.
 *
 * @note
 *  - The returned context is uninitialized; call uni_crypto_hmac_init()
 *    before use, and uni_crypto_hmac_free() to release resources.
 */
UNI_CRYPTO_EXPORT uni_crypto_hmac_context* uni_crypto_hmac_create(void);

/**
 * @brief Release resources held by the context and zeroize sensitive material.
 *
 * @param[in,out] ctx  Context to free; NULL is allowed (no-op).
 *
 * After this call, the context memory is released and must not be used.
 */
UNI_CRYPTO_EXPORT void uni_crypto_hmac_free(uni_crypto_hmac_context* ctx);

/**
 * @brief Initialize an HMAC context for a specific algorithm and key.
 *
 * @param[in,out] ctx       Pointer to a context from uni_crypto_hmac_create() (not NULL).
 * @param[in]  alg          HMAC algorithm to use (e.g., UNI_CRYPTO_HMAC_ALG_SHA256).
 * @param[in]  key          Key bytes pointer (may be NULL only if key_len == 0).
 * @param[in]  key_len      Length of key in bytes (can be 0).
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success.
 * @retval UNI_CRYPTO_HMAC_EINVAL    If ctx is NULL, or key is NULL while key_len > 0.
 * @retval UNI_CRYPTO_HMAC_EALGO     If the algorithm is unsupported.
 * @retval UNI_CRYPTO_HMAC_EINTERNAL If the backend (mbedTLS) fails to initialize.
 *
 * Notes:
 *  - A zero-length key is valid per HMAC specification.
 *  - If ctx was already initialized, the context is safely re-initialized.
 *  - On success, ctx is ready to accept data via uni_crypto_hmac_update().
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_init(uni_crypto_hmac_context* ctx,
                         uni_crypto_hmac_algorithm alg,
                         const uint8_t* key,
                         size_t key_len);

/**
 * @brief Absorb message data into the HMAC computation.
 *
 * @param[in,out] ctx       Initialized context (not NULL).
 * @param[in]     data      Message bytes pointer (may be NULL if data_len == 0).
 * @param[in]     data_len  Number of bytes to process (can be 0).
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success.
 * @retval UNI_CRYPTO_HMAC_EINVAL   If ctx is NULL, or data is NULL while data_len > 0.
 * @retval UNI_CRYPTO_HMAC_ESTATE   If ctx is not initialized.
 * @retval UNI_CRYPTO_HMAC_EINTERNAL If the backend update fails.
 *
 * This function can be called multiple times to process streaming data.
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_update(uni_crypto_hmac_context* ctx,
                           const void* data,
                           size_t data_len);

/**
 * @brief Finalize the HMAC computation and write the tag to the output buffer.
 *
 * @param[in,out] ctx          Initialized context (not NULL).
 * @param[out]    out_tag      Buffer to receive the authentication tag (not NULL).
 * @param[in]     out_tag_len  Size of the output buffer in bytes.
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success.
 * @retval UNI_CRYPTO_HMAC_EINVAL   If ctx or out_tag is NULL.
 * @retval UNI_CRYPTO_HMAC_ESTATE   If ctx is not initialized.
 * @retval UNI_CRYPTO_HMAC_EBUFFER  If out_tag_len is smaller than the algorithm's digest size.
 * @retval UNI_CRYPTO_HMAC_EINTERNAL If the backend finalization fails.
 *
 * Notes:
 *  - Exactly uni_crypto_hmac_digest_size() bytes are written to out_tag on success.
 *  - After final, the context remains associated with the same key and algorithm
 *    and can be re-used for a new message by calling uni_crypto_hmac_reset().
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_final(uni_crypto_hmac_context* ctx,
                          uint8_t* out_tag,
                          size_t out_tag_len);

/**
 * @brief Reset the HMAC context to the initial state preserving the key.
 *
 * @param[in,out] ctx  Initialized context (not NULL).
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success.
 * @retval UNI_CRYPTO_HMAC_EINVAL   If ctx is NULL.
 * @retval UNI_CRYPTO_HMAC_ESTATE   If ctx is not initialized.
 * @retval UNI_CRYPTO_HMAC_EINTERNAL If the backend reset fails.
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_reset(uni_crypto_hmac_context* ctx);

/**
 * @brief Compute an HMAC in one shot.
 *
 * @param[in]  alg           HMAC algorithm.
 * @param[in]  key           Key pointer (may be NULL if key_len == 0).
 * @param[in]  key_len       Key length in bytes.
 * @param[in]  data          Message data pointer (may be NULL if data_len == 0).
 * @param[in]  data_len      Message length in bytes.
 * @param[out] out_tag       Output buffer for the tag (not NULL).
 * @param[in]  out_tag_len   Size of out_tag; must be >= digest size for alg.
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS on success or a negative error code on failure.
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_compute(uni_crypto_hmac_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const void* data, size_t data_len,
                            uint8_t* out_tag, size_t out_tag_len);

/**
 * @brief Constant-time verification of an expected HMAC tag.
 *
 * This helper computes HMAC(key, data) and compares it to expected_tag in
 * constant-time over expected_tag_len bytes. Truncated tags are supported:
 * expected_tag_len must be > 0 and <= digest size for the algorithm.
 *
 * @param[in] alg                HMAC algorithm.
 * @param[in] key                Key pointer (may be NULL if key_len == 0).
 * @param[in] key_len            Key length in bytes.
 * @param[in] data               Message pointer (may be NULL if data_len == 0).
 * @param[in] data_len           Message length in bytes.
 * @param[in] expected_tag       Expected tag bytes (not NULL).
 * @param[in] expected_tag_len   Number of bytes to compare (1..digest_size).
 *
 * @return UNI_CRYPTO_HMAC_SUCCESS if tags match.
 * @retval UNI_CRYPTO_HMAC_EINVAL   If expected_tag is NULL, or expected_tag_len == 0.
 * @retval UNI_CRYPTO_HMAC_EALGO    If algorithm is invalid or unsupported.
 * @retval UNI_CRYPTO_HMAC_EBUFFER  If expected_tag_len > digest size.
 * @retval UNI_CRYPTO_HMAC_EVERIFY  If tags do not match (constant-time).
 * @retval negative                 Other errors from compute/init/update/final.
 */
UNI_CRYPTO_EXPORT int uni_crypto_hmac_verify(uni_crypto_hmac_algorithm alg,
                           const uint8_t* key, size_t key_len,
                           const void* data, size_t data_len,
                           const uint8_t* expected_tag, size_t expected_tag_len);

/**
 * @brief Get the HMAC digest size (in bytes) for an algorithm.
 *
 * @param[in] alg  Algorithm identifier.
 * @return Digest size in bytes; 0 if alg is invalid/unsupported.
 */
UNI_CRYPTO_EXPORT size_t uni_crypto_hmac_digest_size(uni_crypto_hmac_algorithm alg);

/**
 * @brief Get the HMAC block size (in bytes) for an algorithm.
 *
 * @param[in] alg  Algorithm identifier.
 * @return Block size in bytes; 0 if alg is invalid/unsupported.
 */
UNI_CRYPTO_EXPORT size_t uni_crypto_hmac_block_size(uni_crypto_hmac_algorithm alg);

#ifdef __cplusplus
} /* extern "C" */
#endif
