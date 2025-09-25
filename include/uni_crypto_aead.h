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
int uni_crypto_aead_encrypt(uni_crypto_aead_algorithm alg,
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
int uni_crypto_aead_decrypt(uni_crypto_aead_algorithm alg,
                            const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            const uint8_t* expected_tag, size_t expected_tag_len,
                            uint8_t* plaintext_out);

/**
 * @brief Helper utilities for AEAD configuration.
 */

/**
 * @brief Returns the recommended nonce length for an algorithm.
 * @param alg AEAD algorithm identifier.
 * @return Recommended nonce length in bytes, or 0 if unspecified.
 */
size_t uni_crypto_aead_recommended_nonce_len(uni_crypto_aead_algorithm alg);

/**
 * @brief Returns the maximum tag length for an algorithm.
 * @param alg AEAD algorithm identifier.
 * @return Maximum authentication tag length in bytes, or 0 if the algorithm is invalid.
 */
size_t uni_crypto_aead_max_tag_len(uni_crypto_aead_algorithm alg);

#ifdef __cplusplus
} /* extern "C" */
#endif
