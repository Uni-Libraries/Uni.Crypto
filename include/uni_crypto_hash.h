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

/**
 * Streaming hash state for data that does not fit in memory or arrives in pieces.
 *
 * Lifetime: uni_crypto_hash_create() -> any number of uni_crypto_hash_update() ->
 * uni_crypto_hash_final() -> uni_crypto_hash_free(). A context produces one digest; create a new
 * one for the next message. A context must not be used concurrently by multiple threads.
 */
typedef struct uni_crypto_hash_context uni_crypto_hash_context;

/**
 * Allocate a context and start hashing with @p alg.
 *
 * @return the context, or NULL when the algorithm is unknown or allocation fails
 */
UNI_CRYPTO_EXPORT uni_crypto_hash_context* uni_crypto_hash_create(uni_crypto_hash_algorithm alg);

/**
 * Hash the next @p data_len bytes.
 *
 * @return UNI_CRYPTO_HASH_SUCCESS; UNI_CRYPTO_HASH_EINVAL for a NULL context, NULL data with a
 *         non-zero length or a context that is already finalized; UNI_CRYPTO_HASH_EINTERNAL when
 *         the backend fails
 */
UNI_CRYPTO_EXPORT int uni_crypto_hash_update(uni_crypto_hash_context* ctx, const void* data, size_t data_len);

/**
 * Finish the message and write its digest.
 *
 * @param out_digest_len at least uni_crypto_hash_digest_size() of the context's algorithm
 * @return UNI_CRYPTO_HASH_SUCCESS; UNI_CRYPTO_HASH_EINVAL for a NULL argument or a context that is
 *         already finalized; UNI_CRYPTO_HASH_EBUFFER when the output is too small (the context
 *         stays usable); UNI_CRYPTO_HASH_EINTERNAL when the backend fails
 */
UNI_CRYPTO_EXPORT int uni_crypto_hash_final(uni_crypto_hash_context* ctx, uint8_t* out_digest, size_t out_digest_len);

/** Release a context; NULL is allowed. */
UNI_CRYPTO_EXPORT void uni_crypto_hash_free(uni_crypto_hash_context* ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
