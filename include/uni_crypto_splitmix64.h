// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Includes
//

#include <stdint.h>



//
// Typedefs
//

/**
 * SplitMix64 generator state.
 *
 * For reproducible test signals and simulations: the same seed gives the same sequence on every
 * platform and standard library. It is NOT cryptographically secure; use uni_crypto_random.h for
 * keys, nonces and anything an attacker must not predict.
 */
typedef struct {
    uint64_t state;
} uni_crypto_splitmix64_t;



//
// Functions
//

/** Start the sequence of @p seed. */
static inline void uni_crypto_splitmix64_seed(uni_crypto_splitmix64_t* generator, uint64_t seed) {
    generator->state = seed;
}

/** Next 64 uniformly distributed bits. */
static inline uint64_t uni_crypto_splitmix64_next(uni_crypto_splitmix64_t* generator) {
    generator->state += UINT64_C(0x9E3779B97F4A7C15);
    uint64_t value = generator->state;
    value = (value ^ (value >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94D049BB133111EB);
    return value ^ (value >> 31U);
}

/** Uniform double in (0, 1]: never zero, so it is safe as a logarithm argument. */
static inline double uni_crypto_splitmix64_next_unit_open(uni_crypto_splitmix64_t* generator) {
    return ((double)(uni_crypto_splitmix64_next(generator) >> 11U) + 1.0) * (1.0 / 9007199254740992.0);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
