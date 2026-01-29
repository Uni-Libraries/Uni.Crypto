// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

//
// Includes
//

// mbedtls
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// stdlib
#include <string.h>

// uni.crypto
#include "uni_crypto_random.h"



//
// Functions
//

bool uni_crypto_random_fill(uint8_t* data, size_t data_len){
    if(data == NULL || data_len == 0U){
        return false;
    }

    int rc = -1;

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_CTR_DRBG_C)
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char* pers = "uni_crypto_random";
    rc = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)pers,
        strlen(pers)
    );
    if(rc == 0){
        rc = mbedtls_ctr_drbg_random(&ctr_drbg, (unsigned char*)data, data_len);
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
#else
    /* Fallback: fill directly from entropy source.
       Note: this is not a deterministic DRBG and depends entirely on
       mbedTLS entropy sources configured for the platform. */
    rc = mbedtls_entropy_func(&entropy, (unsigned char*)data, data_len);
#endif

    mbedtls_entropy_free(&entropy);
    return (rc == 0);
}
