#pragma once

#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA1_C

/* Ensure SHA-1 is available through PSA-backed paths when enabled */
#define PSA_WANT_ALG_SHA_1 1
#define PSA_WANT_ALG_HMAC  1
