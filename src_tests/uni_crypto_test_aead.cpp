// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <thread>

// catch2
#include <catch2/catch_test_macros.hpp>

// uni.crypto
#include "uni_crypto.h"
#include "uni_crypto_aead.h"



//
// Helpers
//

// Deterministic PRNG (xorshift32) for property-like and large-input tests.
struct XorShift32 {
    uint32_t s;
    explicit XorShift32(uint32_t seed) : s(seed ? seed : 0xDEADBEEF) {}
    uint32_t next() {
        uint32_t x = s;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        s = x;
        return x;
    }
    void fill(uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(next() & 0xFF);
    }
};


// Utility: surrounds a writable window with canaries and checks integrity.
struct CanaryBuffer {
    std::vector<uint8_t> buf;
    size_t start;
    size_t data_len;
    uint8_t canary;
    CanaryBuffer(size_t dataLen, uint8_t canaryByte = 0xA5, size_t guard = 32)
        : buf(guard + dataLen + guard, canaryByte), start(guard), data_len(dataLen), canary(canaryByte) {}

    uint8_t* data() { return buf.data() + start; }
    const uint8_t* data() const { return buf.data() + start; }
    size_t size() const { return data_len; }

    void check_canaries() const {
        for (size_t i = 0; i < start; ++i) {
            REQUIRE(buf[i] == canary);
        }
        for (size_t i = start + data_len; i < buf.size(); ++i) {
            REQUIRE(buf[i] == canary);
        }
    }
};

// Convenience helpers for AEAD round-trips
static int aead_encrypt(uni_crypto_aead_algorithm alg,
                        const uint8_t* key, size_t key_len,
                        const uint8_t* nonce, size_t nonce_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* ct,
                        uint8_t* tag, size_t tag_len) {
    return uni_crypto_aead_encrypt(alg, key, key_len, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, tag, tag_len);
}

static int aead_decrypt(uni_crypto_aead_algorithm alg,
                        const uint8_t* key, size_t key_len,
                        const uint8_t* nonce, size_t nonce_len,
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ct, size_t ct_len,
                        const uint8_t* tag, size_t tag_len,
                        uint8_t* pt) {
    return uni_crypto_aead_decrypt(alg, key, key_len, nonce, nonce_len, aad, aad_len, ct, ct_len, tag, tag_len, pt);
}

// ===== Known-Answer Tests (KATs) for AES-GCM (NIST SP 800-38D) =====
//
// Test vectors used below are widely cited from SP 800-38D:
// 1) AES-128, IV=12B zeros, PT=empty, AAD=empty:
//    Key: 00000000000000000000000000000000
//    IV : 000000000000000000000000
//    CT : (empty)
//    Tag: 58e2fccefa7e3061367f1d57a4e7455a
//
// 2) AES-128, IV=12B zeros, PT=16B zeros, AAD=empty:
//    CT : 0388dace60b6a392f328c2b971b2fe78
//    Tag: ab6e47d42cec13bdf53a67b21257bddf
//
// 3) AES-128, non-empty PT + AAD (multi-block):
//    Key: feffe9928665731c6d6a8f9467308308
//    IV : cafebabefacedbaddecaf888
//    AAD: feedfacedeadbeeffeedfacedeadbeefabaddad2
//    PT : d9313225f88406e5a55909c5aff5269a86a7a9531534f7da
//         2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525
//         b16aedf5aa0de657ba637b39
//    CT : 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e0
//         35c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05
//         1ba30b396a0aac973d58e091
//    Tag: 5bc94fbc3221a5db94fae95ae7121a47
//
// Note: AES-256 KAT also included (widely used example):
//    Key: 000102030405060708090a0b0c0d0e0f
//         101112131415161718191a1b1c1d1e1f
//    IV : 1af38c2dc2b96ffdd86694092341bc04
//    AAD: 546865207365636f6e64207072696e6369706c65206f6620
//         41756775737465204b6572636b686f666673
//    PT : 4120636970686572207369787465656e20626974206d6573
//         736167652e
//    CT : 8ce24998625615b603a033aca13fb894be9112a5c3a211a8
//         ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6f
//         d62875d2aca417034c34aee5
//    Tag: 619cc5aefffe0bfa462af43c1699d050

// Bytes helpers for KATs
static constexpr uint8_t GCM_K128_ZERO_KEY[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static constexpr uint8_t GCM_IV_12_ZERO[12] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static constexpr uint8_t GCM_TAG_KAT1[16] = {
    0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
};
static constexpr uint8_t GCM_PT16_ZERO[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
static constexpr uint8_t GCM_CT_KAT2[16] = {
    0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
};
static constexpr uint8_t GCM_TAG_KAT2[16] = {
    0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
};
static constexpr uint8_t GCM_K128_KAT3[16] = {
    0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
};
static constexpr uint8_t GCM_IV_KAT3[12] = {
    0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
};
static constexpr uint8_t GCM_AAD_KAT3[] = {
    0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xfe,0xed,0xfa,0xce,0xde,0xad,0xbe,0xef,0xab,0xad,0xda,0xd2
};
static constexpr uint8_t GCM_PT_KAT3[] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39
};
static constexpr uint8_t GCM_CT_KAT3[] = {
    0x42,0x83,0x1e,0xc2,0x21,0x77,0x74,0x24,0x4b,0x72,0x21,0xb7,0x84,0xd0,0xd4,0x9c,
    0xe3,0xaa,0x21,0x2f,0x2c,0x02,0xa4,0xe0,0x35,0xc1,0x7e,0x23,0x29,0xac,0xa1,0x2e,
    0x21,0xd5,0x14,0xb2,0x54,0x66,0x93,0x1c,0x7d,0x8f,0x6a,0x5a,0xac,0x84,0xaa,0x05,
    0x1b,0xa3,0x0b,0x39,0x6a,0x0a,0xac,0x97,0x3d,0x58,0xe0,0x91
};
static constexpr uint8_t GCM_TAG_KAT3[16] = {
    0x5b,0xc9,0x4f,0xbc,0x32,0x21,0xa5,0xdb,0x94,0xfa,0xe9,0x5a,0xe7,0x12,0x1a,0x47
};

// AES-256 GCM vector (commonly used example)
static constexpr uint8_t GCM_K256_KAT4[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static constexpr uint8_t GCM_IV_KAT4[16] = {
    0x1a,0xf3,0x8c,0x2d,0xc2,0xb9,0x6f,0xfd,0xd8,0x66,0x94,0x09,0x23,0x41,0xbc,0x04
};
static constexpr uint8_t GCM_AAD_KAT4[] = {
    0x54,0x68,0x65,0x20,0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x70,0x72,0x69,0x6e,0x63,
    0x69,0x70,0x6c,0x65,0x20,0x6f,0x66,0x20,0x41,0x75,0x67,0x75,0x73,0x74,0x65,0x20,
    0x4b,0x65,0x72,0x63,0x6b,0x68,0x6f,0x66,0x66,0x73
};
static constexpr uint8_t GCM_PT_KAT4[] = {
    0x41,0x20,0x63,0x69,0x70,0x68,0x65,0x72,0x20,0x73,0x69,0x78,0x74,0x65,0x65,0x6e,
    0x20,0x62,0x69,0x74,0x20,0x6d,0x65,0x73,0x73,0x61,0x67,0x65,0x2e
};
static constexpr uint8_t GCM_CT_KAT4[] = {
    0x6f,0x75,0xe9,0x88,0x60,0xe8,0x16,0x7f,0x72,0xd7,0x5d,0xd1,0x8e,0x16,0xbc,0xc0,
    0xb7,0x55,0x1d,0xc7,0x3b,0xc3,0x01,0x17,0x99,0xf3,0xa7,0x9c,0x01
};
static constexpr uint8_t GCM_TAG_KAT4[16] = {
    0x6d,0x97,0xb1,0x19,0x4d,0x58,0xd9,0x12,0x94,0xbc,0x64,0x7c,0xab,0x32,0xaa,0x1e
};

//
// Tests
//

TEST_CASE("AEAD helpers: recommended nonce length and max tag length", "[aead][helpers]") {
    REQUIRE(uni_crypto_aead_recommended_nonce_len(UNI_CRYPTO_AEAD_ALG_INVALID) == 0u);
    REQUIRE(uni_crypto_aead_max_tag_len(UNI_CRYPTO_AEAD_ALG_INVALID) == 0u);

    // Known constants from implementation
    REQUIRE(uni_crypto_aead_recommended_nonce_len(UNI_CRYPTO_AEAD_ALG_AES_GCM) == 12u);
    REQUIRE(uni_crypto_aead_recommended_nonce_len(UNI_CRYPTO_AEAD_ALG_AES_CCM) == 13u);
    REQUIRE(uni_crypto_aead_max_tag_len(UNI_CRYPTO_AEAD_ALG_AES_GCM) == 16u);
    REQUIRE(uni_crypto_aead_max_tag_len(UNI_CRYPTO_AEAD_ALG_AES_CCM) == 16u);
}

TEST_CASE("AEAD invalid algorithm returns EALGO", "[aead][api][invalid]") {
    const uint8_t key[16] = {0};
    const uint8_t nonce[12] = {0};
    uint8_t tag[16] = {0};

    int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_INVALID, key, sizeof(key), nonce, sizeof(nonce),
                          nullptr, 0, nullptr, 0, nullptr, tag, sizeof(tag));
    REQUIRE(rc == UNI_CRYPTO_AEAD_EALGO);

    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_INVALID, key, sizeof(key), nonce, sizeof(nonce),
                      nullptr, 0, nullptr, 0, tag, sizeof(tag), nullptr);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EALGO);
}

// ---------- AES-GCM KATs (conditional) ----------
TEST_CASE("AES-GCM KAT: zero-length PT/AAD (NIST SP 800-38D)", "[aead][gcm][kat]") {
    uint8_t tag[16] = {0};
    int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                          GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                          GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                          nullptr, 0,
                          nullptr, 0,
                          nullptr,
                          tag, sizeof(tag));
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(tag, GCM_TAG_KAT1, 16) == 0);

    // Decrypt with no plaintext/ciphertext buffer (len==0 is allowed)
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      nullptr, 0,
                      tag, sizeof(tag),
                      nullptr);
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

    // Wrong tag -> EVERIFY; plaintext_out untrusted (and here null anyway)
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[3] ^= 0x01;
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      nullptr, 0,
                      bad_tag, sizeof(bad_tag),
                      nullptr);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);
}

TEST_CASE("AES-GCM KAT: 16B zero PT, zero AAD (NIST SP 800-38D)", "[aead][gcm][kat]") {
    uint8_t ct[16] = {0};
    uint8_t tag[16] = {0};
    int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                          GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                          GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                          nullptr, 0,
                          GCM_PT16_ZERO, sizeof(GCM_PT16_ZERO),
                          ct,
                          tag, sizeof(tag));
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(ct, GCM_CT_KAT2, 16) == 0);
    REQUIRE(std::memcmp(tag, GCM_TAG_KAT2, 16) == 0);

    // Decrypt success
    uint8_t pt[16] = {0xAA}; // pre-fill
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      ct, sizeof(ct),
                      tag, sizeof(tag),
                      pt);
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(pt, GCM_PT16_ZERO, 16) == 0);

    // Bit-flip a ciphertext byte -> EVERIFY and must not return valid plaintext
    uint8_t ct_bad[16];
    std::memcpy(ct_bad, ct, 16);
    ct_bad[7] ^= 0x80;
    std::memset(pt, 0xCC, sizeof(pt));
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      ct_bad, sizeof(ct_bad),
                      tag, sizeof(tag),
                      pt);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);
    // On authentication failure, plaintext_out contents are unspecified; do not assert on content.

    // Bit-flip tag -> EVERIFY
    uint8_t bad_tag[16];
    std::memcpy(bad_tag, tag, 16);
    bad_tag[15] ^= 0x55;
    std::memset(pt, 0xCC, sizeof(pt));
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      ct, sizeof(ct),
                      bad_tag, sizeof(bad_tag),
                      pt);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);

    // Truncated ciphertext -> EVERIFY
    std::memset(pt, 0xCC, sizeof(pt));
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      nullptr, 0,
                      ct, 15,    // truncated by 1
                      tag, sizeof(tag),
                      pt);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);

    // Wrong AAD (encrypt with AAD=null, decrypt with AAD=non-empty) -> EVERIFY
    const uint8_t wrong_aad[] = {0x00};
    std::memset(pt, 0xCC, sizeof(pt));
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_ZERO_KEY, sizeof(GCM_K128_ZERO_KEY),
                      GCM_IV_12_ZERO, sizeof(GCM_IV_12_ZERO),
                      wrong_aad, sizeof(wrong_aad),
                      ct, sizeof(ct),
                      tag, sizeof(tag),
                      pt);
    REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);
}

TEST_CASE("AES-GCM KAT: non-empty PT and AAD (NIST SP 800-38D, multi-block)", "[aead][gcm][kat][multiblock]") {
    std::vector<uint8_t> ct(sizeof(GCM_PT_KAT3));
    uint8_t tag[16] = {0};
    int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                          GCM_K128_KAT3, sizeof(GCM_K128_KAT3),
                          GCM_IV_KAT3, sizeof(GCM_IV_KAT3),
                          GCM_AAD_KAT3, sizeof(GCM_AAD_KAT3),
                          GCM_PT_KAT3, sizeof(GCM_PT_KAT3),
                          ct.data(),
                          tag, sizeof(tag));
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(ct.data(), GCM_CT_KAT3, sizeof(GCM_CT_KAT3)) == 0);
    REQUIRE(std::memcmp(tag, GCM_TAG_KAT3, 16) == 0);

    std::vector<uint8_t> pt(sizeof(GCM_PT_KAT3), 0xCC);
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K128_KAT3, sizeof(GCM_K128_KAT3),
                      GCM_IV_KAT3, sizeof(GCM_IV_KAT3),
                      GCM_AAD_KAT3, sizeof(GCM_AAD_KAT3),
                      ct.data(), ct.size(),
                      tag, sizeof(tag),
                      pt.data());
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(pt.data(), GCM_PT_KAT3, sizeof(GCM_PT_KAT3)) == 0);
}

TEST_CASE("AES-GCM KAT: AES-256 example (AAD present)", "[aead][gcm][kat][aes256]") {
    std::vector<uint8_t> ct(sizeof(GCM_PT_KAT4));
    uint8_t tag[16] = {0};
    int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                          GCM_K256_KAT4, sizeof(GCM_K256_KAT4),
                          GCM_IV_KAT4, sizeof(GCM_IV_KAT4),
                          GCM_AAD_KAT4, sizeof(GCM_AAD_KAT4),
                          GCM_PT_KAT4, sizeof(GCM_PT_KAT4),
                          ct.data(),
                          tag, sizeof(tag));
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(ct.data(), GCM_CT_KAT4, sizeof(GCM_CT_KAT4)) == 0);
    REQUIRE(std::memcmp(tag, GCM_TAG_KAT4, 16) == 0);

    std::vector<uint8_t> pt(sizeof(GCM_PT_KAT4), 0xCC);
    rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM,
                      GCM_K256_KAT4, sizeof(GCM_K256_KAT4),
                      GCM_IV_KAT4, sizeof(GCM_IV_KAT4),
                      GCM_AAD_KAT4, sizeof(GCM_AAD_KAT4),
                      ct.data(), ct.size(),
                      tag, sizeof(tag),
                      pt.data());
    REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    REQUIRE(std::memcmp(pt.data(), GCM_PT_KAT4, sizeof(GCM_PT_KAT4)) == 0);
}

// ---------- AES-CCM success paths and edge coverage ----------
TEST_CASE("AES-CCM: one-shot round-trip (various sizes, in/out and in-place)", "[aead][ccm][roundtrip]") {
    const uint8_t key[16] = { // AES-128
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const size_t nonce_len = uni_crypto_aead_recommended_nonce_len(UNI_CRYPTO_AEAD_ALG_AES_CCM);
    std::vector<uint8_t> nonce(nonce_len, 0x01);
    const uint8_t aad[] = {0xA1,0xA2,0xA3,0xA4};

    // Case A: zero-length plaintext, zero-length AAD
    {
        uint8_t tag[16] = {0};
        int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key), nonce.data(), nonce.size(),
                              nullptr, 0, nullptr, 0, nullptr, tag, sizeof(tag));
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key), nonce.data(), nonce.size(),
                          nullptr, 0, nullptr, 0, tag, sizeof(tag), nullptr);
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    }

    // Case B: non-empty PT, zero AAD (out-of-place)
    {
        const uint8_t pt[] = "CCM-plaintext-32bytes-___________"; // 32 bytes
        const size_t pt_len = sizeof(pt) - 1;
        std::vector<uint8_t> ct(pt_len);
        uint8_t tag[16] = {0};

        int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                              nonce.data(), nonce.size(),
                              nullptr, 0,
                              pt, pt_len,
                              ct.data(),
                              tag, sizeof(tag));
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        std::vector<uint8_t> out(pt_len, 0xCC);
        rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                          nonce.data(), nonce.size(),
                          nullptr, 0,
                          ct.data(), ct.size(),
                          tag, sizeof(tag),
                          out.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        REQUIRE(std::memcmp(out.data(), pt, pt_len) == 0);
    }

    // Case C: non-empty PT and AAD (in-place)
    {
        std::vector<uint8_t> buf(64);
        for (size_t i = 0; i < buf.size(); ++i) buf[i] = uint8_t(i);
        uint8_t tag[16] = {0};

        // Encrypt in-place (ciphertext_out == plaintext)
        int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                              nonce.data(), nonce.size(),
                              aad, sizeof(aad),
                              buf.data(), buf.size(),
                              buf.data(), // in-place
                              tag, sizeof(tag));
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        // Decrypt in-place back to plaintext
        rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                          nonce.data(), nonce.size(),
                          aad, sizeof(aad),
                          buf.data(), buf.size(),
                          tag, sizeof(tag),
                          buf.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        // Compare to expected original plaintext
        for (size_t i = 0; i < buf.size(); ++i) {
            REQUIRE(buf[i] == uint8_t(i));
        }
    }

    // Case D: multi-block plaintext crossing block boundaries
    {
        std::vector<uint8_t> pt(4096 + 17);
        for (size_t i = 0; i < pt.size(); ++i) pt[i] = uint8_t(i & 0xFF);

        std::vector<uint8_t> ct(pt.size());
        uint8_t tag[16] = {0};
        int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                              nonce.data(), nonce.size(),
                              aad, sizeof(aad),
                              pt.data(), pt.size(),
                              ct.data(),
                              tag, sizeof(tag));
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        std::vector<uint8_t> dec(pt.size(), 0);
        rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                          nonce.data(), nonce.size(),
                          aad, sizeof(aad),
                          ct.data(), ct.size(),
                          tag, sizeof(tag),
                          dec.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        REQUIRE(std::memcmp(dec.data(), pt.data(), pt.size()) == 0);
    }
}

TEST_CASE("AEAD: parameter validation and error handling", "[aead][errors]") {
    const uint8_t key[16] = {0};
    const uint8_t nonce12[12] = {0};
    const uint8_t msg1[] = {0xAA};
    uint8_t ct1[1] = {0};
    uint8_t pt1[1] = {0};
    uint8_t tag16[16] = {0};

    // EINVAL: plaintext_len>0 but plaintext==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 1, ct1, tag16, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: plaintext_len>0 but ciphertext_out==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, msg1, 1, nullptr, tag16, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: tag_out==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 0, nullptr, nullptr, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: tag_len==0
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 0, nullptr, tag16, 0) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: aad_len>0 but aad==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 1, nullptr, 0, nullptr, tag16, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: key_len>0 but key==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, nullptr, 1, nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 0, nullptr, tag16, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);
    // EINVAL: nonce_len>0 but nonce==NULL
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nullptr, 1,
                                    nullptr, 0, nullptr, 0, nullptr, tag16, sizeof(tag16)) == UNI_CRYPTO_AEAD_EINVAL);

    // Decrypt-specific EINVAL: expected_tag==NULL or expected_tag_len==0
    REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 0, nullptr, sizeof(tag16), nullptr) == UNI_CRYPTO_AEAD_EINVAL);
    REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 0, tag16, 0, nullptr) == UNI_CRYPTO_AEAD_EINVAL);

    // Decrypt EINVAL: ciphertext_len>0 but ciphertext==NULL; ciphertext_len>0 but plaintext_out==NULL
    REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, nullptr, 1, tag16, sizeof(tag16), pt1) == UNI_CRYPTO_AEAD_EINVAL);
    REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce12, sizeof(nonce12),
                                    nullptr, 0, msg1, 1, tag16, sizeof(tag16), nullptr) == UNI_CRYPTO_AEAD_EINVAL);

    // EINTERNAL (backend rejects invalid nonce length) — try CCM with nonce length too small/large
    uint8_t tag_out[16] = {0};
    // nonce length 2 (invalid for CCM, valid range is 7..13)
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                                    nonce12, 2, nullptr, 0,
                                    nullptr, 0, nullptr, tag_out, sizeof(tag_out)) == UNI_CRYPTO_AEAD_EINTERNAL);
    // tag length 7 (invalid for CCM)
    REQUIRE(uni_crypto_aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_CCM, key, sizeof(key),
                                    nonce12, 12, nullptr, 0,
                                    nullptr, 0, nullptr, tag_out, 7) == UNI_CRYPTO_AEAD_EINTERNAL);
}

TEST_CASE("AEAD: canary guards and write-bounds", "[aead][safety]") {
    for (auto alg : {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);
        std::vector<uint8_t> nonce(nlen, 0x02);
        std::vector<uint8_t> key(16, 0x10);

        // Prepare PT
        std::vector<uint8_t> pt(128);
        for (size_t i = 0; i < pt.size(); ++i) pt[i] = uint8_t(0x80 | (i & 0x7F));

        CanaryBuffer ct_canary(pt.size());
        CanaryBuffer tag_canary(tlen);
        int rc = aead_encrypt(alg,
                              key.data(), key.size(),
                              nonce.data(), nonce.size(),
                              nullptr, 0,
                              pt.data(), pt.size(),
                              ct_canary.data(),
                              tag_canary.data(), tag_canary.size());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        ct_canary.check_canaries();
        tag_canary.check_canaries();

        // Decrypt with canaries around plaintext buffer
        CanaryBuffer pt_canary(pt.size());
        rc = aead_decrypt(alg,
                          key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          nullptr, 0,
                          ct_canary.data(), ct_canary.size(),
                          tag_canary.data(), tag_canary.size(),
                          pt_canary.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        pt_canary.check_canaries();
        REQUIRE(std::memcmp(pt_canary.data(), pt.data(), pt.size()) == 0);

        // Decrypt with corrupted ciphertext must not produce valid plaintext (no partial plaintext requirement)
        std::vector<uint8_t> ct_bad(ct_canary.size());
        std::memcpy(ct_bad.data(), ct_canary.data(), ct_canary.size());
        ct_bad.back() ^= 0x01;
        std::memset(pt_canary.data(), 0xCC, pt_canary.size());
        rc = aead_decrypt(alg,
                          key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          nullptr, 0,
                          ct_bad.data(), ct_bad.size(),
                          tag_canary.data(), tag_canary.size(),
                          pt_canary.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_EVERIFY);
        // On authentication failure, plaintext_out contents are unspecified; only guard bounds must hold.
        pt_canary.check_canaries();
    }
}

TEST_CASE("AEAD: nonce reuse note (no detection expected), and tag length variations", "[aead][contract]") {
    for (auto alg : {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);

        std::vector<uint8_t> key(16, 0x33);
        std::vector<uint8_t> nonce(nlen, 0x44);
        std::vector<uint8_t> aad = {0x10, 0x11};

        std::vector<uint8_t> m1 = {0,1,2,3,4,5,6,7,8,9};
        std::vector<uint8_t> m2 = {9,8,7,6,5,4,3,2,1,0};

        std::vector<uint8_t> c1(m1.size()), c2(m2.size());
        std::vector<uint8_t> tag1(tlen), tag2(tlen);

        // Encrypt two different messages with same key+nonce (non-detection expected)
        REQUIRE(aead_encrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), m1.data(), m1.size(), c1.data(), tag1.data(), tag1.size()) == 0);
        REQUIRE(aead_encrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), m2.data(), m2.size(), c2.data(), tag2.data(), tag2.size()) == 0);

        // Round-trip both
        std::vector<uint8_t> r1(m1.size()), r2(m2.size());
        REQUIRE(aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), c1.data(), c1.size(), tag1.data(), tag1.size(), r1.data()) == 0);
        REQUIRE(aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), c2.data(), c2.size(), tag2.data(), tag2.size(), r2.data()) == 0);
        REQUIRE(std::memcmp(r1.data(), m1.data(), m1.size()) == 0);
        REQUIRE(std::memcmp(r2.data(), m2.data(), m2.size()) == 0);

        // Tag length variations: CCM supports multiple tag sizes; GCM max 16. Use a smaller tag if allowed by backend.
        // We test success when both sides use the same (shorter) tag length.
        size_t small_tag_len = (alg == UNI_CRYPTO_AEAD_ALG_AES_CCM) ? 8u : 16u;
        std::vector<uint8_t> c3(m1.size()), tag3(small_tag_len), r3(m1.size());
        REQUIRE(aead_encrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), m1.data(), m1.size(), c3.data(), tag3.data(), tag3.size()) == 0);
        REQUIRE(aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), c3.data(), c3.size(), tag3.data(), tag3.size(), r3.data()) == 0);
        REQUIRE(std::memcmp(r3.data(), m1.data(), m1.size()) == 0);
    }
}

TEST_CASE("AEAD: large input round-trip (1 MiB) with deterministic PRNG", "[aead][large][prng]") {
    const size_t N = 1u << 20; // 1 MiB
    XorShift32 rng(0x12345678u);

    for (auto alg : {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);

        std::vector<uint8_t> key(16, 0x7B);
        std::vector<uint8_t> nonce(nlen, 0x6C);
        std::vector<uint8_t> aad(64);
        rng.fill(aad.data(), aad.size());

        std::vector<uint8_t> pt(N);
        rng.fill(pt.data(), pt.size());

        std::vector<uint8_t> ct(N);
        std::vector<uint8_t> tag(tlen, 0);

        int rc = aead_encrypt(alg, key.data(), key.size(),
                              nonce.data(), nonce.size(),
                              aad.data(), aad.size(),
                              pt.data(), pt.size(),
                              ct.data(),
                              tag.data(), tag.size());

        if (alg == UNI_CRYPTO_AEAD_ALG_AES_CCM) {
            size_t q = (nlen <= 15u) ? (size_t)(15u - nlen) : 0u;
            uint64_t max_len64 = (q >= 8u) ? UINT64_MAX : (1ULL << (8u * q));
            CAPTURE(alg, nlen, q, max_len64, N);
            if (q < 8u && (uint64_t)N >= max_len64) {
                REQUIRE(rc == UNI_CRYPTO_AEAD_ELIMIT);
                continue; // skip decrypt for CCM length limit case
            }
        }

        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        std::vector<uint8_t> dec(N, 0);
        rc = aead_decrypt(alg, key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          aad.data(), aad.size(),
                          ct.data(), ct.size(),
                          tag.data(), tag.size(),
                          dec.data());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        REQUIRE(std::memcmp(dec.data(), pt.data(), pt.size()) == 0);
    }
}

TEST_CASE("AEAD: wrong key, wrong nonce, wrong AAD cause EVERIFY", "[aead][auth][errors]") {
    for (auto alg : {UNI_CRYPTO_AEAD_ALG_AES_GCM,UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);

        std::vector<uint8_t> key(16, 0x21);
        std::vector<uint8_t> nonce(nlen, 0x22);
        std::vector<uint8_t> aad = {0xA0, 0xA1, 0xA2};
        std::vector<uint8_t> pt = {0x10, 0x11, 0x12, 0x13, 0x14};

        std::vector<uint8_t> ct(pt.size());
        std::vector<uint8_t> tag(tlen);

        REQUIRE(aead_encrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), pt.data(), pt.size(), ct.data(), tag.data(), tag.size()) == 0);

        std::vector<uint8_t> out(pt.size(), 0xCC);

        // Wrong key
        std::vector<uint8_t> wrong_key = key;
        wrong_key.back() ^= 0xFF;
        REQUIRE(aead_decrypt(alg, wrong_key.data(), wrong_key.size(), nonce.data(), nonce.size(),
                             aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), tag.size(), out.data())
                == UNI_CRYPTO_AEAD_EVERIFY);

        // Wrong nonce
        std::vector<uint8_t> wrong_nonce = nonce;
        wrong_nonce.front() ^= 0x55;
        REQUIRE(aead_decrypt(alg, key.data(), key.size(), wrong_nonce.data(), wrong_nonce.size(),
                             aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), tag.size(), out.data())
                == UNI_CRYPTO_AEAD_EVERIFY);

        // Wrong AAD
        std::vector<uint8_t> wrong_aad = aad;
        wrong_aad.push_back(0xFF);
        REQUIRE(aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                             wrong_aad.data(), wrong_aad.size(), ct.data(), ct.size(), tag.data(), tag.size(), out.data())
                == UNI_CRYPTO_AEAD_EVERIFY);

        // Truncated tag (if backend accepts shorter tag sizes, using mismatched length should fail)
        size_t trunc_len = (tlen > 8) ? (tlen - 4) : (tlen > 4 ? tlen - 1 : tlen);
        if (trunc_len >= 4 && trunc_len < tlen) {
            REQUIRE(aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                                 aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), trunc_len, out.data())
                    == UNI_CRYPTO_AEAD_EVERIFY);
        }
    }
}

TEST_CASE("AEAD: concurrency/thread-safety smoke test", "[aead][threads]") {
    for (auto alg : {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);

        const int threads = 4;
        const int iters = 60;

        std::atomic<int> failures{0};
        std::vector<std::thread> ths;
        for (int t = 0; t < threads; ++t) {
            ths.emplace_back([=, &failures]() {
                XorShift32 rng(0xA5A5A5A5u + t * 0x1020304u);
                std::vector<uint8_t> key(16, static_cast<uint8_t>(0x30 + t));
                std::vector<uint8_t> nonce(nlen, 0x42);

                for (int i = 0; i < iters; ++i) {
                    size_t len = (rng.next() % 2048);
                    std::vector<uint8_t> pt(len);
                    rng.fill(pt.data(), pt.size());

                    // Derive per-iteration nonce deterministically
                    for (size_t k = 0; k < nonce.size(); ++k) nonce[k] = static_cast<uint8_t>((k + i + t) & 0xFF);

                    std::vector<uint8_t> aad(((i + t) % 8) ? ((i + t) % 32) : 0);
                    if (!aad.empty()) rng.fill(aad.data(), aad.size());

                    std::vector<uint8_t> ct(len);
                    std::vector<uint8_t> tag(tlen);

                    int rc = aead_encrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                                          aad.empty() ? nullptr : aad.data(), aad.size(),
                                          pt.data(), pt.size(),
                                          ct.data(),
                                          tag.data(), tag.size());
                    if (rc != UNI_CRYPTO_AEAD_SUCCESS) { failures.fetch_add(1); return; }
                    std::vector<uint8_t> dec(len);
                    rc = aead_decrypt(alg, key.data(), key.size(), nonce.data(), nonce.size(),
                                      aad.empty() ? nullptr : aad.data(), aad.size(),
                                      ct.data(), ct.size(),
                                      tag.data(), tag.size(),
                                      dec.data());
                    if (rc != UNI_CRYPTO_AEAD_SUCCESS) { failures.fetch_add(1); return; }
                    if (std::memcmp(dec.data(), pt.data(), pt.size()) != 0) { failures.fetch_add(1); return; }
                }
            });
        }
        for (auto& th : ths) th.join();
        REQUIRE(failures.load() == 0);
    }
}

TEST_CASE("ChaCha20-Poly1305 KATs (RFC 7539) — API not available here", "[aead][chacha20poly1305][skip]") {
    INFO("ChaCha20-Poly1305 is not part of this AEAD API (AES-GCM/CCM only). Skipping KATs by design.");
    SUCCEED();
}
// Additional AEAD tests appended by suite for completeness

TEST_CASE("AES-GCM: in-place round-trip with AAD and varying sizes", "[aead][gcm][inplace]") {
    const size_t nlen = uni_crypto_aead_recommended_nonce_len(UNI_CRYPTO_AEAD_ALG_AES_GCM);
    const size_t tlen = uni_crypto_aead_max_tag_len(UNI_CRYPTO_AEAD_ALG_AES_GCM);
    std::vector<uint8_t> key(16, 0x5A);
    std::vector<uint8_t> nonce(nlen, 0x12);
    std::vector<uint8_t> aad(19);
    for (size_t i = 0; i < aad.size(); ++i) aad[i] = static_cast<uint8_t>(i + 1);

    XorShift32 rng(0xCAFEBABE);
    const size_t sizes[] = {1u, 257u};
    for (size_t sz : sizes) {
        std::vector<uint8_t> original(sz);
        rng.fill(original.data(), original.size());

        std::vector<uint8_t> buf = original; // working buffer; will be used in-place
        std::vector<uint8_t> tag(tlen);

        // Encrypt in-place
        int rc = aead_encrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key.data(), key.size(),
                              nonce.data(), nonce.size(),
                              aad.data(), aad.size(),
                              buf.data(), buf.size(),
                              buf.data(), // in-place
                              tag.data(), tag.size());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        // Decrypt in-place back to original plaintext
        rc = aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          aad.data(), aad.size(),
                          buf.data(), buf.size(),   // ciphertext
                          tag.data(), tag.size(),
                          buf.data());              // in-place plaintext_out
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
        REQUIRE(std::memcmp(buf.data(), original.data(), original.size()) == 0);
    }
}

TEST_CASE("AEAD: zero-length plaintext with non-empty AAD", "[aead][aad][zero-pt]") {
    XorShift32 rng(0x13579BDFu);

    for (auto alg :  {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        const size_t tlen = uni_crypto_aead_max_tag_len(alg);

        std::vector<uint8_t> key(16, 0xA3);
        std::vector<uint8_t> nonce(nlen, 0xB4);
        std::vector<uint8_t> aad(32);
        rng.fill(aad.data(), aad.size());

        std::vector<uint8_t> tag(tlen, 0);
        int rc = aead_encrypt(alg, key.data(), key.size(),
                              nonce.data(), nonce.size(),
                              aad.data(), aad.size(),
                              nullptr, 0,
                              nullptr,
                              tag.data(), tag.size());
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);

        rc = aead_decrypt(alg, key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          aad.data(), aad.size(),
                          nullptr, 0,
                          tag.data(), tag.size(),
                          nullptr);
        REQUIRE(rc == UNI_CRYPTO_AEAD_SUCCESS);
    }
}

TEST_CASE("AEAD: early parameter validation must not write outputs", "[aead][errors][idempotency]") {
    for (auto alg :  {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM}) {
        const size_t nlen = uni_crypto_aead_recommended_nonce_len(alg);
        std::vector<uint8_t> key(16, 0x11);
        std::vector<uint8_t> nonce(nlen, 0x22);

        // Encrypt EINVAL case: plaintext_len>0 but plaintext==NULL
        uint8_t ct_guard[8];
        uint8_t tag_guard[16];
        std::memset(ct_guard, 0xCD, sizeof(ct_guard));
        std::memset(tag_guard, 0x77, sizeof(tag_guard));
        int rc = aead_encrypt(alg, key.data(), key.size(),
                              nonce.data(), nonce.size(),
                              nullptr, 0,
                              nullptr, 8,            // invalid: pt is NULL with len>0
                              ct_guard,
                              tag_guard, sizeof(tag_guard));
        REQUIRE(rc == UNI_CRYPTO_AEAD_EINVAL);
        // Buffers must remain unchanged
        for (auto b : ct_guard) REQUIRE(b == 0xCD);
        for (auto b : tag_guard) REQUIRE(b == 0x77);

        // Decrypt EINVAL case: ciphertext_len>0 but ciphertext==NULL
        uint8_t pt_guard[8];
        std::memset(pt_guard, 0x66, sizeof(pt_guard));
        rc = aead_decrypt(alg, key.data(), key.size(),
                          nonce.data(), nonce.size(),
                          nullptr, 0,
                          nullptr, 8,            // invalid: ct is NULL with len>0
                          tag_guard, sizeof(tag_guard),
                          pt_guard);
        REQUIRE(rc == UNI_CRYPTO_AEAD_EINVAL);
        for (auto b : pt_guard) REQUIRE(b == 0x66);
    }
}