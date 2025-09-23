// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <cstring>

// catch2
#include <catch2/catch_test_macros.hpp>

// uni.crypto
#include "uni_crypto.h"



//
// Tests
//

TEST_CASE("hmac size", "[hmac]") {
    REQUIRE(uni_crypto_hmac_digest_size(UNI_CRYPTO_HMAC_ALG_SHA256) == 32u);
    REQUIRE(uni_crypto_hmac_digest_size(UNI_CRYPTO_HMAC_ALG_SHA1) == 20u);
    REQUIRE(uni_crypto_hmac_block_size(UNI_CRYPTO_HMAC_ALG_SHA256) == 64u);
    REQUIRE(uni_crypto_hmac_block_size(UNI_CRYPTO_HMAC_ALG_SHA1) == 64u);
}

TEST_CASE("hmac sha256 RFC4231 known vectors", "[hmac][sha256]") {
    // TC1
    {
        std::array<uint8_t, 20> key{};
        key.fill(0x0b);
        const uint8_t msg[] = "Hi There";
        const uint8_t exp[32] = {
            0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
            0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
        };
        uint8_t out[32]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                         key.data(), key.size(),
                                         msg, sizeof("Hi There") - 1,
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 32) == 0);
    }

    // TC2
    {
        const uint8_t key[] = "Jefe";
        const uint8_t msg[] = "what do ya want for nothing?";
        const uint8_t exp[32] = {
            0x5b,0xdc,0xc1,0x46,0xbf,0x60,0x75,0x4e,0x6a,0x04,0x24,0x26,0x08,0x95,0x75,0xc7,
            0x5a,0x00,0x3f,0x08,0x9d,0x27,0x39,0x83,0x9d,0xec,0x58,0xb9,0x64,0xec,0x38,0x43
        };
        uint8_t out[32]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                         key, sizeof(key) - 1,
                                         msg, sizeof(msg) - 1,
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 32) == 0);
    }

    // TC3
    {
        std::array<uint8_t, 20> key{};
        key.fill(0xaa);
        std::array<uint8_t, 50> msg{};
        msg.fill(0xdd);

        const uint8_t exp[32] = {
            0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,
            0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
        };
        uint8_t out[32]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                         key.data(), key.size(),
                                         msg.data(), msg.size(),
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 32) == 0);
    }
}

TEST_CASE("HMAC SHA1 RFC2202 known vectors", "[hmac][sha1]") {
    // TC1
    {
        std::array<uint8_t, 20> key{};
        key.fill(0x0b);
        const uint8_t msg[] = "Hi There";
        const uint8_t exp[20] = {
            0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,0xe2,0x8b,0xc0,0xb6,0xfb,0x37,0x8c,0x8e,0xf1,0x46,0xbe,0x00
        };
        uint8_t out[20]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA1,
                                         key.data(), key.size(),
                                         msg, sizeof("Hi There") - 1,
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 20) == 0);
    }

    // TC2
    {
        const uint8_t key[] = "Jefe";
        const uint8_t msg[] = "what do ya want for nothing?";
        const uint8_t exp[20] = {
            0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,0xd2,0x74,0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79
        };
        uint8_t out[20]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA1,
                                         key, sizeof(key) - 1,
                                         msg, sizeof(msg) - 1,
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 20) == 0);
    }

    // TC3
    {
        std::array<uint8_t, 20> key{};
        key.fill(0xaa);
        std::array<uint8_t, 50> msg{};
        msg.fill(0xdd);
        const uint8_t exp[20] = {
            0x12,0x5d,0x73,0x42,0xb9,0xac,0x11,0xcd,0x91,0xa3,0x9a,0xf4,0x8a,0xa1,0x7b,0x4f,0x63,0xf1,0x75,0xd3
        };
        uint8_t out[20]{};
        int rc = uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA1,
                                         key.data(), key.size(),
                                         msg.data(), msg.size(),
                                         out, sizeof(out));
        REQUIRE(rc == 0);
        REQUIRE(std::memcmp(out, exp, 20) == 0);
    }
}

TEST_CASE("HMAC streaming vs one-shot equivalence and reset", "[hmac][stream]") {
    const uint8_t key[] = "stream-key";
    const uint8_t msg[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t msg_len = sizeof(msg) - 1;

    // one-shot
    uint8_t tag256_one[32]{};
    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    key, sizeof(key) - 1,
                                    msg, msg_len,
                                    tag256_one, sizeof(tag256_one)) == 0);

    // streaming in 3 chunks
    uni_crypto_hmac_context* ctx = uni_crypto_hmac_create();
    REQUIRE(ctx != nullptr);
    REQUIRE(uni_crypto_hmac_init(ctx, UNI_CRYPTO_HMAC_ALG_SHA256, key, sizeof(key) - 1) == 0);

    REQUIRE(uni_crypto_hmac_update(ctx, msg, 10) == 0);
    REQUIRE(uni_crypto_hmac_update(ctx, msg + 10, 10) == 0);
    REQUIRE(uni_crypto_hmac_update(ctx, msg + 20, msg_len - 20) == 0);

    uint8_t tag256_stream[32]{};
    REQUIRE(uni_crypto_hmac_final(ctx, tag256_stream, sizeof(tag256_stream)) == 0);
    REQUIRE(std::memcmp(tag256_one, tag256_stream, 32) == 0);

    // reset and re-use with different message
    const uint8_t msg2[] = "another-message";
    const size_t msg2_len = sizeof(msg2) - 1;

    REQUIRE(uni_crypto_hmac_reset(ctx) == 0);
    REQUIRE(uni_crypto_hmac_update(ctx, msg2, msg2_len) == 0);

    uint8_t tag2_stream[32]{};
    REQUIRE(uni_crypto_hmac_final(ctx, tag2_stream, sizeof(tag2_stream)) == 0);

    uint8_t tag2_one[32]{};
    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    key, sizeof(key) - 1,
                                    msg2, msg2_len,
                                    tag2_one, sizeof(tag2_one)) == 0);
    REQUIRE(std::memcmp(tag2_one, tag2_stream, 32) == 0);

    uni_crypto_hmac_free(ctx);
}

TEST_CASE("HMAC verify helper (full and truncated), success and failure", "[hmac][verify]") {
    const uint8_t key[] = "verify-key";
    const uint8_t data[] = "verify-data";
    uint8_t tag256[32]{};
    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    key, sizeof(key) - 1,
                                    data, sizeof(data) - 1,
                                    tag256, sizeof(tag256)) == 0);

    // Full-length verify should succeed
    REQUIRE(uni_crypto_hmac_verify(UNI_CRYPTO_HMAC_ALG_SHA256,
                                   key, sizeof(key) - 1,
                                   data, sizeof(data) - 1,
                                   tag256, 32) == 0);

    // Truncated verify (first 16 bytes) should also succeed
    REQUIRE(uni_crypto_hmac_verify(UNI_CRYPTO_HMAC_ALG_SHA256,
                                   key, sizeof(key) - 1,
                                   data, sizeof(data) - 1,
                                   tag256, 16) == 0);

    // Corrupt one byte and verify should fail with EVERIFY
    uint8_t bad[32]{};
    std::memcpy(bad, tag256, 32);
    bad[5] ^= 0x01;
    REQUIRE(uni_crypto_hmac_verify(UNI_CRYPTO_HMAC_ALG_SHA256,
                                   key, sizeof(key) - 1,
                                   data, sizeof(data) - 1,
                                   bad, 32) == UNI_CRYPTO_HMAC_EVERIFY);
}

TEST_CASE("HMAC edge cases: zero-length key and data", "[hmac][edge]") {
    // Empty key and empty data are valid per spec
    uint8_t out1[32]{};
    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    nullptr, 0,
                                    nullptr, 0,
                                    out1, sizeof(out1)) == 0);

    // Verify against itself (full length)
    REQUIRE(uni_crypto_hmac_verify(UNI_CRYPTO_HMAC_ALG_SHA256,
                                   nullptr, 0,
                                   nullptr, 0,
                                   out1, 32) == 0);

    // Also test SHA-1 empty/empty
    uint8_t out2[20]{};
    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA1,
                                    nullptr, 0,
                                    nullptr, 0,
                                    out2, sizeof(out2)) == 0);
    REQUIRE(uni_crypto_hmac_verify(UNI_CRYPTO_HMAC_ALG_SHA1,
                                   nullptr, 0,
                                   nullptr, 0,
                                   out2, 20) == 0);
}

TEST_CASE("HMAC static context initialization and usage", "[hmac][static-ctx]") {
    // Allocate statically with required size and suitable alignment
    alignas(std::max_align_t) std::array<unsigned char, UNI_CRYPTO_HMAC_CONTEXT_SIZE> storage{};
    uni_crypto_hmac_context* ctx = nullptr;

    // Initialize the context view over the static buffer
    int rc = uni_crypto_hmac_context_create_static(storage.data(), storage.size(), &ctx);
    REQUIRE(rc == 0);
    REQUIRE(ctx != nullptr);

    // Use the static context for a normal HMAC operation and compare to one-shot
    const uint8_t key[] = "static-key";
    const uint8_t msg[] = "abc";
    uint8_t tag_stream[32]{};
    uint8_t tag_one_shot[32]{};

    REQUIRE(uni_crypto_hmac_init(ctx, UNI_CRYPTO_HMAC_ALG_SHA256, key, sizeof(key) - 1) == 0);
    REQUIRE(uni_crypto_hmac_update(ctx, msg, sizeof(msg) - 1) == 0);
    REQUIRE(uni_crypto_hmac_final(ctx, tag_stream, sizeof(tag_stream)) == 0);

    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    key, sizeof(key) - 1,
                                    msg, sizeof(msg) - 1,
                                    tag_one_shot, sizeof(tag_one_shot)) == 0);

    REQUIRE(std::memcmp(tag_stream, tag_one_shot, 32) == 0);

    // Validate reset and reuse on the same static context
    const uint8_t msg2[] = "abcd";
    uint8_t tag2_stream[32]{};
    uint8_t tag2_one[32]{};

    REQUIRE(uni_crypto_hmac_reset(ctx) == 0);
    REQUIRE(uni_crypto_hmac_update(ctx, msg2, sizeof(msg2) - 1) == 0);
    REQUIRE(uni_crypto_hmac_final(ctx, tag2_stream, sizeof(tag2_stream)) == 0);

    REQUIRE(uni_crypto_hmac_compute(UNI_CRYPTO_HMAC_ALG_SHA256,
                                    key, sizeof(key) - 1,
                                    msg2, sizeof(msg2) - 1,
                                    tag2_one, sizeof(tag2_one)) == 0);

    REQUIRE(std::memcmp(tag2_stream, tag2_one, 32) == 0);

    // Free releases backend state, does not free the caller-provided storage
    uni_crypto_hmac_free(ctx);
}
