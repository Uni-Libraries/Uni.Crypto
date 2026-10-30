// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <catch2/catch_test_macros.hpp>

#include "uni_crypto.h"

TEST_CASE("hash SHA-224 known vector", "[hash][sha224]") {
    const uint8_t message[] = "abc";
    const std::array<uint8_t, 28> expected{
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
        0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7};
    std::array<uint8_t, 28> digest{};

    REQUIRE(uni_crypto_hash_digest_size(UNI_CRYPTO_HASH_ALG_SHA224) == digest.size());
    REQUIRE(uni_crypto_hash_compute(UNI_CRYPTO_HASH_ALG_SHA224,
                                    message,
                                    sizeof(message) - 1u,
                                    digest.data(),
                                    digest.size()) == UNI_CRYPTO_HASH_SUCCESS);
    REQUIRE(std::memcmp(digest.data(), expected.data(), digest.size()) == 0);
}

TEST_CASE("hash rejects undersized output", "[hash]") {
    const uint8_t message[] = "abc";
    std::array<uint8_t, 27> digest{};

    REQUIRE(uni_crypto_hash_compute(UNI_CRYPTO_HASH_ALG_SHA224,
                                    message,
                                    sizeof(message) - 1u,
                                    digest.data(),
                                    digest.size()) == UNI_CRYPTO_HASH_EBUFFER);
}

TEST_CASE("hash streaming matches the one-shot digest across chunk sizes", "[hash][streaming]") {
    std::array<uint8_t, 1000> message{};
    for (std::size_t index = 0u; index < message.size(); ++index) {
        message[index] = static_cast<uint8_t>(index * 7u);
    }
    std::array<uint8_t, 32> expected{};
    REQUIRE(uni_crypto_hash_compute(UNI_CRYPTO_HASH_ALG_SHA256, message.data(), message.size(), expected.data(), expected.size()) ==
            UNI_CRYPTO_HASH_SUCCESS);

    for (const std::size_t chunk : {std::size_t{1u}, std::size_t{63u}, std::size_t{64u}, std::size_t{1000u}}) {
        uni_crypto_hash_context* ctx = uni_crypto_hash_create(UNI_CRYPTO_HASH_ALG_SHA256);
        REQUIRE(ctx != nullptr);
        for (std::size_t offset = 0u; offset < message.size(); offset += chunk) {
            const std::size_t length = std::min(chunk, message.size() - offset);
            REQUIRE(uni_crypto_hash_update(ctx, message.data() + offset, length) == UNI_CRYPTO_HASH_SUCCESS);
        }
        std::array<uint8_t, 32> digest{};
        REQUIRE(uni_crypto_hash_final(ctx, digest.data(), digest.size()) == UNI_CRYPTO_HASH_SUCCESS);
        CHECK(digest == expected);
        uni_crypto_hash_free(ctx);
    }
}

TEST_CASE("hash streaming of an empty message gives the standard SHA-256 digest", "[hash][streaming]") {
    const std::array<uint8_t, 32> expected{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                           0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    uni_crypto_hash_context* ctx = uni_crypto_hash_create(UNI_CRYPTO_HASH_ALG_SHA256);
    REQUIRE(ctx != nullptr);
    REQUIRE(uni_crypto_hash_update(ctx, nullptr, 0u) == UNI_CRYPTO_HASH_SUCCESS);
    std::array<uint8_t, 32> digest{};
    REQUIRE(uni_crypto_hash_final(ctx, digest.data(), digest.size()) == UNI_CRYPTO_HASH_SUCCESS);
    CHECK(digest == expected);
    uni_crypto_hash_free(ctx);
}

TEST_CASE("hash streaming rejects invalid use", "[hash][streaming]") {
    CHECK(uni_crypto_hash_create(UNI_CRYPTO_HASH_ALG_INVALID) == nullptr);
    CHECK(uni_crypto_hash_update(nullptr, nullptr, 0u) == UNI_CRYPTO_HASH_EINVAL);
    uni_crypto_hash_free(nullptr);

    uni_crypto_hash_context* ctx = uni_crypto_hash_create(UNI_CRYPTO_HASH_ALG_SHA256);
    REQUIRE(ctx != nullptr);
    CHECK(uni_crypto_hash_update(ctx, nullptr, 1u) == UNI_CRYPTO_HASH_EINVAL);

    std::array<uint8_t, 31> small{};
    CHECK(uni_crypto_hash_final(ctx, small.data(), small.size()) == UNI_CRYPTO_HASH_EBUFFER);

    std::array<uint8_t, 32> digest{};
    REQUIRE(uni_crypto_hash_final(ctx, digest.data(), digest.size()) == UNI_CRYPTO_HASH_SUCCESS);
    CHECK(uni_crypto_hash_update(ctx, digest.data(), 1u) == UNI_CRYPTO_HASH_EINVAL);
    CHECK(uni_crypto_hash_final(ctx, digest.data(), digest.size()) == UNI_CRYPTO_HASH_EINVAL);
    uni_crypto_hash_free(ctx);
}
