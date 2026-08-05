// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#include <array>
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
