// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

// stdlib
#include <algorithm>
#include <cstdint>
#include <vector>

// catch2
#include <catch2/catch_test_macros.hpp>

// uni.crypto
#include "uni_crypto.h"

TEST_CASE("Random fill serves requests larger than one DRBG request", "[random]") {
    // 1024 octets is the default MBEDTLS_CTR_DRBG_MAX_REQUEST; larger buffers used to fail.
    for (const size_t len : {1u, 64u, 1024u, 1025u, 10000u}) {
        std::vector<uint8_t> a(len, 0), b(len, 0);
        REQUIRE(uni_crypto_random_fill(a.data(), a.size()));
        REQUIRE(uni_crypto_random_fill(b.data(), b.size()));
        if (len >= 64u) {
            CHECK(a != b);
            // The tail is written too (an all-zero 32-octet tail has negligible probability).
            CHECK(std::any_of(a.end() - 32, a.end(), [](uint8_t v) { return v != 0u; }));
        }
    }
}

TEST_CASE("Random fill rejects invalid arguments", "[random]") {
    uint8_t byte = 0;
    CHECK_FALSE(uni_crypto_random_fill(nullptr, 1));
    CHECK_FALSE(uni_crypto_random_fill(&byte, 0));
}
