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

TEST_CASE("uni_crypto_utils_compare: basic equality and inequality", "[utils][compare]") {
    SECTION("len=0 is equal even with null pointers") {
        REQUIRE(uni_crypto_utils_compare(nullptr, nullptr, 0u) == 0);
    }

    SECTION("equal buffers (same pointer)") {
        std::array<uint8_t, 3> a{1, 2, 3};
        REQUIRE(uni_crypto_utils_compare(a.data(), a.data(), a.size()) == 0);
    }

    SECTION("equal buffers (different arrays with same content)") {
        std::array<uint8_t, 3> a{1, 2, 3};
        std::array<uint8_t, 3> b{1, 2, 3};
        REQUIRE(uni_crypto_utils_compare(a.data(), b.data(), a.size()) == 0);
    }

    SECTION("inequality at start/middle/end") {
        std::array<uint8_t, 3> base{1, 2, 3};

        auto expect_diff = [&](std::array<uint8_t, 3> other) {
            REQUIRE(uni_crypto_utils_compare(base.data(), other.data(), base.size()) == 1);
        };

        std::array<uint8_t, 3> s = base;
        s[0] ^= 0x01;
        expect_diff(s);

        std::array<uint8_t, 3> m = base;
        m[1] ^= 0x01;
        expect_diff(m);

        std::array<uint8_t, 3> e = base;
        e[2] ^= 0x01;
        expect_diff(e);
    }

    SECTION("large buffer: equal vs modified last byte") {
        std::vector<uint8_t> v(1024);
        for (size_t i = 0; i < v.size(); ++i) {
            v[i] = static_cast<uint8_t>(i & 0xFF);
        }
        std::vector<uint8_t> w = v;
        REQUIRE(uni_crypto_utils_compare(v.data(), w.data(), v.size()) == 0);
        w.back() ^= 0x01;
        REQUIRE(uni_crypto_utils_compare(v.data(), w.data(), v.size()) == 1);
    }
}

TEST_CASE("uni_crypto_utils_compare: invalid arguments and edge cases", "[utils][compare][invalid]") {
    uint8_t b = 0x12;

    SECTION("a is null with non-zero len -> -1") {
        REQUIRE(uni_crypto_utils_compare(nullptr, &b, 1u) == -1);
    }
    SECTION("b is null with non-zero len -> -1") {
        REQUIRE(uni_crypto_utils_compare(&b, nullptr, 1u) == -1);
    }
    SECTION("len=0 with non-null pointers -> 0") {
        REQUIRE(uni_crypto_utils_compare(&b, &b, 0u) == 0);
    }
}

TEST_CASE("uni_crypto_utils_zeroize: wipes memory", "[utils][zeroize]") {
    std::array<uint8_t, 8> buf{1,2,3,4,5,6,7,8};
    uni_crypto_utils_zeroize(buf.data(), buf.size());
    for (auto v : buf) {
        REQUIRE(v == 0);
    }
}

TEST_CASE("uni_crypto_utils_zeroize: partial and edge cases", "[utils][zeroize][edge]") {
    SECTION("partial wipe leaves other bytes untouched") {
        std::array<uint8_t, 10> buf{};
        for (size_t i = 0; i < buf.size(); ++i) {
            buf[i] = static_cast<uint8_t>(i + 1);
        }
        // zero bytes [2..6]
        uni_crypto_utils_zeroize(buf.data() + 2, 5u);

        // Check bytes 0-1 unchanged
        REQUIRE(buf[0] == 1);
        REQUIRE(buf[1] == 2);
        // Check 2..6 zero
        for (size_t i = 2; i <= 6; ++i) {
            REQUIRE(buf[i] == 0);
        }
        // Check remaining unchanged
        REQUIRE(buf[7] == 8);
        REQUIRE(buf[8] == 9);
        REQUIRE(buf[9] == 10);
    }

    SECTION("len=0 no-op") {
        std::array<uint8_t, 4> buf{11,22,33,44};
        uni_crypto_utils_zeroize(buf.data(), 0u);
        REQUIRE(buf[0] == 11);
        REQUIRE(buf[1] == 22);
        REQUIRE(buf[2] == 33);
        REQUIRE(buf[3] == 44);
    }

    SECTION("nullptr with non-zero length is no-op (should not crash)") {
        uni_crypto_utils_zeroize(nullptr, 16u);
        SUCCEED("zeroize(nullptr, >0) did not crash");
    }
}