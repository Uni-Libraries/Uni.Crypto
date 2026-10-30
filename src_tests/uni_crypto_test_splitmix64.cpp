// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

#include <array>
#include <cstddef>
#include <cstdint>

#include <catch2/catch_test_macros.hpp>

#include "uni_crypto.h"

TEST_CASE("splitmix64 matches the reference sequence", "[splitmix64]") {
    // Reference implementation by Sebastiano Vigna, seed 1234567.
    constexpr std::array<std::uint64_t, 5U> Expected{6457827717110365317ULL, 3203168211198807973ULL, 9817491932198370423ULL, 4593380528125082431ULL,
                                                     16408922859458223821ULL};
    uni_crypto_splitmix64_t generator{};
    uni_crypto_splitmix64_seed(&generator, 1234567U);
    for (const auto value : Expected) {
        CHECK(uni_crypto_splitmix64_next(&generator) == value);
    }
}

TEST_CASE("splitmix64 restarts from its seed", "[splitmix64]") {
    uni_crypto_splitmix64_t generator{};
    uni_crypto_splitmix64_seed(&generator, 42U);
    const auto first = uni_crypto_splitmix64_next(&generator);
    (void)uni_crypto_splitmix64_next(&generator);
    uni_crypto_splitmix64_seed(&generator, 42U);
    CHECK(uni_crypto_splitmix64_next(&generator) == first);
}

TEST_CASE("splitmix64 unit interval excludes zero and includes one", "[splitmix64]") {
    // All-zero and all-one outputs are the two ends of the mapping; the state is chosen to reach neither by chance.
    uni_crypto_splitmix64_t generator{};
    uni_crypto_splitmix64_seed(&generator, 7U);
    for (std::size_t index = 0U; index < 100000U; ++index) {
        const double value = uni_crypto_splitmix64_next_unit_open(&generator);
        REQUIRE(value > 0.0);
        REQUIRE(value <= 1.0);
    }
}
