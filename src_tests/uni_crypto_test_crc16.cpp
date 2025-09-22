// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2022-2025 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <cstring>
#include <vector>
#include <cstdint>

// catch
#include <catch2/catch_test_macros.hpp>

// uni.crypto
#include "uni_crypto.h"

//
// tests
//

TEST_CASE("CRC-16 CCITT Basic Functionality", "[crc16]") {
    SECTION("Empty data returns initial value") {
        uint16_t crc = uni_crypto_crc16_ccitt(nullptr, 0);
        REQUIRE(crc == UNI_CRYPTO_CRC16_INITIAL);
    }

    SECTION("Single byte calculations (determinism and non-initial)") {
        uint8_t data_00[] = {0x00};
        uint16_t crc_00 = uni_crypto_crc16_ccitt(data_00, sizeof(data_00));
        REQUIRE(crc_00 != UNI_CRYPTO_CRC16_INITIAL);

        uint8_t data_ff[] = {0xFF};
        uint16_t crc_ff = uni_crypto_crc16_ccitt(data_ff, sizeof(data_ff));
        REQUIRE(crc_ff != UNI_CRYPTO_CRC16_INITIAL);
        REQUIRE(crc_ff != crc_00);
    }

    SECTION("Multi-byte sequence") {
        uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
        uint16_t crc = uni_crypto_crc16_ccitt(data, sizeof(data));
        REQUIRE(crc != 0);
        REQUIRE(crc != UNI_CRYPTO_CRC16_INITIAL);
    }

    SECTION("Incremental calculation matches direct calculation") {
        uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

        // Direct calculation
        uint16_t crc_direct = uni_crypto_crc16_ccitt(data, sizeof(data));

        // Incremental calculation
        uint16_t crc_inc = UNI_CRYPTO_CRC16_INITIAL;
        crc_inc = uni_crypto_crc16_ccitt_update(crc_inc, data, 4);
        crc_inc = uni_crypto_crc16_ccitt_update(crc_inc, data + 4, 4);

        REQUIRE(crc_direct == crc_inc);
    }

    SECTION("Known vector: \"123456789\" -> 0x29B1 (CRC-CCITT-FALSE)") {
        const uint8_t seq[] = {'1','2','3','4','5','6','7','8','9'};
        uint16_t crc = uni_crypto_crc16_ccitt(seq, sizeof(seq));
        REQUIRE(crc == 0x29B1u);
    }
}

TEST_CASE("CRC-16 CCITT Append and Verify", "[crc16]") {
    SECTION("Append CRC to buffer") {
        uint8_t buffer[10] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x00};

        uni_crypto_crc16_status_t status = uni_crypto_crc16_ccitt_append(buffer, 4, sizeof(buffer));
        REQUIRE(status == UNI_CRYPTO_CRC16_SUCCESS);

        // Verify CRC was appended (should not be both zeroes for this input)
        REQUIRE((buffer[4] != 0 || buffer[5] != 0));
    }

    SECTION("Verify CRC in frame") {
        uint8_t frame[] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x00};

        // Append CRC
        uni_crypto_crc16_status_t status = uni_crypto_crc16_ccitt_append(frame, 4, sizeof(frame));
        REQUIRE(status == UNI_CRYPTO_CRC16_SUCCESS);

        // Verify CRC
        bool valid = uni_crypto_crc16_ccitt_verify(frame, sizeof(frame));
        REQUIRE(valid == true);
    }

    SECTION("Detect corrupted CRC") {
        uint8_t frame[] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x00};

        // Append correct CRC
        uni_crypto_crc16_ccitt_append(frame, 4, sizeof(frame));

        // Corrupt the CRC
        frame[4] ^= 0x01;

        // Verify should fail
        bool valid = uni_crypto_crc16_ccitt_verify(frame, sizeof(frame));
        REQUIRE(valid == false);
    }

    SECTION("Buffer too small error") {
        uint8_t buffer[4] = {0x12, 0x34, 0x56, 0x78};

        uni_crypto_crc16_status_t status = uni_crypto_crc16_ccitt_append(buffer, 4, sizeof(buffer));
        REQUIRE(status == UNI_CRYPTO_CRC16_ERROR_BUFFER_TOO_SMALL);
    }
}

TEST_CASE("CRC-16 CCITT Edge Cases", "[crc16]") {
    SECTION("Null pointer handling") {
        uint16_t crc = uni_crypto_crc16_ccitt(nullptr, 1);
        REQUIRE(crc == 0);

        uint16_t crc_update = uni_crypto_crc16_ccitt_update(0x1234, nullptr, 1);
        REQUIRE(crc_update == 0x1234);

        bool verify = uni_crypto_crc16_ccitt_verify(nullptr, 2);
        REQUIRE(verify == false);
    }

    SECTION("Zero length data returns initial value") {
        uint8_t data[] = {0x12, 0x34};
        uint16_t crc = uni_crypto_crc16_ccitt(data, 0);
        REQUIRE(crc == UNI_CRYPTO_CRC16_INITIAL);
    }

    SECTION("Large data buffer") {
        std::vector<uint8_t> large_data(1024);
        for (size_t i = 0; i < large_data.size(); i++) {
            large_data[i] = static_cast<uint8_t>(i & 0xFF);
        }

        uint16_t crc = uni_crypto_crc16_ccitt(large_data.data(), large_data.size());
        REQUIRE(crc != 0);
        REQUIRE(crc != UNI_CRYPTO_CRC16_INITIAL);
    }
}



// Additional self-test migrated from library: replicate internal checks as unit tests
TEST_CASE("CRC-16 CCITT Implementation Self-Checks (migrated from lib)", "[crc16][selftest]") {
    // Property 1: Empty data yields initial value
    SECTION("Empty data -> initial value") {
        uint16_t crc_empty = uni_crypto_crc16_ccitt(nullptr, 0u);
        REQUIRE(crc_empty == UNI_CRYPTO_CRC16_INITIAL);
    }

    // Property 2: Direct vs incremental equality
    SECTION("Direct equals incremental") {
        const uint8_t seq[] = {0x12, 0x34, 0x56, 0x78};
        uint16_t crc_direct = uni_crypto_crc16_ccitt(seq, sizeof(seq));
        uint16_t crc_inc = UNI_CRYPTO_CRC16_INITIAL;
        crc_inc = uni_crypto_crc16_ccitt_update(crc_inc, seq, 2u);
        crc_inc = uni_crypto_crc16_ccitt_update(crc_inc, seq + 2, 2u);
        REQUIRE(crc_direct == crc_inc);
    }

    // Property 3: Append + verify round-trip
    SECTION("Append then verify round-trip") {
        uint8_t frame[6] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x00};
        auto status = uni_crypto_crc16_ccitt_append(frame, 4u, sizeof(frame));
        REQUIRE(status == UNI_CRYPTO_CRC16_SUCCESS);
        bool valid = uni_crypto_crc16_ccitt_verify(frame, sizeof(frame));
        REQUIRE(valid == true);
    }

    // Property 4: Single byte inputs produce deterministic, non-initial values
    SECTION("Single byte inputs are non-initial") {
        const uint8_t b0[] = {0x00};
        const uint8_t bf[] = {0xFF};
        uint16_t crc_b0 = uni_crypto_crc16_ccitt(b0, sizeof(b0));
        uint16_t crc_bf = uni_crypto_crc16_ccitt(bf, sizeof(bf));
        REQUIRE(crc_b0 != UNI_CRYPTO_CRC16_INITIAL);
        REQUIRE(crc_bf != UNI_CRYPTO_CRC16_INITIAL);
        // And they should differ for these two distinct inputs
        REQUIRE(crc_b0 != crc_bf);
    }
}
