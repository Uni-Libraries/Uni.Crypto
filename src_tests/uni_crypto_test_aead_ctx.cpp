// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2026 Uni-Libraries contributors

//
// Includes
//

// stdlib
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// catch2
#include <catch2/catch_test_macros.hpp>

// uni.crypto
#include "uni_crypto.h"



//
// Helpers
//

namespace {

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

const uni_crypto_aead_algorithm kAlgorithms[] = {UNI_CRYPTO_AEAD_ALG_AES_GCM, UNI_CRYPTO_AEAD_ALG_AES_CCM};

} // namespace



//
// Tests
//

TEST_CASE("AEAD context gives the same ciphertext and tag as the one-shot API", "[aead][ctx]") {
    XorShift32 rng(0x1234);
    for (const auto alg : kAlgorithms) {
        for (const size_t key_len : {16u, 24u, 32u}) {
            std::vector<uint8_t> key(key_len);
            rng.fill(key.data(), key.size());

            uni_crypto_aead_ctx ctx{};
            REQUIRE(uni_crypto_aead_ctx_init(&ctx, alg, key.data(), key.size()) == UNI_CRYPTO_AEAD_SUCCESS);

            // Many messages with one keyed context, including the SDLS frame sizes of the plan benchmark.
            for (const size_t len : {0u, 1u, 15u, 16u, 258u, 1140u, 4096u}) {
                uint8_t nonce[12];
                uint8_t aad[23];
                rng.fill(nonce, sizeof(nonce));
                rng.fill(aad, sizeof(aad));
                std::vector<uint8_t> pt(len), ct_ref(len), ct(len), out(len);
                rng.fill(pt.data(), pt.size());
                uint8_t tag_ref[16], tag[16];

                REQUIRE(uni_crypto_aead_encrypt(alg, key.data(), key.size(), nonce, sizeof(nonce), aad, sizeof(aad), pt.data(), len, ct_ref.data(),
                                                tag_ref, sizeof(tag_ref)) == UNI_CRYPTO_AEAD_SUCCESS);
                REQUIRE(uni_crypto_aead_ctx_encrypt(&ctx, nonce, sizeof(nonce), aad, sizeof(aad), pt.data(), len, ct.data(), tag, sizeof(tag)) ==
                        UNI_CRYPTO_AEAD_SUCCESS);
                CHECK(ct == ct_ref);
                CHECK(std::memcmp(tag, tag_ref, sizeof(tag)) == 0);

                REQUIRE(uni_crypto_aead_ctx_decrypt(&ctx, nonce, sizeof(nonce), aad, sizeof(aad), ct.data(), len, tag, sizeof(tag), out.data()) ==
                        UNI_CRYPTO_AEAD_SUCCESS);
                CHECK(out == pt);

                // Tampered AAD is rejected.
                aad[0] ^= 0x01;
                CHECK(uni_crypto_aead_ctx_decrypt(&ctx, nonce, sizeof(nonce), aad, sizeof(aad), ct.data(), len, tag, sizeof(tag), out.data()) ==
                      UNI_CRYPTO_AEAD_EVERIFY);
            }
            uni_crypto_aead_ctx_free(&ctx);
        }
    }
}

TEST_CASE("AEAD context encrypts and decrypts in place", "[aead][ctx][inplace]") {
    XorShift32 rng(0x55AA);
    uint8_t key[32];
    rng.fill(key, sizeof(key));
    for (const auto alg : kAlgorithms) {
        uni_crypto_aead_ctx ctx{};
        REQUIRE(uni_crypto_aead_ctx_init(&ctx, alg, key, sizeof(key)) == UNI_CRYPTO_AEAD_SUCCESS);

        uint8_t nonce[12];
        rng.fill(nonce, sizeof(nonce));
        std::vector<uint8_t> pt(4096), ct_ref(4096);
        rng.fill(pt.data(), pt.size());
        uint8_t tag_ref[16], tag[16];
        REQUIRE(uni_crypto_aead_ctx_encrypt(&ctx, nonce, sizeof(nonce), nullptr, 0, pt.data(), pt.size(), ct_ref.data(), tag_ref, sizeof(tag_ref)) ==
                UNI_CRYPTO_AEAD_SUCCESS);

        std::vector<uint8_t> buf = pt;
        REQUIRE(uni_crypto_aead_ctx_encrypt(&ctx, nonce, sizeof(nonce), nullptr, 0, buf.data(), buf.size(), buf.data(), tag, sizeof(tag)) ==
                UNI_CRYPTO_AEAD_SUCCESS);
        CHECK(buf == ct_ref);
        CHECK(std::memcmp(tag, tag_ref, sizeof(tag)) == 0);

        REQUIRE(uni_crypto_aead_ctx_decrypt(&ctx, nonce, sizeof(nonce), nullptr, 0, buf.data(), buf.size(), tag, sizeof(tag), buf.data()) ==
                UNI_CRYPTO_AEAD_SUCCESS);
        CHECK(buf == pt);
        uni_crypto_aead_ctx_free(&ctx);
    }
}

TEST_CASE("AEAD context rejects use before init and after free", "[aead][ctx][invalid]") {
    uint8_t key[16] = {};
    uint8_t nonce[12] = {};
    uint8_t data[8] = {};
    uint8_t tag[16] = {};

    uni_crypto_aead_ctx ctx{};
    CHECK(uni_crypto_aead_ctx_encrypt(&ctx, nonce, sizeof(nonce), nullptr, 0, data, sizeof(data), data, tag, sizeof(tag)) == UNI_CRYPTO_AEAD_EINVAL);
    CHECK(uni_crypto_aead_ctx_init(nullptr, UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key)) == UNI_CRYPTO_AEAD_EINVAL);
    CHECK(uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_AES_GCM, nullptr, sizeof(key)) == UNI_CRYPTO_AEAD_EINVAL);
    CHECK(uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_INVALID, key, sizeof(key)) == UNI_CRYPTO_AEAD_EALGO);
    CHECK(uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_AES_GCM, key, 7) == UNI_CRYPTO_AEAD_EALGO);

    REQUIRE(uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key)) == UNI_CRYPTO_AEAD_SUCCESS);
    uni_crypto_aead_ctx_free(&ctx);
    CHECK(uni_crypto_aead_ctx_decrypt(&ctx, nonce, sizeof(nonce), nullptr, 0, data, sizeof(data), tag, sizeof(tag), data) == UNI_CRYPTO_AEAD_EINVAL);

    // free zeroizes the key schedule and is idempotent.
    for (unsigned char byte : ctx.opaque.bytes) {
        REQUIRE(byte == 0u);
    }
    uni_crypto_aead_ctx_free(&ctx);
    uni_crypto_aead_ctx_free(nullptr);
}

// Plan item CRYPTO-1: one-shot API (key schedule per frame) vs keyed context, AES-256-GCM, SDLS frame sizes.
// Hidden from the default run; execute with `uni_crypto_test "[.benchmark]"`.
TEST_CASE("AEAD context throughput", "[.benchmark][aead][ctx]") {
    uint8_t key[32] = {1, 2, 3};
    uint8_t nonce[12] = {};
    uint8_t aad[16] = {};
    uint8_t tag[16];
    for (const size_t len : {258u, 1140u}) {
        std::vector<uint8_t> pt(len, 0x5A), ct(len);
        constexpr int kFrames = 200000;

        const auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < kFrames; ++i) {
            nonce[11] = static_cast<uint8_t>(i);
            REQUIRE(uni_crypto_aead_decrypt(UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key), nonce, sizeof(nonce), aad, sizeof(aad), pt.data(), len, tag,
                                            sizeof(tag), ct.data()) != UNI_CRYPTO_AEAD_EINVAL);
        }
        const auto t1 = std::chrono::steady_clock::now();

        uni_crypto_aead_ctx ctx{};
        REQUIRE(uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_AES_GCM, key, sizeof(key)) == UNI_CRYPTO_AEAD_SUCCESS);
        for (int i = 0; i < kFrames; ++i) {
            nonce[11] = static_cast<uint8_t>(i);
            REQUIRE(uni_crypto_aead_ctx_decrypt(&ctx, nonce, sizeof(nonce), aad, sizeof(aad), pt.data(), len, tag, sizeof(tag), ct.data()) !=
                    UNI_CRYPTO_AEAD_EINVAL);
        }
        const auto t2 = std::chrono::steady_clock::now();
        uni_crypto_aead_ctx_free(&ctx);

        const double one_shot = kFrames / std::chrono::duration<double>(t1 - t0).count();
        const double keyed = kFrames / std::chrono::duration<double>(t2 - t1).count();
        std::printf("AES-256-GCM decrypt %4zu octets: one-shot %.3g frames/s, context %.3g frames/s (x%.2f)\n", len, one_shot, keyed, keyed / one_shot);
    }
}
