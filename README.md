# uni.crypto

Small, allocation-conscious C library with the cryptographic primitives needed by the Uni-Libraries protocol stacks
(Uni.CCSDS SDLS, Uni.SDR). Cryptography is delegated to Mbed TLS; the library adds a stable C API, argument
validation, constant-time helpers and key-material hygiene.

| Header | Functionality |
| --- | --- |
| `uni_crypto_crc16.h` | CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF): compute, update, verify, append. Table-driven, no Mbed TLS dependency. |
| `uni_crypto_hash.h` | One-shot SHA-1, SHA-224, SHA-256. |
| `uni_crypto_hmac.h` | HMAC-SHA-1/224/256: one-shot `compute` / constant-time `verify`, and a streaming context (`init` / `update` / `final` / `reset`) that can live in caller-provided memory (`uni_crypto_hmac_context_create_static`). |
| `uni_crypto_aead.h` | AES-GCM and AES-CCM authenticated encryption: one-shot `uni_crypto_aead_encrypt` / `decrypt`, and a keyed context (`uni_crypto_aead_ctx_init` / `_encrypt` / `_decrypt` / `_free`) that computes the AES key schedule once. |
| `uni_crypto_random.h` | Cryptographically secure random bytes from the Mbed TLS CTR-DRBG. |
| `uni_crypto_utils.h` | Constant-time comparison and guaranteed zeroization. |
| `uni_crypto.h` | Umbrella header. |

## AEAD: one-shot vs keyed context

The one-shot AEAD functions build the AES key schedule (and, for GCM, the GHASH tables) on every call and, with the
default Mbed TLS configuration, allocate and free the cipher state on the heap each time. A protocol that protects
many messages with one key (an SDLS security association) should key a `uni_crypto_aead_ctx` once:

```c
uni_crypto_aead_ctx ctx = {0};                      /* zero-initialized storage, no heap use by the API itself */
uni_crypto_aead_ctx_init(&ctx, UNI_CRYPTO_AEAD_ALG_AES_GCM, key, 32);
uni_crypto_aead_ctx_encrypt(&ctx, iv, 12, aad, aad_len, pt, pt_len, ct, tag, 16);   /* ct may equal pt */
uni_crypto_aead_ctx_decrypt(&ctx, iv, 12, aad, aad_len, ct, ct_len, tag, 16, pt);   /* pt may equal ct */
uni_crypto_aead_ctx_free(&ctx);                     /* releases backend state, zeroizes the key schedule */
```

The context returns exactly the same ciphertext, tags and error codes as the one-shot API (covered by
`src_tests/uni_crypto_test_aead_ctx.cpp`). In-place operation (output pointer equal to input pointer) is supported for
both GCM and CCM; partial overlap is not.

Measured with `uni_crypto_test "[.benchmark]"` (Release, Mbed TLS 3.6.7 with AES-NI/PCLMUL, AES-256-GCM decrypt,
one core): 258-octet frames 1.41·10⁶ → 1.61·10⁶ frames/s (×1.14); 1140-octet frames 4.1·10⁵ → 4.0·10⁵ frames/s
(no change — the payload dominates). The main benefit is the removal of the per-message key setup and heap traffic
from real-time paths.

Constraints:

- AES-GCM decryption accepts only 16-octet tags; shorter tags are reported as `UNI_CRYPTO_AEAD_EVERIFY`.
- AES-CCM nonces are 7..13 octets; the payload length limit follows from the nonce length (`UNI_CRYPTO_AEAD_ELIMIT`).
- `UNI_CRYPTO_AEAD_CTX_SIZE` (1024 octets) bounds the backend state; a Mbed TLS build with `MBEDTLS_GCM_LARGE_TABLE`
  fails the compile-time check and needs a larger value.
- Contexts are not thread-safe; use one per thread.

## Build and test

Requirements: CMake 3.10+, a C17/C23 compiler, Mbed TLS 3.x (`find_package(MbedTLS)`; set `UNI_CRYPTO_STM=ON` to
build the bundled STM32 hardware-accelerated configuration instead), and Catch2 v3 for the tests (fetched by CPM, or
taken from the system with `-DCPM_USE_LOCAL_PACKAGES=ON` for offline builds).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release        # add -DCPM_USE_LOCAL_PACKAGES=ON to use an installed Catch2
cmake --build build
ctest --test-dir build --output-on-failure
build/src_tests/uni_crypto_test "[.benchmark]"         # AEAD throughput, one-shot vs context
```

Options: `SANITIZE=ON` (ASan/UBSan), `COVERAGE=ON`, `UNI_CRYPTO_INSTALL` (default ON when top-level).

As a subproject: `add_subdirectory(uni.crypto)` and `target_link_libraries(app PRIVATE uni_crypto)`; the parent must
make an `mbedcrypto` target available (e.g. `find_package(MbedTLS)` plus an alias of `MbedTLS::mbedcrypto`).

## License

MIT, see the SPDX headers of the source files.
