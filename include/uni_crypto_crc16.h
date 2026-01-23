// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText : 2022-2025 Uni-Libraries contributors

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//
// Includes
//

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// uni.crypto
#include "uni_crypto_export.h"


//
// Defines
//

#define UNI_CRYPTO_CRC16_POLY    0x1021u
#define UNI_CRYPTO_CRC16_INITIAL 0xFFFFu



//
// Enums
//

typedef enum {
    UNI_CRYPTO_CRC16_SUCCESS = 0,
    UNI_CRYPTO_CRC16_ERROR_BUFFER_TOO_SMALL = -1,
    UNI_CRYPTO_CRC16_ERROR_INVALID_ARGUMENT = -2
} uni_crypto_crc16_status_t;



//
// Functions
//

/**
 * Compute CRC-16/CCITT-FALSE over a buffer.
 *
 * Parameters:
 *  - data: pointer to input bytes (may be NULL if length == 0)
 *  - length: number of bytes to process
 *
 * Returns:
 *  - 16-bit CRC value. If data is NULL and length > 0, returns 0u.
 *
 * Notes:
 *  - Algorithm: CRC-16/CCITT-FALSE (CCSDS): poly 0x1021, init 0xFFFF, MSB-first, no final XOR.
 */
UNI_CRYPTO_EXPORT uint16_t uni_crypto_crc16_ccitt(const uint8_t *data, size_t length);

/**
 * Incrementally update a CRC-16/CCITT-FALSE value with additional data.
 *
 * Parameters:
 *  - crc: current CRC accumulator value
 *  - data: pointer to input bytes (may be NULL to perform no-op)
 *  - length: number of bytes to process
 *
 * Returns:
 *  - Updated CRC accumulator. If data is NULL, returns crc unchanged.
 */
UNI_CRYPTO_EXPORT uint16_t uni_crypto_crc16_ccitt_update(uint16_t crc, const uint8_t *data, size_t length);

/**
 * Verify that the last two bytes of a frame contain the correct CRC-16/CCITT-FALSE.
 *
 * Parameters:
 *  - data: pointer to a frame with data followed by a 2-byte big-endian CRC
 *  - length: total frame length (data + 2-byte CRC), must be >= 2
 *
 * Returns:
 *  - true if CRC matches; false otherwise or on invalid arguments.
 */
UNI_CRYPTO_EXPORT bool uni_crypto_crc16_ccitt_verify(const uint8_t *data, size_t length);

/**
 * Compute CRC-16/CCITT-FALSE for data and append it to the buffer in big-endian order.
 *
 * Parameters:
 *  - buffer: destination buffer that already contains data bytes to protect
 *  - data_length: number of data bytes in buffer to CRC (CRC is appended after them)
 *  - buffer_size: total size of buffer in bytes
 *
 * Returns:
 *  - UNI_CRYPTO_SUCCESS on success
 *  - UNI_CRYPTO_ERROR_BUFFER_TOO_SMALL if buffer cannot hold data + 2 CRC bytes
 *  - UNI_CRYPTO_ERROR_INVALID_ARGUMENT if buffer is NULL
 */
UNI_CRYPTO_EXPORT uni_crypto_crc16_status_t uni_crypto_crc16_ccitt_append(uint8_t *buffer, size_t data_length, size_t buffer_size);


#ifdef __cplusplus
}
#endif
