# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

include(../cmake/cpm.cmake)
include(../cmake/cpm-catch.cmake)

# catch
list(APPEND CMAKE_MODULE_PATH "${Catch2_SOURCE_DIR}/extras")
include(Catch)

# test
add_executable(uni_crypto_test)
target_sources(uni_crypto_test PRIVATE uni_crypto_test_crc16.cpp)
target_link_libraries(uni_crypto_test PRIVATE uni_crypto)
target_link_libraries(uni_crypto_test PRIVATE Catch2::Catch2WithMain)
catch_discover_tests(uni_crypto_test)
