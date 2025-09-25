# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2025 Uni-Libraries contributors

include(../cmake/cpm-catch.cmake)

# catch
list(APPEND CMAKE_MODULE_PATH "${Catch2_SOURCE_DIR}/extras")
include(Catch)

# test
add_executable(uni_crypto_test)
target_sources(uni_crypto_test PRIVATE
    uni_crypto_test_crc16.cpp
    uni_crypto_test_hmac.cpp
    uni_crypto_test_utils.cpp
    uni_crypto_test_aead.cpp
)
target_link_libraries(uni_crypto_test PRIVATE uni_crypto)
target_link_libraries(uni_crypto_test PRIVATE Catch2::Catch2WithMain)

# Use C++17
target_compile_features(uni_crypto_test PRIVATE cxx_std_17)

# Warnings as errors
if(MSVC)
    target_compile_options(uni_crypto_test PRIVATE /W4 /WX)
else()
    target_compile_options(uni_crypto_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Propagate sanitizer and coverage to test binary as well
if(SANITIZE AND (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU"))
    target_compile_options(uni_crypto_test PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(uni_crypto_test PRIVATE -fsanitize=address,undefined)
endif()

if(COVERAGE AND (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU"))
    target_compile_options(uni_crypto_test PRIVATE -O0 -g --coverage)
    target_link_options(uni_crypto_test PRIVATE --coverage)
endif()

catch_discover_tests(uni_crypto_test)
