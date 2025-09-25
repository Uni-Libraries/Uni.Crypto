# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2022-2024 Uni-Libraries contributors

#
# CMake
#

cmake_minimum_required(VERSION 3.10)

project(uni_crypto)

# Options
option(SANITIZE "Enable ASan/UBSan on supported compilers" OFF)
option(COVERAGE "Enable code coverage (GCC/Clang)" OFF)

#
# 3rdparty
#

include(cmake/cpm.cmake)
include(cmake/cpm-mbedtls.cmake)



#
# Library
#

add_library(uni_crypto)

target_sources(uni_crypto PRIVATE
    src/uni_crypto_crc16.c
    src/uni_crypto_hmac.c
    src/uni_crypto_aead.c
    src/uni_crypto_utils.c
)


target_include_directories(uni_crypto PUBLIC include)
target_link_libraries(uni_crypto PUBLIC mbedcrypto)

# Instrumentation for sanitizers and coverage on the library too (to see library-side coverage)
if(SANITIZE AND (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU"))
    target_compile_options(uni_crypto PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(uni_crypto PUBLIC -fsanitize=address,undefined)
endif()

if(COVERAGE AND (CMAKE_C_COMPILER_ID MATCHES "Clang|GNU"))
    target_compile_options(uni_crypto PUBLIC -O0 -g --coverage)
    target_link_options(uni_crypto PUBLIC --coverage)
endif()

if(MSVC)
    set_target_properties(uni_crypto PROPERTIES C_STANDARD 17)
else()
    set_target_properties(uni_crypto PROPERTIES C_STANDARD 23)
endif()



#
# Installation
#

install(
    TARGETS uni_crypto
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)



#
# Tests
#

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(src_tests)
endif()
