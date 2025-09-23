# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText : 2022-2024 Uni-Libraries contributors

#
# CMake
#

cmake_minimum_required(VERSION 3.10)

project(uni_crypto)

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
)


target_include_directories(uni_crypto PUBLIC include)
target_link_libraries(uni_crypto PUBLIC mbedcrypto)

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
