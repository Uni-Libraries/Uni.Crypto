# Mbed TLS 3.x backend. Provides UNI_CRYPTO_MBEDCRYPTO_TARGET, the target uni_crypto links against.
#
# UNI_CRYPTO_STM: the bundled STM32 hardware-accelerated build (target `mbedcrypto`).
# Otherwise: an installed Mbed TLS 3.x, through its CMake package (MbedTLS::mbedcrypto) when available, else
# through its headers and library (distribution packages that ship no CMake package files).

if(UNI_CRYPTO_STM)
    set(ENABLE_TESTING OFF CACHE BOOL "mbedtls testing" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "mbedtls programs" FORCE)
    set(MBEDTLS_AS_SUBPROJECT ON CACHE BOOL "mbedtls subproject" FORCE)
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "mbedtls install" FORCE)
    add_subdirectory(3rdparty/mbedtls_stm32)
    target_compile_definitions(mbedcrypto PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/mbedtls-config-stm32.h")
    target_compile_definitions(mbedtls    PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/mbedtls-config-stm32.h")
    target_compile_definitions(mbedx509   PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/mbedtls-config-stm32.h")
    set(UNI_CRYPTO_MBEDCRYPTO_TARGET mbedcrypto)
    return()
endif()

if(NOT TARGET MbedTLS::mbedcrypto)
    find_package(MbedTLS 3 CONFIG QUIET)
endif()

if(NOT TARGET MbedTLS::mbedcrypto)
    # mbedtls/build_info.h exists since Mbed TLS 3.0, so finding it also rejects 2.x installations.
    find_path(UNI_CRYPTO_MBEDTLS_INCLUDE_DIR mbedtls/build_info.h)
    find_library(UNI_CRYPTO_MBEDCRYPTO_LIBRARY NAMES mbedcrypto)
    if(NOT UNI_CRYPTO_MBEDTLS_INCLUDE_DIR OR NOT UNI_CRYPTO_MBEDCRYPTO_LIBRARY)
        message(FATAL_ERROR "uni.crypto needs Mbed TLS 3.x (CMake package MbedTLS, or mbedtls/build_info.h and the mbedcrypto library)")
    endif()
    add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
        IMPORTED_LOCATION "${UNI_CRYPTO_MBEDCRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${UNI_CRYPTO_MBEDTLS_INCLUDE_DIR}")
endif()

set(UNI_CRYPTO_MBEDCRYPTO_TARGET MbedTLS::mbedcrypto)
