CPMAddPackage(
    NAME MbedTLS
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.4/mbedtls-3.6.4.tar.bz2
    OPTIONS
        "ENABLE_PROGRAMS OFF"
        "ENABLE_TESTING OFF"
)

target_compile_definitions(mbedcrypto PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/cpm-mbedtls-config.h")
target_compile_definitions(mbedtls    PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/cpm-mbedtls-config.h")
target_compile_definitions(mbedx509   PUBLIC MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_LIST_DIR}/cpm-mbedtls-config.h")
