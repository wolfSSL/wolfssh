cmake_minimum_required(VERSION 3.18)
project(wolfssh_dart C)

# Builds libwolfssh_dart, a self-contained shared library that statically
# links wolfSSH and wolfSSL so the Dart FFI consumer only has to ship one
# binary. wolfSSL is fetched if not available on the system.

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(WOLFSSH_DART_FETCH_WOLFSSL
       "Use FetchContent to obtain wolfSSL when not found on the system" ON)
option(WOLFSSH_DART_BUILD_TESTS "Build native smoke-test binary" OFF)

# wolfSSL is a hard dependency. Prefer pkg-config / installed package; only
# fetch when explicitly enabled. Network-restricted CI must pre-install it.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(WOLFSSL IMPORTED_TARGET wolfssl)
endif()

if(NOT WOLFSSL_FOUND AND WOLFSSH_DART_FETCH_WOLFSSL)
    include(FetchContent)
    # Pin a wolfSSL release tested against wolfSSH 1.5.0. Bump alongside the
    # vendored wolfSSH version; mismatch can defeat the protocol-hardening
    # intent of upgrading wolfSSH.
    FetchContent_Declare(
        wolfssl
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG        v5.7.6-stable
        GIT_SHALLOW    TRUE
    )
    set(WOLFSSL_SSH ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ECC ON CACHE BOOL "" FORCE)
    set(WOLFSSL_DH ON CACHE BOOL "" FORCE)
    set(WOLFSSL_RSA ON CACHE BOOL "" FORCE)
    set(WOLFSSL_AESGCM ON CACHE BOOL "" FORCE)
    set(WOLFSSL_CHACHAPOLY ON CACHE BOOL "" FORCE)
    set(WOLFSSL_CURVE25519 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ED25519 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_SHA256 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_SHA384 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_SHA512 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_HKDF ON CACHE BOOL "" FORCE)
    set(WOLFSSL_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_FILESYSTEM ON CACHE BOOL "" FORCE)
    # Critical: ensure a real CSPRNG seed source. wolfCrypt picks up
    # /dev/urandom on POSIX and BCryptGenRandom on Windows when these are
    # left at their defaults; never enable WOLFSSL_GENSEED_FORTEST.
    FetchContent_MakeAvailable(wolfssl)
    set(WOLFSSL_TARGET wolfssl)
elseif(WOLFSSL_FOUND)
    set(WOLFSSL_TARGET PkgConfig::WOLFSSL)
else()
    message(FATAL_ERROR
        "wolfSSL not found and WOLFSSH_DART_FETCH_WOLFSSL is OFF. "
        "Install libwolfssl-dev or rerun with -DWOLFSSH_DART_FETCH_WOLFSSL=ON.")
endif()

# Vendored wolfSSH sources sit one directory up.
set(WOLFSSH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
file(GLOB WOLFSSH_SRC
    "${WOLFSSH_ROOT}/src/ssh.c"
    "${WOLFSSH_ROOT}/src/internal.c"
    "${WOLFSSH_ROOT}/src/io.c"
    "${WOLFSSH_ROOT}/src/log.c"
    "${WOLFSSH_ROOT}/src/misc.c"
    "${WOLFSSH_ROOT}/src/port.c"
    "${WOLFSSH_ROOT}/src/keygen.c"
    "${WOLFSSH_ROOT}/src/agent.c"
    "${WOLFSSH_ROOT}/src/certman.c"
)

add_library(wolfssh_dart SHARED
    ${WOLFSSH_SRC}
    native/wolfssh_dart_glue.c
)

target_include_directories(wolfssh_dart
    PRIVATE
        "${WOLFSSH_ROOT}"
        "${CMAKE_CURRENT_SOURCE_DIR}/native"
)

target_compile_definitions(wolfssh_dart PRIVATE
    WOLFSSH_TERM
    WOLFSSH_NO_SCP    # client-only Dart FFI scope
    HAVE_WC_ECC_SET_RNG
    NO_WOLFSSH_DIR    # dart-side does not load known-hosts via libc dirs
)

target_link_libraries(wolfssh_dart PRIVATE ${WOLFSSL_TARGET})

if(WIN32)
    target_compile_definitions(wolfssh_dart PRIVATE WOLFSSH_DLL_EXPORT)
    target_link_libraries(wolfssh_dart PRIVATE ws2_32)
endif()

set_target_properties(wolfssh_dart PROPERTIES
    OUTPUT_NAME "wolfssh_dart"
    SOVERSION 0
    VERSION 0.1.0
)

if(WOLFSSH_DART_BUILD_TESTS)
    add_executable(wolfssh_dart_smoke native/smoke.c)
    target_link_libraries(wolfssh_dart_smoke PRIVATE wolfssh_dart)
endif()
