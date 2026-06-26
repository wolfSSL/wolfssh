cmake_minimum_required(VERSION 3.20.0)

# Need the Zephyr version before find_package (KERNEL_VERSION_* is not set yet)
# to gate the RAM disk / POSIX config below; parse $ZEPHYR_BASE/VERSION directly.
# find_package() tolerates an unset ZEPHYR_BASE, but reading VERSION does not,
# so check it here rather than letting file(STRINGS) fail on "/VERSION".
if(NOT DEFINED ENV{ZEPHYR_BASE} OR NOT EXISTS "$ENV{ZEPHYR_BASE}/VERSION")
  message(FATAL_ERROR
    "ZEPHYR_BASE must be set in the environment (west build and zephyr-env.sh "
    "both do this); this sample needs it to detect the Zephyr version.")
endif()
file(STRINGS "$ENV{ZEPHYR_BASE}/VERSION" zephyr_version_lines)
foreach(line ${zephyr_version_lines})
  if("${line}" MATCHES "VERSION_MAJOR[ \t]*=[ \t]*([0-9]+)")
    set(ZEPHYR_VER_MAJOR ${CMAKE_MATCH_1})
  elseif("${line}" MATCHES "VERSION_MINOR[ \t]*=[ \t]*([0-9]+)")
    set(ZEPHYR_VER_MINOR ${CMAKE_MATCH_1})
  endif()
endforeach()
if(NOT DEFINED ZEPHYR_VER_MAJOR OR NOT DEFINED ZEPHYR_VER_MINOR)
  message(FATAL_ERROR
    "Could not determine Zephyr version from $ENV{ZEPHYR_BASE}/VERSION")
endif()
set(ZEPHYR_VER "${ZEPHYR_VER_MAJOR}.${ZEPHYR_VER_MINOR}")

# RAM disk (devicetree on >= 3.5, Kconfig before): only the filesystem-backed
# scenarios need it, not the nofs build.
if(NOT "${CONF_FILE}" MATCHES "nofs")
  if(ZEPHYR_VER VERSION_LESS 3.5)
    list(APPEND EXTRA_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ramdisk_legacy.conf)
  else()
    list(APPEND EXTRA_DTC_OVERLAY_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ramdisk.overlay)
  endif()
endif()

# CONFIG_POSIX_API (in prj*.conf) covers POSIX sockets/pthreads/clock on
# >= 4.1; older releases need the symbols the 4.1 reorg removed.
if(ZEPHYR_VER VERSION_LESS 4.1)
  list(APPEND EXTRA_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/posix_legacy.conf)
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfssl_tests)

FILE(GLOB app_sources ../../../tests/*.c ../../../examples/client/client.c
    ../../../examples/client/common.c ../../../examples/echoserver/echoserver.c
    ../../../examples/sftpclient/sftpclient.c tests.c)
# Remove the file regress.c from the list of test app sources. The regression
# test is covered in many other environments.
list(REMOVE_ITEM app_sources
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../tests/regress.c")
target_sources(app PRIVATE ${app_sources})
add_definitions(-DWOLFSSL_ZEPHYR)
add_definitions(-DWOLFSSL_USER_SETTINGS)
