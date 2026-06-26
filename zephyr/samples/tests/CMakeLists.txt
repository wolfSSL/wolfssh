cmake_minimum_required(VERSION 3.20.0)

# Determine the Zephyr kernel version before find_package(Zephyr): the
# KERNEL_VERSION_* variables it would set are not available yet, and the
# RAM disk and POSIX config below depend on APIs that changed across releases.
# Parse $ZEPHYR_BASE/VERSION directly instead.
file(STRINGS $ENV{ZEPHYR_BASE}/VERSION zephyr_version_lines)
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

# RAM disk: configured via the devicetree "zephyr,ram-disk" node on Zephyr
# >= 3.5, via Kconfig before that. Only the filesystem-backed scenarios need
# it; the nofs build (CONF_FILE="prj_nofs.conf") has no disk.
if(NOT "${CONF_FILE}" MATCHES "nofs")
  if(ZEPHYR_VER VERSION_LESS 3.5)
    list(APPEND EXTRA_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ramdisk_legacy.conf)
  else()
    list(APPEND EXTRA_DTC_OVERLAY_FILE ${CMAKE_CURRENT_SOURCE_DIR}/ramdisk.overlay)
  endif()
endif()

# POSIX socket names / pthreads / clock: CONFIG_POSIX_API (in prj*.conf)
# covers these on Zephyr >= 4.1; older releases need the symbols the 4.1
# POSIX reorg removed.
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
