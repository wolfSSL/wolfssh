cmake_minimum_required(VERSION 3.20.0)

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
