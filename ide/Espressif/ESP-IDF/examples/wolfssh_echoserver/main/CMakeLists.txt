#  [wolfSSL Project]/main/CMakeLists.txt
#
#  Copyright (C) 2014-2024 wolfSSL Inc.
#
#  This file is part of wolfSSH.
#
#  wolfSSH is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  wolfSSH is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
#
# cmake for WOLFSSH Espressif projects
#
# See https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html
# wolfSSL wolfSSH Espressif Example Project/main/CMakeLists.txt
#   v1.0
#
message(STATUS "main cmake found WOLFSSL_COMPONENT_NAME = ${WOLFSSL_COMPONENT_NAME}")

if(WIN32)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
    message("Detected Windows")
endif()
if(CMAKE_HOST_UNIX)
    message("Detected UNIX")
endif()
if(APPLE)
    message("Detected APPLE")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND EXISTS "/proc/sys/fs/binfmt_misc/WSLInterop")
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WSL")
    message("Detected WSL")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND (NOT WIN32))
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_LINUX")
    message("Detected Linux")
endif()
if(APPLE)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
    message("Detected Apple")
endif()
set (git_cmd "git")

if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl/" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
    #
    # wolfSSL found in both ESP-IDF and local project - needs to be resolved by user
    #
    message(STATUS "")
    message(STATUS "WARNING: Found components/wolfssl in both local project and IDF_PATH")
    message(STATUS "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_MULTI_INSTALL_WARNING")
endif()

if( "$ENV{IDF_COMPONENT_REGISTRY_URL}" STREQUAL "https://components-staging.espressif.com" )
    if( ("${managed_components}" STREQUAL "") AND ("${component_manager_interface_version}" STREQUAL "") )
        # We've found a staging component, but did not detect the component manager
        if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../components/mywolfssh/CMakeLists.txt)
            # This is typically during publish-time build test
            message(STATUS "Set name mywolfssh (1)")
            set(WOLFSSL_COMPONENT_NAME "mywolfssl")
            set(WOLFSSH_COMPONENT_NAME "mywolfssh")
        else()
            if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../managed_components/gojimmypi__mywolfmqtt/CMakeLists.txt)
                # This is typically upon creating a project from managed component examples
                message(STATUS "Set name mywolfssh (2)")
                set(WOLFSSL_COMPONENT_NAME "mywolfssl")
                set(WOLFSSH_COMPONENT_NAME "mywolfssh")
            else()
                message(STATUS "Set name wolfmqtt (1) CMAKE_CURRENT_LIST_DIR = ${CMAKE_CURRENT_LIST_DIR}")
                set(WOLFSSL_COMPONENT_NAME "wolfssl")
                set(WOLFSSH_COMPONENT_NAME "wolfssh")
            endif()
        endif()
    else()
        message(STATUS "Set name mywolfssh (3)")
        set(WOLFSSL_COMPONENT_NAME "mywolfssl")
        set(WOLFSSH_COMPONENT_NAME "mywolfssh")
    endif()
else()
    message(STATUS "Set name wolfssh (2)")
    set(WOLFSSL_COMPONENT_NAME "wolfssl")
    set(WOLFSSH_COMPONENT_NAME "wolfssh")
endif()

## register_component()
idf_component_register(
                       SRCS main.c echoserver.c time_helper.c wifi_connect.c
                       INCLUDE_DIRS "." "./include")
#

#
# LIBWOLFSSL_SAVE_INFO(VAR_OUPUT THIS_VAR VAR_RESULT)
#
# Save the THIS_VAR as a string in a macro called VAR_OUPUT
#
# VAR_OUPUT:  the name of the macro to define
# THIS_VAR:   the OUTPUT_VARIABLE result from a execute_process()
# VAR_RESULT: the RESULT_VARIABLE from a execute_process(); "0" if successful.
#
function ( LIBWOLFSSL_SAVE_INFO VAR_OUPUT THIS_VAR VAR_RESULT )
    # is the RESULT_VARIABLE output value 0? If so, IS_VALID_VALUE is true.
    string(COMPARE EQUAL "${VAR_RESULT}" "0" IS_VALID_VALUE)

    # if we had a successful operation, save the THIS_VAR in VAR_OUPUT
    if(${IS_VALID_VALUE})
        # strip newline chars in THIS_VAR parameter and save in VAR_VALUE
        string(REPLACE "\n" ""  VAR_VALUE  ${THIS_VAR})

        # we'll could percolate the value to the parent for possible later use
        # set(${VAR_OUPUT} ${VAR_VALUE} PARENT_SCOPE)

        # but we're only using it here in this function
        set(${VAR_OUPUT} ${VAR_VALUE})

        # we'll print what we found to the console
        message(STATUS "Found ${VAR_OUPUT}=${VAR_VALUE}")

        # the interesting part is defining the VAR_OUPUT name a value to use in the app
        add_definitions(-D${VAR_OUPUT}=\"${VAR_VALUE}\")
    else()
        # if we get here, check the execute_process command and parameters.
        message(STATUS "LIBWOLFSSL_SAVE_INFO encountered a non-zero VAR_RESULT")
        set(${VAR_OUPUT} "Unknown")
    endif()
endfunction() # LIBWOLFSSL_SAVE_INFO

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    # LIBWOLFSSL_VERSION_GIT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "--short" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_SHORT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_HASH_DATE
    execute_process(COMMAND ${git_cmd} "show" "--no-patch" "--no-notes" "--pretty=\'\%cd\'" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH_DATE "${TMP_OUT}" "${TMP_RES}")
endif()

message(STATUS "")

