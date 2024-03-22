#  [wolfSSL Project]/CMakeLists.txt
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

# wolfSSL Espressif Example Project CMakeLists.txt
#   v1.0
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# enable wolfssl user_settings.h project-wide
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
set(WOLFSSL_USER_SETTINGS ON)

# Assume we have a ESP_ENABLE_WOLFSSH section in user_settings.h
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DESP_ENABLE_WOLFSSH")

# The wolfSSL CMake file should be able to find the source code.
# Otherwise, assign an environment variable or set it here:
#
# set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
# set(WOLFSSH_ROOT "~/workspace/wolfssh-other-source")
# set(WOLFSSL_ROOT "C:/workspace/wolfssl-master")

# Optional WOLFSSL_CMAKE_SYSTEM_NAME detection to find
# USE_MY_PRIVATE_CONFIG path for my_private_config.h
#
# Expected path varies:
#
#     WSL:  /mnt/c/workspace
#   Linux:  ~/workspace
# Windows:  C:\workspace
#
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
# End optional WOLFSSL_CMAKE_SYSTEM_NAME

# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
    message("Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
else()
    message("NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
endif()

# Check that there are not conflicting wolfSSL components
# The ESP Registry Component will be in ./managed_components/wolfssl__wolfssl
# The local component wolfSSL directory will be in ./components/wolfssl
if( EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" AND EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl" )
    # These exclude statements don't seem to be honored by the $ENV{IDF_PATH}/tools/cmake/project.cmake'
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" EXCLUDE_FROM_ALL)
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl/include" EXCLUDE_FROM_ALL)
    # So we'll error out and let the user decide how to proceed:
    message(WARNING "\nFound wolfSSL components in\n"
                    "./managed_components/wolfssl__wolfssl\n"
                    "and\n"
                    "./components/wolfssl\n"
                    "in project directory: \n"
                    "${CMAKE_HOME_DIRECTORY}")
    message(FATAL_ERROR "\nPlease use either the ESP Registry Managed Component or the wolfSSL component directory but not both.\n"
                        "If removing the ./managed_components/wolfssl__wolfssl directory, remember to also remove "
                        "or rename the idf_component.yml file typically found in ./main/")
else()
    message(STATUS "No conflicting wolfSSL components found.")
endif()


# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
    message("Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
else()
    message("NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(wolfssh_echoserver)
