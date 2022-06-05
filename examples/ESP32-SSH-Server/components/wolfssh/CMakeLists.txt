#
# cmake for wolfssh
# 
cmake_minimum_required(VERSION 3.5)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

set(CMAKE_CURRENT_SOURCE_DIR ".")
set(WOLFSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(INCLUDE_PATH ${WOLFSSL_ROOT})

set(COMPONENT_SRCDIRS "./src/"
                      "../wolfssl/wolfcrypt/src/"
                      "../wolfssl/wolfcrypt/src/port/Espressif/"
                      "../wolfssl/wolfcrypt/src/port/atmel/"
                      )

set(COMPONENT_REQUIRES lwip)

string(REPLACE "\\" "/" RTOS_IDF_PATH "$ENV{IDF_PATH}/components/freertos/include/freertos")
# ESP-IDF after version 4.4x has a different RTOS directory structure
string(REPLACE "\\" "/" RTOS_IDF_PATH5 "$ENV{IDF_PATH}/components/freertos/FreeRTOS-Kernel/include/freertos")

if(IS_DIRECTORY ${IDF_PATH}/components/freertos/FreeRTOS-Kernel/)
    set(COMPONENT_ADD_INCLUDEDIRS
        "."
        "./include"
       "${RTOS_IDF_PATH5}"
       "${WOLFSSL_ROOT}"
       )
else()

   set(COMPONENT_ADD_INCLUDEDIRS
       "."
       "./include"
       "${RTOS_IDF_PATH}"
       "${WOLFSSL_ROOT}"
      )
endif()

if(IS_DIRECTORY ${IDF_PATH}/components/cryptoauthlib)
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "../cryptoauthlib/lib")
endif()

set(COMPONENT_SRCEXCLUDE
    "wolfcrypt/src/aes_asm.S"
    "wolfcrypt/src/evp.c"
    "wolfcrypt/src/misc.c"
    "src/bio.c"
    )
set(COMPONENT_PRIV_INCLUDEDIRS . ../wolfssl ../wolfssl/include)

register_component()

# check to see if there's both a local copy and EDP-IDF copy of the wolfssh components
if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssh/" AND EXISTS "$ENV{IDF_PATH}/components/wolfssh/" ) 
    message(STATUS  "") 
    message(STATUS  "WARNING: Found components/wolfssh in both local project and IDF_PATH")
    message(STATUS  "") 
endif()
# end multiple component check
