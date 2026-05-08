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

if(IS_DIRECTORY ${IDF_PATH}/components/freertos/FreeRTOS-Kernel/)
    set(COMPONENT_ADD_INCLUDEDIRS
        "."
        "./include"
        "../freertos/FreeRTOS-Kernel/include/freertos"
       "${WOLFSSL_ROOT}"
       )
else()

   set(COMPONENT_ADD_INCLUDEDIRS
       "."
       "./include"
       # "/Users/gojimmypi/Desktop/esp-idf/components/freertos/include/freertos"
       "${RTOS_IDF_PATH}"
       "${WOLFSSL_ROOT}"
      )
endif()

if(IS_DIRECTORY ${IDF_PATH}/components/cryptoauthlib)
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "../cryptoauthlib/lib")
endif()

set(COMPONENT_SRCEXCLUDE
    "./src/misc.c"
    "../wolfssl/wolfcrypt/src/evp.c"
    "../wolfssl/wolfcrypt/src/misc.c"
    )
set(COMPONENT_PRIV_INCLUDEDIRS . ../wolfssl ../wolfssl/include)

register_component()
