#
# Component Makefile
#

COMPONENT_ADD_INCLUDEDIRS := . ./include
COMPONENT_ADD_INCLUDEDIRS += /Users/gojimmypi/Desktop/esp-idf/components/freertos/include/freertos

COMPONENT_SRCDIRS := src ../wolfssl/wolfcrypt/src
COMPONENT_SRCDIRS += ../wolfssl/wolfcrypt/src/port/Espressif
COMPONENT_SRCDIRS += ../wolfssl/wolfcrypt/src/port/atmel

CFLAGS +=-DWOLFSSL_USER_SETTINGS

COMPONENT_OBJEXCLUDE := ../wolfssl/wolfcrypt/src/aes_asm.o
COMPONENT_OBJEXCLUDE += ../wolfssl/wolfcrypt/src/evp.o
COMPONENT_OBJEXCLUDE += ../wolfssl/wolfcrypt/src/misc.o
COMPONENT_OBJEXCLUDE += src/bio.o
