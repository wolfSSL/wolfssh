#pragma once


//#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    int int_to_string_VERSION();

    char *int_to_base(char *dest, unsigned long n, int base);

    char *int_to_string(char *dest, unsigned long n, long x);
    char *int_to_hex(char *dest, unsigned long n);
    char *int_to_dec(char *dest, unsigned long n);
    char *int_to_bin(char *dest, unsigned long n);

#ifdef __cplusplus
}
#endif