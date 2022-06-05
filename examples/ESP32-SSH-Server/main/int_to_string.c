/* int_to_string.c
 *
 * Copyright (C) 2014-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "int_to_string.h"

#ifdef __cplusplus
extern "C" {
#endif

    int int_to_string_VERSION() {
        return 1;
    }


    /* based on code from https://stackoverflow.com/questions/3464194/how-can-i-convert-an-integer-to-a-hexadecimal-string-in-c
     * see also           https://stackoverflow.com/questions/8257714/how-to-convert-an-int-to-string-in-c
     * see also https://github.com/kevmuret/libhex/blob/master/hex.c
     */

    /*
     * convert [n] to a text string in [dest].
     * m is minus sign negative number indicator: 0 if positive, 1 if negative
     */
    char *int_to_base(char *dest, long n, int base, int m) {
        char *outbuf = dest;
        int i = 12;
        int j = 0;

        /* only base 2 .. 16 supported at this time, assume base 10 otherwise*/
        if ((base < 2) || (base > 16))  {
            base = 10;
        }

        do {
            outbuf[i] = "0123456789ABCDEF"[n % base];
            i--;
            n = n / base;
        } while (n > 0);


        /* see if we need to add the minus sign */
        if (m)
        {
            outbuf[j++] = '-';
        }

        while (++i < 13) {
            outbuf[j++] = outbuf[i];
        }

        /* zero terminated string */
        outbuf[j] = 0;
        return dest;
    }

    /*
     * if we wanted a signed number from n, check the high bit
     */
    char *int_to_signed_base(char *dest, long n, int base) {
        int m = 0;
        /* check to see if we have a negative number
         * we'll check the high bit by shiftinh a 1 over by 1 minus the number
         * of bytes in our log (typically 4) by 3 bits
         * (which multiplies by 8). (e.g. 32-1)
        */
        if (n & ((unsigned long)(1 << ((sizeof(n) << 3) - 1)))) {
            n = -n;
            m = 1;
        }
        return int_to_base(dest, n, base, m);
    }


    /*
     * convert [n] to unsigned hex string
     */
    char *int_to_hex(char *dest, unsigned long n)
    {
        return int_to_base(dest, n, 16, 0);
    }

    /*
     * convert [n] to unsigned decimal string
     */
    char *int_to_dec(char *dest, unsigned long n)
    {
        return int_to_base(dest, n, 10, 0);
    }

    /*
     * convert [n] to signed decimal string
     */
    char *int_to_signed_dec(char *dest, long n) {
        return int_to_signed_base(dest, n, 10);
    }

    /*
     * convert [n] to unsigned binary string
     */
    char *int_to_bin(char *dest, unsigned long n)
    {
        return int_to_base(dest, n, 2, 0);
    }

#ifdef __cplusplus
}
#endif