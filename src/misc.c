/* misc.c
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

/*
 * The misc module contains inline functions. This file is either included
 * into source files or built separately depending on the inline configure
 * option.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif

#ifndef WOLFSSH_MISC_C
#define WOLFSSH_MISC_C


#include <wolfssh/misc.h>
#include <wolfssh/log.h>


#ifdef NO_INLINE
    #define STATIC
#else
    #define STATIC static
#endif


/* Check for if compiling misc.c when not needed. */
#if !defined(WOLFSSH_MISC_INCLUDED) && !defined(NO_INLINE)
    #define MISC_WARNING "misc.c does not need to be compiled when using inline (NO_INLINE not defined))"

    #ifndef _MSC_VER
        #warning MISC_WARNING
    #else
        #pragma message("warning: " MISC_WARNING)
    #endif

#else /* !WOLFSSL_MISC_INCLUDED && !NO_INLINE */


#ifndef min
STATIC INLINE word32 min(word32 a, word32 b)
{
    return a > b ? b : a;
}
#endif /* min */


/* convert opaque to 32 bit integer */
STATIC INLINE void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}


/* 
 * These word64 functions come from wolfSSL. wolfSSL doesn't export them, so
 * they're re-implemented here.
 */
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_NO_WORD64_OPS)
STATIC INLINE word64 rotlFixed64(word64 x, word64 y)
{
    return (x << y) | (x >> (sizeof(y) * 8 - y));
}


STATIC INLINE word64 ByteReverseWord64(word64 value)
{
#if defined(WOLF_ALLOW_BUILTIN) && defined(__GNUC_PREREQ) && __GNUC_PREREQ(4, 3)
    return (word64)__builtin_bswap64(value);
#elif defined(WOLFCRYPT_SLOW_WORD64)
    return (word64)((word64)ByteReverseWord32((word32) value)) << 32 |
        (word64)ByteReverseWord32((word32)(value   >> 32));
#else
    value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) |
        ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
    value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) |
        ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
    return rotlFixed64(value, 32U);
#endif
}
#endif /* WORD64_AVAILABLE && !WOLFSSL_NO_WORD64_OPS */


#ifdef WORD64_AVAILABLE
STATIC INLINE void ato64(const byte *in, w64wrapper *w64)
{
#ifdef BIG_ENDIAN_ORDER
    XMEMCPY(&w64->n, in, sizeof(w64->n));
#else
    word64 _in;
    XMEMCPY(&_in, in, sizeof(_in));
    w64->n = ByteReverseWord64(_in);
#endif /* BIG_ENDIAN_ORDER */
}


STATIC INLINE w64wrapper w64From32(word32 hi, word32 lo)
{
    w64wrapper ret;
    ret.n = ((word64)hi << 32) | lo;
    return ret;
}


STATIC INLINE byte w64GTE(w64wrapper a, w64wrapper b)
{
    return a.n >= b.n;
}


STATIC INLINE byte w64LT(w64wrapper a, w64wrapper b)
{
    return a.n < b.n;
}

#else

STATIC INLINE void ato64(const byte *in, w64wrapper *w64)
{
#ifdef BIG_ENDIAN_ORDER
    const word32 *_in = (const word32*)(in);
    w64->n[0] = *_in;
    w64->n[1] = *(_in + 1);
#else
    ato32(in, &w64->n[0]);
    ato32(in + 4, &w64->n[1]);
#endif /* BIG_ENDIAN_ORDER */
}


STATIC INLINE w64wrapper w64From32(word32 hi, word32 lo)
{
    w64wrapper w64;
    w64.n[0] = hi;
    w64.n[1] = lo;
    return w64;
}


STATIC INLINE byte w64GTE(w64wrapper a, w64wrapper b)
{
    if (a.n[0] > b.n[0])
        return 1;
    if (a.n[0] == b.n[0])
        return a.n[1] >= b.n[1];
    return 0;
}


STATIC INLINE byte w64LT(w64wrapper a, w64wrapper b)
{
    if (a.n[0] < b.n[0])
        return 1;
    if (a.n[0] == b.n[0])
        return a.n[1] < b.n[1];

    return 0;
}
#endif /* WORD64_AVAILABLE */


/* convert 32 bit integer to opaque */
STATIC INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


/* Make sure compiler doesn't skip */
STATIC INLINE void ForceZero(const void* mem, word32 length)
{
    volatile byte* z = (volatile byte*)mem;

    while (length--) *z++ = 0;
}


/* check all length bytes for equality, return 0 on success */
STATIC INLINE int ConstantCompare(const byte* a, const byte* b,
                                  word32 length)
{
    word32 i;
    word32 compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum;
}


#undef STATIC


#endif /* !WOLFSSL_MISC_INCLUDED && !NO_INLINE */


#endif /* WOLFSSH_MISC_C */
