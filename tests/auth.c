/* auth.c
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssh/port.h>

#include <stdio.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#if !defined(NO_SHA256)
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#ifdef NO_FILESYSTEM
    #include <wolfssh/certs_test.h>
#endif
#define WOLFSSH_TEST_CLIENT
#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_LOCKING
#ifndef SINGLE_THREADED
    #define WOLFSSH_TEST_THREADING
#endif
#include <wolfssh/test.h>
#include "tests/auth.h"

#ifndef WOLFSSH_NO_ABORT
    #define WABORT() abort()
#else
    #define WABORT()
#endif

#define PrintError(description, result) do {                                   \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
} while(0)

#ifdef WOLFSSH_ZEPHYR
#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WABORT();                                                                  \
} while(0)
#else
#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WFFLUSH(stdout);                                                           \
    WABORT();                                                                  \
} while(0)
#endif

#define Assert(test, description, result) if (!(test)) Fail(description, result)

#define AssertTrue(x)    Assert( (x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert( (x), ("%s is not null", #x), (#x " => NULL"))

#define AssertNull(x) do {                                                     \
    PEDANTIC_EXTENSION void* _x = (void*)(x);                                  \
                                                                               \
    Assert(!_x, ("%s is null", #x), (#x " => %p", _x));                        \
} while(0)

#define AssertInt(x, y, op, er) do {                                           \
    int _x = (int)(x);                                                         \
    int _y = (int)(y);                                                         \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%d " #er " %d", _x, _y));    \
} while(0)

#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
#define AssertIntNE(x, y) AssertInt(x, y, !=, ==)
#define AssertIntGT(x, y) AssertInt(x, y,  >, <=)
#define AssertIntLT(x, y) AssertInt(x, y,  <, >=)
#define AssertIntGE(x, y) AssertInt(x, y, >=,  <)
#define AssertIntLE(x, y) AssertInt(x, y, <=,  >)

#define AssertStr(x, y, op, er) do {                                           \
    const char* _x = (const char*)(x);                                         \
    const char* _y = (const char*)(y);                                         \
    int         _z = (_x && _y) ? strcmp(_x, _y) : -1;                         \
    Assert(_z op 0, ("%s " #op " %s", #x, #y),                                 \
                                            ("\"%s\" " #er " \"%s\"", _x, _y));\
} while(0)

#define AssertStrEQ(x, y) AssertStr(x, y, ==, !=)
#define AssertStrNE(x, y) AssertStr(x, y, !=, ==)
#define AssertStrGT(x, y) AssertStr(x, y,  >, <=)
#define AssertStrLT(x, y) AssertStr(x, y,  <, >=)
#define AssertStrGE(x, y) AssertStr(x, y, >=,  <)
#define AssertStrLE(x, y) AssertStr(x, y, <=,  >)

#define AssertPtr(x, y, op, er) do {                                           \
    PRAGMA_GCC_DIAG_PUSH                                                       \
      /* remarkably, without this inhibition, */                               \
      /* the _Pragma()s make the declarations warn. */                         \
    PRAGMA_GCC("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")     \
      /* inhibit "ISO C forbids conversion of function pointer */              \
      /* to object pointer type [-Werror=pedantic]" */                         \
    PRAGMA_GCC("GCC diagnostic ignored \"-Wpedantic\"")                        \
    void* _x = (void*)(x);                                                     \
    void* _y = (void*)(y);                                                     \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%p " #er " %p", _x, _y));    \
    PRAGMA_GCC_DIAG_POP;                                                       \
} while(0)

#define AssertPtrEq(x, y) AssertPtr(x, y, ==, !=)
#define AssertPtrNE(x, y) AssertPtr(x, y, !=, ==)
#define AssertPtrGT(x, y) AssertPtr(x, y,  >, <=)
#define AssertPtrLT(x, y) AssertPtr(x, y,  <, >=)
#define AssertPtrGE(x, y) AssertPtr(x, y, >=,  <)
#define AssertPtrLE(x, y) AssertPtr(x, y, <=,  >)

#define ES_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    serverArgs->return_code = ret; \
    WOLFSSL_RETURN_FROM_THREAD(0); \
} while(0)

#define EXAMPLE_KEYLOAD_BUFFER_SZ 1200

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    #define ECC_PATH "./keys/server-key-ecc.der"
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384)
    #define ECC_PATH "./keys/server-key-ecc-384.der"
#else
    #define ECC_PATH "./keys/server-key-ecc-521.der"
#endif

#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK)

static INLINE void SignalTcpReady(tcp_ready* ready, word16 port)
{
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
}

#ifndef NO_FILESYSTEM
static int load_file(const char* fileName, byte* buf, word32* bufSz)
{
    WFILE* file;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return 0;

    if (WFOPEN(NULL, &file, fileName, "rb") != 0)
        return 0;
    WFSEEK(NULL, file, 0, WSEEK_END);
    fileSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (buf == NULL || fileSz > *bufSz) {
        *bufSz = fileSz;
        WFCLOSE(NULL, file);
        return 0;
    }

    readSz = (word32)WFREAD(NULL, buf, 1, fileSz, file);
    WFCLOSE(NULL, file);

    if (readSz < fileSz) {
        fileSz = 0;
    }

    return fileSz;
}
#endif /* NO_FILESYSTEM */

static int load_key(byte isEcc, byte* buf, word32 bufSz)
{
    word32 sz = 0;

#ifndef NO_FILESYSTEM
    const char* bufName;
    bufName = isEcc ? ECC_PATH : "./keys/server-key-rsa.der";
    sz = load_file(bufName, buf, &bufSz);
#else
    /* using buffers instead */
    if (isEcc) {
        if ((word32)sizeof_ecc_key_der_256_ssh > bufSz) {
            return 0;
        }
        WMEMCPY(buf, ecc_key_der_256_ssh, sizeof_ecc_key_der_256_ssh);
        sz = sizeof_ecc_key_der_256_ssh;
    }
    else {
        if ((word32)sizeof_rsa_key_der_2048_ssh > bufSz) {
            return 0;
        }
        WMEMCPY(buf, (byte*)rsa_key_der_2048_ssh, sizeof_rsa_key_der_2048_ssh);
        sz = sizeof_rsa_key_der_2048_ssh;
    }
#endif

    return sz;
}
#endif /* !NO_WOLFSSH_SERVER && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED && !WOLFSSH_TEST_BLOCK */

/* =========================================================
 * Public-key auth integration test helpers (issue 2483)
 * ========================================================= */

 #if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK) && \
    !defined(NO_SHA256)
/* Hansel's RSA keypair (ASN.1 DER private key, OpenSSH text public key).
 * Copied from examples/client/common.c so this test file is self-contained. */
#ifndef WOLFSSH_NO_RSA
static const char* hanselPublicRsa =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9P3ZFowOsONXHD5MwWiCciXytBRZGho"
    "MNiisWSgUs5HdHcACuHYPi2W6Z1PBFmBWT9odOrGRjoZXJfDDoPi+j8SSfDGsc/hsCmc3G"
    "p2yEhUZUEkDhtOXyqjns1ickC9Gh4u80aSVtwHRnJZh9xPhSq5tLOhId4eP61s+a5pwjTj"
    "nEhBaIPUJO2C/M0pFnnbZxKgJlX7t1Doy7h5eXxviymOIvaCZKU+x5OopfzM/wFkey0EPW"
    "NmzI5y/+pzU5afsdeEWdiQDIQc80H6Pz8fsoFPvYSG+s4/wz0duu7yeeV1Ypoho65Zr+pE"
    "nIf7dO0B8EblgWt+ud+JI8wrAhfE4x hansel";
static const byte hanselPrivateRsa[] = {
  0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
  0xbd, 0x3f, 0x76, 0x45, 0xa3, 0x03, 0xac, 0x38, 0xd5, 0xc7, 0x0f, 0x93,
  0x30, 0x5a, 0x20, 0x9c, 0x89, 0x7c, 0xad, 0x05, 0x16, 0x46, 0x86, 0x83,
  0x0d, 0x8a, 0x2b, 0x16, 0x4a, 0x05, 0x2c, 0xe4, 0x77, 0x47, 0x70, 0x00,
  0xae, 0x1d, 0x83, 0xe2, 0xd9, 0x6e, 0x99, 0xd4, 0xf0, 0x45, 0x98, 0x15,
  0x93, 0xf6, 0x87, 0x4e, 0xac, 0x64, 0x63, 0xa1, 0x95, 0xc9, 0x7c, 0x30,
  0xe8, 0x3e, 0x2f, 0xa3, 0xf1, 0x24, 0x9f, 0x0c, 0x6b, 0x1c, 0xfe, 0x1b,
  0x02, 0x99, 0xcd, 0xc6, 0xa7, 0x6c, 0x84, 0x85, 0x46, 0x54, 0x12, 0x40,
  0xe1, 0xb4, 0xe5, 0xf2, 0xaa, 0x39, 0xec, 0xd6, 0x27, 0x24, 0x0b, 0xd1,
  0xa1, 0xe2, 0xef, 0x34, 0x69, 0x25, 0x6d, 0xc0, 0x74, 0x67, 0x25, 0x98,
  0x7d, 0xc4, 0xf8, 0x52, 0xab, 0x9b, 0x4b, 0x3a, 0x12, 0x1d, 0xe1, 0xe3,
  0xfa, 0xd6, 0xcf, 0x9a, 0xe6, 0x9c, 0x23, 0x4e, 0x39, 0xc4, 0x84, 0x16,
  0x88, 0x3d, 0x42, 0x4e, 0xd8, 0x2f, 0xcc, 0xd2, 0x91, 0x67, 0x9d, 0xb6,
  0x71, 0x2a, 0x02, 0x65, 0x5f, 0xbb, 0x75, 0x0e, 0x8c, 0xbb, 0x87, 0x97,
  0x97, 0xc6, 0xf8, 0xb2, 0x98, 0xe2, 0x2f, 0x68, 0x26, 0x4a, 0x53, 0xec,
  0x79, 0x3a, 0x8a, 0x5f, 0xcc, 0xcf, 0xf0, 0x16, 0x47, 0xb2, 0xd0, 0x43,
  0xd6, 0x36, 0x6c, 0xc8, 0xe7, 0x2f, 0xfe, 0xa7, 0x35, 0x39, 0x69, 0xfb,
  0x1d, 0x78, 0x45, 0x9d, 0x89, 0x00, 0xc8, 0x41, 0xcf, 0x34, 0x1f, 0xa3,
  0xf3, 0xf1, 0xfb, 0x28, 0x14, 0xfb, 0xd8, 0x48, 0x6f, 0xac, 0xe3, 0xfc,
  0x33, 0xd1, 0xdb, 0xae, 0xef, 0x27, 0x9e, 0x57, 0x56, 0x29, 0xa2, 0x1a,
  0x3a, 0xe5, 0x9a, 0xfe, 0xa4, 0x49, 0xc8, 0x7f, 0xb7, 0x4e, 0xd0, 0x1f,
  0x04, 0x6e, 0x58, 0x16, 0xb7, 0xeb, 0x9d, 0xf8, 0x92, 0x3c, 0xc2, 0xb0,
  0x21, 0x7c, 0x4e, 0x31, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
  0x01, 0x00, 0x8d, 0xa4, 0x61, 0x06, 0x2f, 0xc3, 0x40, 0xf4, 0x6c, 0xf4,
  0x87, 0x30, 0xb8, 0x00, 0xcc, 0xe5, 0xbc, 0x75, 0x87, 0x1e, 0x06, 0x95,
  0x14, 0x7a, 0x23, 0xf9, 0x24, 0xd4, 0x92, 0xe4, 0x1a, 0xbc, 0x88, 0x95,
  0xfc, 0x3b, 0x56, 0x16, 0x1b, 0x2e, 0xff, 0x64, 0x2b, 0x58, 0xd7, 0xd8,
  0x8e, 0xc2, 0x9f, 0xb2, 0xe5, 0x84, 0xb9, 0xbc, 0x8d, 0x61, 0x54, 0x35,
  0xb0, 0x70, 0xfe, 0x72, 0x04, 0xc0, 0x24, 0x6d, 0x2f, 0x69, 0x61, 0x06,
  0x1b, 0x1d, 0xe6, 0x2d, 0x6d, 0x79, 0x60, 0xb7, 0xf4, 0xdb, 0xb7, 0x4e,
  0x97, 0x36, 0xde, 0x77, 0xc1, 0x9f, 0x85, 0x4e, 0xc3, 0x77, 0x69, 0x66,
  0x2e, 0x3e, 0x61, 0x76, 0xf3, 0x67, 0xfb, 0xc6, 0x9a, 0xc5, 0x6f, 0x99,
  0xff, 0xe6, 0x89, 0x43, 0x92, 0x44, 0x75, 0xd2, 0x4e, 0x54, 0x91, 0x58,
  0xb2, 0x48, 0x2a, 0xe6, 0xfa, 0x0d, 0x4a, 0xca, 0xd4, 0x14, 0x9e, 0xf6,
  0x27, 0x67, 0xb7, 0x25, 0x7a, 0x43, 0xbb, 0x2b, 0x67, 0xd1, 0xfe, 0xd1,
  0x68, 0x23, 0x06, 0x30, 0x7c, 0xbf, 0x60, 0x49, 0xde, 0xcc, 0x7e, 0x26,
  0x5a, 0x3b, 0xfe, 0xa6, 0xa6, 0xe7, 0xa8, 0xdd, 0xac, 0xb9, 0xaf, 0x82,
  0x9a, 0x3a, 0x41, 0x7e, 0x61, 0x21, 0x37, 0xa3, 0x08, 0xe4, 0xc4, 0xbc,
  0x11, 0xf5, 0x3b, 0x8e, 0x4d, 0x51, 0xf3, 0xbd, 0xda, 0xba, 0xb2, 0xc5,
  0xee, 0xfb, 0xcf, 0xdf, 0x83, 0xa1, 0x82, 0x01, 0xe1, 0x51, 0x9d, 0x07,
  0x5a, 0x5d, 0xd8, 0xc7, 0x5b, 0x3f, 0x97, 0x13, 0x6a, 0x4d, 0x1e, 0x8d,
  0x39, 0xac, 0x40, 0x95, 0x82, 0x6c, 0xa2, 0xa1, 0xcc, 0x8a, 0x9b, 0x21,
  0x32, 0x3a, 0x58, 0xcc, 0xe7, 0x2d, 0x1a, 0x79, 0xa4, 0x31, 0x50, 0xb1,
  0x4b, 0x76, 0x23, 0x1b, 0xb3, 0x40, 0x3d, 0x3d, 0x72, 0x72, 0x32, 0xec,
  0x5f, 0x38, 0xb5, 0x8d, 0xb2, 0x8d, 0x02, 0x81, 0x81, 0x00, 0xed, 0x5a,
  0x7e, 0x8e, 0xa1, 0x62, 0x7d, 0x26, 0x5c, 0x78, 0xc4, 0x87, 0x71, 0xc9,
  0x41, 0x57, 0x77, 0x94, 0x93, 0x93, 0x26, 0x78, 0xc8, 0xa3, 0x15, 0xbd,
  0x59, 0xcb, 0x1b, 0xb4, 0xb2, 0x6b, 0x0f, 0xe7, 0x80, 0xf2, 0xfa, 0xfc,
  0x8e, 0x32, 0xa9, 0x1b, 0x1e, 0x7f, 0xe1, 0x26, 0xef, 0x00, 0x25, 0xd8,
  0xdd, 0xc9, 0x1a, 0x23, 0x00, 0x26, 0x3b, 0x46, 0x23, 0xc0, 0x50, 0xe7,
  0xce, 0x62, 0xb2, 0x36, 0xb2, 0x98, 0x09, 0x16, 0x34, 0x18, 0x9e, 0x46,
  0xbc, 0xaf, 0x2c, 0x28, 0x94, 0x2f, 0xe0, 0x5d, 0xc9, 0xb2, 0xc8, 0xfb,
  0x5d, 0x13, 0xd5, 0x36, 0xaa, 0x15, 0x0f, 0x89, 0xa5, 0x16, 0x59, 0x5d,
  0x22, 0x74, 0xa4, 0x47, 0x5d, 0xfa, 0xfb, 0x0c, 0x5e, 0x80, 0xbf, 0x0f,
  0xc2, 0x9c, 0x95, 0x0f, 0xe7, 0xaa, 0x7f, 0x16, 0x1b, 0xd4, 0xdb, 0x38,
  0x7d, 0x58, 0x2e, 0x57, 0x78, 0x2f, 0x02, 0x81, 0x81, 0x00, 0xcc, 0x1d,
  0x7f, 0x74, 0x36, 0x6d, 0xb4, 0x92, 0x25, 0x62, 0xc5, 0x50, 0xb0, 0x5c,
  0xa1, 0xda, 0xf3, 0xb2, 0xfd, 0x1e, 0x98, 0x0d, 0x8b, 0x05, 0x69, 0x60,
  0x8e, 0x5e, 0xd2, 0x89, 0x90, 0x4a, 0x0d, 0x46, 0x7e, 0xe2, 0x54, 0x69,
  0xae, 0x16, 0xe6, 0xcb, 0xd5, 0xbd, 0x7b, 0x30, 0x2b, 0x7b, 0x5c, 0xee,
  0x93, 0x12, 0xcf, 0x63, 0x89, 0x9c, 0x3d, 0xc8, 0x2d, 0xe4, 0x7a, 0x61,
  0x09, 0x5e, 0x80, 0xfb, 0x3c, 0x03, 0xb3, 0x73, 0xd6, 0x98, 0xd0, 0x84,
  0x0c, 0x59, 0x9f, 0x4e, 0x80, 0xf3, 0x46, 0xed, 0x03, 0x9d, 0xd5, 0xdc,
  0x8b, 0xe7, 0xb1, 0xe8, 0xaa, 0x57, 0xdc, 0xd1, 0x41, 0x55, 0x07, 0xc7,
  0xdf, 0x67, 0x3c, 0x72, 0x78, 0xb0, 0x60, 0x8f, 0x85, 0xa1, 0x90, 0x99,
  0x0c, 0xa5, 0x67, 0xab, 0xf0, 0xb6, 0x74, 0x90, 0x03, 0x55, 0x7b, 0x5e,
  0xcc, 0xc5, 0xbf, 0xde, 0xa7, 0x9f, 0x02, 0x81, 0x80, 0x40, 0x81, 0x6e,
  0x91, 0xae, 0xd4, 0x88, 0x74, 0xab, 0x7e, 0xfa, 0xd2, 0x60, 0x9f, 0x34,
  0x8d, 0xe3, 0xe6, 0xd2, 0x30, 0x94, 0xad, 0x10, 0xc2, 0x19, 0xbf, 0x6b,
  0x2e, 0xe2, 0xe9, 0xb9, 0xef, 0x94, 0xd3, 0xf2, 0xdc, 0x96, 0x4f, 0x9b,
  0x09, 0xb3, 0xa1, 0xb6, 0x29, 0x44, 0xf4, 0x82, 0xd1, 0xc4, 0x77, 0x6a,
  0xd7, 0x23, 0xae, 0x4d, 0x75, 0x16, 0x78, 0xda, 0x70, 0x82, 0xcc, 0x6c,
  0xef, 0xaf, 0xc5, 0x63, 0xc6, 0x23, 0xfa, 0x0f, 0xd0, 0x7c, 0xfb, 0x76,
  0x7e, 0x18, 0xff, 0x32, 0x3e, 0xcc, 0xb8, 0x50, 0x7f, 0xb1, 0x55, 0x77,
  0x17, 0x53, 0xc3, 0xd6, 0x77, 0x80, 0xd0, 0x84, 0xb8, 0x4d, 0x33, 0x1d,
  0x91, 0x1b, 0xb0, 0x75, 0x9f, 0x27, 0x29, 0x56, 0x69, 0xa1, 0x03, 0x54,
  0x7d, 0x9f, 0x99, 0x41, 0xf9, 0xb9, 0x2e, 0x36, 0x04, 0x24, 0x4b, 0xf6,
  0xec, 0xc7, 0x33, 0x68, 0x6b, 0x02, 0x81, 0x80, 0x60, 0x35, 0xcb, 0x3c,
  0xd0, 0xe6, 0xf7, 0x05, 0x28, 0x20, 0x1d, 0x57, 0x82, 0x39, 0xb7, 0x85,
  0x07, 0xf7, 0xa7, 0x3d, 0xc3, 0x78, 0x26, 0xbe, 0x3f, 0x44, 0x66, 0xf7,
  0x25, 0x0f, 0xf8, 0x76, 0x1f, 0x39, 0xca, 0x57, 0x0e, 0x68, 0xdd, 0xc9,
  0x27, 0xb2, 0x8e, 0xa6, 0x08, 0xa9, 0xd4, 0xe5, 0x0a, 0x11, 0xde, 0x3b,
  0x30, 0x8b, 0xff, 0x72, 0x28, 0xe0, 0xf1, 0x58, 0xcf, 0xa2, 0x6b, 0x93,
  0x23, 0x02, 0xc8, 0xf0, 0x09, 0xa7, 0x21, 0x50, 0xd8, 0x80, 0x55, 0x7d,
  0xed, 0x0c, 0x48, 0xd5, 0xe2, 0xe9, 0x97, 0x19, 0xcf, 0x93, 0x6c, 0x52,
  0xa2, 0xd6, 0x43, 0x6c, 0xb4, 0xc5, 0xe1, 0xa0, 0x9d, 0xd1, 0x45, 0x69,
  0x58, 0xe1, 0xb0, 0x27, 0x9a, 0xec, 0x2b, 0x95, 0xd3, 0x1d, 0x81, 0x0b,
  0x7a, 0x09, 0x5e, 0xa5, 0xf1, 0xdd, 0x6b, 0xe4, 0xe0, 0x08, 0xf8, 0x46,
  0x81, 0xc1, 0x06, 0x8b, 0x02, 0x81, 0x80, 0x00, 0xf6, 0xf2, 0xeb, 0x25,
  0xba, 0x78, 0x04, 0xad, 0x0e, 0x0d, 0x2e, 0xa7, 0x69, 0xd6, 0x57, 0xe6,
  0x36, 0x32, 0x50, 0xd2, 0xf2, 0xeb, 0xad, 0x31, 0x46, 0x65, 0xc0, 0x07,
  0x97, 0x83, 0x6c, 0x66, 0x27, 0x3e, 0x94, 0x2c, 0x05, 0x01, 0x5f, 0x5c,
  0xe0, 0x31, 0x30, 0xec, 0x61, 0xd2, 0x74, 0x35, 0xb7, 0x9f, 0x38, 0xe7,
  0x8e, 0x67, 0xb1, 0x50, 0x08, 0x68, 0xce, 0xcf, 0xd8, 0xee, 0x88, 0xfd,
  0x5d, 0xc4, 0xcd, 0xe2, 0x86, 0x3d, 0x4a, 0x0e, 0x04, 0x7f, 0xee, 0x8a,
  0xe8, 0x9b, 0x16, 0xa1, 0xfc, 0x09, 0x82, 0xe2, 0x62, 0x03, 0x3c, 0xe8,
  0x25, 0x7f, 0x3c, 0x9a, 0xaa, 0x83, 0xf8, 0xd8, 0x93, 0xd1, 0x54, 0xf9,
  0xce, 0xb4, 0xfa, 0x35, 0x36, 0xcc, 0x18, 0x54, 0xaa, 0xf2, 0x90, 0xb7,
  0x7c, 0x97, 0x0b, 0x27, 0x2f, 0xae, 0xfc, 0xc3, 0x93, 0xaf, 0x1a, 0x75,
  0xec, 0x18, 0xdb
};
static const unsigned int hanselPrivateRsaSz = (unsigned int)sizeof(hanselPrivateRsa);
#endif /* WOLFSSH_NO_RSA */

/* Hansel's ECC keypair */
#ifndef WOLFSSH_NO_ECC
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static const char* hanselPublicEcc =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBNkI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzTP5CQEJSvm25"
    "qUzgDtH7oyaQROUnNvk= hansel";
static const byte hanselPrivateEcc[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x03, 0x6e, 0x17, 0xd3, 0xb9,
  0xb8, 0xab, 0xc8, 0xf9, 0x1f, 0xf1, 0x2d, 0x44, 0x4c, 0x3b, 0x12, 0xb1,
  0xa4, 0x77, 0xd8, 0xed, 0x0e, 0x6a, 0xbe, 0x60, 0xc2, 0xf6, 0x8b, 0xe7,
  0xd3, 0x87, 0x83, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xd9, 0x08, 0xe4,
  0x94, 0xcf, 0xe8, 0x3d, 0x25, 0x17, 0x8d, 0xad, 0x6f, 0x15, 0xf5, 0xf5,
  0xc1, 0x3c, 0xee, 0x1c, 0xed, 0x51, 0x2e, 0x85, 0x48, 0x3a, 0x06, 0xbc,
  0xf7, 0xe2, 0x53, 0x40, 0xa0, 0x78, 0xd4, 0x9b, 0x23, 0xe6, 0x85, 0x74,
  0xa2, 0x33, 0x4c, 0xfe, 0x42, 0x40, 0x42, 0x52, 0xbe, 0x6d, 0xb9, 0xa9,
  0x4c, 0xe0, 0x0e, 0xd1, 0xfb, 0xa3, 0x26, 0x90, 0x44, 0xe5, 0x27, 0x36,
  0xf9
};
static const unsigned int hanselPrivateEccSz = (unsigned int)sizeof(hanselPrivateEcc);
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384)
static const char* hanselPublicEcc =
    "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAA"
    "BhBCvZiZ6i2Izx0FW8/Xug7zwsahoEcqMEjlIPFNwRo385HpRw0mxtbV1zZYnhtE63"
    "GvAWGgrhD5WuTRHDB1x0jpIcc3XbaHj4opHhPc4bikpyzL10w0tDo/RMxebqSW5Rwg== hansel";
static const byte hanselPrivateEcc[] = {
  0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04, 0x30, 0x5a, 0xc6, 0xae, 0x91,
  0x10, 0x20, 0xea, 0x76, 0x7f, 0x84, 0x3f, 0xa1, 0x64, 0xa1, 0xab, 0x0b,
  0xd1, 0xc9, 0xc1, 0xb3, 0x87, 0x3f, 0x7b, 0xe9, 0xde, 0xbe, 0xe5, 0xb3,
  0x21, 0xe9, 0x51, 0xea, 0xd0, 0x06, 0x0c, 0xbd, 0x60, 0x52, 0xdf, 0x53,
  0x62, 0x42, 0xb8, 0x9d, 0x56, 0xb7, 0xc2, 0xb5, 0xa0, 0x07, 0x06, 0x05,
  0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x2b,
  0xd9, 0x89, 0x9e, 0xa2, 0xd8, 0x8c, 0xf1, 0xd0, 0x55, 0xbc, 0xfd, 0x7b,
  0xa0, 0xef, 0x3c, 0x2c, 0x6a, 0x1a, 0x04, 0x72, 0xa3, 0x04, 0x8e, 0x52,
  0x0f, 0x14, 0xdc, 0x11, 0xa3, 0x7f, 0x39, 0x1e, 0x94, 0x70, 0xd2, 0x6c,
  0x6d, 0x6d, 0x5d, 0x73, 0x65, 0x89, 0xe1, 0xb4, 0x4e, 0xb7, 0x1a, 0xf0,
  0x16, 0x1a, 0x0a, 0xe1, 0x0f, 0x95, 0xae, 0x4d, 0x11, 0xc3, 0x07, 0x5c,
  0x74, 0x8e, 0x92, 0x1c, 0x73, 0x75, 0xdb, 0x68, 0x78, 0xf8, 0xa2, 0x91,
  0xe1, 0x3d, 0xce, 0x1b, 0x8a, 0x4a, 0x72, 0xcc, 0xbd, 0x74, 0xc3, 0x4b,
  0x43, 0xa3, 0xf4, 0x4c, 0xc5, 0xe6, 0xea, 0x49, 0x6e, 0x51, 0xc2
};
static const unsigned int hanselPrivateEccSz = (unsigned int)sizeof(hanselPrivateEcc);
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
static const char* hanselPublicEcc =
    "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAA"
    "CFBAET/BOzBb9Jx9b52VIHFP4g/uk5KceDpz2M+/Ln9WiDjsMfb4NgNCAB+EMNJUX/TNBL"
    "FFmqr7c6+zUH+QAo2qstvQDsReyFkETRB2vZD//nCZfcAe0RMtKZmgtQLKXzSlimUjXBM4"
    "/zE5lwE05aXADp88h8nuaT/X4bll9cWJlH0fUykA== hansel";
static const byte hanselPrivateEcc[] = {
  0x30, 0x81, 0xdc, 0x02, 0x01, 0x01, 0x04, 0x42, 0x01, 0x79, 0x40, 0xb8,
  0x33, 0xe5, 0x53, 0x5b, 0x9e, 0xfd, 0xed, 0xbe, 0x7c, 0x68, 0xe4, 0xb6,
  0xc3, 0x50, 0x00, 0x0d, 0x39, 0x64, 0x05, 0xf6, 0x5a, 0x5d, 0x41, 0xab,
  0xb3, 0xd9, 0xa7, 0xcb, 0x1c, 0x7d, 0x34, 0x46, 0x5c, 0x2d, 0x56, 0x26,
  0xa0, 0x6a, 0xc7, 0x3d, 0x4f, 0x78, 0x58, 0x14, 0x66, 0x6c, 0xfc, 0x86,
  0x3c, 0x8b, 0x5b, 0x54, 0x29, 0x89, 0x93, 0x48, 0xd9, 0x54, 0x8b, 0xbe,
  0x9d, 0x91, 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0xa1,
  0x81, 0x89, 0x03, 0x81, 0x86, 0x00, 0x04, 0x01, 0x13, 0xfc, 0x13, 0xb3,
  0x05, 0xbf, 0x49, 0xc7, 0xd6, 0xf9, 0xd9, 0x52, 0x07, 0x14, 0xfe, 0x20,
  0xfe, 0xe9, 0x39, 0x29, 0xc7, 0x83, 0xa7, 0x3d, 0x8c, 0xfb, 0xf2, 0xe7,
  0xf5, 0x68, 0x83, 0x8e, 0xc3, 0x1f, 0x6f, 0x83, 0x60, 0x34, 0x20, 0x01,
  0xf8, 0x43, 0x0d, 0x25, 0x45, 0xff, 0x4c, 0xd0, 0x4b, 0x14, 0x59, 0xaa,
  0xaf, 0xb7, 0x3a, 0xfb, 0x35, 0x07, 0xf9, 0x00, 0x28, 0xda, 0xab, 0x2d,
  0xbd, 0x00, 0xec, 0x45, 0xec, 0x85, 0x90, 0x44, 0xd1, 0x07, 0x6b, 0xd9,
  0x0f, 0xff, 0xe7, 0x09, 0x97, 0xdc, 0x01, 0xed, 0x11, 0x32, 0xd2, 0x99,
  0x9a, 0x0b, 0x50, 0x2c, 0xa5, 0xf3, 0x4a, 0x58, 0xa6, 0x52, 0x35, 0xc1,
  0x33, 0x8f, 0xf3, 0x13, 0x99, 0x70, 0x13, 0x4e, 0x5a, 0x5c, 0x00, 0xe9,
  0xf3, 0xc8, 0x7c, 0x9e, 0xe6, 0x93, 0xfd, 0x7e, 0x1b, 0x96, 0x5f, 0x5c,
  0x58, 0x99, 0x47, 0xd1, 0xf5, 0x32, 0x90
};
static const unsigned int hanselPrivateEccSz = (unsigned int)sizeof(hanselPrivateEcc);
#else
    #error "Enable nistp256, nistp384, nistp521, or disable ECC."
#endif
#endif /* WOLFSSH_NO_ECC */

/* Server context: SHA256 hash of the one authorized public key */
typedef struct PubkeyServerCtx {
    byte hash[WC_SHA256_DIGEST_SIZE];
} PubkeyServerCtx;

/* Client context: key material to present during authentication */
typedef struct PubkeyClientCtx {
    const byte* publicKeyType;
    word32      publicKeyTypeSz;
    byte*       publicKey;
    word32      publicKeySz;
    const byte* privateKey;
    word32      privateKeySz;
} PubkeyClientCtx;

/* Server userAuth callback for pubkey tests: accept only the pre-authorised key */
static int serverPubkeyUserAuth(byte authType, WS_UserAuthData* authData,
                                void* ctx)
{
    byte hash[WC_SHA256_DIGEST_SIZE];
    PubkeyServerCtx* sCtx = (PubkeyServerCtx*)ctx;

    if (authType != WOLFSSH_USERAUTH_PUBLICKEY || sCtx == NULL)
        return WOLFSSH_USERAUTH_FAILURE;

    if (wc_Sha256Hash(authData->sf.publicKey.publicKey,
                      authData->sf.publicKey.publicKeySz, hash) != 0)
        return WOLFSSH_USERAUTH_FAILURE;

    if (WMEMCMP(hash, sCtx->hash, WC_SHA256_DIGEST_SIZE) == 0)
        return WOLFSSH_USERAUTH_SUCCESS;
    return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
}

/* Client userAuth callback for pubkey tests: supply key material from context */
static int clientPubkeyUserAuth(byte authType, WS_UserAuthData* authData,
                                void* ctx)
{
    PubkeyClientCtx* cCtx = (PubkeyClientCtx*)ctx;

    if (authType != WOLFSSH_USERAUTH_PUBLICKEY || cCtx == NULL)
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    authData->sf.publicKey.publicKeyType   = cCtx->publicKeyType;
    authData->sf.publicKey.publicKeyTypeSz = cCtx->publicKeyTypeSz;
    authData->sf.publicKey.publicKey       = cCtx->publicKey;
    authData->sf.publicKey.publicKeySz     = cCtx->publicKeySz;
    authData->sf.publicKey.privateKey      = cCtx->privateKey;
    authData->sf.publicKey.privateKeySz    = cCtx->privateKeySz;
    return WOLFSSH_USERAUTH_SUCCESS;
}


/* Server thread used by pubkey auth tests */
static THREAD_RETURN WOLFSSH_THREAD pubkey_server_thread(void* args)
{
    thread_args* serverArgs = (thread_args*)args;
    int ret = WS_SUCCESS;
    word16 port = 0;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
    word32 bufSz;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    WS_SOCKET_T clientFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);

    serverArgs->return_code = EXIT_SUCCESS;

    tcp_listen(&listenFd, &port, 1);
    SignalTcpReady(serverArgs->signal, port);

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        serverArgs->return_code = WS_MEMORY_E;
        goto cleanup;
    }

    wolfSSH_SetUserAuth(ctx, serverPubkeyUserAuth);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        serverArgs->return_code = WS_MEMORY_E;
        goto cleanup;
    }

    wolfSSH_SetUserAuthCtx(ssh, serverArgs->pubkeyServerCtx);

    /* Load the server's host key. If ECDSA is available, let ECC_PATH pick
     * the enabled curve-specific key file; otherwise fall back to RSA. */
#ifndef WOLFSSH_NO_ECDSA
    bufSz = (word32)load_key(1, buf, sizeof(buf));
#else
    bufSz = (word32)load_key(0, buf, sizeof(buf));
#endif
    if (bufSz == 0 || wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, bufSz,
                                         WOLFSSH_FORMAT_ASN1) < 0) {
        serverArgs->return_code = WS_BAD_FILE_E;
        goto cleanup;
    }

    clientFd = accept(listenFd, (struct sockaddr*)&clientAddr, &clientAddrSz);
    if (clientFd == WOLFSSH_SOCKET_INVALID) {
        serverArgs->return_code = WS_SOCKET_ERROR_E;
        goto cleanup;
    }
    wolfSSH_set_fd(ssh, (int)clientFd);

    ret = wolfSSH_accept(ssh);
    serverArgs->return_code = ret;

cleanup:
    if (ssh != NULL && clientFd != WOLFSSH_SOCKET_INVALID)
        wolfSSH_shutdown(ssh);
    if (ssh != NULL)
        wolfSSH_free(ssh);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    if (clientFd != WOLFSSH_SOCKET_INVALID)
        WCLOSESOCKET(clientFd);
    if (listenFd != WOLFSSH_SOCKET_INVALID)
        WCLOSESOCKET(listenFd);

    WOLFSSL_RETURN_FROM_THREAD(0);
}

/* Run one pubkey auth attempt.
 * sCtx   – server context (authorised key hash)
 * cCtx   – client context (key material to present)
 * expect – expected return value from both wolfSSH_connect() and
 *           wolfSSH_accept(): WS_SUCCESS for a valid-key test,
 *           WS_FATAL_ERROR for a reject test */
static int run_pubkey_test(PubkeyServerCtx* sCtx, PubkeyClientCtx* cCtx,
                           int expect)
{
    thread_args serverArgs;
    tcp_ready   ready;
    THREAD_TYPE serThread;
    WOLFSSH_CTX* clientCtx = NULL;
    WOLFSSH*     clientSsh = NULL;
    SOCKET_T     sockFd    = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    int clientErr = WS_SUCCESS;

    serverArgs.signal          = &ready;
    serverArgs.pubkeyServerCtx = sCtx;
    InitTcpReady(serverArgs.signal);

    ThreadStart(pubkey_server_thread, (void*)&serverArgs, &serThread);
    WaitTcpReady(&ready);

    clientCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(clientCtx);
    wolfSSH_SetUserAuth(clientCtx, clientPubkeyUserAuth);

    clientSsh = wolfSSH_new(clientCtx);
    AssertNotNull(clientSsh);
    wolfSSH_SetUserAuthCtx(clientSsh, cCtx);
    wolfSSH_SetUsername(clientSsh, "hansel");

    build_addr(&clientAddr, (char*)wolfSshIp, ready.port);
    tcp_socket(&sockFd, ((struct sockaddr_in*)&clientAddr)->sin_family);
    AssertIntEQ(connect(sockFd, (const struct sockaddr*)&clientAddr,
                        clientAddrSz), 0);
    wolfSSH_set_fd(clientSsh, (int)sockFd);

    ret = wolfSSH_connect(clientSsh);
    AssertIntEQ(ret, expect);

    if (expect != WS_SUCCESS) {
        /* wolfSSH_connect() wraps the inner error as WS_FATAL_ERROR; verify
         * that the underlying cause is an auth or algorithm failure */
        clientErr = wolfSSH_get_error(clientSsh);
        AssertTrue(clientErr == WS_USER_AUTH_E ||
                   clientErr == WS_INVALID_ALGO_ID);
    }

    wolfSSH_shutdown(clientSsh);
    WCLOSESOCKET(sockFd);
    wolfSSH_free(clientSsh);
    wolfSSH_CTX_free(clientCtx);

    ThreadJoin(serThread);

    /* wolfSSH_accept() wraps errors the same way; assert exact expected code */
    AssertIntEQ(serverArgs.return_code, expect);

    FreeTcpReady(&ready);
    return WS_SUCCESS;
}

#ifndef WOLFSSH_NO_RSA
static void test_pubkey_auth_rsa(void)
{
    PubkeyServerCtx sCtx;
    PubkeyClientCtx cCtx;
    byte  pubKeyBuf[512];
    byte* p = pubKeyBuf;
    word32 pubKeySz = sizeof(pubKeyBuf);
    const byte* pubKeyType  = NULL;
    word32      pubKeyTypeSz = 0;
    byte  privKeyBuf[1300];
    byte* privKeyPtr = privKeyBuf;
    word32 privKeySz = sizeof(privKeyBuf);
    const byte* privKeyType  = NULL;
    word32      privKeyTypeSz = 0;

    printf("Testing RSA public key authentication\n");

    /* Parse the public key from its OpenSSH text representation */
    AssertIntEQ(wolfSSH_ReadKey_buffer((const byte*)hanselPublicRsa,
            (word32)WSTRLEN(hanselPublicRsa), WOLFSSH_FORMAT_SSH,
            &p, &pubKeySz, &pubKeyType, &pubKeyTypeSz, NULL), WS_SUCCESS);

    /* Pre-compute the SHA256 hash that the server will compare against */
    AssertIntEQ(wc_Sha256Hash(pubKeyBuf, pubKeySz, sCtx.hash), 0);

    /* Parse the private key */
    AssertIntEQ(wolfSSH_ReadKey_buffer(hanselPrivateRsa, hanselPrivateRsaSz,
            WOLFSSH_FORMAT_ASN1,
            &privKeyPtr, &privKeySz, &privKeyType, &privKeyTypeSz, NULL),
            WS_SUCCESS);

    cCtx.publicKeyType   = pubKeyType;
    cCtx.publicKeyTypeSz = pubKeyTypeSz;
    cCtx.publicKey       = pubKeyBuf;
    cCtx.publicKeySz     = pubKeySz;
    cCtx.privateKey      = privKeyBuf;
    cCtx.privateKeySz    = privKeySz;

    run_pubkey_test(&sCtx, &cCtx, WS_SUCCESS);
}
#endif /* WOLFSSH_NO_RSA */

#ifndef WOLFSSH_NO_ECC
static void test_pubkey_auth_ecc(void)
{
    PubkeyServerCtx sCtx;
    PubkeyClientCtx cCtx;
    byte  pubKeyBuf[256];
    byte* p = pubKeyBuf;
    word32 pubKeySz = sizeof(pubKeyBuf);
    const byte* pubKeyType   = NULL;
    word32      pubKeyTypeSz = 0;
    byte  privKeyBuf[256];
    byte* privKeyPtr = privKeyBuf;
    word32 privKeySz = sizeof(privKeyBuf);
    const byte* privKeyType   = NULL;
    word32      privKeyTypeSz = 0;

    printf("Testing ECC public key authentication\n");

    AssertIntEQ(wolfSSH_ReadKey_buffer((const byte*)hanselPublicEcc,
            (word32)WSTRLEN(hanselPublicEcc), WOLFSSH_FORMAT_SSH,
            &p, &pubKeySz, &pubKeyType, &pubKeyTypeSz, NULL), WS_SUCCESS);

    AssertIntEQ(wc_Sha256Hash(pubKeyBuf, pubKeySz, sCtx.hash), 0);

    AssertIntEQ(wolfSSH_ReadKey_buffer(hanselPrivateEcc, hanselPrivateEccSz,
            WOLFSSH_FORMAT_ASN1,
            &privKeyPtr, &privKeySz, &privKeyType, &privKeyTypeSz, NULL),
            WS_SUCCESS);

    cCtx.publicKeyType   = pubKeyType;
    cCtx.publicKeyTypeSz = pubKeyTypeSz;
    cCtx.publicKey       = pubKeyBuf;
    cCtx.publicKeySz     = pubKeySz;
    cCtx.privateKey      = privKeyBuf;
    cCtx.privateKeySz    = privKeySz;

    run_pubkey_test(&sCtx, &cCtx, WS_SUCCESS);
}
#endif /* WOLFSSH_NO_ECC */

#if !defined(WOLFSSH_NO_RSA) && !defined(WOLFSSH_NO_ECC)
/* Negative test: server authorises the RSA key but client presents the ECC key.
 * The unauthorised key must be rejected.
 */
static void test_pubkey_auth_wrong_key(void)
{
    PubkeyServerCtx sCtx;
    PubkeyClientCtx cCtx;
    /* Server expects RSA */
    byte  rsaPubBuf[512];
    byte* rp = rsaPubBuf;
    word32 rsaPubSz = sizeof(rsaPubBuf);
    const byte* rsaPubType  = NULL;
    word32      rsaPubTypeSz = 0;
    /* Client presents ECC */
    byte  eccPubBuf[256];
    byte* ep = eccPubBuf;
    word32 eccPubSz = sizeof(eccPubBuf);
    const byte* eccPubType   = NULL;
    word32      eccPubTypeSz = 0;
    byte  eccPrivBuf[256];
    byte* epriv = eccPrivBuf;
    word32 eccPrivSz = sizeof(eccPrivBuf);
    const byte* eccPrivType   = NULL;
    word32      eccPrivTypeSz = 0;

    printf("Testing pubkey auth rejection with wrong key\n");

    /* Server hash is for the RSA key */
    AssertIntEQ(wolfSSH_ReadKey_buffer((const byte*)hanselPublicRsa,
            (word32)WSTRLEN(hanselPublicRsa), WOLFSSH_FORMAT_SSH,
            &rp, &rsaPubSz, &rsaPubType, &rsaPubTypeSz, NULL), WS_SUCCESS);
    AssertIntEQ(wc_Sha256Hash(rsaPubBuf, rsaPubSz, sCtx.hash), 0);

    /* Client uses the ECC key */
    AssertIntEQ(wolfSSH_ReadKey_buffer((const byte*)hanselPublicEcc,
            (word32)WSTRLEN(hanselPublicEcc), WOLFSSH_FORMAT_SSH,
            &ep, &eccPubSz, &eccPubType, &eccPubTypeSz, NULL), WS_SUCCESS);
    AssertIntEQ(wolfSSH_ReadKey_buffer(hanselPrivateEcc, hanselPrivateEccSz,
            WOLFSSH_FORMAT_ASN1,
            &epriv, &eccPrivSz, &eccPrivType, &eccPrivTypeSz, NULL),
            WS_SUCCESS);

    cCtx.publicKeyType   = eccPubType;
    cCtx.publicKeyTypeSz = eccPubTypeSz;
    cCtx.publicKey       = eccPubBuf;
    cCtx.publicKeySz     = eccPubSz;
    cCtx.privateKey      = eccPrivBuf;
    cCtx.privateKeySz    = eccPrivSz;

    /* Connection must fail; both wolfSSH_connect() and wolfSSH_accept()
     * wrap inner errors as WS_FATAL_ERROR at the API boundary */
    run_pubkey_test(&sCtx, &cCtx, WS_FATAL_ERROR);
}
#endif /* !WOLFSSH_NO_RSA && !WOLFSSH_NO_ECC */

#endif /* pubkey test guard */

#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK) && \
    !defined(NO_FILESYSTEM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)

const char *testText1 = "test";
const char *testText2 = "password";

byte *kbResponses[4];
word32 kbResponseLengths[4];
word32 kbResponseCount;
byte kbMultiRound = 0;
byte currentRound = 0;
byte unbalanced = 0;

WS_UserAuthData_Keyboard promptData;


static int serverUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    WS_UserAuthData_Keyboard* prompts = (WS_UserAuthData_Keyboard*)ctx;

    if (ctx == NULL) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_KEYBOARD &&
            authType != WOLFSSH_USERAUTH_KEYBOARD_SETUP) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType == WOLFSSH_USERAUTH_KEYBOARD_SETUP) {
        WMEMCPY(&authData->sf.keyboard, prompts,
            sizeof(WS_UserAuthData_Keyboard));
        return WS_SUCCESS;
    }

    if (authData->sf.keyboard.responseCount != kbResponseCount) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    for (word32 resp = 0; resp < kbResponseCount; resp++) {
        if (authData->sf.keyboard.responseLengths[resp] !=
                kbResponseLengths[resp]) {
            return WOLFSSH_USERAUTH_FAILURE;

        }
        if (WSTRNCMP((const char*)authData->sf.keyboard.responses[resp],
                    (const char*)kbResponses[resp],
                    kbResponseLengths[resp]) != 0) {
            return WOLFSSH_USERAUTH_FAILURE;
        }
    }
    if (kbMultiRound && currentRound == 0) {
        currentRound++;
        kbResponses[0] = (byte*)testText2;
        kbResponseLengths[0] = 8;
        return WOLFSSH_USERAUTH_SUCCESS_ANOTHER;
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}

static THREAD_RETURN WOLFSSH_THREAD server_thread(void* args)
{
    thread_args* serverArgs;
    int ret = WS_SUCCESS;
    word16 port = 0;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
    byte* keyLoadBuf;
    int peerEcc = 1;
    word32 bufSz;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    WS_SOCKET_T clientFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t     clientAddrSz = sizeof(clientAddr);

    serverArgs = (thread_args*) args;
    serverArgs->return_code = EXIT_SUCCESS;

    promptData.promptCount = kbResponseCount;
    promptData.promptName = NULL;
    promptData.promptNameSz = 0;
    promptData.promptInstruction = NULL;
    promptData.promptInstructionSz = 0;
    promptData.promptLanguage = NULL;
    promptData.promptLanguageSz = 0;
    if (kbResponseCount) {
        promptData.prompts =
            (byte**)WMALLOC(sizeof(byte*) * kbResponseCount, NULL, 0);
        if (promptData.prompts == NULL) {
            ES_ERROR("Could not allocate prompts");
        }
        promptData.promptLengths =
            (word32*)WMALLOC(sizeof(word32) * kbResponseCount, NULL, 0);
        if (promptData.promptLengths == NULL) {
            ES_ERROR("Could not allocate promptLengths");
        }
        promptData.promptEcho =
            (byte*)WMALLOC(sizeof(byte) * kbResponseCount, NULL, 0);
        if (promptData.promptEcho == NULL) {
            ES_ERROR("Could not allocate promptEcho");
        }
        for (word32 prompt = 0; prompt < kbResponseCount; prompt++) {
            promptData.prompts[prompt] = (byte*)"Password: ";
            promptData.promptLengths[prompt] = 10;
            promptData.promptEcho[prompt] = 0;
        }
    }
    else {
        promptData.prompts = NULL;
        promptData.promptLengths = NULL;
        promptData.promptEcho = NULL;
    }


    tcp_listen(&listenFd, &port, 1);
    SignalTcpReady(serverArgs->signal, port);

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        ES_ERROR("Couldn't allocate SSH CTX data.\n");
    }

    wolfSSH_SetUserAuth(ctx, serverUserAuth);
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        ES_ERROR("Couldn't allocate SSH data.\n");
    }
    keyLoadBuf = buf;
    bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;
    wolfSSH_SetUserAuthCtx(ssh, &promptData);

    bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
    if (bufSz == 0) {
        ES_ERROR("Couldn't load first key file.\n");
    }
    if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
                                         WOLFSSH_FORMAT_ASN1) < 0) {
        ES_ERROR("Couldn't use first key buffer.\n");
    }

    clientFd = accept(listenFd, (struct sockaddr*)&clientAddr, &clientAddrSz);
    if (clientFd == -1) {
        ES_ERROR("tcp accept failed");
    }
    wolfSSH_set_fd(ssh, (int)clientFd);

    ret = wolfSSH_accept(ssh);
    if (ret && !unbalanced) {
        ES_ERROR("wolfSSH Accept Error");
    }

    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        /* fine on shutdown */
        ret = WS_SUCCESS;
#if DEFAULT_HIGHWATER_MARK < 8000
        if (ret == WS_REKEYING) {
            ret = WS_SUCCESS;
        }
#endif
    }
    if (promptData.promptCount > 0) {
        WFREE(promptData.promptLengths, NULL, 0);
        WFREE(promptData.prompts, NULL, 0);
        WFREE(promptData.promptEcho, NULL, 0);
    }


    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    if (ret) {
        ES_ERROR("wolfSSH Shutdown Error");
    }

    WOLFSSL_RETURN_FROM_THREAD(0);
}

static int keyboardUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    (void) ctx;
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_KEYBOARD) {
        AssertIntEQ(kbResponseCount, authData->sf.keyboard.promptCount);
        for (word32 prompt = 0; prompt < kbResponseCount; prompt++) {
            AssertStrEQ("Password: ", authData->sf.keyboard.prompts[prompt]);
        }

        authData->sf.keyboard.responseCount = kbResponseCount;
        if (unbalanced) {
            authData->sf.keyboard.responseCount++;
        }
        authData->sf.keyboard.responseLengths = kbResponseLengths;
        authData->sf.keyboard.responses = (byte**)kbResponses;
        ret = WS_SUCCESS;
    }
    return ret;
}

static int basic_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port)
{
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret = WS_SUCCESS;
    char* host = (char*)wolfSshIp;
    const char* username = "test";

    if (ctx == NULL || ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL) {
        return WS_BAD_ARGUMENT;
    }

    wolfSSH_SetUserAuth(*ctx, keyboardUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return WS_MEMORY_E;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0){
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        return ret;
    }

    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret != WS_SUCCESS) {
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        fprintf(stderr, "line= %d\n", __LINE__);
        return ret;
    }

    ret = wolfSSH_set_fd(*ssh, (int)sockFd);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "line= %d\n", __LINE__);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        return ret;
    }

    ret = wolfSSH_connect(*ssh);

    return ret;
}

static void test_client(void)
{
    int ret;
    thread_args serverArgs;
    tcp_ready ready;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    THREAD_TYPE serThread;
    WS_SOCKET_T clientFd;

    serverArgs.signal = &ready;
    InitTcpReady(serverArgs.signal);
    ThreadStart(server_thread, (void*)&serverArgs, &serThread);
    WaitTcpReady(&ready);

    ret = basic_client_connect(&ctx, &ssh, ready.port);

    /* for the unbalanced auth test */
    if (unbalanced) {
        AssertIntEQ(ret, WS_FATAL_ERROR);
    }
    else {
        AssertIntEQ(ret, WS_SUCCESS);
    }

    AssertNotNull(ctx);
    AssertNotNull(ssh);
    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        /* fine on shutdown */
        ret = WS_SUCCESS;
    }
#if DEFAULT_HIGHWATER_MARK < 8000
    if (ret == WS_REKEYING) {
        ret = WS_SUCCESS;
    }
#endif

    if (!unbalanced) {
        AssertIntEQ(ret, WS_SUCCESS);
    }


    /* close client socket down */
    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    ThreadJoin(serThread);
#if DEFAULT_HIGHWATER_MARK < 8000
    if (serverArgs.return_code == WS_REKEYING) {
        serverArgs.return_code = WS_SUCCESS;
    }
#endif
    if (!unbalanced) {
        AssertIntEQ(serverArgs.return_code, WS_SUCCESS);
    }
}

static void test_basic_KeyboardInteractive(void)
{
    printf("Testing single prompt / response\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;

    test_client();
}

static void test_empty_KeyboardInteractive(void)
{
    printf("Testing empty prompt / no response\n");
    kbResponses[0] = NULL;
    kbResponseLengths[0] = 0;
    kbResponseCount = 0;

    test_client();
}

static void test_multi_prompt_KeyboardInteractive(void)
{
    printf("Testing multiple prompts\n");
    kbResponses[0] = (byte*)testText1;
    kbResponses[1] = (byte*)testText2;
    kbResponseLengths[0] = 4;
    kbResponseLengths[1] = 8;
    kbResponseCount = 2;

    test_client();
}

static void test_multi_round_KeyboardInteractive(void)
{
    printf("Testing multiple prompt rounds\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;
    kbMultiRound = 1;

    test_client();
    AssertIntEQ(currentRound, 1);
    currentRound = 0;
    kbMultiRound = 0;
}

static void test_unbalanced_client_KeyboardInteractive(void)
{
    printf("Testing too many responses\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;
    unbalanced = 1;

    test_client();
    unbalanced = 0;
}
#endif /* WOLFSSH_TEST_BLOCK */

int wolfSSH_AuthTest(int argc, char** argv)
{
    (void) argc;
    (void) argv;

#if defined(NO_WOLFSSH_SERVER) || defined(NO_WOLFSSH_CLIENT) || \
    defined(SINGLE_THREADED) || defined(WOLFSSH_TEST_BLOCK) || \
    (defined(NO_SHA256) && \
     (defined(NO_FILESYSTEM) || !defined(WOLFSSH_KEYBOARD_INTERACTIVE)))
    return 77;
#else

#if defined(DEBUG_WOLFSSH)
    wolfSSH_Debugging_ON();
#endif

    AssertIntEQ(wolfSSH_Init(), WS_SUCCESS);

    #if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,2)
    {
        int i;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            AssertIntEQ(wc_RunCast_fips(i), WS_SUCCESS);
        }
    }
    #endif /* HAVE_FIPS */

    /* Public-key auth integration tests (issue 2483) */
#if !defined(NO_SHA256)
#ifndef WOLFSSH_NO_RSA
    test_pubkey_auth_rsa();
#endif
#ifndef WOLFSSH_NO_ECC
    test_pubkey_auth_ecc();
#endif
#if !defined(WOLFSSH_NO_RSA) && !defined(WOLFSSH_NO_ECC)
    test_pubkey_auth_wrong_key();
#endif
#endif /* !NO_SHA256 */

    /* Keyboard-interactive auth tests */
#if !defined(NO_FILESYSTEM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)
    test_basic_KeyboardInteractive();
    test_empty_KeyboardInteractive();
    test_multi_prompt_KeyboardInteractive();
    test_multi_round_KeyboardInteractive();
    test_unbalanced_client_KeyboardInteractive();
#endif

    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
#endif
}

#ifndef NO_AUTHTEST_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfSSH_AuthTest(argc, argv);
}
#endif


