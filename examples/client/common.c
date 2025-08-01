/* common.c
 *
 * Copyright (C) 2014-2024 wolfSSL Inc.
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

#define WOLFSSH_TEST_CLIENT

#include <stdio.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>

#ifdef WOLFSSH_TPM
    #include <wolftpm/tpm2_wrap.h>
    #include <hal/tpm_io.h>
#endif

#include "examples/client/common.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    !defined(WOLFSSH_ZEPHYR)
    #include <termios.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif

static byte userPublicKeyBuf[512];
static byte* userPublicKey = userPublicKeyBuf;
static const byte* userPublicKeyType = NULL;
static byte userPassword[256];
static const byte* userPrivateKeyType = NULL;
static word32 userPublicKeySz = 0;
static byte pubKeyLoaded = 0; /* was a public key loaded */
static byte userPrivateKeyBuf[1191]; /* Size equal to hanselPrivateRsaSz. */
static byte* userPrivateKey = userPrivateKeyBuf;
static word32 userPublicKeyTypeSz = 0;
static byte userPrivateKeyAlloc = 0;
static word32 userPrivateKeySz = 0;
static word32 userPrivateKeyTypeSz = 0;
static byte isPrivate = 0;

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
static word32 keyboardResponseCount = 0;
static byte** keyboardResponses;
static word32* keyboardResponseLengths;
#endif

#ifdef WOLFSSH_CERTS
#if 0
/* compiled in for using RSA certificates instead of ECC certificate */
static const byte publicKeyType[] = "x509v3-ssh-rsa";
static const byte privateKeyType[] = "ssh-rsa";
#else
static const byte publicKeyType[] = "x509v3-ecdsa-sha2-nistp256";
#endif
#endif


#ifdef WOLFSSH_TPM
    WOLFTPM2_DEV tpmDev;
    WOLFTPM2_KEY tpmKey;
#endif /* WOLFSSH_TPM */


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
static const unsigned int hanselPrivateRsaSz = 1191;
#endif


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
static const unsigned int hanselPrivateEccSz = 121;
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
static const unsigned int hanselPrivateEccSz = 223;
#else
    #error "Enable an ECC Curve or disable ECC."
#endif
#endif


#if defined(WOLFSSH_CERTS)

static int load_der_file(const char* filename, byte** out, word32* outSz,
        void* heap)
{
    WFILE* file;
    byte* in;
    long inSz;
    int ret;

    if (filename == NULL || out == NULL || outSz == NULL)
        return -1;

    ret = WFOPEN(NULL, &file, filename, "rb");
    if (ret != 0 || file == WBADFILE)
        return -1;

    if (WFSEEK(NULL, file, 0, WSEEK_END) != 0) {
        WFCLOSE(NULL, file);
        return -1;
    }
    inSz = WFTELL(NULL, file);
    if (inSz <= 0) {
        WFCLOSE(NULL, file);
        return -1;
    }
    WREWIND(NULL, file);

    in = (byte*)WMALLOC(inSz, heap, 0);
    if (in == NULL) {
        WFCLOSE(NULL, file);
        return -1;
    }

    ret = (int)WFREAD(NULL, in, 1, inSz, file);
    if (ret <= 0 || ret != inSz) {
        ret = -1;
        WFREE(in, heap, 0);
        in = 0;
        inSz = 0;
    }
    else
        ret = 0;

    *out = in;
    *outSz = (word32)inSz;

    WFCLOSE(NULL, file);

    return ret;
}


#if (defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME))
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

/* when set as true then ignore miss matching IP addresses */
static int IPOverride = 0;

static int ParseRFC6187(const byte* in, word32 inSz, byte** leafOut,
    word32* leafOutSz)
{
    int ret = WS_SUCCESS;
    word32 l = 0, m = 0;

    if (inSz < sizeof(word32)) {
        printf("inSz %d too small for holding cert name\n", inSz);
        return WS_BUFFER_E;
    }

    /* Skip the name */
    ato32(in, &l);
    m += l + sizeof(word32);

    /* Get the cert count */
    if (ret == WS_SUCCESS) {
        word32 count;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &count);
        m += sizeof(word32);
        if (ret == WS_SUCCESS && count == 0)
            ret = WS_FATAL_ERROR; /* need at least one cert */
    }

    if (ret == WS_SUCCESS) {
        word32 certSz = 0;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &certSz);
        m += sizeof(word32);
        if (ret == WS_SUCCESS) {
            /* store leaf cert size to present to user callback */
            *leafOutSz = certSz;
            *leafOut   = (byte*)in + m;
        }

        if (inSz - m < certSz)
            return WS_BUFFER_E;

   }

    return ret;
}

void ClientIPOverride(int flag)
{
    IPOverride = flag;
}
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
#endif /* WOLFSSH_CERTS */


int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    int ret = 0;

    #ifdef DEBUG_WOLFSSH
        printf("Sample public key check callback\n"
               "  public key = %p\n"
               "  public key size = %u\n"
               "  ctx = %s\n", pubKey, pubKeySz, (const char*)ctx);
    #else
        (void)pubKey;
        (void)pubKeySz;
        (void)ctx;
    #endif

#ifdef WOLFSSH_CERTS
#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
    /* try to parse the certificate and check it's IP address */
    if (pubKeySz > 0) {
        DecodedCert dCert;
        byte*  der   = NULL;
        word32 derSz = 0;

        if (ParseRFC6187(pubKey, pubKeySz, &der, &derSz) == WS_SUCCESS) {
            wc_InitDecodedCert(&dCert, der,  derSz, NULL);
            if (wc_ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
                WLOG(WS_LOG_DEBUG, "public key not a cert");
            }
            else {
                int ipMatch = 0;
                DNS_entry* current = dCert.altNames;

                if (ctx == NULL) {
                    WLOG(WS_LOG_ERROR, "No host IP set to check against!");
                    ret = -1;
                }

                if (ret == 0) {
                    while (current != NULL) {
                        if (current->type == ASN_IP_TYPE) {
                            WLOG(WS_LOG_DEBUG, "host cert alt. name IP : %s",
                                current->ipString);
                            WLOG(WS_LOG_DEBUG,
                                "\texpecting host IP : %s", (char*)ctx);
                            if (XSTRCMP((const char*)ctx,
                                        current->ipString) == 0) {
                                WLOG(WS_LOG_DEBUG, "\tmatched!");
                                ipMatch = 1;
                            }
                        }
                        current = current->next;
                    }
                }

                if (ipMatch == 0) {
                    printf("IP did not match expected IP");
                    if (!IPOverride) {
                        printf("\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                        printf("..overriding\n");
                    }
                }
            }
            FreeDecodedCert(&dCert);
        }
    }
#else
    WLOG(WS_LOG_DEBUG, "wolfSSL not built with OPENSSL_ALL or WOLFSSL_IP_ALT_NAME");
    WLOG(WS_LOG_DEBUG, "\tnot checking IP address from peer's cert");
#endif
#endif

    return ret;
}


int ClientUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    const char* defaultPassword = (const char*)ctx;
    word32 passwordSz = 0;
#if defined(WOLFSSH_TERM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)
    word32 entry;
#endif
    int ret = WOLFSSH_USERAUTH_SUCCESS;

#ifdef DEBUG_WOLFSSH
    /* inspect supported types from server */
    printf("Server supports:\n");
    if (authData->type & WOLFSSH_USERAUTH_PASSWORD) {
        printf(" - password\n");
    }
    if (authData->type & WOLFSSH_USERAUTH_PUBLICKEY) {
        printf(" - publickey\n");
    }
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    if (authData->type & WOLFSSH_USERAUTH_KEYBOARD) {
        printf(" - keyboard\n");
    }
#endif
    printf("wolfSSH requesting to use type %d\n", authType);
#endif

    /* Wait for request of public key on names known to have one */
    if ((authData->type & WOLFSSH_USERAUTH_PUBLICKEY) &&
            authData->username != NULL &&
            authData->usernameSz > 0) {

        /* in the case that the name is hansel or in the case that the user
         * passed in a public key file, use public key auth */
        if (pubKeyLoaded == 1) {
            if (authType == WOLFSSH_USERAUTH_PASSWORD) {
            #ifdef WOLFSSH_DEBUG
                printf("rejecting password type with %s in favor of pub key\n",
                    (char*)authData->username);
            #endif
                return WOLFSSH_USERAUTH_FAILURE;
            }
        }
    }

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        WS_UserAuthData_PublicKey* pk = &authData->sf.publicKey;

        pk->publicKeyType = userPublicKeyType;
        pk->publicKeyTypeSz = userPublicKeyTypeSz;
        pk->publicKey = userPublicKey;
        pk->publicKeySz = userPublicKeySz;
        pk->privateKey = userPrivateKey;
        pk->privateKeySz = userPrivateKeySz;

        ret = WOLFSSH_USERAUTH_SUCCESS;
    }
    else if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        if (defaultPassword != NULL) {
            passwordSz = (word32)strlen(defaultPassword);
            memcpy(userPassword, defaultPassword, passwordSz);
        }
#ifdef WOLFSSH_TERM
        else {
            printf("Password: ");
            WFFLUSH(stdout);
            ClientSetEcho(0);
            if (WFGETS((char*)userPassword, sizeof(userPassword), stdin)
                    == NULL) {
                fprintf(stderr, "Getting password failed.\n");
                ret = WOLFSSH_USERAUTH_FAILURE;
            }
            else {
                char* c = strpbrk((char*)userPassword, "\r\n");
                if (c != NULL)
                    *c = '\0';
            }
            passwordSz = (word32)strlen((const char*)userPassword);
            ClientSetEcho(1);
            #ifdef USE_WINDOWS_API
                printf("\r\n");
            #endif
            WFFLUSH(stdout);
        }
#endif

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }
#if defined(WOLFSSH_TERM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)
    else if (authType == WOLFSSH_USERAUTH_KEYBOARD) {
        if (authData->sf.keyboard.promptName &&
            authData->sf.keyboard.promptName[0] != '\0') {
            printf("%s\n", authData->sf.keyboard.promptName);
        }
        if (authData->sf.keyboard.promptInstruction &&
            authData->sf.keyboard.promptInstruction[0] != '\0') {
            printf("%s\n", authData->sf.keyboard.promptInstruction);
        }
        keyboardResponseCount = authData->sf.keyboard.promptCount;
        keyboardResponses =
            (byte**)WMALLOC(sizeof(byte*) * keyboardResponseCount, NULL, 0);
        if (keyboardResponses == NULL) {
            ret = WS_MEMORY_E;
        }
        if (ret == WS_SUCCESS) {
            authData->sf.keyboard.responses = (byte**)keyboardResponses;
            keyboardResponseLengths = (word32*)WMALLOC(
                sizeof(word32) * keyboardResponseCount, NULL, 0);
            authData->sf.keyboard.responseLengths = keyboardResponseLengths;
        }

        if (keyboardResponseLengths == NULL) {
            ret = WS_MEMORY_E;
        }

        for (entry = 0; entry < authData->sf.keyboard.promptCount; entry++) {
            if (ret == WS_SUCCESS) {
                printf("%s", authData->sf.keyboard.prompts[entry]);
                if (!authData->sf.keyboard.promptEcho[entry]) {
                    ClientSetEcho(0);
                }
                if (WFGETS((char*)userPassword, sizeof(userPassword), stdin)
                        == NULL) {
                    fprintf(stderr, "Getting response failed.\n");
                    ret = WOLFSSH_USERAUTH_FAILURE;
                }
                else {
                    char* c = strpbrk((char*)userPassword, "\r\n");
                    if (c != NULL)
                        *c = '\0';
                }
                passwordSz = (word32)strlen((const char*)userPassword);
                ClientSetEcho(1);
                #ifdef USE_WINDOWS_API
                    printf("\r\n");
                #endif
                WFFLUSH(stdout);
                authData->sf.keyboard.responses[entry] =
                    (byte*) WSTRDUP((char*)userPassword, NULL, 0);
                authData->sf.keyboard.responseLengths[entry] = passwordSz;
                authData->sf.keyboard.responseCount++;
            }
        }
    }
#endif
    return ret;
}


#ifdef WOLFSSH_TERM
/* type = 2 : shell / execute command settings
 * type = 0 : password
 * type = 1 : restore default
 * return 0 on success */
int ClientSetEcho(int type)
{
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    static int echoInit = 0;
    static struct termios originalTerm;

    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (echoInit) {
        if (type == 1) {
            if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
                printf("Couldn't restore the terminal settings.\n");
                return -1;
            }
        }
        else {
            struct termios newTerm;
            memcpy(&newTerm, &originalTerm, sizeof(struct termios));

            newTerm.c_lflag &= ~ECHO;
            if (type == 2) {
                newTerm.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE
                    | ECHOK | ECHONL | NOFLSH | TOSTOP);

                /* check macros set for some BSD dependent and not missing on
                 * QNX flags */
            #ifdef ECHOPRT
                newTerm.c_lflag &= ~(ECHOPRT);
            #endif
            #ifdef FLUSHO
                newTerm.c_lflag &= ~(FLUSHO);
            #endif
            #ifdef PENDIN
                newTerm.c_lflag &= ~(PENDIN);
            #endif
            #ifdef EXTPROC
                newTerm.c_lflag &= ~(EXTPROC);
            #endif

                newTerm.c_iflag &= ~(ISTRIP | INLCR | ICRNL | IGNCR | IXON
                | IXOFF | IXANY | IGNBRK | INPCK | PARMRK);
            #ifdef IUCLC
                newTerm.c_iflag &= ~IUCLC;
            #endif
                newTerm.c_iflag |= IGNPAR;

                newTerm.c_oflag &= ~(OPOST | ONOCR | ONLRET);
            #ifdef OUCLC
                newTerm.c_oflag &= ~OLCUC;
            #endif

                newTerm.c_cflag &= ~(CSTOPB | PARENB | PARODD | CLOCAL);
            #ifdef CRTSCTS
                newTerm.c_cflag &= ~(CRTSCTS);
            #endif
            }
            else {
                newTerm.c_lflag |= (ICANON | ECHONL);
            }

            if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
                printf("Couldn't turn off echo.\n");
                return -1;
            }
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    static CONSOLE_SCREEN_BUFFER_INFO screenOrig;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else if (type == 2) {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_PROCESSED_INPUT;
        newTerm &= ~ENABLE_PROCESSED_OUTPUT;
        newTerm &= ~ENABLE_LINE_INPUT;
        newTerm &= ~ENABLE_ECHO_INPUT;
        newTerm &= ~(ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE);

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
    else {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_ECHO_INPUT;

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#endif

    return 0;
}
#endif


/* Set certificate to use and public key.
 * returns 0 on success */
int ClientUseCert(const char* certName, void* heap)
{
    int ret = 0;

    if (certName != NULL) {
    #ifdef WOLFSSH_CERTS
        ret = load_der_file(certName, &userPublicKey, &userPublicKeySz, heap);
        if (ret == 0) {
            userPublicKeyType = publicKeyType;
            userPublicKeyTypeSz = (word32)WSTRLEN((const char*)publicKeyType);
            pubKeyLoaded = 1;
        }
    #else
        (void)heap;
        fprintf(stderr, "Certificate support not compiled in");
        ret = WS_NOT_COMPILED;
    #endif
    }

    return ret;
}

#ifdef WOLFSSH_TPM

static int readKeyBlob(const char* filename, WOLFTPM2_KEYBLOB* key)
{
    int rc = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    WFILE* fp = NULL;
    size_t fileSz = 0;
    size_t bytes_read = 0;
    byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    int pubAreaSize;

    WLOG(WS_LOG_DEBUG, "Entering readKeyBlob()");

    WMEMSET(key, 0, sizeof(WOLFTPM2_KEYBLOB));

    if (WFOPEN(NULL, &fp, filename, "rb") != 0) {
        printf("Failed to open file %s\n", filename);
        rc = BUFFER_E; goto exit;
    }
    if (fp != WBADFILE) {
        WFSEEK(NULL, fp, 0, WSEEK_END);
        fileSz = WFTELL(NULL, fp);
        WREWIND(NULL, fp);

        if (fileSz > sizeof(key->priv) + sizeof(key->pub)) {
            printf("File size check failed\n");
            rc = BUFFER_E; goto exit;
        }
        printf("Reading %d bytes from %s\n", (int)fileSz, filename);

        bytes_read = WFREAD(NULL, &key->pub.size, 1,
            sizeof(key->pub.size), fp);
        if (bytes_read != sizeof(key->pub.size)) {
            printf("Read %zu, expected size marker of %zu bytes\n",
                bytes_read, sizeof(key->pub.size));
            goto exit;
        }
        fileSz -= bytes_read;

        bytes_read = WFREAD(NULL, pubAreaBuffer, 1,
            sizeof(UINT16) + key->pub.size, fp);
        if (bytes_read != sizeof(UINT16) + key->pub.size) {
            printf("Read %zu, expected public blob %zu bytes\n",
                bytes_read, sizeof(UINT16) + key->pub.size);
            goto exit;
        }
        fileSz -= bytes_read; /* Reminder bytes for private key part */

        /* Decode the byte stream into a publicArea structure ready for use */
        rc = TPM2_ParsePublic(&key->pub, pubAreaBuffer,
            (word32)sizeof(pubAreaBuffer), &pubAreaSize);
        if (rc != 0) return rc;

        if (fileSz > 0) {
            printf("Reading the private part of the key\n");
            bytes_read = WFREAD(NULL, &key->priv, 1, fileSz, fp);
            if (bytes_read != fileSz) {
                printf("Read %zu, expected private blob %zu bytes\n",
                    bytes_read, fileSz);
                goto exit;
            }
            rc = 0; /* success */
        }

        /* sanity check the sizes */
        if (pubAreaSize != (key->pub.size + (int)sizeof(key->pub.size)) ||
             key->priv.size > sizeof(key->priv.buffer)) {
            printf("Struct size check failed (pub %d, priv %d)\n",
                   key->pub.size, key->priv.size);
            rc = BUFFER_E;
        }
    }
    else {
        rc = BUFFER_E;
        printf("File %s not found!\n", filename);
        printf("Key can be generated by running:\n"
               "  ./examples/keygen/keygen keyblob.bin -rsa -t -pem -eh\n");
    }

exit:
    if (fp)
      WFCLOSE(NULL, fp);
#else
    (void)filename;
    (void)key;
#endif /* !NO_FILESYSTEM && !NO_WRITE_TEMP_FILES */
    WLOG(WS_LOG_DEBUG, "Leaving readKeyBlob(), rc = %d", rc);
    return rc;
}

static int wolfSSH_TPM_InitKey(WOLFTPM2_DEV* dev, const char* name,
    WOLFTPM2_KEY* pTpmKey, const char* tpmKeyAuth)
{
    int rc = 0;
    WOLFTPM2_KEY endorse;
    WOLFTPM2_KEYBLOB tpmKeyBlob;
    WOLFTPM2_SESSION tpmSession;
    byte* p = NULL;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_TPM_InitKey()");

    /* Initialize the TPM 2.0 device */
    if (rc == 0) {
        rc = wolfTPM2_Init(dev, TPM2_IoCb, NULL);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG,
                "TPM 2.0 Device initialization failed, rc: %d", rc);
        }
    }

    /* Create primary endorsement key (EK) */
    if (rc == 0) {
        rc = wolfTPM2_CreateEK(dev, &endorse, TPM_ALG_RSA);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG, "Creating EK failed, rc: %d", rc);
        }
    }

    /* Create and set policy session for EK */
    if (rc == 0) {
        endorse.handle.policyAuth = 1;
        rc = wolfTPM2_CreateAuthSession_EkPolicy(dev, &tpmSession);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG,
                "Creating EK policy session failed, rc: %d", rc);
        }
    }

    if (rc == 0) {
        rc = wolfTPM2_SetAuthSession(dev, 0, &tpmSession, 0);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG, "Setting auth session failed, rc: %d", rc);
        }
    }

    /* Load the TPM 2.0 key blob from disk */
    if (rc == 0) {
        rc = readKeyBlob(name, &tpmKeyBlob);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG,
                "Reading key blob from disk failed, rc: %d", rc);
        }
    }

    /* Use global auth if provided */
    if (rc == 0 && tpmKeyAuth != NULL) {
        tpmKeyBlob.handle.auth.size = (word32)XSTRLEN(tpmKeyAuth);
        XMEMCPY(tpmKeyBlob.handle.auth.buffer, tpmKeyAuth,
            tpmKeyBlob.handle.auth.size);
    }

    /* Load the public key into the TPM device */
    if (rc == 0) {
        rc = wolfTPM2_LoadKey(dev, &tpmKeyBlob, &endorse.handle);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG, "wolfTPM2_LoadKey failed, rc: %d", rc);
        } else {
            WLOG(WS_LOG_DEBUG, "Loaded key to 0x%x\n",
                (word32)tpmKeyBlob.handle.hndl);
        }
    }

    /* Read the public key and extract the public key as a DER/ASN.1 */
    if (rc == 0) {
        userPublicKeySz = sizeof(userPublicKeyBuf);
        rc = wolfTPM2_ExportPublicKeyBuffer(dev, (WOLFTPM2_KEY*)&tpmKeyBlob,
            ENCODING_TYPE_ASN1, userPublicKey, &userPublicKeySz);
        if (rc != 0) {
            WLOG(WS_LOG_DEBUG, "Exporting TPM key failed, rc: %d", rc);
        }
    }

    /* Read public key from buffer and convert key to OpenSSH format */
    if (rc == 0) {
        rc = wolfSSH_ReadPublicKey_buffer(userPublicKey, userPublicKeySz,
            WOLFSSH_FORMAT_ASN1, &p, &userPublicKeySz, &userPublicKeyType,
            &userPublicKeyTypeSz, NULL);
        if (rc == 0) {
            userPublicKey = p;
        } else {
            WLOG(WS_LOG_DEBUG, "Reading public key failed, rc: %d", rc);
        }
    }

    /* Copy key info */
    if (rc == 0) {
        XMEMCPY(&pTpmKey->handle, &tpmKeyBlob.handle, sizeof(pTpmKey->handle));
        XMEMCPY(&pTpmKey->pub, &tpmKeyBlob.pub, sizeof(pTpmKey->pub));
        wolfTPM2_UnloadHandle(dev, &endorse.handle);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_TPM_InitKey(), rc = %d", rc);
    return rc;
}

static void wolfSSH_TPM_Cleanup(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key)
{
    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_TPM_Cleanup()");
    if (key != NULL) {
        wolfTPM2_UnloadHandle(dev, &key->handle);
    }

    if (dev != NULL) {
        wolfTPM2_Cleanup(dev);
    }
    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_TPM_Cleanup()");
}

/* Set the tpm device and key for the client side */
int ClientSetTpm(WOLFSSH* ssh)
{
    if (ssh != NULL) {
        wolfSSH_SetTpmDev(ssh, &tpmDev);
        wolfSSH_SetTpmKey(ssh, &tpmKey);
    }
    return 0;
}

#endif /* WOLFSSH_TPM */


/* Reads the private key to use from file name privKeyName.
 * returns 0 on success */
int ClientSetPrivateKey(const char* privKeyName, int userEcc,
    void* heap, const char* tpmKeyAuth)
{
    int ret = 0;
    (void)tpmKeyAuth; /* Not used */

    if (privKeyName == NULL) {
        if (userEcc) {
        #ifndef WOLFSSH_NO_ECC
            userPrivateKeySz = sizeof(userPrivateKeyBuf);
            ret = wolfSSH_ReadKey_buffer(hanselPrivateEcc, hanselPrivateEccSz,
                    WOLFSSH_FORMAT_ASN1, &userPrivateKey, &userPrivateKeySz,
                    &userPrivateKeyType, &userPrivateKeyTypeSz, heap);
        #endif
        }
        else {
        #ifndef WOLFSSH_NO_RSA
            userPrivateKeySz = sizeof(userPrivateKeyBuf);
            ret = wolfSSH_ReadKey_buffer(hanselPrivateRsa, hanselPrivateRsaSz,
                    WOLFSSH_FORMAT_ASN1, &userPrivateKey, &userPrivateKeySz,
                    &userPrivateKeyType, &userPrivateKeyTypeSz, heap);
        #endif
        }
        isPrivate = 1;
    }
    else {
    #if defined(WOLFSSH_TPM)
        /* Protecting the SSH Private Key using a TPM 2.0 device
         *
         * TPM-backed keys do not require a user buffer, because
         * the private key is loaded securely inside the TPM and
         * used only from within the TPM for higher security.
         *
         * Successfully loaded TPM key has a TPM Handle that is
         * later passed to wolfSSH for use
         */
        WMEMSET(&tpmDev, 0, sizeof(tpmDev));
        WMEMSET(&tpmKey, 0, sizeof(tpmKey));
        ret = wolfSSH_TPM_InitKey(&tpmDev, privKeyName, &tpmKey, tpmKeyAuth);
    #elif !defined(NO_FILESYSTEM)
        userPrivateKey = NULL; /* create new buffer based on parsed input */
        userPrivateKeyAlloc = 1;
        userPrivateKeySz = sizeof(userPrivateKeyBuf);
        ret = wolfSSH_ReadKey_file(privKeyName,
                (byte**)&userPrivateKey, &userPrivateKeySz,
                (const byte**)&userPrivateKeyType, &userPrivateKeyTypeSz,
                &isPrivate, heap);
    #else
        printf("file system not compiled in!\n");
        ret = NOT_COMPILED_IN;
    #endif /* WOLFSSH_TPM / NO_FILESYSTEM */
    }

    return ret;
}

/* Set public key to use
 * returns 0 on success */
int ClientUsePubKey(const char* pubKeyName, int userEcc, void* heap)
{
    int ret = 0;

    if (pubKeyName == NULL) {
        byte* p = userPublicKey;
        userPublicKeySz = sizeof(userPublicKeyBuf);

        if (userEcc) {
        #ifndef WOLFSSH_NO_ECC
            ret = wolfSSH_ReadKey_buffer((const byte*)hanselPublicEcc,
                    (word32)strlen(hanselPublicEcc), WOLFSSH_FORMAT_SSH,
                    &p, &userPublicKeySz,
                    &userPublicKeyType, &userPublicKeyTypeSz, heap);
        #endif
        }
        else {
        #ifndef WOLFSSH_NO_RSA
            ret = wolfSSH_ReadKey_buffer((const byte*)hanselPublicRsa,
                    (word32)strlen(hanselPublicRsa), WOLFSSH_FORMAT_SSH,
                    &p, &userPublicKeySz,
                    &userPublicKeyType, &userPublicKeyTypeSz, heap);
        #endif
        }
        isPrivate = 1;
    }
    else {
    #ifndef NO_FILESYSTEM
        userPublicKey = NULL; /* create new buffer based on parsed input */
        ret = wolfSSH_ReadKey_file(pubKeyName,
                &userPublicKey, &userPublicKeySz,
                (const byte**)&userPublicKeyType, &userPublicKeyTypeSz,
                &isPrivate, heap);
    #else
        printf("file system not compiled in!\n");
        ret = NOT_COMPILED_IN;
    #endif /* NO_FILESYSTEM */
        if (ret == 0) {
            pubKeyLoaded = 1;
        }
    }

    return ret;
}

int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert)
{
    int ret = 0;

    /* CA certificate to verify host cert with */
    if (caCert) {
    #ifdef WOLFSSH_CERTS
        byte* der = NULL;
        word32 derSz;

        ret = load_der_file(caCert, &der, &derSz, ctx->heap);
        if (ret == 0) {
            if (wolfSSH_CTX_AddRootCert_buffer(ctx, der, derSz,
                WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
                fprintf(stderr, "Couldn't parse in CA certificate.");
                ret = WS_PARSE_E;
            }
            WFREE(der, NULL, 0);
        }
    #else
        (void)ctx;
        fprintf(stderr, "Support for certificates not compiled in.");
        ret = WS_NOT_COMPILED;
    #endif
    }
    return ret;
}

void ClientFreeBuffers(const char* pubKeyName, const char* privKeyName,
        void* heap)
{
#if defined(WOLFSSH_TERM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)
    word32 entry;
#endif
#ifdef WOLFSSH_TPM
    wolfSSH_TPM_Cleanup(&tpmDev, &tpmKey);
#endif
    if (pubKeyName != NULL && userPublicKey != NULL &&
        userPublicKey != userPublicKeyBuf) {
        WFREE(userPublicKey, heap, DYNTYPE_PRIVKEY);
    }

    if (privKeyName != NULL && userPrivateKey != NULL &&
        userPrivateKeyAlloc) {
        WFREE(userPrivateKey, heap, DYNTYPE_PRIVKEY);
    }

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    for (entry = 0; entry < keyboardResponseCount; entry++) {
        WFREE(keyboardResponses[entry], NULL, 0);
    }
    WFREE(keyboardResponses, NULL, 0);
    WFREE(keyboardResponseLengths, NULL, 0);
#endif
}
