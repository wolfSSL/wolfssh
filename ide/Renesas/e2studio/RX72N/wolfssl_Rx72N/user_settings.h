/* user_settings.h
 *
 * Copyright (C) 2014-2025 wolfSSL Inc.
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
#define WOLFCRYPT_ONLY
#define NO_ERROR_STRINGS

#define NO_MAIN_DRIVER
#define NO_WRITEV
#define NO_DEV_RANDOM
#define NO_WOLFSSL_DIR
#define NO_WOLFSSL_STUB
/* for compilers not allowed dynamic size array */
#define NO_DYNAMIC_ARRAY
#define NO_RC4
#define NO_OLD_SHA256
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8
#define NO_DES3
#define NO_MD4
#define NO_FILESYSTEM
#define WOLFSSL_NO_CURRDIR
#define WOLFSSL_LOG_PRINTF
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_DH_CONST
#define WOLFSSL_USER_IO

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define FP_MAX_BITS   4096
#define SP_WORD_SIZE 32
#define WOLFSSL_SP_NO_DYN_STACK
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
#define WOLFSSL_SP_NONBLOCK
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WC_ECC_NONBLOCK
#define HAVE_AESGCM
#define HAVE_ECC
/* enable RSA if needed */
/*#efine WOLFSSL_HAVE_SP_RSA*/
/* disable if RSA is enabled */
#define NO_RSA

#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048
#define SIZEOF_LONG_LONG 8
/* Warning: define your own seed gen */
#define WOLFSSL_GENSEED_FORTEST

#define SINGLE_THREADED  /* or define RTOS  option */
#define WOLFSSL_NO_SOCK
#define WOLFSSL_LOG_PRINTF
#define TIME_OVERRIDES
#define XTIME    time
#define WOLFSSL_GMTIME
#define XGMTIME(c,t)  gmtime(c)
#define USE_WOLF_SUSECONDS_T
#define USE_WOLF_TIMEVAL_T

/*-- strcasecmp */
#define XSTRCASECMP(s1,s2) strcmp((s1),(s2))

#include "wolfssh_user_setting.h"
