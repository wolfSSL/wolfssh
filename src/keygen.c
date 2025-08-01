/* keygen.c
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


/*
 * The keygen module contains utility functions wrapping the wolfCrypt
 * key generation functions to product SSH friendly keys.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif


#include <wolfssl/wolfcrypt/random.h>
#include <wolfssh/internal.h>
#include <wolfssh/error.h>
#include <wolfssh/keygen.h>
#include <wolfssh/log.h>
#ifndef WOLFSSH_NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef WOLFSSH_NO_ECDSA
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef WOLFSSH_KEYGEN

#ifdef WOLFSSL_KEY_GEN

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif


int wolfSSH_MakeRsaKey(byte* out, word32 outSz, word32 size, word32 e)
{
#ifndef WOLFSSH_NO_RSA

    int ret = WS_SUCCESS;
    WC_RNG rng;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_MakeRsaKey()");

    if (wc_InitRng(&rng) != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't create RNG");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        RsaKey key;

        if (wc_InitRsaKey(&key, NULL) != 0)
            ret = WS_CRYPTO_FAILED;

        if (ret == WS_SUCCESS) {
            if (wc_MakeRsaKey(&key, size, e, &rng) != 0) {
                WLOG(WS_LOG_DEBUG, "RSA key generation failed");
                ret = WS_CRYPTO_FAILED;
            }
        }

        if (ret == WS_SUCCESS) {
            int keySz;

            keySz = wc_RsaKeyToDer(&key, out, outSz);
            if (keySz < 0) {
                WLOG(WS_LOG_DEBUG, "RSA key to DER failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = keySz;
        }

        if (wc_FreeRsaKey(&key) != 0) {
            WLOG(WS_LOG_DEBUG, "RSA key free failed");
            ret = WS_CRYPTO_FAILED;
        }

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            ret = WS_CRYPTO_FAILED;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_MakeRsaKey(), ret = %d", ret);
    return ret;
#else
    WOLFSSH_UNUSED(out);
    WOLFSSH_UNUSED(outSz);
    WOLFSSH_UNUSED(size);
    WOLFSSH_UNUSED(e);
    return WS_NOT_COMPILED;
#endif
}


int wolfSSH_MakeEcdsaKey(byte* out, word32 outSz, word32 size)
{
#ifndef WOLFSSH_NO_ECDSA

    int ret = WS_SUCCESS;
    WC_RNG rng;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_MakeEcdsaKey()");

    if (wc_InitRng(&rng) != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't create RNG");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        ecc_key key;

        if (wc_ecc_init(&key) != 0)
            ret = WS_CRYPTO_FAILED;

        if (ret == WS_SUCCESS) {
            ret = wc_ecc_make_key(&rng, size/8, &key);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG, "ECDSA key generation failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = WS_SUCCESS;
        }

        if (ret == WS_SUCCESS) {
            int keySz;

            keySz = wc_EccKeyToDer(&key, out, outSz);
            if (keySz < 0) {
                WLOG(WS_LOG_DEBUG, "ECDSA key to DER failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = keySz;
        }

        if (wc_ecc_free(&key) != 0) {
            WLOG(WS_LOG_DEBUG, "ECDSA key free failed");
            ret = WS_CRYPTO_FAILED;
        }

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            ret = WS_CRYPTO_FAILED;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_MakeEcdsaKey(), ret = %d", ret);
    return ret;
#else
    WOLFSSH_UNUSED(out);
    WOLFSSH_UNUSED(outSz);
    WOLFSSH_UNUSED(size);
    return WS_NOT_COMPILED;
#endif
}


int wolfSSH_MakeEd25519Key(byte* out, word32 outSz, word32 size)
{
#ifndef WOLFSSH_NO_ED25519

    int ret = WS_SUCCESS;
    WC_RNG rng;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_MakeEd25519Key()");

    if (wc_InitRng(&rng) != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't create RNG");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        ed25519_key key;

        if (wc_ed25519_init(&key) != 0)
            ret = WS_CRYPTO_FAILED;

        if (ret == WS_SUCCESS) {
            ret = wc_ed25519_make_key(&rng, size/8, &key);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG, "ED25519 key generation failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = WS_SUCCESS;
        }

        if (ret == WS_SUCCESS) {
            int keySz;

            keySz = wc_Ed25519KeyToDer(&key, out, outSz);
            if (keySz < 0) {
                WLOG(WS_LOG_DEBUG, "ED25519 key to DER failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = keySz;
        }

	wc_ed25519_free(&key);

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            ret = WS_CRYPTO_FAILED;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_MakeEd25519Key(), ret = %d", ret);
    return ret;
#else
    WOLFSSH_UNUSED(out);
    WOLFSSH_UNUSED(outSz);
    WOLFSSH_UNUSED(size);
    return WS_NOT_COMPILED;
#endif
}


#else /* WOLFSSL_KEY_GEN */
    #error "wolfSSH keygen requires that keygen is enabled in wolfSSL, use --enable-keygen or #define WOLFSSL_KEY_GEN."
#endif /* WOLFSSL_KEY_GEN */

#endif /* WOLFSSH_KEYGEN */
