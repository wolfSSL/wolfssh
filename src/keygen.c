/* keygen.c
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
#ifndef WOLFSSH_NO_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif
#ifdef HAVE_ED448
    #include <wolfssl/wolfcrypt/ed448.h>
#endif
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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
            if (ret >= 0)
                ret = WS_CRYPTO_FAILED;
        }

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            if (ret >= 0)
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
            if (ret >= 0)
                ret = WS_CRYPTO_FAILED;
        }

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            if (ret >= 0)
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
#if !defined(WOLFSSH_NO_ED25519) && defined(HAVE_ED25519) && \
    defined(HAVE_ED25519_MAKE_KEY) && defined(HAVE_ED25519_KEY_EXPORT)

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
            if (ret >= 0)
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

int wolfSSH_MakeMlDsaKey(byte* out, word32 outSz, word32 level)
{
#if !defined(WOLFSSH_NO_MLDSA)
    int ret = WS_SUCCESS;
    WC_RNG rng = {0};
    byte wc_level;

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_MakeMlDsaKey()");

    if      (level == WOLFSSH_MLDSAKEY_44) wc_level = WC_ML_DSA_44;
    else if (level == WOLFSSH_MLDSAKEY_65) wc_level = WC_ML_DSA_65;
    else if (level == WOLFSSH_MLDSAKEY_87) wc_level = WC_ML_DSA_87;
    else {
        WLOG(WS_LOG_DEBUG, "Invalid ML-DSA key level requested");
        return WS_BAD_ARGUMENT;
    }

    if (wc_InitRng(&rng) != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't create RNG");
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == WS_SUCCESS) {
        MlDsaKey key;
        int keyInit = 0;

        if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0)
            ret = WS_CRYPTO_FAILED;
        else {
            keyInit = 1;
            if (wc_MlDsaKey_SetParams(&key, wc_level) != 0)
                ret = WS_CRYPTO_FAILED;
        }

        if (ret == WS_SUCCESS) {
            ret = wc_MlDsaKey_MakeKey(&key, &rng);
            if (ret != 0) {
                WLOG(WS_LOG_DEBUG, "ML-DSA key generation failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = WS_SUCCESS;
        }

        if (ret == WS_SUCCESS) {
            int keySz;

            keySz = wc_MlDsaKey_KeyToDer(&key, out, outSz);
            if (keySz < 0) {
                WLOG(WS_LOG_DEBUG, "ML-DSA key to DER failed");
                ret = WS_CRYPTO_FAILED;
            }
            else
                ret = keySz;
        }

        if (keyInit) {
            wc_MlDsaKey_Free(&key);
        }

        if (wc_FreeRng(&rng) != 0) {
            WLOG(WS_LOG_DEBUG, "Couldn't free RNG");
            if (ret >= 0)
                ret = WS_CRYPTO_FAILED;
        }
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_MakeMlDsaKey(), ret = %d", ret);
    return ret;
#else
    WOLFSSH_UNUSED(out);
    WOLFSSH_UNUSED(outSz);
    WOLFSSH_UNUSED(level);
    return WS_NOT_COMPILED;
#endif
}


/* Builds the OpenSSH-key-v1 envelope (composite keys have no ASN.1
 * form); see GetOpenSshKeyMlDsaComposite() in internal.c for the parser. */
#if !defined(WOLFSSH_NO_MLDSA)
/* Generates the traditional half of a composite key pair; exports raw
 * material into the caller's buffers. */
static int MakeCompositeTradKey(WC_RNG* rng, const CompositeParams* params,
        byte* tradPub, byte* tradPriv)
{
    int ret = WS_NOT_COMPILED;

    WOLFSSH_UNUSED(rng);
    WOLFSSH_UNUSED(tradPub);
    WOLFSSH_UNUSED(tradPriv);

    if (params->tradType == TRAD_TYPE_ED25519) {
#ifndef WOLFSSH_NO_ED25519
        ed25519_key key;
        word32 sz;

        if (wc_ed25519_init(&key) != 0) {
            return WS_CRYPTO_FAILED;
        }
        ret = (wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key) == 0) ?
                0 : WS_CRYPTO_FAILED;
        if (ret == 0) {
            sz = params->tradPrivSz;
            if (wc_ed25519_export_private_only(&key, tradPriv, &sz) != 0 ||
                    sz != params->tradPrivSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        if (ret == 0) {
            sz = params->tradPubSz;
            if (wc_ed25519_export_public(&key, tradPub, &sz) != 0 ||
                    sz != params->tradPubSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        wc_ed25519_free(&key);
#endif
    }
    else if (params->tradType == TRAD_TYPE_ED448) {
#ifdef HAVE_ED448
        ed448_key key;
        word32 sz;

        if (wc_ed448_init(&key) != 0) {
            return WS_CRYPTO_FAILED;
        }
        ret = (wc_ed448_make_key(rng, ED448_KEY_SIZE, &key) == 0) ?
                0 : WS_CRYPTO_FAILED;
        if (ret == 0) {
            sz = params->tradPrivSz;
            if (wc_ed448_export_private_only(&key, tradPriv, &sz) != 0 ||
                    sz != params->tradPrivSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        if (ret == 0) {
            sz = params->tradPubSz;
            if (wc_ed448_export_public(&key, tradPub, &sz) != 0 ||
                    sz != params->tradPubSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        wc_ed448_free(&key);
#endif
    }
    else if (params->tradType == TRAD_TYPE_ECC) {
#ifndef WOLFSSH_NO_ECDSA
        ecc_key key;
        word32 sz;
        /* Pin the curve explicitly: the draft requires P-256 for
         * ML-DSA-44/65, P-384 for 87 -- key-size matching isn't guaranteed. */
        int curveId = (params->tradPrivSz <= 32) ?
                ECC_SECP256R1 : ECC_SECP384R1;

        if (wc_ecc_init(&key) != 0) {
            return WS_CRYPTO_FAILED;
        }
        ret = (wc_ecc_make_key_ex(rng, (int)params->tradPrivSz, &key,
                curveId) == 0) ? 0 : WS_CRYPTO_FAILED;
        if (ret == 0) {
            sz = params->tradPrivSz;
            if (wc_ecc_export_private_only(&key, tradPriv, &sz) != 0 ||
                    sz != params->tradPrivSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        if (ret == 0) {
            sz = params->tradPubSz;
            if (wc_ecc_export_x963(&key, tradPub, &sz) != 0 ||
                    sz != params->tradPubSz) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        wc_ecc_free(&key);
#endif
    }

    return ret;
}
#endif /* !WOLFSSH_NO_MLDSA */

#if !defined(WOLFSSH_NO_MLDSA)
/* Base64_Encode() output size, mirrored from DoBase64_Encode(), so
 * callers can size a buffer without a throwaway encode pass. */
static word32 MlDsaCompositeBase64Sz(word32 fileSz)
{
    word32 chars = (fileSz + 2) / 3 * 4;
    word32 lines = (chars + PEM_LINE_SZ - 1) / PEM_LINE_SZ;

    return chars + lines;
}
#endif /* !WOLFSSH_NO_MLDSA */

int wolfSSH_MakeMlDsaCompositeKey(byte* out, word32 outSz, word32 level,
        word32 tradType)
{
#if !defined(WOLFSSH_NO_MLDSA)
    static const char magic[] = "openssh-key-v1";
    static const char none[] = "none";
    const word32 noneSz = (word32)WSTRLEN(none);
    const char* keyTypeName;
    word32 keyTypeNameSz;
    byte keyId;
    CompositeParams params;
    int ret;
    WC_RNG rng;
    int rngInit = 0;
    MlDsaKey mldsaKey;
    int mldsaInit = 0;
    int mldsaGenOk;
    byte mldsaSeed[MLDSA_SEED_SZ];
    byte mldsaPub[WC_MLDSA_87_PUB_KEY_SIZE];
    byte tradPub[COMPOSITE_MAX_TRAD_PUB_SZ];
    byte tradPriv[COMPOSITE_MAX_TRAD_PRIV_SZ];
    word32 sz;
    word32 fileSz, pubBlobSz, compositePubSz, compositePrivSz;
    word32 privKeysStrSz, padSz, off, i, checkint;

    byte* tmpBuf = NULL;
    word32 b64Sz = 0;
    static const char header[] = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
    static const char footer[] = "-----END OPENSSH PRIVATE KEY-----\n";

    WLOG(WS_LOG_DEBUG, "Entering wolfSSH_MakeMlDsaCompositeKey()");

    if (level == WOLFSSH_MLDSAKEY_44 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ED25519)
        keyId = ID_MLDSA44_ED25519;
    else if (level == WOLFSSH_MLDSAKEY_44 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ECDSA)
        keyId = ID_MLDSA44_ES256;
    else if (level == WOLFSSH_MLDSAKEY_65 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ED25519)
        keyId = ID_MLDSA65_ED25519;
    else if (level == WOLFSSH_MLDSAKEY_65 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ECDSA)
        keyId = ID_MLDSA65_ES256;
    else if (level == WOLFSSH_MLDSAKEY_87 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ED448)
        keyId = ID_MLDSA87_ED448;
    else if (level == WOLFSSH_MLDSAKEY_87 &&
            tradType == WOLFSSH_COMPOSITE_TRAD_ECDSA)
        keyId = ID_MLDSA87_ES384;
    else {
        WLOG(WS_LOG_DEBUG, "Invalid ML-DSA composite level/trad combination");
        return WS_BAD_ARGUMENT;
    }

    if (WS_GetCompositeParams(keyId, &params) != WS_SUCCESS) {
        WLOG(WS_LOG_DEBUG, "Composite algorithm not compiled in");
        return WS_NOT_COMPILED;
    }

    keyTypeName = IdToName(keyId);
    keyTypeNameSz = (word32)WSTRLEN(keyTypeName);

    /* final base64 size vs. outSz is checked below, after PEM body build */
    compositePubSz = params.mldsaPubSz + params.tradPubSz;
    compositePrivSz = MLDSA_SEED_SZ + params.tradPrivSz;

    pubBlobSz = UINT32_SZ + keyTypeNameSz + UINT32_SZ + compositePubSz;
    privKeysStrSz = UINT32_SZ * 2 /* checkints */
            + UINT32_SZ + keyTypeNameSz
            + UINT32_SZ + compositePubSz
            + UINT32_SZ + compositePrivSz
            + UINT32_SZ /* comment (empty) */;
    padSz = (MIN_BLOCK_SZ - (privKeysStrSz % MIN_BLOCK_SZ)) % MIN_BLOCK_SZ;
    privKeysStrSz += padSz;

    fileSz = (word32)WSTRLEN(magic) + 1
            + UINT32_SZ + noneSz   /* ciphername */
            + UINT32_SZ + noneSz   /* kdfname */
            + UINT32_SZ            /* kdfoptions (empty) */
            + UINT32_SZ            /* keycount */
            + UINT32_SZ + pubBlobSz
            + UINT32_SZ + privKeysStrSz;

    /* the encoded size depends only on fileSz, so it (and outSz
     * feasibility) can be determined before doing any RNG/keygen work */
    b64Sz = MlDsaCompositeBase64Sz(fileSz);

    if (out == NULL) {
        /* size query: caller wants the required buffer size only */
        return (int)(WSTRLEN(header) + b64Sz + WSTRLEN(footer));
    }
    if (outSz < b64Sz + WSTRLEN(header) + WSTRLEN(footer)) {
        WLOG(WS_LOG_DEBUG, "Output buffer too small for composite key");
        return WS_BUFFER_E;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't create RNG");
        return WS_CRYPTO_FAILED;
    }
    rngInit = 1;

    ret = wc_RNG_GenerateBlock(&rng, mldsaSeed, sizeof(mldsaSeed));
    if (ret != 0) {
        ret = WS_CRYPTO_FAILED;
    }
    else {
        if (wc_MlDsaKey_Init(&mldsaKey, NULL, INVALID_DEVID) != 0) {
            ret = WS_CRYPTO_FAILED;
        }
        else {
            mldsaInit = 1;
            if (wc_MlDsaKey_SetParams(&mldsaKey, params.mldsaLevel) != 0 ||
                    wc_MlDsaKey_MakeKeyFromSeed(&mldsaKey, mldsaSeed) != 0) {
                ret = WS_CRYPTO_FAILED;
            }
        }
    }
    if (ret == 0) {
        sz = params.mldsaPubSz;
        if (wc_MlDsaKey_ExportPubRaw(&mldsaKey, mldsaPub, &sz) != 0 ||
                sz != params.mldsaPubSz) {
            ret = WS_CRYPTO_FAILED;
        }
    }
    if (ret != 0) {
        WLOG(WS_LOG_DEBUG, "Couldn't generate ML-DSA half of composite key");
    }
    mldsaGenOk = (ret == 0);

    if (ret == 0) {
        ret = MakeCompositeTradKey(&rng, &params, tradPub, tradPriv);
    }
    if (ret != 0 && mldsaGenOk) {
        WLOG(WS_LOG_DEBUG,
                "Couldn't generate traditional half of composite key");
    }

    if (ret == 0 && wc_RNG_GenerateBlock(&rng, (byte*)&checkint,
            sizeof(checkint)) != 0) {
        ret = WS_CRYPTO_FAILED;
    }

    if (ret == 0) {
        tmpBuf = (byte*)WMALLOC(fileSz, NULL, DYNTYPE_BUFFER);
        if (tmpBuf == NULL) {
            ret = WS_MEMORY_E;
        }
    }

    if (ret == 0) {
        off = 0;
        WMEMCPY(tmpBuf + off, magic, WSTRLEN(magic) + 1);
        off += (word32)WSTRLEN(magic) + 1;
        c32toa(noneSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, none, noneSz); off += noneSz;
        c32toa(noneSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, none, noneSz); off += noneSz;
        c32toa(0, tmpBuf + off); off += UINT32_SZ; /* kdfoptions */
        c32toa(1, tmpBuf + off); off += UINT32_SZ; /* keycount */

        c32toa(pubBlobSz, tmpBuf + off); off += UINT32_SZ;
        c32toa(keyTypeNameSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
        c32toa(compositePubSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, mldsaPub, params.mldsaPubSz);
        off += params.mldsaPubSz;
        WMEMCPY(tmpBuf + off, tradPub, params.tradPubSz);
        off += params.tradPubSz;

        c32toa(privKeysStrSz, tmpBuf + off); off += UINT32_SZ;
        c32toa(checkint, tmpBuf + off); off += UINT32_SZ;
        c32toa(checkint, tmpBuf + off); off += UINT32_SZ;
        c32toa(keyTypeNameSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, keyTypeName, keyTypeNameSz); off += keyTypeNameSz;
        c32toa(compositePubSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, mldsaPub, params.mldsaPubSz);
        off += params.mldsaPubSz;
        WMEMCPY(tmpBuf + off, tradPub, params.tradPubSz);
        off += params.tradPubSz;
        c32toa(compositePrivSz, tmpBuf + off); off += UINT32_SZ;
        WMEMCPY(tmpBuf + off, mldsaSeed, MLDSA_SEED_SZ); off += MLDSA_SEED_SZ;
        WMEMCPY(tmpBuf + off, tradPriv, params.tradPrivSz);
        off += params.tradPrivSz;
        c32toa(0, tmpBuf + off); off += UINT32_SZ; /* comment (empty) */
        for (i = 1; i <= padSz; i++) {
            tmpBuf[off++] = (byte)i;
        }

        if (off != fileSz) {
            ret = WS_CRYPTO_FAILED;
        }
        else {
            /* outSz feasibility for this exact b64Sz was already verified
             * against the deterministic size probe above */
            off = 0;
            WMEMCPY(out + off, header, WSTRLEN(header));
            off += (word32)WSTRLEN(header);
            if (Base64_Encode(tmpBuf, fileSz, out + off, &b64Sz) == 0) {
                off += b64Sz;
                WMEMCPY(out + off, footer, WSTRLEN(footer));
                off += (word32)WSTRLEN(footer);
                /* out is PEM text of exactly `off` bytes; NUL-terminate
                 * only if the caller's buffer has room to spare */
                if (outSz > off) {
                    out[off] = '\0';
                }
                ret = (int)off;
            }
            else ret = WS_CRYPTO_FAILED;
        }
    }

    if (mldsaInit) wc_MlDsaKey_Free(&mldsaKey);
    if (rngInit) wc_FreeRng(&rng);

    wc_ForceZero(mldsaSeed, sizeof(mldsaSeed));
    wc_ForceZero(tradPriv, sizeof(tradPriv));

    if (tmpBuf != NULL) {
        wc_ForceZero(tmpBuf, fileSz);
        WFREE(tmpBuf, NULL, DYNTYPE_BUFFER);
    }

    WLOG(WS_LOG_DEBUG, "Leaving wolfSSH_MakeMlDsaCompositeKey(), ret = %d",
            ret);
    return ret;
#else
    WOLFSSH_UNUSED(out);
    WOLFSSH_UNUSED(outSz);
    WOLFSSH_UNUSED(level);
    WOLFSSH_UNUSED(tradType);
    return WS_NOT_COMPILED;
#endif
}

#else /* WOLFSSL_KEY_GEN */
    #error "wolfSSH keygen requires that keygen is enabled in wolfSSL, use --enable-keygen or #define WOLFSSL_KEY_GEN."
#endif /* WOLFSSL_KEY_GEN */

#endif /* WOLFSSH_KEYGEN */
