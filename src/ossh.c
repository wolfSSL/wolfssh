/* ossh.c
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
 * The ossh module parses and verifies OpenSSH ("*-cert-v01@openssh.com")
 * user certificates.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/ossh.h>

#include <wolfssh/internal.h>
#include <wolfssh/log.h>
#include <wolfssh/error.h>

#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>
#ifndef WOLFSSH_NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef WOLFSSH_NO_ECDSA
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef WOLFSSH_NO_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif



/* OpenSSH binary key-format decoders (moved from internal.c);
 * compiled regardless of WOLFSSH_OSSH_CERTS. */

#ifndef WOLFSSH_NO_RSA

#if (LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0) && !defined(HAVE_FIPS)
/*
 * The function wc_RsaPrivateKeyDecodeRaw() is available
 * from wolfSSL after v5.7.0.
 */

/*
 * Utility for GetOpenSshKey() to read in RSA keys.
 */
static int GetOpenSshKeyRsa(RsaKey* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *n, *e, *d, *u, *p, *q;
    word32 nSz, eSz, dSz, uSz, pSz, qSz;
    int ret;

    ret = wc_InitRsaKey(key, NULL);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&nSz, &n, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&eSz, &e, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&dSz, &d, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&uSz, &u, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&pSz, &p, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpint(&qSz, &q, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = wc_RsaPrivateKeyDecodeRaw(n, nSz, e, eSz, d, dSz,
                u, uSz, p, pSz, q, qSz, NULL, 0, NULL, 0, key);

    if (ret != WS_SUCCESS)
        ret = WS_RSA_E;

    return ret;
}

#else /* LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0 */

#include <wolfssl/wolfcrypt/wolfmath.h>

/*
 * Utility function to read an Mpint from the stream directly into a mp_int.
 * The RsaKey members u, dP, and dQ do not exist when wolfCrypt is built
 * with RSA_LOW_MEM. (That mode of wolfCrypt isn't using the extra values
 * for the Chinese Remainder Theorem.)
 */
static int GetMpintToMp(mp_int* mp,
        const byte* buf, word32 len, word32* idx)
{
    const byte* val = NULL;
    word32 valSz = 0;
    int ret;

    ret = GetMpint(&valSz, &val, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = mp_read_unsigned_bin(mp, val, valSz);

    return ret;
}


#ifndef RSA_LOW_MEM
/*
 * For the given RSA key, calculate d mod(p-1) and d mod(q-1).
 * wolfCrypt's RSA code expects them, but the OpenSSH format key
 * doesn't store them.
 */
static int CalcRsaDX(RsaKey* key)
{
    mp_int m;
    int ret;

    ret = mp_init(&m);
    if (ret == MP_OKAY) {
        ret = mp_sub_d(&key->p, 1, &m);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &m, &key->dP);
        if (ret == MP_OKAY)
            ret = mp_sub_d(&key->q, 1, &m);
        if (ret == MP_OKAY)
            ret = mp_mod(&key->d, &m, &key->dQ);
        mp_forcezero(&m);
    }

    return ret;
}
#endif

/*
 * Utility for GetOpenSshKey() to read in RSA keys.
 */
static int GetOpenSshKeyRsa(RsaKey* key,
        const byte* buf, word32 len, word32* idx)
{
    int ret;

    ret = wc_InitRsaKey(key, NULL);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->n, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->e, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->d, buf, len, idx);
#ifndef RSA_LOW_MEM
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->u, buf, len, idx);
#else
    /* Skipping the u value in the key. */
    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx);
#endif
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->p, buf, len, idx);
    if (ret == WS_SUCCESS)
        ret = GetMpintToMp(&key->q, buf, len, idx);

#ifndef RSA_LOW_MEM
    /* Calculate dP and dQ for wolfCrypt. */
    if (ret == WS_SUCCESS)
        ret = CalcRsaDX(key);
#endif

    if (ret != WS_SUCCESS)
        ret = WS_RSA_E;

    return ret;
}

#endif /* LIBWOLFSSL_VERSION_HEX > WOLFSSL_V5_7_0 */

#endif /* WOLFSSH_NO_RSA */


#ifndef WOLFSSH_NO_ECDSA
/*
 * Utility for GetOpenSshKey() to read in ECDSA keys.
 */
static int GetOpenSshKeyEcc(ecc_key* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *name = NULL, *priv = NULL, *pub = NULL;
    word32 nameSz = 0, privSz = 0, pubSz = 0;
    int ret;

    ret = wc_ecc_init(key);
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&nameSz, &name, buf, len, idx); /* curve name */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&pubSz, &pub, buf, len, idx); /* Q */
    if (ret == WS_SUCCESS)
        ret = GetMpint(&privSz, &priv, buf, len, idx); /* d */

    if (ret == WS_SUCCESS)
        ret = wc_ecc_import_private_key_ex(priv, privSz, pub, pubSz,
                key, ECC_CURVE_DEF);

    if (ret != WS_SUCCESS)
        ret = WS_ECC_E;

    return ret;
}
#endif

#ifndef WOLFSSH_NO_ED25519
/*
 * Utility for GetOpenSshKey() to read in Ed25519 keys.
 */
static int GetOpenSshKeyEd25519(ed25519_key* key,
        const byte* buf, word32 len, word32* idx)
{
    const byte *priv = NULL, *pub = NULL;
    word32 privSz = 0, pubSz = 0;
    int ret;

    ret = wc_ed25519_init_ex(key, key->heap, INVALID_DEVID);

    /* OpenSSH key formatting stores the public key, ENC(A), and the
     * private key (k) concatenated with the public key, k || ENC(A). */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&pubSz, &pub, buf, len, idx); /* ENC(A) */
    if (ret == WS_SUCCESS)
        ret = GetStringRef(&privSz, &priv, buf, len, idx); /* k || ENC(A) */
    if (ret == WS_SUCCESS)
        if (privSz < pubSz)
            ret = WS_KEY_FORMAT_E;

    if (ret == WS_SUCCESS)
        ret = wc_ed25519_import_private_key(priv, privSz - pubSz,
                pub, pubSz, key);

    if (ret != WS_SUCCESS)
        ret = WS_ECC_E;

    return ret;
}
#endif

#ifdef WOLFSSH_TPM

#ifndef WOLFSSH_NO_ECDSA
static int GetOpenSshPublicKeyEcc(ecc_key* key, const byte* buf, word32 len,
    word32* idx)
{
    int ret = WS_CRYPTO_FAILED;
    (void)key;
    (void)buf;
    (void)len;
    (void)idx;
    /* TODO: Add ECC public key: See DoUserAuthRequestEcc and wc_ecc_import_x963 */
    return ret;
}
#endif
#ifndef WOLFSSH_NO_ED25519
static int GetOpenSshKeyPublicEd25519(ed25519_key* key, const byte* buf,
    word32 len, word32* idx)
{
    int ret = WS_CRYPTO_FAILED;
    (void)key;
    (void)buf;
    (void)len;
    (void)idx;
    /* TODO: Add ECC public key: See DoUserAuthRequestEd25519 and wc_ed25519_import_public */
    return ret;
}
#endif
#ifndef WOLFSSH_NO_RSA
static int GetOpenSshPublicKeyRsa(RsaKey* key, const byte* buf, word32 len,
    word32* idx)
{
    int ret;
    const byte *n = NULL, *e = NULL;
    word32 nSz = 0, eSz = 0;

    ret = GetMpint(&eSz, &e, buf, len, idx);
    if (ret == WS_SUCCESS) {
        ret = GetMpint(&nSz, &n, buf, len, idx);
    }
    if (ret == WS_SUCCESS) {
        ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
        if (ret != 0) {
            WLOG(WS_LOG_DEBUG, "Could not decode RSA public key");
            ret = WS_CRYPTO_FAILED;
        }
    }
    return ret;
}
#endif

int GetOpenSshPublicKey(WS_KeySignature *key,
        const byte* buf, word32 len, word32* idx)
{
    int ret = WS_SUCCESS;
    const byte* publicKeyType;
    word32 publicKeyTypeSz = 0;
    byte keyId;

    ret = GetStringRef(&publicKeyTypeSz, &publicKeyType, buf, len, idx);
    keyId = NameToId((const char*)publicKeyType, publicKeyTypeSz);

    switch (keyId) {
    #ifndef WOLFSSH_NO_RSA
        case ID_SSH_RSA:
            ret = GetOpenSshPublicKeyRsa(&key->ks.rsa.key, buf, len, idx);
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA
        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
            ret = GetOpenSshPublicKeyEcc(&key->ks.ecc.key, buf, len, idx);
            break;
    #endif
    #ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            ret = GetOpenSshKeyPublicEd25519(&key->ks.ed25519.key, buf, len, idx);
            break;
    #endif
        default:
            ret = WS_UNIMPLEMENTED_E;
            break;
    }
    return ret;
}

#endif /* WOLFSSH_TPM */

/*
 * Decodes an OpenSSH format key.
 */
int GetOpenSshKey(WS_KeySignature *key,
        const byte* buf, word32 len, word32* idx)
{
    const char AuthMagic[] = "openssh-key-v1";
    const byte* str = NULL;
    word32 keyCount = 0, strSz, i;
    int ret = WS_SUCCESS;

    if (WSTRCMP(AuthMagic, (const char*)buf) != 0) {
        ret = WS_KEY_AUTH_MAGIC_E;
    }

    if (ret == WS_SUCCESS) {
        *idx += (word32)WSTRLEN(AuthMagic) + 1;
        ret = GetSkip(buf, len, idx); /* ciphername */
    }

    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx); /* kdfname */

    if (ret == WS_SUCCESS)
        ret = GetSkip(buf, len, idx); /* kdfoptions */

    if (ret == WS_SUCCESS)
        ret = GetUint32(&keyCount, buf, len, idx); /* key count */

    if (ret == WS_SUCCESS) {
        if (keyCount != WOLFSSH_KEY_QUANTITY_REQ) {
            ret = WS_KEY_FORMAT_E;
        }
    }

    if (ret == WS_SUCCESS) {
        strSz = 0;
        ret = GetStringRef(&strSz, &str, buf, len, idx);
                /* public buf */
    }

    if (ret == WS_SUCCESS) {
        strSz = 0;
        ret = GetStringRef(&strSz, &str, buf, len, idx);
                /* list of private keys */

        /* If there isn't a private key, the key file is bad. */
        if (ret == WS_SUCCESS && strSz == 0) {
            ret = WS_KEY_FORMAT_E;
        }

        if (ret == WS_SUCCESS) {
            const byte* subStr = NULL;
            word32 subStrSz = 0, subIdx = 0, check1 = 0, check2 = ~0;
            byte keyId;

            ret = GetUint32(&check1, str, strSz, &subIdx); /* checkint 1 */
            if (ret == WS_SUCCESS)
                ret = GetUint32(&check2, str, strSz, &subIdx); /* checkint 2 */
            if (ret == WS_SUCCESS) {
                if (check1 != check2) {
                    ret = WS_KEY_CHECK_VAL_E;
                }
            }
            if (ret == WS_SUCCESS) {
                for (i = 0; i < keyCount; i++) {
                    ret = GetStringRef(&subStrSz, &subStr,
                            str, strSz, &subIdx);
                    if (ret == WS_SUCCESS) {
                        keyId = NameToId((const char*)subStr, subStrSz);
                        key->keyId = keyId;
                    }
                    if (ret == WS_SUCCESS) {
                        switch (keyId) {
                        #ifndef WOLFSSH_NO_RSA
                            case ID_SSH_RSA:
                                ret = GetOpenSshKeyRsa(&key->ks.rsa.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                        #ifndef WOLFSSH_NO_ECDSA
                            case ID_ECDSA_SHA2_NISTP256:
                            case ID_ECDSA_SHA2_NISTP384:
                            case ID_ECDSA_SHA2_NISTP521:
                                ret = GetOpenSshKeyEcc(&key->ks.ecc.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                        #ifndef WOLFSSH_NO_ED25519
                            case ID_ED25519:
                                ret = GetOpenSshKeyEd25519(&key->ks.ed25519.key,
                                        str, strSz, &subIdx);
                                break;
                        #endif
                            default:
                                ret = WS_UNIMPLEMENTED_E;
                                break;
                        }
                        if (ret == WS_SUCCESS)
                            ret = GetSkip(str, strSz, &subIdx);
                                    /* key comment */
                    }
                }
                /* Padding: Add increasing digits to pad to the nearest
                 * block size. Default block size is 8, but depends on
                 * the encryption algo. The private key chunk's length,
                 * and the length of the comment delimit the end of the
                 * encrypted blob. No added padding required. */
                if (ret == WS_SUCCESS) {
                    if (strSz % MIN_BLOCK_SZ == 0) {
                        if (strSz > subIdx) {
                            /* The padding starts at 1. */
                            check2 = strSz - subIdx;
                            for (check1 = 1;
                                 check1 <= check2;
                                 check1++, subIdx++) {
                                if (check1 != str[subIdx]) {
                                    /* Bad pad value. */
                                    ret = WS_KEY_FORMAT_E;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return ret;
}


/*
 * Identifies the flavor of an OpenSSH key, RSA or ECDSA, and returns the
 * key type ID. The process is to decode the key extracting the identifiers,
 * and try to decode the key as the type indicated type. For RSA keys, the
 * key format is described as "ssh-rsa".
 *
 * @param in        key to identify
 * @param inSz      size of key
 * @param heap      heap to use for memory allocation
 * @return          keyId as int, WS_MEMORY_E, WS_UNIMPLEMENTED_E,
 *                  WS_INVALID_ALGO_ID
 */
int IdentifyOpenSshKey(const byte* in, word32 inSz, void* heap)
{
    WS_KeySignature *key = NULL;
    word32 idx = 0;
    int ret;

    key = (WS_KeySignature*)WMALLOC(sizeof(WS_KeySignature),
            heap, DYNTYPE_PRIVKEY);

    if (key == NULL) {
        ret = WS_MEMORY_E;
    }
    else {
        WMEMSET(key, 0, sizeof(*key));
        key->heap = heap;
        key->keyId = ID_NONE;

        ret = GetOpenSshKey(key, in, inSz, &idx);

        if (ret == WS_SUCCESS) {
            ret = key->keyId;
        }
        else if (key->keyId == ID_UNKNOWN) {
            ret = WS_UNIMPLEMENTED_E;
        }

        wolfSSH_KEY_clean(key);
        WFREE(key, heap, DYNTYPE_PRIVKEY);
    }

    return ret;
}


#ifdef WOLFSSH_OSSH_CERTS

byte OsshCertBaseId(byte certId)
{
    byte id;

    switch (certId) {
    #ifndef WOLFSSH_NO_RSA_SHA2_256
        case ID_OSSH_CERT_RSA:
            id = ID_SSH_RSA;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
        case ID_OSSH_CERT_ECDSA_SHA2_NISTP256:
            id = ID_ECDSA_SHA2_NISTP256;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP384
        case ID_OSSH_CERT_ECDSA_SHA2_NISTP384:
            id = ID_ECDSA_SHA2_NISTP384;
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP521
        case ID_OSSH_CERT_ECDSA_SHA2_NISTP521:
            id = ID_ECDSA_SHA2_NISTP521;
            break;
    #endif
    #ifndef WOLFSSH_NO_ED25519
        case ID_OSSH_CERT_ED25519:
            id = ID_ED25519;
            break;
    #endif
        default:
            id = ID_UNKNOWN;
    }

    return id;
}


byte OsshRsaCertSigId(const byte* peerSigId, word32 peerSigIdSz)
{
    byte sigId = ID_RSA_SHA2_256;
#ifndef WOLFSSH_NO_RSA_SHA2_512
    word32 k;

    for (k = 0; k < peerSigIdSz; k++) {
        if (peerSigId[k] == ID_RSA_SHA2_512) {
            sigId = ID_RSA_SHA2_512;
            break;
        }
    }
#else
    (void)peerSigId;
    (void)peerSigIdSz;
#endif
    return sigId;
}


/* Skip the type-specific public key fields embedded in the certificate so the
 * raw region can be captured for later reconstruction. Advances *idx. */
static int OsshSkipUserKey(byte baseId, const byte* blob, word32 blobSz,
        word32* idx)
{
    int ret = WS_SUCCESS;
    word32 sz = 0;
    const byte* p = NULL;

    switch (baseId) {
    #ifndef WOLFSSH_NO_RSA
        case ID_SSH_RSA:
            ret = GetMpint(&sz, &p, blob, blobSz, idx);     /* e */
            if (ret == WS_SUCCESS)
                ret = GetMpint(&sz, &p, blob, blobSz, idx); /* n */
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA
        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
            ret = GetStringRef(&sz, &p, blob, blobSz, idx);     /* curve */
            if (ret == WS_SUCCESS)
                ret = GetStringRef(&sz, &p, blob, blobSz, idx); /* Q */
            break;
    #endif
    #ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            ret = GetStringRef(&sz, &p, blob, blobSz, idx);     /* pk */
            break;
    #endif
        default:
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}


int OsshCertParse(WS_OsshCert* cert, byte typeId, const byte* blob,
        word32 blobSz)
{
    int ret = WS_SUCCESS;
    word32 idx = 0;
    word32 ukStart = 0;
    word32 caIdx = 0;
    const byte* str = NULL;
    word32 strSz = 0;

    if (cert == NULL || blob == NULL || blobSz == 0) {
        return WS_BAD_ARGUMENT;
    }

    WMEMSET(cert, 0, sizeof(*cert));
    cert->blob = blob;
    cert->blobSz = blobSz;
    cert->typeId = typeId;
    cert->baseTypeId = OsshCertBaseId(typeId);
    if (cert->baseTypeId == ID_UNKNOWN) {
        ret = WS_INVALID_ALGO_ID;
    }

    /* string: certificate type name, must match typeId */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&strSz, &str, blob, blobSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        if (NameToId((const char*)str, strSz) != typeId) {
            WLOG(WS_LOG_DEBUG, "OSSH: cert type name mismatch");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    /* string: nonce */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->nonceSz, &cert->nonce, blob, blobSz, &idx);
    }

    /* type-specific public key fields (captured as a raw region) */
    ukStart = idx;
    if (ret == WS_SUCCESS) {
        ret = OsshSkipUserKey(cert->baseTypeId, blob, blobSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        cert->userKeyParms = blob + ukStart;
        cert->userKeyParmsSz = idx - ukStart;
    }

    /* uint64: serial */
    if (ret == WS_SUCCESS) {
        ret = GetUint64(&cert->serial, blob, blobSz, &idx);
    }
    /* uint32: type (user vs host) */
    if (ret == WS_SUCCESS) {
        ret = GetUint32(&cert->certType, blob, blobSz, &idx);
    }
    /* string: key id */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->keyIdSz, &cert->keyId, blob, blobSz, &idx);
    }
    /* string: valid principals (a run of inner SSH strings) */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->principalsSz, &cert->principals, blob, blobSz,
                &idx);
    }
    /* uint64: valid after / valid before */
    if (ret == WS_SUCCESS) {
        ret = GetUint64(&cert->validAfter, blob, blobSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetUint64(&cert->validBefore, blob, blobSz, &idx);
    }
    /* string: critical options */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->critOptsSz, &cert->critOpts, blob, blobSz,
                &idx);
    }
    /* string: extensions */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->extensionsSz, &cert->extensions, blob, blobSz,
                &idx);
    }
    /* string: reserved (ignored) */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&strSz, &str, blob, blobSz, &idx);
    }
    /* string: signature key (the CA public key blob) */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->caKeySz, &cert->caKey, blob, blobSz, &idx);
    }
    /* The CA key blob itself begins with its own type name string. */
    if (ret == WS_SUCCESS) {
        caIdx = 0;
        ret = GetStringRef(&cert->caKeyTypeSz, &cert->caKeyType, cert->caKey,
                cert->caKeySz, &caIdx);
    }

    /* Everything up to (but not including) the signature is signed. */
    if (ret == WS_SUCCESS) {
        cert->signedLen = idx;
    }

    /* string: signature */
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&cert->signatureSz, &cert->signature, blob, blobSz,
                &idx);
    }

    /* Reject trailing bytes after the signature, matching OpenSSH strictness. */
    if (ret == WS_SUCCESS && idx != blobSz) {
        WLOG(WS_LOG_DEBUG, "OSSH: trailing bytes after certificate signature");
        ret = WS_PARSE_E;
    }

    return ret;
}


int OsshCertCheckType(const WS_OsshCert* cert)
{
    int ret = WS_SUCCESS;
    byte caId;

    if (cert == NULL) {
        return WS_BAD_ARGUMENT;
    }

    if (cert->certType != WOLFSSH_OSSH_CERT_TYPE_USER) {
        WLOG(WS_LOG_DEBUG, "OSSH: not a user certificate");
        ret = WS_INVALID_ALGO_ID;
    }

    if (ret == WS_SUCCESS) {
        caId = NameToId((const char*)cert->caKeyType, cert->caKeyTypeSz);
        if (caId != ID_SSH_RSA
                && caId != ID_ECDSA_SHA2_NISTP256
                && caId != ID_ECDSA_SHA2_NISTP384
                && caId != ID_ECDSA_SHA2_NISTP521
                && caId != ID_ED25519) {
            WLOG(WS_LOG_DEBUG, "OSSH: unsupported CA key type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    return ret;
}


/* Lexicographic comparison of two length-delimited names. */
static int OsshNameCmp(const byte* a, word32 aSz, const byte* b, word32 bSz)
{
    word32 n = (aSz < bSz) ? aSz : bSz;
    int c = 0;

    if (n > 0) {
        c = WMEMCMP(a, b, n);
    }
    if (c == 0) {
        if (aSz < bSz) {
            c = -1;
        }
        else if (aSz > bSz) {
            c = 1;
        }
    }

    return c;
}


static int OsshNameEq(const byte* a, word32 aSz, const char* lit)
{
    word32 litSz = (word32)WSTRLEN(lit);
    return (aSz == litSz && WMEMCMP(a, lit, litSz) == 0);
}


int OsshCertCheckOptions(WS_OsshCert* cert)
{
    int ret = WS_SUCCESS;
    word32 idx;
    const byte* name = NULL;
    word32 nameSz = 0;
    const byte* data = NULL;
    word32 dataSz = 0;
    word32 di = 0;
    const byte* prevName = NULL;
    word32 prevNameSz = 0;

    if (cert == NULL) {
        return WS_BAD_ARGUMENT;
    }

    cert->forceCommand = NULL;
    cert->forceCommandSz = 0;
    cert->sourceAddress = NULL;
    cert->sourceAddressSz = 0;

    /* Critical options: ascending order, no duplicates, all recognized. */
    idx = 0;
    while (ret == WS_SUCCESS && idx < cert->critOptsSz) {
        ret = GetStringRef(&nameSz, &name, cert->critOpts, cert->critOptsSz,
                &idx);
        if (ret == WS_SUCCESS && prevName != NULL &&
                OsshNameCmp(prevName, prevNameSz, name, nameSz) >= 0) {
            WLOG(WS_LOG_DEBUG, "OSSH: critical options out of order");
            ret = WS_PARSE_E;
        }
        if (ret == WS_SUCCESS) {
            ret = GetStringRef(&dataSz, &data, cert->critOpts,
                    cert->critOptsSz, &idx);
        }
        if (ret == WS_SUCCESS) {
            di = 0;
            if (OsshNameEq(name, nameSz, "force-command")) {
                ret = GetStringRef(&cert->forceCommandSz, &cert->forceCommand,
                        data, dataSz, &di);
            }
            else if (OsshNameEq(name, nameSz, "source-address")) {
                ret = GetStringRef(&cert->sourceAddressSz,
                        &cert->sourceAddress, data, dataSz, &di);
            }
            else {
                WLOG(WS_LOG_DEBUG,
                    "OSSH: unsupported critical option, rejecting");
                ret = WS_UNIMPLEMENTED_E;
            }
            if (ret == WS_SUCCESS && di != dataSz) {
                WLOG(WS_LOG_DEBUG, "OSSH: critical option data malformed");
                ret = WS_PARSE_E;
            }
        }
        prevName = name;
        prevNameSz = nameSz;
    }

    /* Extensions: ascending order, no duplicates; unknown ones are ignored. */
    idx = 0;
    prevName = NULL;
    prevNameSz = 0;
    while (ret == WS_SUCCESS && idx < cert->extensionsSz) {
        ret = GetStringRef(&nameSz, &name, cert->extensions,
                cert->extensionsSz, &idx);
        if (ret == WS_SUCCESS && prevName != NULL &&
                OsshNameCmp(prevName, prevNameSz, name, nameSz) >= 0) {
            WLOG(WS_LOG_DEBUG, "OSSH: extensions out of order");
            ret = WS_PARSE_E;
        }
        if (ret == WS_SUCCESS) {
            ret = GetStringRef(&dataSz, &data, cert->extensions,
                    cert->extensionsSz, &idx);
        }
        if (ret == WS_SUCCESS) {
            if (!OsshNameEq(name, nameSz, "permit-X11-forwarding")
                    && !OsshNameEq(name, nameSz, "permit-agent-forwarding")
                    && !OsshNameEq(name, nameSz, "permit-port-forwarding")
                    && !OsshNameEq(name, nameSz, "permit-pty")
                    && !OsshNameEq(name, nameSz, "permit-user-rc")
                    && !OsshNameEq(name, nameSz, "no-touch-required")) {
                WLOG(WS_LOG_DEBUG,
                    "OSSH: ignoring unrecognized certificate extension");
            }
        }
        prevName = name;
        prevNameSz = nameSz;
    }

    return ret;
}


#ifndef WOLFSSH_NO_ED25519
static int OsshVerifyEd25519(const WS_OsshCert* cert, void* heap)
{
    int ret = WS_SUCCESS;
    int verified = 0;
    word32 idx;
    const byte* a = NULL;
    word32 aSz = 0;
    const byte* sig = NULL;
    word32 sigSz = 0;
    ed25519_key* key = NULL;

    key = (ed25519_key*)WMALLOC(sizeof(ed25519_key), heap, DYNTYPE_PUBKEY);
    if (key == NULL) {
        return WS_MEMORY_E;
    }

    /* CA key blob: string "ssh-ed25519", string A */
    idx = cert->caKeyTypeSz + LENGTH_SZ;
    ret = GetStringRef(&aSz, &a, cert->caKey, cert->caKeySz, &idx);

    /* signature: string "ssh-ed25519", string sig. The sig-type name is
     * skipped. */
    if (ret == WS_SUCCESS) {
        idx = 0;
        ret = GetSkip(cert->signature, cert->signatureSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sigSz, &sig, cert->signature, cert->signatureSz,
                &idx);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ed25519_init_ex(key, heap, INVALID_DEVID);

        if (ret == WS_SUCCESS) {
            ret = wc_ed25519_import_public(a, aSz, key);
        }
        if (ret == WS_SUCCESS) {
            ret = wc_ed25519_verify_msg(sig, sigSz, cert->blob, cert->signedLen,
                    &verified, key);
        }
        if (ret == WS_SUCCESS && verified != 1) {
            WLOG(WS_LOG_DEBUG, "OSSH: ed25519 CA signature verify failed");
            ret = WS_ED25519_E;
        }

        wc_ed25519_free(key);
    }
    WFREE(key, heap, DYNTYPE_PUBKEY);

    return ret;
}
#endif /* WOLFSSH_NO_ED25519 */


#ifndef WOLFSSH_NO_RSA
static int OsshVerifyRsa(const WS_OsshCert* cert, void* heap)
{
    int ret = WS_SUCCESS;
    word32 idx;
    const byte* e = NULL;
    const byte* n = NULL;
    word32 eSz = 0;
    word32 nSz = 0;
    const byte* sigType = NULL;
    word32 sigTypeSz = 0;
    const byte* sig = NULL;
    word32 sigSz = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    int hashOid = 0;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = 0;
    word32 encDigestSz = 0;
    RsaKey* key = NULL;
#ifdef WOLFSSH_SMALL_STACK
    byte* encDigest = NULL;
#else
    byte encDigest[MAX_ENCODED_SIG_SZ];
#endif

    key = (RsaKey*)WMALLOC(sizeof(RsaKey), heap, DYNTYPE_PUBKEY);
    if (key == NULL) {
        return WS_MEMORY_E;
    }
#ifdef WOLFSSH_SMALL_STACK
    encDigest = (byte*)WMALLOC(MAX_ENCODED_SIG_SZ, heap, DYNTYPE_TEMP);
    if (encDigest == NULL) {
        WFREE(key, heap, DYNTYPE_PUBKEY);
        return WS_MEMORY_E;
    }
#endif

    /* CA key blob: string "ssh-rsa", mpint e, mpint n */
    idx = cert->caKeyTypeSz + LENGTH_SZ;
    ret = GetMpint(&eSz, &e, cert->caKey, cert->caKeySz, &idx);
    if (ret == WS_SUCCESS) {
        ret = GetMpint(&nSz, &n, cert->caKey, cert->caKeySz, &idx);
    }

    /* signature: string sigType, string sig */
    if (ret == WS_SUCCESS) {
        idx = 0;
        ret = GetStringRef(&sigTypeSz, &sigType, cert->signature,
                cert->signatureSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sigSz, &sig, cert->signature, cert->signatureSz,
                &idx);
    }

    /* select hash from the signature algorithm name */
    if (ret == WS_SUCCESS) {
        if (sigTypeSz == 12 && WMEMCMP(sigType, "rsa-sha2-256", 12) == 0) {
            hashType = WC_HASH_TYPE_SHA256;
        }
        else if (sigTypeSz == 12 && WMEMCMP(sigType, "rsa-sha2-512", 12) == 0) {
            hashType = WC_HASH_TYPE_SHA512;
        }
    #ifndef WOLFSSH_NO_SSH_RSA_SHA1
        else if (sigTypeSz == 7 && WMEMCMP(sigType, "ssh-rsa", 7) == 0) {
            hashType = WC_HASH_TYPE_SHA;
        }
    #endif
        else {
            WLOG(WS_LOG_DEBUG, "OSSH: unsupported RSA CA signature type");
            ret = WS_INVALID_ALGO_ID;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wc_InitRsaKey(key, heap);

        if (ret == WS_SUCCESS) {
            ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, key);
        }
        if (ret == WS_SUCCESS) {
            digestSz = (word32)wc_HashGetDigestSize(hashType);
            ret = wc_Hash(hashType, cert->blob, cert->signedLen, digest,
                    digestSz);
        }
        if (ret == WS_SUCCESS) {
            hashOid = wc_HashGetOID(hashType);
            if (hashOid <= 0) {
                ret = WS_INVALID_ALGO_ID;
            }
        }
        if (ret == WS_SUCCESS) {
            encDigestSz = wc_EncodeSignature(encDigest, digest, digestSz,
                    hashOid);
            if (encDigestSz == 0) {
                ret = WS_CRYPTO_FAILED;
            }
        }
        if (ret == WS_SUCCESS) {
            ret = wolfSSH_RsaVerify(sig, sigSz, encDigest, encDigestSz, key,
                    heap, "OSSH CA");
        }

        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "OSSH: RSA CA signature verify failed (%d)",
                    ret);
        }

        wc_FreeRsaKey(key);
    }
    WFREE(key, heap, DYNTYPE_PUBKEY);
#ifdef WOLFSSH_SMALL_STACK
    WFREE(encDigest, heap, DYNTYPE_TEMP);
#endif

    return ret;
}
#endif /* WOLFSSH_NO_RSA */


#ifndef WOLFSSH_NO_ECDSA
static int OsshVerifyEcc(const WS_OsshCert* cert, void* heap)
{
    int ret = WS_SUCCESS;
    word32 idx;
    const byte* q = NULL;
    word32 qSz = 0;
    const byte* sigBlob = NULL;
    word32 sigBlobSz = 0;
    const byte* r = NULL;
    const byte* s = NULL;
    word32 rSz = 0;
    word32 sSz = 0;
    word32 blobIdx = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = 0;
    word32 asnSigSz = ECC_MAX_SIG_SIZE;
    ecc_key* key = NULL;
#ifdef WOLFSSH_SMALL_STACK
    byte* asnSig = NULL;
#else
    byte asnSig[ECC_MAX_SIG_SIZE];
#endif

    key = (ecc_key*)WMALLOC(sizeof(ecc_key), heap, DYNTYPE_PUBKEY);
    if (key == NULL) {
        return WS_MEMORY_E;
    }
#ifdef WOLFSSH_SMALL_STACK
    asnSig = (byte*)WMALLOC(ECC_MAX_SIG_SIZE, heap, DYNTYPE_TEMP);
    if (asnSig == NULL) {
        WFREE(key, heap, DYNTYPE_PUBKEY);
        return WS_MEMORY_E;
    }
#endif

    /* hash by the CA key's curve: the CA produced the signature, so the digest
     * is bound to the CA key type, not the certified user key. */
    switch (NameToId((const char*)cert->caKeyType, cert->caKeyTypeSz)) {
        case ID_ECDSA_SHA2_NISTP256:
            hashType = WC_HASH_TYPE_SHA256;
            break;
        case ID_ECDSA_SHA2_NISTP384:
            hashType = WC_HASH_TYPE_SHA384;
            break;
        case ID_ECDSA_SHA2_NISTP521:
            hashType = WC_HASH_TYPE_SHA512;
            break;
        default:
            ret = WS_INVALID_ALGO_ID;
    }

    /* CA key blob: string type, string curve, string Q. The curve name is
     * skipped; the hash comes from the CA key type and the curve is derived
     * from Q by wc_ecc_import_x963. */
    if (ret == WS_SUCCESS) {
        idx = cert->caKeyTypeSz + LENGTH_SZ;
        ret = GetSkip(cert->caKey, cert->caKeySz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&qSz, &q, cert->caKey, cert->caKeySz, &idx);
    }

    /* signature: string sigType, string (mpint r, mpint s). The sig-type name
     * is skipped. */
    if (ret == WS_SUCCESS) {
        idx = 0;
        ret = GetSkip(cert->signature, cert->signatureSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sigBlobSz, &sigBlob, cert->signature,
                cert->signatureSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetMpint(&rSz, &r, sigBlob, sigBlobSz, &blobIdx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetMpint(&sSz, &s, sigBlob, sigBlobSz, &blobIdx);
    }

    if (ret == WS_SUCCESS) {
        ret = wc_ecc_init_ex(key, heap, INVALID_DEVID);

        if (ret == WS_SUCCESS) {
            ret = wc_ecc_import_x963(q, qSz, key);
        }
        if (ret == WS_SUCCESS) {
            ret = wc_ecc_rs_raw_to_sig(r, rSz, s, sSz, asnSig, &asnSigSz);
        }
        if (ret == WS_SUCCESS) {
            digestSz = (word32)wc_HashGetDigestSize(hashType);
            ret = wc_Hash(hashType, cert->blob, cert->signedLen, digest,
                    digestSz);
        }
        if (ret == WS_SUCCESS) {
            ret = wc_SignatureVerifyHash(hashType, WC_SIGNATURE_TYPE_ECC,
                    digest, digestSz, asnSig, asnSigSz, key,
                    (word32)sizeof(*key));
        }
        if (ret != WS_SUCCESS) {
            /* Preserve the specific error (import/hash/verify), like the RSA
             * path, instead of collapsing every failure to WS_ECC_E. */
            WLOG(WS_LOG_DEBUG, "OSSH: ECDSA CA signature verify failed (%d)",
                    ret);
        }

        wc_ecc_free(key);
    }
    WFREE(key, heap, DYNTYPE_PUBKEY);
#ifdef WOLFSSH_SMALL_STACK
    WFREE(asnSig, heap, DYNTYPE_TEMP);
#endif

    return ret;
}
#endif /* WOLFSSH_NO_ECDSA */


int OsshCertVerifySignature(const WS_OsshCert* cert, void* heap)
{
    int ret;
    byte caId;

    if (cert == NULL || cert->caKey == NULL || cert->signature == NULL) {
        return WS_BAD_ARGUMENT;
    }

    caId = NameToId((const char*)cert->caKeyType, cert->caKeyTypeSz);

    switch (caId) {
    #ifndef WOLFSSH_NO_RSA
        case ID_SSH_RSA:
            ret = OsshVerifyRsa(cert, heap);
            break;
    #endif
    #ifndef WOLFSSH_NO_ECDSA
        case ID_ECDSA_SHA2_NISTP256:
        case ID_ECDSA_SHA2_NISTP384:
        case ID_ECDSA_SHA2_NISTP521:
            ret = OsshVerifyEcc(cert, heap);
            break;
    #endif
    #ifndef WOLFSSH_NO_ED25519
        case ID_ED25519:
            ret = OsshVerifyEd25519(cert, heap);
            break;
    #endif
        default:
            WLOG(WS_LOG_DEBUG, "OSSH: unsupported CA key type for verify");
            ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}

#endif /* WOLFSSH_OSSH_CERTS */
