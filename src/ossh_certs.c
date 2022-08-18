/* ossh_certs.c
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

#ifdef WOLFSSH_OSSH_CERTS

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <wolfssh/ossh_certs.h>
#ifdef NO_INLINE
#include <wolfssh/misc.h>
#else
#define WOLFSSH_MISC_INCLUDED
#include "src/misc.c"
#endif /* NO_INLINE */
#include <wolfssh/internal.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>

static const byte osshCertTypes[] = {
    ID_OSSH_CERT_RSA
};
static const int NUM_OSSH_CERT_TYPES = (int)(sizeof(osshCertTypes) /
                                             sizeof(*osshCertTypes));

enum {
    OSSH_CERT_TYPE_USER = 1,
    OSSH_CERT_TYPE_HOST = 2
};

static int CheckAllowedCertType(byte type) {
    int ret = WS_SUCCESS;
    int i;

    for (i = 0; i < NUM_OSSH_CERT_TYPES; ++i) {
        if (type == osshCertTypes[i]) {
            break;
        }
    }

    if (i == NUM_OSSH_CERT_TYPES) {
        WLOG(WS_LOG_ERROR, "Invalid OpenSSH cert type %u.", type);
        ret = WS_INVALID_ALGO_ID;
    }

    return ret;
}

static int GetRsaParams(byte* in, word32 inSz, word32* idx, byte** e,
                        word32* eSz, byte** n, word32* nSz)
{
    int ret = WS_SUCCESS;
    byte* tmp = NULL;
    word32 tmpSz;

    if (in == NULL || inSz == 0 || idx == NULL || e == NULL || n == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        /* Get exponent, e. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, idx);
        if (ret == WS_SUCCESS) {
            *e = tmp;
            *eSz = tmpSz;
            /* Get modulus, n. */
            ret = GetStringRef(&tmpSz, &tmp, in, inSz, idx);
            if (ret == WS_SUCCESS) {
                *n = tmp;
                *nSz = tmpSz;
            }
            else {
                WLOG(WS_LOG_ERROR, "Failed to get RSA modulus, n.");
            }
        }
        else {
            WLOG(WS_LOG_ERROR, "Failed to get RSA exponent, e.");
        }
    }

    return ret;
}

WOLFSSH_OSSH_PRINCIPAL* OsshPrincipalNew(void* heap)
{
    WOLFSSH_OSSH_PRINCIPAL* ret = NULL;

    ret = (WOLFSSH_OSSH_PRINCIPAL*)WMALLOC(sizeof(WOLFSSH_OSSH_PRINCIPAL), heap,
                                           DYNTYPE_OSSH_PRINCIPAL);
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_OSSH_PRINCIPAL));

        ret->heap = heap;
    }

    return ret;
}

void OsshPrincipalFree(WOLFSSH_OSSH_PRINCIPAL* principal)
{
    if (principal != NULL) {
        WFREE(principal, principal->heap, DYNTYPE_OSSH_PRINCIPAL);
    }
}

/* TODO: Test case with 0 valid principals? */
static int GetValidPrincipals(byte* in, word32 inSz, word32* idx,
                              WOLFSSH_LIST** out, void* heap)
{
    int ret = WS_SUCCESS;
    word32 listSz;
    byte* name = NULL;
    word32 nameSz;
    WOLFSSH_LIST* list = NULL;
    WOLFSSH_OSSH_PRINCIPAL* principal;

    if (in == NULL || idx == NULL || out == NULL || *out != NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = GetUint32(&listSz, in, inSz, idx);
    }
    if (ret == WS_SUCCESS && listSz > 0) {
        list = ListNew(LIST_OSSH_PRINCIPAL, heap);
        if (list == NULL) {
            ret = WS_MEMORY_E;
        }
    }
    while (ret == WS_SUCCESS && listSz > 0) {
        ret = GetStringRef(&nameSz, &name, in, inSz, idx);
        if (ret == WS_SUCCESS) {
            if (nameSz > MAX_OSSH_PRINCIPAL_MAX_NAME_SZ) {
                ret = WS_BUFFER_E;
            }
            else {
                principal = OsshPrincipalNew(heap);
                if (principal == NULL) {
                    ret = WS_MEMORY_E;
                }
                else {
                    WMEMCPY(principal->name, name, nameSz);
                    principal->nameSz = nameSz;
                    ret = ListAdd(list, (void*)principal);
                }
            }
        }
        listSz -= (UINT32_SZ + nameSz);
    }

    if (ret == WS_SUCCESS) {
        *out = list;
    }
    else {
        if (list != NULL) {
            ListFree(list);
        }
    }

    return ret;
}

static int GetCurrentTime(w64wrapper* out)
{
    int ret = WS_SUCCESS;
    time_t currentTime;

    if (out == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret ==  WS_SUCCESS) {
        currentTime = WTIME(NULL);
        if (currentTime == (time_t)-1) {
            ret = WS_FATAL_ERROR;
        }
        else {
            if (sizeof(currentTime) == 8) {
                *out = w64From32(currentTime >> 32,
                                 currentTime & 0x00000000FFFFFFFF);
            }
            else if (sizeof(currentTime) == 4) {
                *out = w64From32(0, currentTime);
            }
            else {
                ret = WS_FATAL_ERROR;
            }
        }
    }

    return ret;
}

static int GetRsaKey(byte* in, word32 inSz, word32* idx, RsaKey** key,
                     void* heap)
{
    int ret = WS_SUCCESS;
    byte* e;
    word32 eSz;
    byte* n;
    word32 nSz;
    RsaKey* tmpKey = NULL;

    if (in == NULL || inSz == 0 || idx == NULL || key == NULL || *key != NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = GetRsaParams(in, inSz, idx, &e, &eSz, &n, &nSz);
        if (ret == WS_SUCCESS) {
            tmpKey = (RsaKey*)WMALLOC(sizeof(RsaKey), heap, DYNTYPE_PUBKEY);
            if (tmpKey == NULL) {
                ret = WS_MEMORY_E;
            }
        }
        if (ret == WS_SUCCESS) {
            ret = wc_InitRsaKey(tmpKey, heap);
            if (ret != 0) {
                WLOG(WS_LOG_ERROR, "Failed to initialize RSA key.");
                ret = WS_RSA_E;
            }
        }
        if (ret == WS_SUCCESS) {
            ret = wc_RsaPublicKeyDecodeRaw(n, nSz, e, eSz, tmpKey);
            if (ret != 0) {
                WLOG(WS_LOG_ERROR, "Failed to create RSA key with parsed "
                                   "params.");
                ret = WS_RSA_E;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        *key = tmpKey;
    }

    return ret;
}

static int GetCAKey(byte* in, word32 inSz, byte* keyId, byte* fingerprint,
                    void** key, void* heap)
{
    int ret = WS_SUCCESS;
    word32 idx = 0;
    byte* keyType = NULL;
    word32 keyTypeSz;
    byte tmpKeyId;
    void* tmpKey = NULL;

    if (in == NULL || inSz == 0 || keyId == NULL || fingerprint == NULL ||
        key == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&keyTypeSz, &keyType, in, inSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        tmpKeyId = NameToId((char*)keyType, keyTypeSz);

        switch (tmpKeyId) {
            case ID_SSH_RSA:
                ret = GetRsaKey(in, inSz, &idx, (RsaKey**)&tmpKey, heap);
                break;
            default:
                ret = WS_INVALID_ALGO_ID;
                break;
        }
    }

    if (ret == WS_SUCCESS) {
        ret = wc_Hash(WC_HASH_TYPE_SHA256, in, inSz, fingerprint,
                      WC_SHA256_DIGEST_SIZE);
    }
    if (ret == WS_SUCCESS) {
        *keyId = tmpKeyId;
        *key = tmpKey;
        ret = idx;
    }
    else {
        if (tmpKey != NULL) {
            WFREE(tmpKey, heap, DYNTYPE_PUBKEY);
        }
    }

    return ret;
}

static int GetCASignature(byte* in, word32 inSz, byte* sigId, byte** sig,
                          word32* sigSz)
{
    int ret = WS_SUCCESS;
    word32 idx = 0;
    byte* sigType = NULL;
    word32 sigTypeSz;
    byte tmpSigId;
    byte* tmpSig = NULL;
    word32 tmpSigSz;

    if (in == NULL || inSz == 0 || sigId == NULL || sig == NULL ||
        sigSz == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&sigTypeSz, &sigType, in, inSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        tmpSigId = NameToId((char*)sigType, sigTypeSz);
        if (tmpSigId == ID_UNKNOWN) {
            ret = WS_INVALID_ALGO_ID;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = GetStringRef(&tmpSigSz, &tmpSig, in, inSz, &idx);
    }

    if (ret == WS_SUCCESS) {
        *sigId = tmpSigId;
        *sig = tmpSig;
        *sigSz = tmpSigSz;
        ret = idx;
    }

    return ret;
}

static INLINE int CheckSigAndKeyTypes(byte sigId, byte keyId)
{
    int ret = WS_OSSH_CERT_CA_E;

    if (keyId == ID_SSH_RSA && (sigId == ID_SSH_RSA ||
        sigId == ID_RSA_SHA2_256 || sigId == ID_RSA_SHA2_512)) {
        ret = WS_SUCCESS;
    }

    return ret;
}

static INLINE enum wc_HashType SigIdToWcHashType(byte sigId)
{
    enum wc_HashType ret = WC_HASH_TYPE_NONE;

    switch (sigId) {
        case ID_SSH_RSA:
            ret = WC_HASH_TYPE_SHA;
            break;
        case ID_RSA_SHA2_256:
            ret = WC_HASH_TYPE_SHA256;
            break;
        case ID_RSA_SHA2_512:
            ret = WC_HASH_TYPE_SHA512;
            break;
        default:
            break;
    }

    return ret;
}

static INLINE enum wc_SignatureType SigIdToWcSigType(byte sigId)
{
    enum wc_SignatureType ret = WC_SIGNATURE_TYPE_NONE;

    switch (sigId) {
        case ID_SSH_RSA:
        case ID_RSA_SHA2_256:
        case ID_RSA_SHA2_512:
            ret = WC_SIGNATURE_TYPE_RSA_W_ENC;
            break;
        default:
            break;
    }

    return ret;
}

static INLINE word32 GetKeyStructSz(byte keyId)
{
    word32 ret = 0;

    switch (keyId) {
        case ID_SSH_RSA:
            ret = sizeof(RsaKey);
            break;
        default:
            break;
    }

    return ret;
}

static int CheckCASignature(const byte* tbs, word32 tbsSz, const byte* sig,
                            word32 sigSz, byte sigId, byte keyId, void* key)
{
    int ret = WS_SUCCESS;
    enum wc_HashType wcHashType;
    enum wc_SignatureType wcSigType;
    word32 keySz;

    if (sig == NULL || sigSz == 0 || key == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = CheckSigAndKeyTypes(sigId, keyId);
    }
    if (ret == WS_SUCCESS) {
        wcHashType = SigIdToWcHashType(sigId);
        if (wcHashType == WC_HASH_TYPE_NONE) {
            ret = WS_INVALID_ALGO_ID;
        }
    }
    if (ret == WS_SUCCESS) {
        wcSigType = SigIdToWcSigType(sigId);
        if (wcSigType == WC_SIGNATURE_TYPE_NONE) {
            ret = WS_INVALID_ALGO_ID;
        }
    }
    if (ret == WS_SUCCESS) {
        keySz = GetKeyStructSz(keyId);
        if (keySz == 0) {
            ret = WS_FATAL_ERROR;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = wc_SignatureVerify(wcHashType, wcSigType, tbs, tbsSz, sig, sigSz,
                                 key, keySz);
    }

    return ret;
}

WOLFSSH_OSSH_CERT* OsshCertNew(void* heap)
{
    WOLFSSH_OSSH_CERT* ret = NULL;

    ret = (WOLFSSH_OSSH_CERT*)WMALLOC(sizeof(WOLFSSH_OSSH_CERT), heap,
                                      DYNTYPE_OSSH_CERT);
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_OSSH_CERT));

        ret->heap = heap;
    }

    return ret;
}

WOLFSSH_OSSH_CA_KEY* OsshCaKeyNew(void* heap)
{
    WOLFSSH_OSSH_CA_KEY* ret = NULL;

    ret = (WOLFSSH_OSSH_CA_KEY*)WMALLOC(sizeof(WOLFSSH_OSSH_CA_KEY), heap,
                                        DYNTYPE_OSSH_CA_KEY);
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_OSSH_CA_KEY));

        ret->heap = heap;
    }

    return ret;
}

int OsshCaKeyInit(WOLFSSH_OSSH_CA_KEY* key, const byte* rawKey, word32 rawKeySz)
{
    int ret = WS_SUCCESS;

    if (key == NULL || rawKey == NULL || rawKeySz == 0) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        ret = wc_Hash(WC_HASH_TYPE_SHA256, rawKey, rawKeySz, key->fingerprint,
                      WC_SHA256_DIGEST_SIZE);
    }

    return ret;
}

void OsshCertFree(WOLFSSH_OSSH_CERT* cert)
{
    if (cert != NULL) {
        if (cert->principals != NULL) {
            ListFree(cert->principals);
        }
        if (cert->pubKey != NULL) {
            switch (cert->type) {
                case ID_OSSH_CERT_RSA:
                    wc_FreeRsaKey((RsaKey*)cert->pubKey);
                    break;
                default:
                    break;
            }
            WFREE(cert->pubKey, cert->heap, DYNTYPE_PUBKEY);
        }

        WFREE(cert, cert->heap, DYNTYPE_OSSH_CERT);
    }
}

void OsshCaKeyFree(WOLFSSH_OSSH_CA_KEY* key)
{
    if (key != NULL) {
        WFREE(key, key->heap, DYNTYPE_OSSH_CA_KEY);
    }
}

/*
 * Parse the OpenSSH-style certificate held in buffer in of size inSz. Populate
 * the passed in WOLFSSH_OSSH_CERT out with the result, allocating it if not
 * already allocated by the caller. The validity of individual fields is checked
 * where appropriate, according to the rules specified by OpenSSH (see
 * https://man.openbsd.org/ssh-keygen#CERTIFICATES). Returns WS_SUCCESS on
 * success and negative values on failure.
 */
int ParseOsshCert(byte* in, word32 inSz, WOLFSSH_OSSH_CERT** out, byte side,
                  void* heap)
{
    int ret = WS_SUCCESS;
    byte* tmp = NULL;
    word32 tmpSz;
    word32 idx = 0;
    byte keyId;
    w64wrapper tmp64;
    word32 tmp32;
    w64wrapper time64;
    byte caKeyId;
    void* caKey = NULL;
    byte* caSig = NULL;
    word32 caSigSz;
    byte caSigId;
    byte allocCert = 0;
    WOLFSSH_OSSH_CERT* certTmp = NULL;
    WOLFSSH_LIST* principals = NULL;

    if (in == NULL || inSz == 0 || out == NULL) {
        ret = WS_BAD_ARGUMENT;
    }

    if (ret == WS_SUCCESS) {
        /* Get cert type from key buffer. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
        if (ret == WS_SUCCESS) {
            keyId = NameToId((const char*)tmp, tmpSz);
            ret = CheckAllowedCertType(keyId);
            if (ret == WS_SUCCESS) {
                if (*out == NULL) {
                    certTmp = OsshCertNew(heap);
                    if (certTmp == NULL) {
                        ret = WS_MEMORY_E;
                    }
                    else {
                        allocCert = 1;
                        certTmp->type = keyId;
                    }
                }
                else {
                    certTmp = *out;
                }
            }
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get nonce. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
        if (ret == WS_SUCCESS && tmpSz == 0) {
            WLOG(WS_LOG_ERROR, "OpenSSH cert's nonce length must be > 0.");
            ret = WS_OSSH_CERT_PARSE_E;
        }
    }
    if (ret == WS_SUCCESS) {
        switch (keyId) {
            case ID_OSSH_CERT_RSA:
                ret = GetRsaKey(in, inSz, &idx, (RsaKey**)&certTmp->pubKey,
                                heap);
                break;
            default:
                ret = WS_INVALID_STATE_E;
                break;
        }
    }
    if (ret == WS_SUCCESS) {
        /*
         * Get serial number. Note that OpenSSH-style certs are allowed to have
         * a serial number of 0, whereas X.509 certs aren't.
         */
        ret = GetUint64(&tmp64, in, inSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        /* Get cert type (host or user). */
        ret = GetUint32(&tmp32, in, inSz, &idx);
        if (ret == WS_SUCCESS) {
            /* Check type is valid. */
            if (tmp32 != OSSH_CERT_TYPE_USER && tmp32 != OSSH_CERT_TYPE_HOST) {
                ret = WS_OSSH_CERT_PARSE_E;
            }
            /*
             * Check that the cert type is coherent with the side of the
             * connection.
             */
            else if ((tmp32 == OSSH_CERT_TYPE_USER &&
                      side != WOLFSSH_ENDPOINT_CLIENT) ||
                     (tmp32 == OSSH_CERT_TYPE_HOST &&
                      side != WOLFSSH_ENDPOINT_SERVER)) {
                ret = WS_OSSH_CERT_PARSE_E;
            }
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get key ID. */
        /* TODO: Any checking needed? */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        ret = GetValidPrincipals(in, inSz, &idx, &principals, heap);
        if (ret == WS_SUCCESS) {
            certTmp->principals = principals;
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get current time, to check certificate expiry. */
        ret = GetCurrentTime(&time64);
    }
    if (ret == WS_SUCCESS) {
        /* Get "valid after" time. */
        ret = GetUint64(&tmp64, in, inSz, &idx);
        /* Current time must be after "valid after" time. */
        if (ret == WS_SUCCESS && w64LT(time64, tmp64)) {
            ret = WS_OSSH_CERT_EXPIRED_E;
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get "valid before" time. */
        ret = GetUint64(&tmp64, in, inSz, &idx);
        /* Current time must be before "valid before" time. */
        if (ret == WS_SUCCESS && w64GTE(time64, tmp64)) {
            ret = WS_OSSH_CERT_EXPIRED_E;
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get critical options. Not supported, currently. Ensure length 0. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
        if (ret == WS_SUCCESS && tmpSz != 0) {
            ret = WS_OSSH_CERT_PARSE_E;
        }
    }
    if (ret == WS_SUCCESS) {
        /* Get extensions. Ignored, currently. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
    }
    if (ret == WS_SUCCESS) {
        /* Reserved field. Should be a 0-length string. */
        ret = GetStringRef(&tmpSz, &tmp, in, inSz, &idx);
        if (ret == WS_SUCCESS && tmpSz != 0) {
            ret = WS_OSSH_CERT_PARSE_E;
        }
    }
    if (ret == WS_SUCCESS) {
        ret = GetUint32(&tmp32, in, inSz, &idx);
        if (ret == WS_SUCCESS) {
            ret = GetCAKey(in + idx, tmp32, &caKeyId,
                           certTmp->caKeyFingerprint, &caKey, heap);
            if (ret > 0) {
                idx += ret;
                ret = WS_SUCCESS;
            }
            else {
                ret = WS_OSSH_CERT_PARSE_E;
            }
        }
    }
    if (ret == WS_SUCCESS) {
        ret = GetUint32(&tmp32, in, inSz, &idx);
        if (ret == WS_SUCCESS) {
            ret = GetCASignature(in + idx, tmp32, &caSigId, &caSig, &caSigSz);
            if (ret > 0) {
                if ((idx + ret) != inSz) {
                    ret = WS_OSSH_CERT_PARSE_E;
                }
                else {
                    ret = WS_SUCCESS;
                }
            }
        }
    }
    if (ret == WS_SUCCESS) {
        ret = CheckCASignature(in, idx - UINT32_SZ, caSig, caSigSz, caSigId,
                               caKeyId, caKey);
    }

    if (caKey != NULL) {
        WFREE(caKey, heap, DYNTYPE_PUBKEY);
    }

    if (ret == WS_SUCCESS) {
        *out = certTmp;
    }
    else {
        if (allocCert && certTmp != NULL) {
            OsshCertFree(certTmp);
        }
    }

    return ret;
}

#endif /* WOLFSSH_OSSH_CERTS */
