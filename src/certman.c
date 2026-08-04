/* certman.c
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
 * The certman module contains utility functions wrapping the wolfSSL
 * certificate manager functions to validate user certificates.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif


#include <wolfssl/ssl.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/error-ssl.h>

#include <wolfssh/internal.h>
#include <wolfssh/certman.h>

#ifdef WOLFSSH_WINDOWS_CERT_STORE
    #include <stdlib.h>
    #include <errno.h>
    #include <windows.h>
    #include <wincrypt.h>
    #ifndef CERT_SYSTEM_STORE_LOCATION_MASK
        #define CERT_SYSTEM_STORE_LOCATION_MASK 0x00FF0000
    #endif
    #ifndef CERT_SYSTEM_STORE_LOCATION_SHIFT
        #define CERT_SYSTEM_STORE_LOCATION_SHIFT 16
    #endif
    #ifndef CERT_SYSTEM_STORE_CURRENT_USER
        #define CERT_SYSTEM_STORE_CURRENT_USER 0x00010000
    #endif
    #ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE
        #define CERT_SYSTEM_STORE_LOCAL_MACHINE 0x00020000
    #endif
    #ifndef CERT_SYSTEM_STORE_USERS
        #define CERT_SYSTEM_STORE_USERS 0x00060000
    #endif
    #ifndef CERT_SYSTEM_STORE_CURRENT_SERVICE
        #define CERT_SYSTEM_STORE_CURRENT_SERVICE 0x00040000
    #endif
    #ifndef CERT_SYSTEM_STORE_SERVICES
        #define CERT_SYSTEM_STORE_SERVICES 0x00050000
    #endif
    #ifndef CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY
        #define CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY 0x00070000
    #endif
    #ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY
        #define CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY 0x00080000
    #endif
    #ifndef CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
        #define CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE 0x00090000
    #endif
#endif

#ifdef WOLFSSH_CERTS

#ifdef NO_INLINE
    #include <wolfssh/misc.h>
#else
    #define WOLFSSH_MISC_INCLUDED
    #include "src/misc.c"
#endif


#define WLOG_ENTER() do { \
    WLOG(WS_LOG_CERTMAN, "Entering %s()", __func__); \
} while (0)

#define WLOG_LEAVE(x) do { \
    WLOG(WS_LOG_CERTMAN, "Leaving %s(), ret = %d", __func__, (x)); \
} while (0)

#define WLOG_LEAVE_VOID() do { \
    WLOG(WS_LOG_CERTMAN, "Leaving %s()", __func__); \
} while (0)

#define WLOG_LEAVE_PTR(x) do { \
    WLOG(WS_LOG_CERTMAN, "Leaving %s(), ret = %p", __func__, (x)); \
} while (0)

#ifdef DEBUG_WOLFSSH
    #define DUMP(x,y) do { DumpOctetString((x),(y)); } while (0)
#else
    #define DUMP(x,y)
#endif


struct WOLFSSH_CERTMAN {
    void* heap;
    WOLFSSL_CERT_MANAGER* cm;
};


/* used to import an external cert manager, frees and replaces existing manager
 * returns WS_SUCCESS on success
 */
int wolfSSH_SetCertManager(WOLFSSH_CTX* ctx, WOLFSSL_CERT_MANAGER* cm)
{
#if LIBWOLFSSL_VERSION_HEX < WOLFSSL_V4_6_0
    WOLFSSH_UNUSED(ctx);
    WOLFSSH_UNUSED(cm);

    WLOG(WS_LOG_CERTMAN, "Importing a cert manager needs wolfSSL 4.6.0");
    return WS_NOT_COMPILED;
#else
    if (ctx == NULL || cm == NULL || ctx->certMan == NULL) {
        return WS_BAD_ARGUMENT;
    }

    /* importing the manager already in use is a no-op beyond the policy;
     * the OCSP policy below is still (re)applied so the documented side
     * effect holds even when the same manager is imported twice */
    if (ctx->certMan->cm != cm) {
        /* Take the reference before mutating the caller's manager so a
         * WS_FATAL_ERROR return always means nothing changed: on an OCSP
         * policy failure below the reference is released again and the
         * caller's manager keeps its previous policy. */
        if (wolfSSL_CertManager_up_ref(cm) != WOLFSSL_SUCCESS) {
            WLOG(WS_LOG_CERTMAN, "Failed to increment cert manager reference");
            return WS_FATAL_ERROR;
        }
    }

#ifdef HAVE_OCSP
    /* an imported manager gets the same policy _CertMan_init() applies, and
     * is rejected if it can't, rather than silently skipping revocation */
    if (wolfSSL_CertManagerEnableOCSP(cm, WOLFSSL_OCSP_CHECKALL)
            != WOLFSSL_SUCCESS) {
        WLOG(WS_LOG_CERTMAN, "Couldn't enable OCSP on imported cert manager");
        if (ctx->certMan->cm != cm) {
            /* drop the reference taken above */
            wolfSSL_CertManagerFree(cm);
        }
        return WS_FATAL_ERROR;
    }
#endif

    if (ctx->certMan->cm != cm) {
        /* free up existing cm if present */
        if (ctx->certMan->cm != NULL) {
            wolfSSL_CertManagerFree(ctx->certMan->cm);
        }
        ctx->certMan->cm = cm;
    }

    return WS_SUCCESS;
#endif
}


static WOLFSSH_CERTMAN* _CertMan_init(WOLFSSH_CERTMAN* cm, void* heap)
{
    WOLFSSH_CERTMAN* ret = NULL;
    WLOG_ENTER();

    ret = cm;
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_CERTMAN));
        ret->heap = heap;
        ret->cm = wolfSSL_CertManagerNew_ex(heap);
        if (ret->cm == NULL) {
            ret = NULL;
        }
    #ifdef HAVE_OCSP
        else {
            int err;

            err = wolfSSL_CertManagerEnableOCSP(ret->cm,
                    WOLFSSL_OCSP_CHECKALL);
            if (err == WOLFSSL_SUCCESS) {
                WLOG(WS_LOG_CERTMAN, "Enabled OCSP");
            }
            else {
                WLOG(WS_LOG_CERTMAN, "Couldn't enable OCSP");
                wolfSSL_CertManagerFree(ret->cm);
                ret = NULL;
            }
        }
    #endif
    }

    WLOG_LEAVE_PTR(ret);
    return ret;
}


static void _CertMan_ResourceFree(WOLFSSH_CERTMAN* cm, void* heap)
{
    WOLFSSH_UNUSED(heap);
    WLOG_ENTER();

    if (cm != NULL) {
        if (cm->cm != NULL) {
            wolfSSL_CertManagerFree(cm->cm);
        }
        WMEMSET(cm, 0, sizeof *cm);
    }

    WLOG_LEAVE_VOID();
}


WOLFSSH_CERTMAN* wolfSSH_CERTMAN_new(void* heap)
{
    WOLFSSH_CERTMAN* cm = NULL;

    WLOG_ENTER();

    cm = (WOLFSSH_CERTMAN*)WMALLOC(sizeof *cm, heap, DYNTYPE_CERTMAN);
    if (cm != NULL) {
        if (_CertMan_init(cm, heap) == NULL) {
            WFREE(cm, heap, DYNTYPE_CERTMAN);
            cm = NULL;
        }
    }

    WLOG_LEAVE_PTR(cm);
    return cm;
}


void wolfSSH_CERTMAN_free(WOLFSSH_CERTMAN* cm)
{
    WLOG_ENTER();

    if (cm) {
        void* heap = cm->heap;

        _CertMan_ResourceFree(cm, heap);
        WFREE(cm, heap, DYNTYPE_CERTMAN);
    }

    WLOG_LEAVE_VOID();
}


/* return WS_SUCCESS on success */
int wolfSSH_CERTMAN_LoadRootCA_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* rootCa, word32 rootCaSz)
{
    int ret = WS_BAD_ARGUMENT;

    WLOG_ENTER();

    if (cm != NULL && rootCa != NULL && rootCaSz > 0) {
        ret = wolfSSL_CertManagerLoadCABuffer(cm->cm, rootCa, rootCaSz,
                WOLFSSL_FILETYPE_ASN1);
        if (ret == WOLFSSL_SUCCESS) {
            ret = WS_SUCCESS;
        }
    }

    WLOG_LEAVE(ret);
    return ret;
}


#ifndef WOLFSSH_NO_FPKI
static int CheckProfile(DecodedCert* cert, int profile);
enum {
    PROFILE_FPKI_WORKSHEET_6 = 6,
    PROFILE_FPKI_WORKSHEET_10 = 10,
    PROFILE_FPKI_WORKSHEET_16 = 16
};
#endif /* WOLFSSH_NO_FPKI */

/* if max chain depth not set in wolfSSL then default to 9 */
#ifndef MAX_CHAIN_DEPTH
    #define MAX_CHAIN_DEPTH 9
#endif

/* Returns 1 if der is a CA: isCA set and, unless self-signed, keyCertSign
 * set. Already signature-verified by the caller, so parse NO_VERIFY. */
static int CertManIntermediateIsCA(WOLFSSH_CERTMAN* cm,
        const unsigned char* der, word32 derSz)
{
    DecodedCert* decoded = NULL;
#ifndef WOLFSSH_SMALL_STACK
    DecodedCert decoded_s;
#endif
    int isCA = 0;

#ifndef WOLFSSH_SMALL_STACK
    decoded = &decoded_s;
#else
    decoded = (DecodedCert*)WMALLOC(sizeof(DecodedCert), cm->heap,
        DYNTYPE_CERT);
#endif

    if (decoded != NULL) {
        wc_InitDecodedCert(decoded, der, derSz, cm->heap);
        if (wc_ParseCert(decoded, WOLFSSL_FILETYPE_ASN1, NO_VERIFY, NULL) == 0) {
            isCA = decoded->isCA;
        #ifndef ALLOW_INVALID_CERTSIGN
            if (isCA && !decoded->selfSigned && decoded->extKeyUsageSet &&
                    (decoded->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0) {
                /* If a KeyUsage extension is present, an intermediate CA must
                 * assert the keyCertSign bit. */
                isCA = 0;
            }
        #endif
        }
        wc_FreeDecodedCert(decoded);
    #ifdef WOLFSSH_SMALL_STACK
        WFREE(decoded, cm->heap, DYNTYPE_CERT);
    #endif
    }
    else {
        /* allocation failed; fail closed (not a CA) but log the real cause so
         * it is not mistaken for a genuine non-CA intermediate */
        WLOG(WS_LOG_CERTMAN, "could not allocate cert to check intermediate CA");
    }

    return isCA;
}

/* if handling a chain it is expected to be the leaf cert first followed by
 * intermediates and CA last (CA may be omitted) */
int wolfSSH_CERTMAN_VerifyCerts_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* certs, word32 certSz, word32 certsCount)
{
    int ret = WS_SUCCESS;

    word32 idx = 0;
    int certIdx = 0;
    unsigned char **certLoc; /* locations of certificate start */
    word32        *certLen;  /* size of certificate, in sync with certLoc */

    WLOG_ENTER();

    if (cm == NULL || certs == NULL || certsCount == 0) {
        return WS_BAD_ARGUMENT;
    }

    if (certsCount > MAX_CHAIN_DEPTH) {
        WLOG(WS_LOG_CERTMAN, "cert count is larger than MAX_CHAIN_DEPTH");
        return WS_BAD_ARGUMENT;
    }

    certLoc = (unsigned char**)WMALLOC(certsCount * sizeof(unsigned char*),
        cm->heap, DYNTYPE_CERT);
    certLen = (word32*)WMALLOC(certsCount * sizeof(word32), cm->heap,
        DYNTYPE_CERT);
    if (certLoc == NULL || certLen == NULL) {
        ret = WS_MEMORY_E;
    }

    if (ret == WS_SUCCESS) {
        for (certIdx = 0; certIdx < (int)certsCount; certIdx++) {
            word32 sz = 0;

            if ((idx + UINT32_SZ) > certSz) {
                WLOG(WS_LOG_CERTMAN, "cert count is past end of buffer");
                ret = ASN_PARSE_E;
                break;
            }

            certLoc[certIdx] = (byte*)certs + idx + UINT32_SZ;

            /* get the size of the certificate */
            ret = GetSize(&sz, certs, certSz, &idx);

            /* advance current pointer and update current total size */
            if (ret == WS_SUCCESS) {
                certLen[certIdx] = sz;
                if (idx + sz > certSz) {
                    WLOG(WS_LOG_CERTMAN, "cert found is too large!");
                    ret = ASN_PARSE_E;
                    break;
                }
                idx += sz;
            }
            else {
                break;
            }
        }
    }

    if (ret == WS_SUCCESS) {
        for (certIdx = certsCount - 1; certIdx >= 0; certIdx--) {
            WLOG(WS_LOG_CERTMAN, "verifying cert at index %d", certIdx);
            ret = wolfSSL_CertManagerVerifyBuffer(cm->cm, certLoc[certIdx],
                certLen[certIdx], WOLFSSL_FILETYPE_ASN1);
            if (ret == WOLFSSL_SUCCESS) {
                ret = WS_SUCCESS;
            }
            else if (ret == ASN_NO_SIGNER_E) {
                WLOG(WS_LOG_CERTMAN, "cert verify: no signer");
                ret = WS_CERT_NO_SIGNER_E;
            }
            else if (ret == ASN_AFTER_DATE_E) {
                WLOG(WS_LOG_CERTMAN, "cert verify: expired");
                ret = WS_CERT_EXPIRED_E;
            }
            else if (ret == ASN_SIG_CONFIRM_E) {
                WLOG(WS_LOG_CERTMAN, "cert verify: bad sig");
                ret = WS_CERT_SIG_CONFIRM_E;
            }
            else {
                WLOG(WS_LOG_CERTMAN, "cert verify: other error (%d)", ret);
                ret = WS_CERT_OTHER_E;
            }

        #ifdef HAVE_OCSP
            if (ret == WS_SUCCESS) {
                ret = wolfSSL_CertManagerCheckOCSP(cm->cm, (byte*)certLoc[certIdx],
                    certLen[certIdx]);

                if (ret == WOLFSSL_SUCCESS) {
                    ret = WS_SUCCESS;
                }
                else if (ret == OCSP_CERT_REVOKED) {
                    WLOG(WS_LOG_CERTMAN, "ocsp lookup: ocsp revoked");
                    ret = WS_CERT_REVOKED_E;
                }
                else if (ret == OCSP_NEED_URL) {
                    /* The cert carries no OCSP responder URL and certman has
                     * no default responder configured, so OCSP cannot be
                     * performed. Treat as not revoked rather than failing the
                     * whole verification. */
                    WLOG(WS_LOG_CERTMAN, "ocsp lookup: no responder url, skipping");
                    ret = WS_SUCCESS;
                }
                else {
                    WLOG(WS_LOG_CERTMAN, "ocsp lookup: other error (%d)", ret);
                    ret = WS_CERT_OTHER_E;
                }
            }
        #endif /* HAVE_OCSP */

            /* promote the intermediate so the next cert has a signer, but
             * only if it's actually a CA */
            if (ret == WS_SUCCESS && certIdx > 0) {
                if (CertManIntermediateIsCA(cm, certLoc[certIdx],
                        certLen[certIdx])) {
                    WLOG(WS_LOG_CERTMAN, "adding intermediate cert as trusted");
                    ret = wolfSSH_CERTMAN_LoadRootCA_buffer(cm,
                        certLoc[certIdx], certLen[certIdx]);
                }
                else {
                    WLOG(WS_LOG_CERTMAN,
                        "peer intermediate is not a CA; not promoting");
                    ret = WS_CERT_NO_SIGNER_E;
                }
            }

            if (ret != WS_SUCCESS) {
                break;
            }
        }
    }

    /* Leaf (index 0) must be an end-entity cert; reject a CA leaf even without
     * FPKI, and match a profile when FPKI is on. cm->cm resolves the signer
     * (ca) that CheckProfile needs for the issuer-DN match. */
    if (ret == WS_SUCCESS) {
        DecodedCert* decoded = NULL;
#ifndef WOLFSSH_SMALL_STACK
        DecodedCert decoded_s;

        decoded = &decoded_s;
#else
        decoded = (DecodedCert*)WMALLOC(sizeof(DecodedCert), cm->heap,
            DYNTYPE_CERT);
        if (decoded == NULL) {
            ret = WS_MEMORY_E;
        }
#endif

        /* NULL only when the small-stack allocation above failed */
        if (decoded != NULL) {
            wc_InitDecodedCert(decoded, certLoc[0], certLen[0], cm->heap);
            if (wc_ParseCert(decoded, WOLFSSL_FILETYPE_ASN1, NO_VERIFY, cm->cm)
                    != 0) {
                WLOG(WS_LOG_CERTMAN, "unable to parse leaf certificate");
                ret = WS_CERT_OTHER_E;
            }
            else if (decoded->isCA) {
                WLOG(WS_LOG_CERTMAN, "leaf certificate is a CA; rejecting");
                ret = WS_CERT_PROFILE_E;
            }
#ifndef WOLFSSH_NO_FPKI
            else if (!(CheckProfile(decoded, PROFILE_FPKI_WORKSHEET_6) ||
                       CheckProfile(decoded, PROFILE_FPKI_WORKSHEET_10) ||
                       CheckProfile(decoded, PROFILE_FPKI_WORKSHEET_16))) {
                WLOG(WS_LOG_CERTMAN, "certificate didn't match profile");
                ret = WS_CERT_PROFILE_E;
            }
#endif /* WOLFSSH_NO_FPKI */
            wc_FreeDecodedCert(decoded);
        }

#ifdef WOLFSSH_SMALL_STACK
        if (decoded != NULL) {
            WFREE(decoded, cm->heap, DYNTYPE_CERT);
        }
#endif
    }

    if (certLoc != NULL)
        WFREE(certLoc, cm->heap, DYNTYPE_CERT);
    if (certLen != NULL)
        WFREE(certLen, cm->heap, DYNTYPE_CERT);
    WLOG_LEAVE(ret);
    return ret;
}


#ifndef WOLFSSH_NO_FPKI
static int CheckProfile(DecodedCert* cert, int profile)
{
    int valid = (cert != NULL);
    const char* certPolicies[2] = {NULL, NULL};
    byte extKeyUsage = 0, extKeyUsageSsh = 0;

    if (profile == PROFILE_FPKI_WORKSHEET_6) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.13";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
        extKeyUsageSsh = EXTKEYUSE_SSH_MSCL;
    }
    else if (profile == PROFILE_FPKI_WORKSHEET_10) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.40";
        certPolicies[1] = "2.16.840.1.101.3.2.1.3.41";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
    }
    else if (profile == PROFILE_FPKI_WORKSHEET_16) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.45";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
        extKeyUsageSsh = EXTKEYUSE_SSH_MSCL;
    }
    else {
        valid = 0;
    }

    if (valid) {
        valid = cert->extKeyUsageSet &&
            cert->extKeyUsage == KEYUSE_DIGITAL_SIG &&
            /*cert->extBasicConstCrit;*/ 1;
    }

    if (valid) {
        valid = WSTRCMP(cert->countryOfCitizenship, "US") == 0;
        if (valid != 1)
            WLOG(WS_LOG_CERTMAN, "cert country of citizenship invalid");
    }

    /* leaf isCA (basic constraint) is enforced unconditionally by the caller
     * before CheckProfile runs, so it is not re-checked here */

    if (valid) {
        valid =
            WMEMCMP(cert->extAuthKeyId, cert->extSubjKeyId, KEYID_SIZE) != 0;
        if (valid != 1)
            WLOG(WS_LOG_CERTMAN, "cert auth key and subject key mismatch");
    }

    if (valid) {
        valid =
            ((certPolicies[1] != NULL) &&
             (WSTRCMP(certPolicies[1], cert->extCertPolicies[0]) == 0 ||
              WSTRCMP(certPolicies[1], cert->extCertPolicies[1]) == 0)) ||
            ((certPolicies[0] != NULL) &&
             (WSTRCMP(certPolicies[0], cert->extCertPolicies[0]) == 0 ||
              WSTRCMP(certPolicies[0], cert->extCertPolicies[1]) == 0));
        if (valid != 1)
            WLOG(WS_LOG_CERTMAN, "cert policy invalid");
    }

    /* validity period must be utc up to and including 2049, general time
     * after 2049 */
    if (valid) {
        const byte* date;
        int         dateSz;
        byte        dateFormat;
        struct tm t = { 0 };

        dateFormat = cert->afterDate[0]; /* i.e ASN_UTC_TIME */
        dateSz     = cert->afterDate[1];
        date       = &cert->afterDate[2];

        if (wc_GetDateAsCalendarTime(date, dateSz, dateFormat, &t) != 0) {
            WLOG(WS_LOG_CERTMAN, "unable to get date");
            valid = 0;
        }

        if (valid && t.tm_year <= 149 && dateFormat != ASN_UTC_TIME) {
            WLOG(WS_LOG_CERTMAN, "date format was not utc for year %d",
            t.tm_year);
            valid = 0;
        }

        if (valid && t.tm_year > 149 && dateFormat != ASN_GENERALIZED_TIME) {
            WLOG(WS_LOG_CERTMAN, "date format was not general for year %d",
            t.tm_year);
            valid = 0;
        }
    }

    /* encoding of issuer DN must be exact match to CA subject DN */
    if (valid) {
        int sz = min(SIGNER_DIGEST_SIZE, KEYID_SIZE);
        if (XMEMCMP(cert->ca->subjectNameHash, cert->issuerHash, sz) != 0) {
            WLOG(WS_LOG_CERTMAN, "CA subject name hash did not match issuer");
            valid = 0;
        }
    }

    /* path length must be absent (i.e. 0) */
    if (valid) {
        if (cert->pathLength != 0) {
            WLOG(WS_LOG_CERTMAN, "non-conforming pathlength of %d was larger "
                "than 0", cert->pathLength);
            valid = 0;
        }
    }

    /* check on FASC-N and UUID */
    if (valid) {
        DNS_entry* current;
        byte hasFascN = 0;
        byte hasUUID  = 0;
        byte uuid[DEFAULT_UUID_SZ];
        word32 uuidSz = DEFAULT_UUID_SZ;

        /* cycle through alt names to check for needed types */
        current = cert->altNames;
        while (current != NULL) {
        #ifdef WOLFSSL_FPKI
            if (current->oidSum == FASCN_OID) {
                hasFascN = 1;
            }
        #endif /* WOLFSSL_FPKI */

            current = current->next;
        }

    #ifdef WOLFSSL_FPKI
        if (wc_GetUUIDFromCert(cert, uuid, &uuidSz) == 0) {
            hasUUID = 1;
        }
    #endif /* WOLFSSL_FPKI */

        /* all must have UUID and worksheet 6 must have FASC-N in addition to
         * UUID */
        if (profile == PROFILE_FPKI_WORKSHEET_6 && hasFascN == 0) {
            WLOG(WS_LOG_CERTMAN, "cert did not include a FASC-N");
            valid = 0;
        }

        if (valid && hasUUID == 0) {
            WLOG(WS_LOG_CERTMAN, "cert did not include a UUID");
            valid = 0;
        }
    }

    if (valid) {
        valid =
            /* Must include all in extKeyUsage */
            ((extKeyUsage == 0) ||
                ((cert->extExtKeyUsage & extKeyUsage) == extKeyUsage)) &&
            /* Must include all in extKeyUsageSsh */
            ((extKeyUsageSsh == 0) ||
                ((cert->extExtKeyUsageSsh & extKeyUsageSsh)
                    == extKeyUsageSsh));
        if (valid != 1) {
            WLOG(WS_LOG_CERTMAN, "cert did not include all ext. key usage");
        }
    }

    if (valid) {
        valid =
            cert->signatureOID == CTC_SHA256wRSA ||
            cert->signatureOID == CTC_SHA384wRSA ||
            cert->signatureOID == CTC_SHA512wRSA ||
            cert->signatureOID == CTC_SHA256wECDSA ||
            cert->signatureOID == CTC_SHA384wECDSA ||
            cert->signatureOID == CTC_SHA512wECDSA;
        if (valid != 1)
            WLOG(WS_LOG_CERTMAN, "cert signature algorithm not FPKI approved");
    }

#ifdef DEBUG_WOLFSSH
    switch (profile) {
        case PROFILE_FPKI_WORKSHEET_6:
            if (valid)
                WLOG(WS_LOG_INFO, "Cert matched FPKI profile 6");
            else
                WLOG(WS_LOG_INFO, "Cert did not match FPKI profile 6");
            break;

        case PROFILE_FPKI_WORKSHEET_10:
            if (valid)
                WLOG(WS_LOG_INFO, "Cert matched FPKI profile 10");
            else
                WLOG(WS_LOG_INFO, "Cert did not match FPKI profile 10");
            break;

        case PROFILE_FPKI_WORKSHEET_16:
            if (valid)
                WLOG(WS_LOG_INFO, "Cert matched FPKI profile 16");
            else
                WLOG(WS_LOG_INFO, "Cert did not match FPKI profile 16");
            break;
    }
#endif /* DEBUG_WOLFSSH */

    return valid;
}
#endif /* WOLFSSH_NO_FPKI */


#ifdef WOLFSSH_WINDOWS_CERT_STORE
/* Returns 1 when dwFlags is exactly one assigned CERT_SYSTEM_STORE_*
 * location with no control flags set, 0 otherwise. Location ids 1, 2 and
 * 4..9 are assigned in wincrypt.h; 3 and 10..255 are not, and CertOpenStore
 * fails opaquely on them. */
int wolfSSH_CertStoreLocationValid(word32 dwFlags)
{
    word32 id;

    if ((dwFlags & ~(word32)CERT_SYSTEM_STORE_LOCATION_MASK) != 0) {
        return 0;
    }
    id = dwFlags >> CERT_SYSTEM_STORE_LOCATION_SHIFT;
    return id == 1 || id == 2 || (id >= 4 && id <= 9);
}


/* The one name-to-value table for CERT_SYSTEM_STORE_* locations, shared by
 * wolfSSH_ParseCertStoreSpec() and wolfsshd's HostKeyStoreFlags and
 * wolfSSH_WinUserDwFlags parsing so the accepted spellings cannot drift. */
static const struct {
    const char* shortName;
    const char* longName;
    word32 value;
} certStoreLocations[] = {
    { "CURRENT_USER", "CERT_SYSTEM_STORE_CURRENT_USER",
      (word32)CERT_SYSTEM_STORE_CURRENT_USER },
    { "LOCAL_MACHINE", "CERT_SYSTEM_STORE_LOCAL_MACHINE",
      (word32)CERT_SYSTEM_STORE_LOCAL_MACHINE },
    { "USERS", "CERT_SYSTEM_STORE_USERS",
      (word32)CERT_SYSTEM_STORE_USERS },
    { "CURRENT_SERVICE", "CERT_SYSTEM_STORE_CURRENT_SERVICE",
      (word32)CERT_SYSTEM_STORE_CURRENT_SERVICE },
    { "SERVICES", "CERT_SYSTEM_STORE_SERVICES",
      (word32)CERT_SYSTEM_STORE_SERVICES },
    { "CURRENT_USER_GROUP_POLICY",
      "CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY",
      (word32)CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY },
    { "LOCAL_MACHINE_GROUP_POLICY",
      "CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY",
      (word32)CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY },
    { "LOCAL_MACHINE_ENTERPRISE",
      "CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE",
      (word32)CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE },
};


/* Parse a Windows system-store location, given as a CERT_SYSTEM_STORE_* name
 * (long or short form) or as a decimal or 0x-prefixed hex number, so both
 * 65536 and 0x00010000 work; a leading zero is not reinterpreted as octal,
 * so "0262144" parses as decimal 262144. The number must be consumed whole
 * and start with a digit: strtoul()'s leading whitespace and sign handling
 * is rejected so a config typo such as "-0xFFFF0000" cannot wrap to a valid
 * location. Only location bits are accepted; anything else is either not a
 * location or a control flag (e.g. CERT_STORE_DELETE_FLAG) that would make
 * CertOpenStore destructive. Returns WS_SUCCESS on success. */
int wolfSSH_CertStoreLocationFromName(const char* in, word32* out)
{
    int ret = WS_BAD_ARGUMENT;
    word32 i;
    unsigned long val;
    char* end;

    if (in == NULL || out == NULL || *in == '\0') {
        return WS_BAD_ARGUMENT;
    }

    for (i = 0; i < (word32)(sizeof(certStoreLocations) /
            sizeof(*certStoreLocations)); i++) {
        if (WSTRCMP(in, certStoreLocations[i].shortName) == 0 ||
                WSTRCMP(in, certStoreLocations[i].longName) == 0) {
            *out = certStoreLocations[i].value;
            ret = WS_SUCCESS;
            break;
        }
    }

    if (ret != WS_SUCCESS && *in >= '0' && *in <= '9') {
        int base = 10;

        if (in[0] == '0' && (in[1] == 'x' || in[1] == 'X')) {
            base = 16;
        }

        end = NULL;
        errno = 0;
        val = strtoul(in, &end, base);
        if (end != in && *end == '\0' && errno != ERANGE &&
                wolfSSH_CertStoreLocationValid((word32)val) &&
                val == (unsigned long)(word32)val) {
            *out = (word32)val;
            ret = WS_SUCCESS;
        }
    }

    return ret;
}


/* Parse a cert store spec string "store:subject[:flags]" into wide-string
 * components.  The spec is split at the first ':' for the store name and at
 * the next one for the flags, so neither the store name nor the subject may
 * contain a ':'; a spec with a third ':' is rejected.  "My:CN=host:65536" is
 * therefore store "My", subject "CN=host", flags 65536, never a two-field
 * spec with a ':' in the subject.  Allocates wStoreName and wSubjectName;
 * caller releases them with wolfSSH_FreeCertStoreSpec().  On success dwFlags
 * is set to the parsed flags value, on failure it is left alone.
 * Returns WS_SUCCESS on success. */
int wolfSSH_ParseCertStoreSpec(const char* spec,
        wchar_t** wStoreName, wchar_t** wSubjectName,
        word32* dwFlags, void* heap)
{
    char* specCopy = NULL;
    char* storeName = NULL;
    char* subjectName = NULL;
    char* flagsStr = NULL;
    word32 flags;
    int wStoreNameLen, wSubjectNameLen;
    size_t specLen;

    /* NULL every supplied out-pointer before any failure return, including
     * the argument rejections below, so the documented "out-pointers are
     * NULL on failure" contract holds even when only one argument is bad. */
    if (wStoreName != NULL) {
        *wStoreName = NULL;
    }
    if (wSubjectName != NULL) {
        *wSubjectName = NULL;
    }
    if (wStoreName == NULL || wSubjectName == NULL || dwFlags == NULL) {
        return WS_BAD_ARGUMENT;
    }
    if (spec == NULL) {
        return WS_BAD_ARGUMENT;
    }

    flags = CERT_SYSTEM_STORE_CURRENT_USER;

    specLen = WSTRLEN(spec) + 1;
    specCopy = (char*)WMALLOC(specLen, heap, DYNTYPE_TEMP);
    if (specCopy == NULL)
        return WS_MEMORY_E;
    WSTRNCPY(specCopy, spec, specLen);

    /* Parse "store:subject:flags" */
    storeName = specCopy;
    subjectName = WSTRCHR(storeName, ':');
    if (subjectName != NULL) {
        *subjectName++ = '\0';
        flagsStr = WSTRCHR(subjectName, ':');
        if (flagsStr != NULL) {
            *flagsStr++ = '\0';
            if (*flagsStr == '\0') {
                WLOG(WS_LOG_CERTMAN,
                        "Cert store spec has an empty flags field; expected "
                        "store:subject[:flags]");
                WFREE(specCopy, heap, DYNTYPE_TEMP);
                return WS_BAD_ARGUMENT;
            }
            if (WSTRCHR(flagsStr, ':') != NULL) {
                WLOG(WS_LOG_CERTMAN,
                        "Cert store spec has too many ':'-separated fields; "
                        "expected store:subject[:flags]");
                WFREE(specCopy, heap, DYNTYPE_TEMP);
                return WS_BAD_ARGUMENT;
            }
            /* Accept the same spellings as wolfsshd's HostKeyStoreFlags and
             * wolfSSH_WinUserDwFlags so one name works everywhere; the
             * shared parser also handles the numeric location forms and
             * rejects control flags. */
            if (wolfSSH_CertStoreLocationFromName(flagsStr, &flags)
                    != WS_SUCCESS) {
                WLOG(WS_LOG_CERTMAN, "Malformed cert store flags value "
                        "'%s'; expected store:subject[:flags] with a "
                        "CERT_SYSTEM_STORE_* name or store location number",
                        flagsStr);
                WFREE(specCopy, heap, DYNTYPE_TEMP);
                return WS_BAD_ARGUMENT;
            }
        }
    }

    if (subjectName == NULL || *storeName == '\0' ||
            *subjectName == '\0') {
        WFREE(specCopy, heap, DYNTYPE_TEMP);
        return WS_BAD_ARGUMENT;
    }

    /* Convert to wide strings. MB_ERR_INVALID_CHARS makes a non-UTF-8 byte
     * sequence fail here instead of being silently replaced with U+FFFD and
     * then never matching any certificate CN. */
    wStoreNameLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            storeName, -1, NULL, 0);
    wSubjectNameLen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            subjectName, -1, NULL, 0);

    if (wStoreNameLen == 0 || wSubjectNameLen == 0) {
        WLOG(WS_LOG_CERTMAN,
                "Cert store spec is not valid UTF-8");
        WFREE(specCopy, heap, DYNTYPE_TEMP);
        return WS_FATAL_ERROR;
    }

    *wStoreName = (wchar_t*)WMALLOC(wStoreNameLen * sizeof(wchar_t),
            heap, DYNTYPE_TEMP);
    *wSubjectName = (wchar_t*)WMALLOC(wSubjectNameLen * sizeof(wchar_t),
            heap, DYNTYPE_TEMP);

    if (*wStoreName == NULL || *wSubjectName == NULL) {
        if (*wStoreName != NULL) {
            WFREE(*wStoreName, heap, DYNTYPE_TEMP);
            *wStoreName = NULL;
        }
        if (*wSubjectName != NULL) {
            WFREE(*wSubjectName, heap, DYNTYPE_TEMP);
            *wSubjectName = NULL;
        }
        WFREE(specCopy, heap, DYNTYPE_TEMP);
        return WS_MEMORY_E;
    }

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, storeName, -1,
                *wStoreName, wStoreNameLen) == 0 ||
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, subjectName, -1,
                *wSubjectName, wSubjectNameLen) == 0) {
        WLOG(WS_LOG_CERTMAN, "Cert store spec wide-string conversion failed");
        WFREE(*wStoreName, heap, DYNTYPE_TEMP);
        WFREE(*wSubjectName, heap, DYNTYPE_TEMP);
        *wStoreName = NULL;
        *wSubjectName = NULL;
        WFREE(specCopy, heap, DYNTYPE_TEMP);
        return WS_FATAL_ERROR;
    }

    *dwFlags = flags;

    WFREE(specCopy, heap, DYNTYPE_TEMP);
    return WS_SUCCESS;
}


/* Releases the wide strings allocated by wolfSSH_ParseCertStoreSpec().
 * Either pointer may be NULL. The heap must match the parse call. */
void wolfSSH_FreeCertStoreSpec(wchar_t* wStoreName, wchar_t* wSubjectName,
        void* heap)
{
    if (wStoreName != NULL) {
        WFREE(wStoreName, heap, DYNTYPE_TEMP);
    }
    if (wSubjectName != NULL) {
        WFREE(wSubjectName, heap, DYNTYPE_TEMP);
    }
    WOLFSSH_UNUSED(heap);
}
#endif /* WOLFSSH_WINDOWS_CERT_STORE */


#endif /* WOLFSSH_CERTS */
