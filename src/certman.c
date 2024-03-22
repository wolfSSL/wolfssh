/* certman.c
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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/error-ssl.h>

#include <wolfssh/internal.h>
#include <wolfssh/certman.h>


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


static WOLFSSH_CERTMAN* _CertMan_init(WOLFSSH_CERTMAN* cm, void* heap)
{
    WOLFSSH_CERTMAN* ret = NULL;
    WLOG_ENTER();

    ret = cm;
    if (ret != NULL) {
        WMEMSET(ret, 0, sizeof(WOLFSSH_CERTMAN));
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
    int ret;

    WLOG_ENTER();

    ret = wolfSSL_CertManagerLoadCABuffer(cm->cm, rootCa, rootCaSz,
            WOLFSSL_FILETYPE_ASN1);
    if (ret == WOLFSSL_SUCCESS) {
        ret = WS_SUCCESS;
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

/* if handling a chain it is expected to be the leaf cert first followed by
 * intermediates and CA last (CA may be ommited) */
int wolfSSH_CERTMAN_VerifyCerts_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* certs, word32 certSz, word32 certsCount)
{
    int ret = WS_SUCCESS;

    word32 idx = 0;
    int certIdx = 0;
    unsigned char **certLoc; /* locations of certificate start */
    word32        *certLen;  /* size of certificate, in sync with certLoc */

    WLOG_ENTER();

    if (cm == NULL || certs == NULL) {
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
                else {
                    WLOG(WS_LOG_CERTMAN, "ocsp lookup: other error (%d)", ret);
                    ret = WS_CERT_OTHER_E;
                }
            }
        #endif /* HAVE_OCSP */

            /* verified successfully, add intermideate as trusted */
            if (ret == WS_SUCCESS && certIdx > 0) {
                WLOG(WS_LOG_CERTMAN, "adding intermidiate cert as trusted");
                ret = wolfSSH_CERTMAN_LoadRootCA_buffer(cm, certLoc[certIdx],
                    certLen[certIdx]);
            }

            if (ret != WS_SUCCESS) {
                break;
            }
        }
    }

#ifndef WOLFSSH_NO_FPKI
    /* FPKI checking on the leaf certificate */
    if (ret == WS_SUCCESS) {
        DecodedCert decoded;

        wc_InitDecodedCert(&decoded, certLoc[0], certLen[0], cm->cm);
        ret = wc_ParseCert(&decoded, WOLFSSL_FILETYPE_ASN1, 0, cm->cm);

        if (ret == 0) {
            ret =
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_6) ||
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_10) ||
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_16);

            if (ret == 0) {
                WLOG(WS_LOG_CERTMAN, "certificate didn't match profile");
                ret = WS_CERT_PROFILE_E;
            }
            else {
                ret = WS_SUCCESS;
            }
        }

        FreeDecodedCert(&decoded);
    }
#endif /* WOLFSSH_NO_FPKI */

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
            WLOG(WS_LOG_CERTMAN, "cert contry of citizenship invalid");
    }

    if (valid) {
        valid = !cert->isCA;
        if (valid != 1)
            WLOG(WS_LOG_CERTMAN, "cert basic constraint invalid");
    }

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
        struct tm t;

        dateFormat = cert->afterDate[0]; /* i.e ASN_UTC_TIME */
        dateSz     = cert->afterDate[1];
        date       = &cert->afterDate[2];

        wc_GetDateAsCalendarTime(date, dateSz, dateFormat, &t);
        if (t.tm_year <= 149 && dateFormat != ASN_UTC_TIME) {
            WLOG(WS_LOG_CERTMAN, "date format was not utc for year %d",
            t.tm_year);
            valid = 0;
        }

        if (t.tm_year > 149 && dateFormat != ASN_GENERALIZED_TIME) {
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
            WLOG(WS_LOG_CERTMAN, "cert did not inclue a FASC-N");
            valid = 0;
        }

        if (valid && hasUUID == 0) {
            WLOG(WS_LOG_CERTMAN, "cert did not inclue a UUID");
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
            WLOG(WS_LOG_CERTMAN, "cert did not inclue all ext. key usage");
        }
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

#endif /* WOLFSSH_CERTS */
