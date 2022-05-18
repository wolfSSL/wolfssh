/* certman.c
 *
 * Copyright (C) 2014-2021 wolfSSL Inc.
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
    WLOG_ENTER();

    if (cm != NULL) {
        WMEMSET(cm, 0, sizeof *cm);
        cm->cm = wolfSSL_CertManagerNew_ex(heap);
        if (cm->cm != NULL) {
            int ret;

            ret = wolfSSL_CertManagerEnableOCSP(cm->cm,
                    WOLFSSL_OCSP_CHECKALL);

            if (ret == WOLFSSL_SUCCESS) {
                WLOG(WS_LOG_CERTMAN, "Enabled OCSP");
            }
            else {
                WLOG(WS_LOG_CERTMAN, "Couldn't enable OCSP");
                wolfSSL_CertManagerFree(cm->cm);
                cm = NULL;
            }
        }
        else {
            cm = NULL;
        }
    }

    WLOG_LEAVE_PTR(cm);
    return cm;
}


static void _CertMan_ResourceFree(WOLFSSH_CERTMAN* cm, void* heap)
{
    (void)heap;
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


int wolfSSH_CERTMAN_LoadRootCA_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* rootCa, word32 rootCaSz)
{
    int ret = WS_SUCCESS;

    WLOG_ENTER();

    ret = wolfSSL_CertManagerLoadCABuffer(cm->cm, rootCa, rootCaSz,
            WOLFSSL_FILETYPE_ASN1);

    WLOG_LEAVE(ret);
    return ret;
}


static int CheckProfile(DecodedCert* cert, int profile);
enum {
    PROFILE_FPKI_WORKSHEET_6 = 6,
    PROFILE_FPKI_WORKSHEET_10 = 10,
    PROFILE_FPKI_WORKSHEET_16 = 16
};

int wolfSSH_CERTMAN_VerifyCert_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* cert, word32 certSz)
{
    int ret = WS_SUCCESS;

    WLOG_ENTER();

    if (ret == WS_SUCCESS) {
        ret = wolfSSL_CertManagerVerifyBuffer(cm->cm, cert, certSz,
                WOLFSSL_FILETYPE_ASN1);

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
    }

    if (ret == WS_SUCCESS) {
        ret = wolfSSL_CertManagerCheckOCSP(cm->cm, (byte*)cert, certSz);

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

    if (ret == WS_SUCCESS) {
        DecodedCert decoded;

        wc_InitDecodedCert(&decoded, cert, certSz, cm->cm);
        ret = wc_ParseCert(&decoded, WOLFSSL_FILETYPE_ASN1, 0, cm->cm);

        if (ret == 0) {
            ret =
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_6) ||
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_10) ||
                CheckProfile(&decoded, PROFILE_FPKI_WORKSHEET_16);

            if (ret != 0) {
                WLOG(WS_LOG_CERTMAN, "certificate didn't match profile");
                ret = WS_CERT_PROFILE_E;
            }
            else
                ret = WS_SUCCESS;
        }

        FreeDecodedCert(&decoded);
    }

    WLOG_LEAVE(ret);
    return ret;
}


static int CheckProfile(DecodedCert* cert, int profile)
{
    int valid = (cert != NULL);
    const char* certPolicies[2] = {NULL, NULL};
    byte extKeyUsage = 0, extKeyUsageSsh = 0, extKeyUsageSshAllowed = 0;

    if (profile == PROFILE_FPKI_WORKSHEET_6) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.13";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
        extKeyUsageSsh = EXTKEYUSE_SSH_MSCL;
        extKeyUsageSshAllowed =
            EXTKEYUSE_SSH_KP_CLIENT_AUTH |
            EXTKEYUSE_SSH_CLIENT_AUTH;
    }
    else if (profile == PROFILE_FPKI_WORKSHEET_10) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.40";
        certPolicies[1] = "2.16.840.1.101.3.2.1.3.41";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
        extKeyUsageSshAllowed =
            EXTKEYUSE_SSH_MSCL |
            EXTKEYUSE_SSH_KP_CLIENT_AUTH |
            EXTKEYUSE_SSH_CLIENT_AUTH;
    }
    else if (profile == PROFILE_FPKI_WORKSHEET_16) {
        certPolicies[0] = "2.16.840.1.101.3.2.1.3.45";
        extKeyUsage = EXTKEYUSE_CLIENT_AUTH;
        extKeyUsageSsh = EXTKEYUSE_SSH_MSCL;
        extKeyUsageSshAllowed =
            EXTKEYUSE_SSH_KP_CLIENT_AUTH |
            EXTKEYUSE_SSH_CLIENT_AUTH;
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
    }

    if (valid) {
        valid = !cert->isCA;
    }

    if (valid) {
        valid =
            WMEMCMP(cert->extAuthKeyId, cert->extSubjKeyId, KEYID_SIZE) != 0;

    }

    if (valid) {
            valid =
                ((certPolicies[1] != NULL) &&
                 (WSTRCMP(certPolicies[1], cert->extCertPolicies[0]) == 0 ||
                  WSTRCMP(certPolicies[1], cert->extCertPolicies[1]) == 0)) ||
                ((certPolicies[0] != NULL) &&
                 (WSTRCMP(certPolicies[0], cert->extCertPolicies[0]) == 0 ||
                  WSTRCMP(certPolicies[0], cert->extCertPolicies[1]) == 0));
    }

    if (valid) {
        valid =
            /* Must include all in extKeyUsage */
            ((extKeyUsage == 0) ||
                ((cert->extExtKeyUsage & extKeyUsage) != extKeyUsage)) &&
            /* Must include all in extKeyUsageSsh */
            ((extKeyUsageSsh == 0) ||
                ((cert->extExtKeyUsageSsh & extKeyUsageSsh)
                    != extKeyUsageSsh)) &&
            /* Must include at least one in extKeyUsageSshAllowed */
            ((extKeyUsageSshAllowed == 0) ||
                ((cert->extExtKeyUsageSsh & extKeyUsageSshAllowed) != 0));

    }

    return valid;
}

#endif /* WOLFSSH_CERTS */
