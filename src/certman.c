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


int wolfSSH_CERTMAN_VerifyCert_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* cert, word32 certSz)
{
    int ret = WS_SUCCESS;

    WLOG_ENTER();

    ret = wolfSSL_CertManagerVerifyBuffer(cm->cm, cert, certSz,
            WOLFSSL_FILETYPE_ASN1);

    WLOG_LEAVE(ret);
    return ret;
}

#endif /* WOLFSSH_CERTS */
