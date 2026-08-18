/* certman.h
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


#ifndef _WOLFSSH_CERTMAN_H_
#define _WOLFSSH_CERTMAN_H_

#include <wolfssh/settings.h>
#include <wolfssh/port.h>
#ifdef WOLFSSH_CERTS
    /* ssh.h establishes wolfSSL's build configuration (options.h or
     * user settings) and must come before any wolfSSL header so the
     * WOLFSSL_CERT_MANAGER/WOLFSSL_CTX layouts match the compiled
     * library. */
    #include <wolfssh/ssh.h> /* included for WOLFSSH_CTX */
    #include <wolfssl/ssl.h> /* included for WOLFSSL_CERT_MANAGER struct */
#endif
#ifdef WOLFSSH_WINDOWS_CERT_STORE
    #include <wchar.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


struct WOLFSSH_CERTMAN;
typedef struct WOLFSSH_CERTMAN WOLFSSH_CERTMAN;


#ifdef WOLFSSH_CERTS
/* Replaces the CTX's cert manager with cm, taking a reference on it and
 * applying wolfSSH's revocation policy. The caller retains ownership, but
 * note the policy is applied to the shared object: in an HAVE_OCSP build
 * this enables WOLFSSL_OCSP_CHECKALL on cm, so a caller that keeps using
 * the same manager for TLS will find every chain requiring an OCSP
 * response. Returns WS_NOT_COMPILED for any arguments when built against
 * wolfSSL older than 4.6.0 (wolfSSL_CertManager_up_ref() is unavailable
 * there). */
WOLFSSH_API
int wolfSSH_SetCertManager(WOLFSSH_CTX* ctx, WOLFSSL_CERT_MANAGER* cm);
#endif /* WOLFSSH_CERTS */

WOLFSSH_API
WOLFSSH_CERTMAN* wolfSSH_CERTMAN_new(void* heap);

WOLFSSH_API
void wolfSSH_CERTMAN_free(WOLFSSH_CERTMAN* cm);

WOLFSSH_API
int wolfSSH_CERTMAN_LoadRootCA_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* rootCa, word32 rootCaSz);

WOLFSSH_API
int wolfSSH_CERTMAN_VerifyCerts_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* cert, word32 certSz, word32 certCount);


#if defined(WOLFSSH_CERTS) && defined(WOLFSSH_WINDOWS_CERT_STORE)
/* Splits "store:subject[:flags]", where flags is CURRENT_USER,
 * LOCAL_MACHINE, USERS, or a decimal or 0x hex CERT_SYSTEM_STORE_* location,
 * and defaults to CURRENT_USER. The spec is split at the first two ':', so
 * neither the store name nor the subject may contain one and a third ':' is
 * rejected. Returns WS_SUCCESS and gives the caller ownership of the two
 * allocated wide strings, which must be released with
 * wolfSSH_FreeCertStoreSpec() using the same heap. On failure both
 * out-pointers are set to NULL and dwFlags is untouched. */
WOLFSSH_API
int wolfSSH_ParseCertStoreSpec(const char* spec,
        wchar_t** wStoreName, wchar_t** wSubjectName,
        word32* dwFlags, void* heap);

/* Frees the strings returned by wolfSSH_ParseCertStoreSpec(). Either
 * pointer may be NULL. */
WOLFSSH_API
void wolfSSH_FreeCertStoreSpec(wchar_t* wStoreName, wchar_t* wSubjectName,
        void* heap);
#endif /* WOLFSSH_CERTS && WOLFSSH_WINDOWS_CERT_STORE */


#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSH_CERTMAN_H_ */
