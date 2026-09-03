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
    #include <wolfssh/ssh.h> /* included for WOLFSSH_CTX */
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
/* Only a pointer to the wolfSSL cert manager is named here, so a forward
 * struct reference keeps <wolfssl/ssl.h> out of every translation unit that
 * includes wolfssh/internal.h; src/certman.c includes the real header. */
struct WOLFSSL_CERT_MANAGER;

/* Replaces the CTX's cert manager with cm, taking a reference on it and
 * applying wolfSSH's revocation policy. The caller retains ownership, but
 * note wolfSSH mutates the shared object: in an HAVE_OCSP build this
 * enables WOLFSSL_OCSP_CHECKALL on cm, so a caller that keeps using the
 * same manager for TLS will find every chain requiring an OCSP response,
 * and during certificate authentication wolfSSH permanently adds verified
 * peer intermediate CAs to the manager as trusted roots. Prefer a manager
 * dedicated to wolfSSH over one shared with a live TLS stack. On failure
 * (WS_FATAL_ERROR) nothing has changed: the CTX keeps its previous manager
 * and no policy has been applied to cm. Returns
 * WS_NOT_COMPILED for any arguments when built against wolfSSL older than
 * 4.6.0 (wolfSSL_CertManager_up_ref() is unavailable there). */
WOLFSSH_API
int wolfSSH_SetCertManager(WOLFSSH_CTX* ctx, struct WOLFSSL_CERT_MANAGER* cm);
#endif /* WOLFSSH_CERTS */

WOLFSSH_API
WOLFSSH_CERTMAN* wolfSSH_CERTMAN_new(void* heap);

WOLFSSH_API
void wolfSSH_CERTMAN_free(WOLFSSH_CERTMAN* cm);

WOLFSSH_API
int wolfSSH_CERTMAN_LoadRootCA_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* rootCa, word32 rootCaSz);

/* Verifies a leaf-first chain against the loaded roots and then applies the
 * RFC 6187 section 2.2 leaf checks in every build: a KeyUsage extension
 * must assert digitalSignature, and an ExtendedKeyUsage extension must name
 * anyExtendedKeyUsage or a purpose usable for the SSH role being verified,
 * id-kp-secureShellClient or TLS clientAuth for a user certificate and
 * id-kp-secureShellServer or TLS serverAuth for a host certificate. Fails
 * with WS_CERT_KEY_USAGE_E otherwise. The role comes from the CTX that owns
 * the manager; a standalone manager accepts either. Builds with FPKI
 * profile matching apply that on top. */
WOLFSSH_API
int wolfSSH_CERTMAN_VerifyCerts_buffer(WOLFSSH_CERTMAN* cm,
        const unsigned char* cert, word32 certSz, word32 certCount);


#if defined(WOLFSSH_CERTS) && defined(WOLFSSH_WINDOWS_CERT_STORE)
/* Parses a Windows system-store location name into its CERT_SYSTEM_STORE_*
 * value. Accepts the short names CURRENT_USER, LOCAL_MACHINE, USERS,
 * CURRENT_SERVICE, SERVICES, CURRENT_USER_GROUP_POLICY,
 * LOCAL_MACHINE_GROUP_POLICY and LOCAL_MACHINE_ENTERPRISE, the same names
 * with a CERT_SYSTEM_STORE_ prefix, or a decimal/0x-hex number consumed
 * whole (a leading sign or whitespace is rejected). Only assigned store
 * locations are accepted, never control flags. Returns WS_SUCCESS on
 * success. */
WOLFSSH_API
int wolfSSH_CertStoreLocationFromName(const char* in, word32* out);

/* Splits "store:subject[:flags]", where flags takes any spelling
 * wolfSSH_CertStoreLocationFromName() accepts and defaults to CURRENT_USER.
 * The spec is split at the first two ':', so neither the store name nor the
 * subject may contain one and a third ':' is rejected. Returns WS_SUCCESS
 * and gives the caller ownership of the two allocated wide strings, which
 * must be released with wolfSSH_FreeCertStoreSpec() using the same heap. On
 * failure any non-NULL out-pointer is set to NULL and dwFlags is
 * untouched. */
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
