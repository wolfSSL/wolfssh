/* ossh.h
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


/* Parsing and verification of OpenSSH ("*-cert-v01@openssh.com") user
 * certificates. */


#ifndef _WOLFSSH_OSSH_H_
#define _WOLFSSH_OSSH_H_

#include <wolfssh/settings.h>
#include <wolfssh/port.h>

#ifdef WOLFSSH_OSSH_CERTS

#ifdef __cplusplus
extern "C" {
#endif

#define WOLFSSH_OSSH_CERT_TYPE_USER 1 /* OpenSSH SSH2_CERT_TYPE_USER */

/* Every pointer member references memory inside the blob passed to
 * OsshCertParse() and is valid only while that blob is. */
typedef struct WS_OsshCert {
    const byte* blob;        /* whole cert blob (for signature hashing) */
    word32      blobSz;
    word32      signedLen;   /* bytes covered by the CA signature */
    byte        typeId;      /* ID_OSSH_CERT_* of the certificate */
    byte        baseTypeId;  /* ID_SSH_RSA / ID_ECDSA_* / ID_ED25519 */

    const byte* nonce;       word32 nonceSz;
    const byte* userKeyParms;/* type-specific public key fields (inline) */
    word32      userKeyParmsSz;
    word64      serial;
    word32      certType;    /* must be WOLFSSH_OSSH_CERT_TYPE_USER */
    const byte* keyId;       word32 keyIdSz;
    const byte* principals;  word32 principalsSz;  /* run of SSH strings */
    word64      validAfter;
    word64      validBefore;
    const byte* critOpts;    word32 critOptsSz;
    const byte* extensions;  word32 extensionsSz;
    const byte* caKey;       word32 caKeySz;       /* signature_key contents */
    const byte* caKeyType;   word32 caKeyTypeSz;
    const byte* signature;   word32 signatureSz;

    /* Extracted by OsshCertCheckOptions(); NULL when the option is absent. */
    const byte* forceCommand;  word32 forceCommandSz;
    const byte* sourceAddress; word32 sourceAddressSz;
} WS_OsshCert;

/* ID_OSSH_CERT_* to its base key algorithm ID; ID_UNKNOWN if not a cert ID. */
WOLFSSH_LOCAL byte OsshCertBaseId(byte certId);

/* Strongest rsa-sha2-* the peer advertised: 512 when offered, else 256. */
WOLFSSH_LOCAL byte OsshRsaCertSigId(const byte* peerSigId, word32 peerSigIdSz);

/* Parse a certificate blob of algorithm typeId into cert. */
WOLFSSH_LOCAL int OsshCertParse(WS_OsshCert* cert, byte typeId,
        const byte* blob, word32 blobSz);

/* Verify the CA signature over the signed body using the embedded
 * signature_key. */
WOLFSSH_LOCAL int OsshCertVerifySignature(const WS_OsshCert* cert, void* heap);

/* Check certType is a user cert and the CA key type is supported. Key-type vs
 * cert-algorithm consistency is checked in OsshCertParse(). */
WOLFSSH_LOCAL int OsshCertCheckType(const WS_OsshCert* cert);

/* Validate options/extensions; extract force-command and source-address.
 * Unknown critical options are rejected; permit-* is parsed, not enforced. */
WOLFSSH_LOCAL int OsshCertCheckOptions(WS_OsshCert* cert);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_OSSH_CERTS */

#endif /* _WOLFSSH_OSSH_H_ */
