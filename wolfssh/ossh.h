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


/*
 * The ossh module parses and verifies OpenSSH ("*-cert-v01@openssh.com")
 * user certificates.
 */


#ifndef _WOLFSSH_OSSH_H_
#define _WOLFSSH_OSSH_H_

#include <wolfssh/settings.h>
#include <wolfssh/port.h>

#ifdef WOLFSSH_OSSH_CERTS

#ifdef __cplusplus
extern "C" {
#endif

/* OpenSSH user certificate, version 1. SSH2_CERT_TYPE_USER == 1. */
#define WOLFSSH_OSSH_CERT_TYPE_USER 1

/* Parsed view of an OpenSSH certificate. All pointer members reference memory
 * inside the input blob passed to OsshCertParse(); they are valid only while
 * that blob is. */
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

    /* Critical option values extracted by OsshCertCheckOptions(); NULL when the
     * option is absent. Both reference memory inside the input blob. */
    const byte* forceCommand;  word32 forceCommandSz;
    const byte* sourceAddress; word32 sourceAddressSz;
} WS_OsshCert;

/* Map the certificate algorithm ID (ID_OSSH_CERT_*) to its base public key
 * algorithm ID (ID_SSH_RSA, ID_ECDSA_SHA2_*, ID_ED25519). Returns ID_UNKNOWN
 * when not an OpenSSH certificate ID. */
WOLFSSH_LOCAL byte OsshCertBaseId(byte certId);

/* Select the rsa-sha2-* signature algorithm to use for an OpenSSH RSA
 * certificate: the strongest the peer advertised (peerSigId/peerSigIdSz).
 * Returns ID_RSA_SHA2_512 when the peer supports it, else ID_RSA_SHA2_256. */
WOLFSSH_LOCAL byte OsshRsaCertSigId(const byte* peerSigId, word32 peerSigIdSz);

/* Parse an OpenSSH certificate blob of algorithm typeId. Fills cert with
 * references into blob. Returns WS_SUCCESS or a negative error. */
WOLFSSH_LOCAL int OsshCertParse(WS_OsshCert* cert, byte typeId,
        const byte* blob, word32 blobSz);

/* Verify the CA signature over the certificate's signed body using the
 * embedded signature_key. Returns WS_SUCCESS when the signature is valid. */
WOLFSSH_LOCAL int OsshCertVerifySignature(const WS_OsshCert* cert, void* heap);

/* Check that certType is a user certificate and the CA signature_key type is
 * supported. Key-type vs cert-algorithm consistency is done in OsshCertParse. */
WOLFSSH_LOCAL int OsshCertCheckType(const WS_OsshCert* cert);

/* Validate critical options and extensions: ascending order, no duplicates,
 * unknown critical option rejected, unknown extension ignored. Extracts the
 * force-command and source-address values into the certificate. */
WOLFSSH_LOCAL int OsshCertCheckOptions(WS_OsshCert* cert);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSH_OSSH_CERTS */

#endif /* _WOLFSSH_OSSH_H_ */
