/* tpmcertserver.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#define WOLFSSH_TEST_SERVER

#include <wolfssh/ssh.h>
#include <wolfssh/test.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#if defined(WOLFSSH_TPM) && defined(WOLFSSH_CERTS)
    #include <wolftpm/tpm2_wrap.h>
#endif

/* wolfTPM's self-signed certificate generation and crypto callback (used to
 * sign the host certificate through the TPM) require wolfTPM built with cert
 * generation and the crypto callback. Match wolfTPM's own csr example. */
#if defined(WOLFSSH_TPM) && defined(WOLFSSH_CERTS) && \
    !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM2_CERT_GEN) && \
    defined(WOLFTPM_CRYPTOCB)

#include <hal/tpm_io.h>

#include <stdio.h>
#include <string.h>

#define TPMCS_USER      "jill"
#define TPMCS_PASSWORD  "upthehill"
#define TPMCS_KEY_AUTH  "ThisIsMyKeyAuth"
#define TPMCS_CERT_MAX  2048
#define TPMCS_BUF_SZ    1024

static const char* certOutFile = "tpm-server-cert.der";

/* Accept a single fixed user/password. The host identity we are proving to the
 * client is the X.509 host certificate, not the user credential. */
static int TpmCsUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_PASSWORD;

    WOLFSSH_UNUSED(ctx);

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* pw = (const char*)authData->sf.password.password;
        word32 pwSz = authData->sf.password.passwordSz;

        if (pwSz == (word32)XSTRLEN(TPMCS_PASSWORD)
                && XMEMCMP(pw, TPMCS_PASSWORD, pwSz) == 0) {
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
    }

    return ret;
}


/* Create a signing key inside the TPM and produce a self-signed X.509
 * certificate over its public key. The private key never leaves the TPM: the
 * certificate is signed through the wolfTPM crypto callback. */
static int TpmCsMakeKeyAndCert(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* key,
        int useEcc, byte* certDer, word32* certDerSz)
{
    int rc;
    int devId = INVALID_DEVID;
    int sigType;
    TpmCryptoDevCtx tpmCtx;
    WOLFTPM2_KEY srk;
    TPMT_PUBLIC pub;
    const char* subject;
    const char* keyUsage = "serverAuth,clientAuth";
    TPMA_OBJECT attr;

    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
    XMEMSET(&srk, 0, sizeof(srk));
    XMEMSET(&pub, 0, sizeof(pub));

    attr = TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth
         | TPMA_OBJECT_sign | TPMA_OBJECT_noDA;

    rc = wolfTPM2_SetCryptoDevCb(dev, wolfTPM2_CryptoDevCb, &tpmCtx, &devId);

    if (rc == 0) {
        rc = wolfTPM2_CreateSRK(dev, &srk, TPM_ALG_RSA,
                (const byte*)TPMCS_KEY_AUTH, (int)XSTRLEN(TPMCS_KEY_AUTH));
    }

    if (rc == 0) {
        if (useEcc) {
            subject = "/C=US/ST=Washington/L=Seattle/O=wolfSSL"
                      "/OU=ECC/CN=127.0.0.1";
            sigType = CTC_SHA256wECDSA;
            rc = wolfTPM2_GetKeyTemplate_ECC(&pub, attr,
                    TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
        }
        else {
            subject = "/C=US/ST=Washington/L=Seattle/O=wolfSSL"
                      "/OU=RSA/CN=127.0.0.1";
            sigType = CTC_SHA256wRSA;
            rc = wolfTPM2_GetKeyTemplate_RSA(&pub,
                    attr | TPMA_OBJECT_decrypt);
        }
    }

    if (rc == 0) {
        rc = wolfTPM2_CreateAndLoadKey(dev, key, &srk.handle, &pub,
                (const byte*)TPMCS_KEY_AUTH, (int)XSTRLEN(TPMCS_KEY_AUTH));
    }

    /* Point the crypto callback at the freshly created key so the self-signed
     * certificate is signed by the TPM. */
    if (rc == 0) {
        if (useEcc)
            tpmCtx.eccKey = key;
        else
            tpmCtx.rsaKey = key;

        rc = wolfTPM2_CSR_Generate_ex(dev, key, subject, keyUsage,
                ENCODING_TYPE_ASN1, certDer, (int)*certDerSz, sigType,
                1, devId);
    }

    if (rc >= 0) {
        *certDerSz = (word32)rc;
        rc = 0;
    }

    /* The crypto callback is only needed to self-sign the certificate. Clear
     * it before wolfSSH runs: host-key signing uses wolfTPM2_SignHashScheme()
     * directly, and a registered callback would route wolfSSH's certificate
     * parsing through the TPM. This reset is required, so treat a failure as
     * fatal. */
    if (rc == 0 && devId != INVALID_DEVID) {
        rc = wolfTPM2_ClearCryptoDevCb(dev, devId);
    }

    /* Restore a clean password session on the device. The certificate signing
     * left the active session state unset; without this, wolfSSH's
     * wolfTPM2_SignHashScheme() call fails with ctx->session == NULL. */
    if (rc == 0) {
        rc = wolfTPM2_UnsetAuth(dev, 0);
    }

    /* On any failure, unload the signing key so a retry does not exhaust TPM
     * transient object memory. */
    if (rc != 0) {
        wolfTPM2_UnloadHandle(dev, &key->handle);
    }

    /* The parent storage key is only needed to create the signing key. */
    wolfTPM2_UnloadHandle(dev, &srk.handle);

    return rc;
}


static int TpmCsWriteCert(const char* file, const byte* der, word32 derSz)
{
    int ret = 0;
    FILE* f = fopen(file, "wb");

    if (f == NULL) {
        ret = -1;
    }
    else {
        if (fwrite(der, 1, derSz, f) != derSz)
            ret = -1;
        fclose(f);
    }

    return ret;
}


static int TpmCsEcho(WOLFSSH* ssh)
{
    int ret = WS_SUCCESS;
    int rxSz;
    int txSz;
    int sent;
    byte buf[TPMCS_BUF_SZ];

    do {
        rxSz = wolfSSH_stream_read(ssh, buf, sizeof(buf));
        if (rxSz > 0) {
            /* stream_send may transmit fewer bytes than requested; loop until
             * the whole chunk is echoed. */
            sent = 0;
            while (sent < rxSz) {
                txSz = wolfSSH_stream_send(ssh, buf + sent, rxSz - sent);
                if (txSz <= 0) {
                    ret = txSz;
                    break;
                }
                sent += txSz;
            }
            if (ret != WS_SUCCESS)
                break;
        }
    } while (rxSz > 0);

    if (rxSz < 0 && rxSz != WS_EOF)
        ret = rxSz;

    return ret;
}


int main(int argc, char* argv[])
{
    int ret;
    int useEcc = 1;
    word16 port = 22222;
    int i;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY hostKey;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    WS_SOCKET_T clientFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    byte certDer[TPMCS_CERT_MAX];
    word32 certDerSz = (word32)sizeof(certDer);

    /* Line-buffer stdout so progress is visible immediately when redirected to
     * a file (the server runs while a test reads its output). */
    setvbuf(stdout, NULL, _IOLBF, 0);

    XMEMSET(&dev, 0, sizeof(dev));
    XMEMSET(&hostKey, 0, sizeof(hostKey));

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-k") == 0 && i + 1 < argc) {
            i++;
            if (XSTRCMP(argv[i], "rsa") == 0)
                useEcc = 0;
            else
                useEcc = 1;
        }
        else if (XSTRCMP(argv[i], "-p") == 0 && i + 1 < argc) {
            i++;
            port = (word16)atoi(argv[i]);
        }
    }

    printf("wolfSSH TPM X.509 host-key server (%s)\n", useEcc ? "ECDSA" : "RSA");

    ret = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (ret != 0) {
        fprintf(stderr, "wolfTPM2_Init failed: %d\n", ret);
        return 1;
    }

    ret = TpmCsMakeKeyAndCert(&dev, &hostKey, useEcc, certDer, &certDerSz);
    if (ret != 0) {
        fprintf(stderr, "TPM key/cert provisioning failed: %d\n", ret);
        wolfTPM2_Cleanup(&dev);
        return 1;
    }
    printf("Provisioned TPM host key and self-signed X.509 cert (%u bytes)\n",
            certDerSz);

    /* The companion client trusts this file as its root CA. If it cannot be
     * written, fail now rather than serve a certificate the client cannot
     * load (or let it read a stale certificate from a previous run). */
    if (TpmCsWriteCert(certOutFile, certDer, certDerSz) != 0) {
        fprintf(stderr, "Could not write server certificate to %s\n",
                certOutFile);
        wolfTPM2_UnloadHandle(&dev, &hostKey.handle);
        wolfTPM2_Cleanup(&dev);
        return 1;
    }
    printf("Wrote server certificate to %s (use as client -A CA)\n",
            certOutFile);

#ifdef DEBUG_WOLFSSH
    wolfSSH_Debugging_ON();
#endif

    if (wolfSSH_Init() != WS_SUCCESS) {
        fprintf(stderr, "wolfSSH_Init failed\n");
        wolfTPM2_UnloadHandle(&dev, &hostKey.handle);
        wolfTPM2_Cleanup(&dev);
        return 1;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSH_CTX_new failed\n");
        ret = WS_MEMORY_E;
    }

    if (ret == 0) {
        wolfSSH_SetUserAuth(ctx, TpmCsUserAuth);

        /* Bind the TPM host key first so a private-key slot exists, then load
         * the matching X.509 certificate. UpdateHostCertificates() ties the
         * certificate to the TPM key so the exchange signs through the TPM. */
        ret = wolfSSH_CTX_UseTpmHostKey(ctx, &dev, &hostKey);
        if (ret != WS_SUCCESS)
            fprintf(stderr, "wolfSSH_CTX_UseTpmHostKey failed: %d (%s)\n",
                    ret, wolfSSH_ErrorToName(ret));
    }

    if (ret == 0) {
        ret = wolfSSH_CTX_UseCert_buffer(ctx, certDer, certDerSz,
                WOLFSSH_FORMAT_ASN1);
        if (ret != WS_SUCCESS)
            fprintf(stderr, "wolfSSH_CTX_UseCert_buffer failed: %d (%s)\n",
                    ret, wolfSSH_ErrorToName(ret));
    }

    if (ret == 0) {
        WSTARTTCP();
        tcp_listen(&listenFd, &port, 1);
        printf("Listening on port %u. Waiting for a client...\n", port);

        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                (socklen_t*)&clientAddrSz);
        if (clientFd == WOLFSSH_SOCKET_INVALID)
            ret = WS_SOCKET_ERROR_E;
    }

    if (ret == 0) {
        ssh = wolfSSH_new(ctx);
        if (ssh == NULL)
            ret = WS_MEMORY_E;
    }

    if (ret == 0) {
        wolfSSH_set_fd(ssh, (int)clientFd);

        ret = wolfSSH_accept(ssh);
        if (ret == WS_SUCCESS) {
            printf("Client connected and verified the TPM-backed host "
                   "certificate.\n");
            ret = TpmCsEcho(ssh);
        }
        else {
            fprintf(stderr, "wolfSSH_accept failed: %d (%s)\n", ret,
                    wolfSSH_ErrorToName(ret));
        }
    }

    if (ssh != NULL) {
        wolfSSH_stream_exit(ssh, 0);
        wolfSSH_free(ssh);
    }
    if (clientFd != WOLFSSH_SOCKET_INVALID)
        WCLOSESOCKET(clientFd);
    if (listenFd != WOLFSSH_SOCKET_INVALID)
        WCLOSESOCKET(listenFd);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    wolfSSH_Cleanup();

    wolfTPM2_UnloadHandle(&dev, &hostKey.handle);
    wolfTPM2_Cleanup(&dev);

    printf("Done (ret = %d).\n", (ret == WS_SUCCESS) ? 0 : ret);
    return (ret == WS_SUCCESS) ? 0 : 1;
}

#else /* missing TPM/cert prerequisites */

int main(void)
{
    printf("This example requires wolfSSH built with --enable-tpm "
           "--enable-certs, and wolfTPM/wolfSSL with certificate generation "
           "and the crypto callback (wolfSSL --enable-certgen --enable-certreq "
           "--enable-certext --enable-cryptocb, wolfTPM cert generation).\n");
    return 0;
}

#endif
