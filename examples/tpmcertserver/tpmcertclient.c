/* tpmcertclient.c
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

#define WOLFSSH_TEST_CLIENT

#include <wolfssh/ssh.h>
#include <wolfssh/test.h>

#ifdef WOLFSSH_CERTS

#include <stdio.h>
#include <string.h>

#define TPMCC_USER      "jill"
#define TPMCC_PASSWORD  "upthehill"
#define TPMCC_BUF_SZ    1024

static int TpmCcUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_FAILURE;

    WOLFSSH_UNUSED(ctx);

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        authData->sf.password.password = (const byte*)TPMCC_PASSWORD;
        authData->sf.password.passwordSz = (word32)XSTRLEN(TPMCC_PASSWORD);
        ret = WOLFSSH_USERAUTH_SUCCESS;
    }

    return ret;
}


/* Host key acceptance callback. wolfSSH verifies the server's X.509 certificate
 * chain against the root CA loaded with wolfSSH_CTX_AddRootCert_buffer() later,
 * during the key exchange, when it extracts the public key from the certificate.
 * Because the client only accepts x509v3 host key algorithms, that CA
 * verification is always performed. This callback just accepts the presented
 * host key blob. */
static int TpmCcHostKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    WOLFSSH_UNUSED(pubKey);
    WOLFSSH_UNUSED(pubKeySz);
    WOLFSSH_UNUSED(ctx);
    return 0;
}


static int TpmCcLoadFile(const char* file, byte* buf, word32* bufSz)
{
    int ret = 0;
    FILE* f = fopen(file, "rb");
    size_t n;
    int extra;

    if (f == NULL) {
        ret = -1;
    }
    else {
        n = fread(buf, 1, *bufSz, f);
        /* If the buffer filled exactly, the file may be larger than the buffer;
         * reject a truncated read rather than loading a partial certificate. */
        extra = (n == (size_t)*bufSz) ? fgetc(f) : EOF;
        fclose(f);
        if (n == 0 || extra != EOF)
            ret = -1;
        else
            *bufSz = (word32)n;
    }

    return ret;
}


int main(int argc, char* argv[])
{
    int ret;
    int i;
    word16 port = 22222;
    const char* host = "127.0.0.1";
    const char* caFile = "tpm-server-cert.der";
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    WS_SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T addr;
    byte caDer[2048];
    word32 caDerSz = (word32)sizeof(caDer);
    byte txt[] = "hello from tpmcertclient\n";
    byte rxBuf[TPMCC_BUF_SZ];

    /* Line-buffer stdout so output is visible immediately when redirected. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    for (i = 1; i < argc; i++) {
        if (XSTRCMP(argv[i], "-p") == 0 && i + 1 < argc)
            port = (word16)atoi(argv[++i]);
        else if (XSTRCMP(argv[i], "-h") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (XSTRCMP(argv[i], "-A") == 0 && i + 1 < argc)
            caFile = argv[++i];
    }

    if (TpmCcLoadFile(caFile, caDer, &caDerSz) != 0) {
        fprintf(stderr, "Could not read CA file %s\n", caFile);
        return 1;
    }

#ifdef DEBUG_WOLFSSH
    wolfSSH_Debugging_ON();
#endif

    ret = (wolfSSH_Init() == WS_SUCCESS) ? 0 : -1;

    if (ret == 0) {
        ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
        if (ctx == NULL)
            ret = -1;
    }

    if (ret == 0) {
        wolfSSH_SetUserAuth(ctx, TpmCcUserAuth);
        wolfSSH_CTX_SetPublicKeyCheck(ctx, TpmCcHostKeyCheck);

        /* Only accept X.509 certificate host keys. Without this the client
         * would also accept a plain host key, and the server's certificate
         * (and therefore CA verification) would be bypassed. */
        if (wolfSSH_CTX_SetAlgoListKey(ctx,
                "x509v3-ecdsa-sha2-nistp256,x509v3-ecdsa-sha2-nistp384,"
                "x509v3-ecdsa-sha2-nistp521,x509v3-ssh-rsa") != WS_SUCCESS) {
            fprintf(stderr, "Could not set host key algorithm list\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        if (wolfSSH_CTX_AddRootCert_buffer(ctx, caDer, caDerSz,
                WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
            fprintf(stderr, "Could not load root CA certificate\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        ssh = wolfSSH_new(ctx);
        if (ssh == NULL)
            ret = -1;
    }

    if (ret == 0)
        ret = (wolfSSH_SetUsername(ssh, TPMCC_USER) == WS_SUCCESS) ? 0 : -1;

    if (ret == 0) {
        WSTARTTCP();
        build_addr(&addr, host, port);
        tcp_socket(&sockFd, ((struct sockaddr_in*)&addr)->sin_family);
        if (connect(sockFd, (const struct sockaddr*)&addr, sizeof(addr)) != 0) {
            fprintf(stderr, "Could not connect to %s:%u\n", host, port);
            ret = -1;
        }
    }

    if (ret == 0) {
        wolfSSH_set_fd(ssh, (int)sockFd);
        ret = wolfSSH_connect(ssh);
        if (ret == WS_SUCCESS) {
            printf("Connected: verified server X.509 host certificate.\n");
            ret = 0;
        }
        else {
            fprintf(stderr, "wolfSSH_connect failed: %d (%s)\n", ret,
                    wolfSSH_ErrorToName(ret));
        }
    }

    if (ret == 0) {
        int txSz = (int)XSTRLEN((char*)txt);
        int sent = 0;
        int rxSz;
        int n;

        /* stream_send may transmit fewer bytes than requested; loop until the
         * whole message is sent. */
        while (sent < txSz) {
            n = wolfSSH_stream_send(ssh, txt + sent, (word32)(txSz - sent));
            if (n <= 0) {
                fprintf(stderr, "stream send failed: %d\n", n);
                ret = -1;
                break;
            }
            sent += n;
        }

        if (ret == 0) {
            rxSz = wolfSSH_stream_read(ssh, rxBuf, sizeof(rxBuf) - 1);
            if (rxSz <= 0) {
                fprintf(stderr, "stream read failed: %d\n", rxSz);
                ret = -1;
            }
            else {
                rxBuf[rxSz] = 0;
                printf("Echo from server: %s", (char*)rxBuf);
            }
        }
    }

    if (ssh != NULL) {
        wolfSSH_stream_exit(ssh, 0);
        wolfSSH_free(ssh);
    }
    if (sockFd != WOLFSSH_SOCKET_INVALID)
        WCLOSESOCKET(sockFd);
    if (ctx != NULL)
        wolfSSH_CTX_free(ctx);
    wolfSSH_Cleanup();

    printf("Done (ret = %d).\n", ret);
    return (ret == 0) ? 0 : 1;
}

#else /* !WOLFSSH_CERTS */

int main(void)
{
    printf("This example requires wolfSSH built with --enable-certs.\n");
    return 0;
}

#endif /* WOLFSSH_CERTS */
