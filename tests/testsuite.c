/* testsuite.c
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

#include <stdio.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#define WOLFSSH_TEST_CLIENT
#define WOLFSSH_TEST_SERVER
#ifndef SINGLE_THREADED
    #define WOLFSSH_TEST_THREADING
#endif
#define WOLFSSH_TEST_LOCKING

#include <wolfssh/settings.h>
#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include "examples/echoserver/echoserver.h"
#include "examples/client/client.h"
#include "examples/client/common.h"
#include "tests/testsuite.h"

#if defined(WOLFSSH_SFTP) && !defined(SINGLE_THREADED)
    #include "tests/sftp.h"
#endif

#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif

#ifndef NO_TESTSUITE_MAIN_DRIVER

int main(int argc, char** argv)
{
    return wolfSSH_TestsuiteTest(argc, argv);
}


int myoptind = 0;
char* myoptarg = NULL;

#endif /* !NO_TESTSUITE_MAIN_DRIVER */


#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK)

#ifdef WOLFSSH_SHELL

static int tsClientUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    static char password[] = "upthehill";

    (void)authType;
    (void)ctx;

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        authData->sf.password.password = (byte*)password;
        authData->sf.password.passwordSz = (word32)WSTRLEN(password);
    }
    else {
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    }

    return WOLFSSH_USERAUTH_SUCCESS;
}


#define NUMARGS 6
#define ARGLEN 64

static void wolfSSH_EchoTest(void)
{
    tcp_ready ready;
    THREAD_TYPE serverThread;
    func_args serverArgs;
    func_args clientArgs;
    char sA[NUMARGS][ARGLEN];
    char *serverArgv[NUMARGS] =
        { sA[0], sA[1], sA[2], sA[3], sA[4] };
    char cA[NUMARGS][ARGLEN];
    char *clientArgv[NUMARGS] =
        { cA[0], cA[1], cA[2], cA[3], cA[4], cA[5] };
    int serverArgc = 0;
    int clientArgc = 0;

    InitTcpReady(&ready);

    WMEMSET(&serverArgs, 0, sizeof(serverArgs));
    WSTRNCPY(serverArgv[serverArgc++], "echoserver", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "-1", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "-f", ARGLEN);
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        WSTRNCPY(serverArgv[serverArgc++], "-p", ARGLEN);
        WSTRNCPY(serverArgv[serverArgc++], "-0", ARGLEN);
    #endif

    serverArgs.argc = serverArgc;
    serverArgs.argv = serverArgv;
    serverArgs.return_code = EXIT_SUCCESS;
    serverArgs.signal = &ready;
    serverArgs.user_auth = NULL;
    ThreadStart(echoserver_test, &serverArgs, &serverThread);
    WaitTcpReady(&ready);

    WSTRNCPY(cA[clientArgc++], "client", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-Y", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-u", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "jill", ARGLEN);
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        WSTRNCPY(cA[clientArgc++], "-p", ARGLEN);
        WSNPRINTF(cA[clientArgc++], ARGLEN, "%d", ready.port);
    #endif

    clientArgs.argc = clientArgc;
    clientArgs.argv = clientArgv;
    clientArgs.return_code = EXIT_SUCCESS;
    clientArgs.signal = &ready;
    clientArgs.user_auth = tsClientUserAuth;

    client_test(&clientArgs);

#ifdef WOLFSSH_ZEPHYR
    /* Weird deadlock without this sleep */
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serverThread);

    FreeTcpReady(&ready);
}

static void wolfSSH_EchoTest_MultiPubKey(void)
{
    tcp_ready ready;
    THREAD_TYPE serverThread;
    func_args serverArgs;
    func_args clientArgs;
    char sA[15][ARGLEN];
    char *serverArgv[15] =
        { sA[0], sA[1], sA[2], sA[3], sA[4], sA[5], sA[6], sA[7], sA[8], sA[9], sA[10] };
    char cA[15][ARGLEN];
    char *clientArgv[15] =
        { cA[0], cA[1], cA[2], cA[3], cA[4], cA[5], cA[6], cA[7], cA[8], cA[9], cA[10], cA[11], cA[12] };
    int serverArgc = 0;
    int clientArgc = 0;

    InitTcpReady(&ready);

    WMEMSET(&serverArgs, 0, sizeof(serverArgs));
    WSTRNCPY(serverArgv[serverArgc++], "echoserver", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "-1", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "-f", ARGLEN);
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        WSTRNCPY(serverArgv[serverArgc++], "-p", ARGLEN);
        WSTRNCPY(serverArgv[serverArgc++], "-0", ARGLEN);
    #endif
    WSTRNCPY(serverArgv[serverArgc++], "-I", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "hansel:./keys/hansel-key-rsa.pub", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "-I", ARGLEN);
    WSTRNCPY(serverArgv[serverArgc++], "hansel:./keys/hansel-key-ecc.pub", ARGLEN);

    serverArgs.argc = serverArgc;
    serverArgs.argv = serverArgv;
    serverArgs.return_code = EXIT_SUCCESS;
    serverArgs.signal = &ready;
    serverArgs.user_auth = NULL;
    ThreadStart(echoserver_test, &serverArgs, &serverThread);
    WaitTcpReady(&ready);

    WSTRNCPY(cA[clientArgc++], "client", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-Y", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-u", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "hansel", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-j", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "./keys/hansel-key-ecc.pub", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "-i", ARGLEN);
    WSTRNCPY(cA[clientArgc++], "./keys/hansel-key-ecc.der", ARGLEN);
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        WSTRNCPY(cA[clientArgc++], "-p", ARGLEN);
        WSNPRINTF(cA[clientArgc++], ARGLEN, "%d", ready.port);
    #endif

    clientArgs.argc = clientArgc;
    clientArgs.argv = clientArgv;
    clientArgs.return_code = EXIT_SUCCESS;
    clientArgs.signal = &ready;
    clientArgs.user_auth = NULL;

    client_test(&clientArgs);
    if (clientArgs.return_code != EXIT_SUCCESS) {
        err_sys("client_test failed");
    }

#ifdef WOLFSSH_ZEPHYR
    /* Weird deadlock without this sleep */
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serverThread);
    if (serverArgs.return_code != EXIT_SUCCESS) {
        err_sys("server_test failed");
    }

    FreeTcpReady(&ready);
}

#endif /* WOLFSSH_SHELL */


#if defined(WOLFSSH_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSH_ZEPHYR)

static void PutU32(word32 u32, byte* c)
{
    c[0] = (byte)(u32 >> 24);
    c[1] = (byte)(u32 >> 16);
    c[2] = (byte)(u32 >> 8);
    c[3] = (byte)u32;
}

/* Checks an RFC 6187 blob of certName against host, expecting expect. */
static void CertHostCheck(const char* certName, const char* host, int expect)
{
    static const char keyType[] = "x509v3-ecdsa-sha2-nistp256";
    byte blob[2048];
    byte cert[1536];
    word32 certSz, typeSz = (word32)sizeof(keyType) - 1, idx = 0;
    WFILE* f = WBADFILE;

    if (WFOPEN(NULL, &f, certName, "rb") != 0 || f == WBADFILE)
        err_sys("couldn't open the test certificate");
    certSz = (word32)WFREAD(NULL, cert, 1, sizeof(cert), f);
    WFCLOSE(NULL, f);
    if (certSz == 0 || certSz == sizeof(cert))
        err_sys("couldn't read the test certificate");

    PutU32(typeSz, blob + idx);
    idx += 4;
    WMEMCPY(blob + idx, keyType, typeSz);
    idx += typeSz;
    PutU32(1, blob + idx); /* certificate count */
    idx += 4;
    PutU32(certSz, blob + idx);
    idx += 4;
    WMEMCPY(blob + idx, cert, certSz);
    idx += certSz;
    PutU32(0, blob + idx); /* OCSP response count */
    idx += 4;

    if (ClientPublicKeyCheck(blob, idx, (void*)host) != expect) {
        printf("host certificate %s checked for %s, expected %d\n",
                certName, host, expect);
        err_sys("host certificate check failed");
    }
}

/* The leaf certificate must name the host. */
static void wolfSSH_CertHostTest(void)
{
    /* DNS:example, IP Address:127.0.0.1, CN=www.wolfssl.com */
    const char* sanCert = "./keys/server-cert.der";
    /* No subjectAltName, CN=www.wolfssl.com */
    const char* cnCert = "./keys/ca-cert-ecc.der";
    /* email:server@example.com only, CN=www.wolfssl.com */
    const char* emailCert = "./keys/server-cert-email-san.der";

    printf("testing host certificate names\n");
    CertHostCheck(sanCert, "example", 0);
    CertHostCheck(sanCert, "EXAMPLE", 0);
#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME) || \
    (LIBWOLFSSL_VERSION_HEX >= 0x05009002)
    /* Older wolfSSL drops an IP SAN unless asked to keep it. */
    CertHostCheck(sanCert, "127.0.0.1", 0);
#endif
    CertHostCheck(sanCert, "127.0.0.2", -1);
    CertHostCheck(sanCert, "::ffff:127.0.0.1", -1);
    CertHostCheck(sanCert, "examples", -1);
    CertHostCheck(sanCert, "exampl", -1);
    /* A SAN rules out the CN. */
    CertHostCheck(sanCert, "www.wolfssl.com", -1);
    CertHostCheck(cnCert, "www.wolfssl.com", 0);
    CertHostCheck(cnCert, "example", -1);
    /* So does an email-only SAN. */
    CertHostCheck(emailCert, "www.wolfssl.com", -1);

    /* -X accepts a certificate for another host. */
    ClientIPOverride(1);
    CertHostCheck(sanCert, "127.0.0.2", 0);
    ClientIPOverride(0);

    /* -Y does not waive the certificate's name. */
    ClientAcceptAnyHostKey(1);
    CertHostCheck(sanCert, "127.0.0.2", -1);
    ClientAcceptAnyHostKey(0);
}
#endif


int wolfSSH_TestsuiteTest(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    WSTARTTCP();

    #if defined(DEBUG_WOLFSSH)
        wolfSSH_Debugging_ON();
    #endif

    wolfSSH_Init();

    #if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,2)
    {
        int i;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            wc_RunCast_fips(i);
        }
    }
    #endif /* HAVE_FIPS */

    #if !defined(WOLFSSL_TIRTOS)
        ChangeToWolfSshRoot();
    #endif

#if defined(WOLFSSH_CERTS) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSH_ZEPHYR)
    wolfSSH_CertHostTest();
#endif

#ifdef WOLFSSH_SHELL
    wolfSSH_EchoTest();
    wolfSSH_EchoTest_MultiPubKey();
#endif

    wolfSSH_Cleanup();

#ifdef WOLFSSH_SFTP
    printf("testing SFTP blocking\n");
    wolfSSH_SftpTest(0);
#ifndef WOLFSSH_NO_NONBLOCKING
    printf("testing SFTP non blocking\n");
    wolfSSH_SftpTest(1);
#endif
#endif
    return EXIT_SUCCESS;
}

#else /* !NO_WOLFSSH_SERVER && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */

int wolfSSH_TestsuiteTest(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    return EXIT_SUCCESS;
}

#endif /* !NO_WOLFSSH_SERVER && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */


