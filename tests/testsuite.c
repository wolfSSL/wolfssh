/* testsuite.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#define WOLFSSH_TEST_CLIENT
#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_THREADING
#define WOLFSSH_TEST_LOCKING


#include <stdio.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/settings.h>
#include <wolfssh/ssh.h>
#include <wolfssh/test.h>
#include "examples/echoserver/echoserver.h"
#include "examples/client/client.h"
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


#define NUMARGS 5
#define ARGLEN 32

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
        { cA[0], cA[1], cA[2], cA[3], cA[4] };
    int serverArgc = 0;
    int clientArgc = 0;

    InitTcpReady(&ready);

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

    wolfSSH_EchoTest();

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


