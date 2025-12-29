/* kex.c
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
#include <wolfssh/internal.h>
#include <wolfssh/test.h>
#include "examples/echoserver/echoserver.h"
#include "examples/client/client.h"
#include "tests/kex.h"

#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif


#ifndef WOLFSSH_NO_ABORT
    #define WABORT() abort()
#else
    #define WABORT()
#endif

#define PrintError(description, result) do {                                   \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
} while(0)

#ifdef WOLFSSH_ZEPHYR
#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WABORT();                                                                  \
} while(0)
#else
#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WFFLUSH(stdout);                                                           \
    WABORT();                                                                  \
} while(0)
#endif

#define Assert(test, description, result) if (!(test)) Fail(description, result)

#define AssertTrue(x)    Assert( (x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert( (x), ("%s is not null", #x), (#x " => NULL"))

#define AssertNull(x) do {                                                     \
    PEDANTIC_EXTENSION void* _x = (void*)(x);                                  \
                                                                               \
    Assert(!_x, ("%s is null", #x), (#x " => %p", _x));                        \
} while(0)

#define AssertInt(x, y, op, er) do {                                           \
    int _x = (int)(x);                                                         \
    int _y = (int)(y);                                                         \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%d " #er " %d", _x, _y));    \
} while(0)

#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
#define AssertIntNE(x, y) AssertInt(x, y, !=, ==)
#define AssertIntGT(x, y) AssertInt(x, y,  >, <=)
#define AssertIntLT(x, y) AssertInt(x, y,  <, >=)
#define AssertIntGE(x, y) AssertInt(x, y, >=,  <)
#define AssertIntLE(x, y) AssertInt(x, y, <=,  >)

#define AssertStr(x, y, op, er) do {                                           \
    const char* _x = (const char*)(x);                                         \
    const char* _y = (const char*)(y);                                         \
    int         _z = (_x && _y) ? strcmp(_x, _y) : -1;                         \
    Assert(_z op 0, ("%s " #op " %s", #x, #y),                                 \
                                            ("\"%s\" " #er " \"%s\"", _x, _y));\
} while(0)

#define AssertStrEQ(x, y) AssertStr(x, y, ==, !=)
#define AssertStrNE(x, y) AssertStr(x, y, !=, ==)
#define AssertStrGT(x, y) AssertStr(x, y,  >, <=)
#define AssertStrLT(x, y) AssertStr(x, y,  <, >=)
#define AssertStrGE(x, y) AssertStr(x, y, >=,  <)
#define AssertStrLE(x, y) AssertStr(x, y, <=,  >)

#define AssertPtr(x, y, op, er) do {                                           \
    PRAGMA_GCC_DIAG_PUSH                                                       \
      /* remarkably, without this inhibition, */                               \
      /* the _Pragma()s make the declarations warn. */                         \
    PRAGMA_GCC("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")     \
      /* inhibit "ISO C forbids conversion of function pointer */              \
      /* to object pointer type [-Werror=pedantic]" */                         \
    PRAGMA_GCC("GCC diagnostic ignored \"-Wpedantic\"")                        \
    void* _x = (void*)(x);                                                     \
    void* _y = (void*)(y);                                                     \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%p " #er " %p", _x, _y));    \
    PRAGMA_GCC_DIAG_POP;                                                       \
} while(0)

#define AssertPtrEq(x, y) AssertPtr(x, y, ==, !=)
#define AssertPtrNE(x, y) AssertPtr(x, y, !=, ==)
#define AssertPtrGT(x, y) AssertPtr(x, y,  >, <=)
#define AssertPtrLT(x, y) AssertPtr(x, y,  <, >=)
#define AssertPtrGE(x, y) AssertPtr(x, y, >=,  <)
#define AssertPtrLE(x, y) AssertPtr(x, y, <=,  >)


#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK) && \
    !defined(WOLFSSH_NO_DH_GROUP16_SHA512) && !defined(WOLFSSH_NO_HMAC_SHA2_512)

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


#define NUMARGS 12
#define ARGLEN 32

/* 
 * Macro: ADD_ARG
 * Purpose: Adds a string argument to the argument list.
 * Parameters:
 *   - argList: The array of argument strings.
 *   - argListCount: The current count of arguments in the list (modified
 *     by the macro).
 *   - arg: The string argument to add.
 * Behavior:
 *   - Copies the string `arg` into the next available slot in `argList`.
 *   - Increments `argListCount` if the operation is successful.
 * Constraints:
 *   - The total number of arguments must not exceed `NUMARGS`.
 *   - Each argument string must not exceed `ARGLEN` characters.
 * Side effects:
 *   - Modifies `argList` and increments `argListCount`.
 */
#define ADD_ARG(argList,argListCount,arg) do { \
    if ((argListCount) < NUMARGS) \
        WSTRNCPY((argList)[(argListCount)++], (arg), ARGLEN); \
} while (0)

/* 
 * Macro: ADD_ARG_INT
 * Purpose: Adds an integer argument to the argument list as a string.
 * Parameters:
 *   - argList: The array of argument strings.
 *   - argListCount: The current count of arguments in the list (modified
 *     by the macro).
 *   - arg: The integer argument to add.
 * Behavior:
 *   - Converts the integer `arg` to a string and stores it in the next
 *     available slot in `argList`.
 *   - Increments `argListCount` if the operation is successful.
 * Constraints:
 *   - The total number of arguments must not exceed `NUMARGS`.
 *   - Each argument string must not exceed `ARGLEN` characters.
 * Side effects:
 *   - Modifies `argList` and increments `argListCount`.
 */
#define ADD_ARG_INT(argList,argListCount,arg) do { \
    if ((argListCount) < NUMARGS) \
        WSNPRINTF((argList)[(argListCount)++], ARGLEN, "%d", (arg)); \
} while (0)


static int wolfSSH_wolfSSH_Group16_512(void)
{
    tcp_ready ready;
    THREAD_TYPE serverThread;
    func_args serverArgs;
    func_args clientArgs;
    char sA[NUMARGS][ARGLEN];
    char *serverArgv[NUMARGS] =
        { sA[0], sA[1], sA[2], sA[3], sA[4], sA[5], sA[6], sA[7], sA[8], sA[9],
          sA[10], sA[11] };
    char cA[NUMARGS][ARGLEN];
    char *clientArgv[NUMARGS] =
        { cA[0], cA[1], cA[2], cA[3], cA[4], cA[5], cA[6], cA[7], cA[8], cA[9],
          cA[10], cA[11] };
    int serverArgc = 0;
    int clientArgc = 0;

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

    InitTcpReady(&ready);

    ADD_ARG(serverArgv, serverArgc, "echoserver");
    ADD_ARG(serverArgv, serverArgc, "-1");
    ADD_ARG(serverArgv, serverArgc, "-f");
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        ADD_ARG(serverArgv, serverArgc, "-p");
        ADD_ARG(serverArgv, serverArgc, "-0");
    #endif
    ADD_ARG(serverArgv, serverArgc, "-x");
    ADD_ARG(serverArgv, serverArgc, "diffie-hellman-group16-sha512");
    ADD_ARG(serverArgv, serverArgc, "-m");
    ADD_ARG(serverArgv, serverArgc, "hmac-sha2-512");
    ADD_ARG(serverArgv, serverArgc, "-c");
    ADD_ARG(serverArgv, serverArgc, "aes256-cbc");

    serverArgs.argc = serverArgc;
    serverArgs.argv = serverArgv;
    serverArgs.return_code = EXIT_SUCCESS;
    serverArgs.signal = &ready;
    serverArgs.user_auth = NULL;
    ThreadStart(echoserver_test, &serverArgs, &serverThread);
    WaitTcpReady(&ready);

    ADD_ARG(clientArgv, clientArgc, "client");
    ADD_ARG(clientArgv, clientArgc, "-u");
    ADD_ARG(clientArgv, clientArgc, "jill");
    ADD_ARG(clientArgv, clientArgc, "-C");
    ADD_ARG(clientArgv, clientArgc, "aes256-cbc");
    #if !defined(USE_WINDOWS_API) && !defined(WOLFSSH_ZEPHYR)
        ADD_ARG(clientArgv, clientArgc, "-p");
        ADD_ARG_INT(clientArgv, clientArgc, ready.port);
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

    if (clientArgs.return_code == WS_SOCKET_ERROR_E) {
        clientArgs.return_code = WS_SUCCESS;
    }
    if (serverArgs.return_code == WS_SOCKET_ERROR_E) {
        serverArgs.return_code = WS_SUCCESS;
    }
#if DEFAULT_HIGHWATER_MARK < 8000
    if (serverArgs.return_code == WS_REKEYING) {
        serverArgs.return_code = WS_SUCCESS;
    }
    if (serverArgs.return_code == WS_REKEYING) {
        serverArgs.return_code = WS_SUCCESS;
    }
#endif
    /* Socket error may printf, but this is fine */
    AssertIntEQ(WS_SUCCESS, clientArgs.return_code);
    AssertIntEQ(WS_SUCCESS, serverArgs.return_code);

    FreeTcpReady(&ready);

    return EXIT_SUCCESS;
}

#endif

int wolfSSH_KexTest(int argc, char** argv)
{
    (void)argc;
    (void)argv;


#if defined(NO_WOLFSSH_SERVER) || defined(NO_WOLFSSH_CLIENT) || \
    defined(SINGLE_THREADED) || defined(WOLFSSH_TEST_BLOCK)
    return 77;
#else
    AssertIntEQ(wolfSSH_Init(), WS_SUCCESS);

    #if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,2)
    {
        int i;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            AssertIntEQ(wc_RunCast_fips(i), WS_SUCCESS);
        }
    }
    #endif /* HAVE_FIPS */

#if !defined(WOLFSSH_NO_DH_GROUP16_SHA512) && !defined(WOLFSSH_NO_HMAC_SHA2_512)
    wolfSSH_wolfSSH_Group16_512();
#endif

    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
#endif
}


#ifndef NO_TESTSUITE_MAIN_DRIVER

int main(int argc, char** argv)
{
    return wolfSSH_KexTest(argc, argv);
}


int myoptind = 0;
char* myoptarg = NULL;

#endif /* !NO_TESTSUITE_MAIN_DRIVER */
