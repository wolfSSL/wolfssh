/* auth.c
 *
 * Copyright (C) 2025 wolfSSL Inc.
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssh/port.h>

#include <stdio.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#define WOLFSSH_TEST_CLIENT
#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_LOCKING
#ifndef SINGLE_THREADED
    #define WOLFSSH_TEST_THREADING
#endif
#include <wolfssh/test.h>
#include "tests/auth.h"

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

#define ES_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    serverArgs->return_code = ret; \
    WOLFSSL_RETURN_FROM_THREAD(0); \
} while(0)

#define EXAMPLE_KEYLOAD_BUFFER_SZ 1200

#ifdef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    #define ECC_PATH "./keys/server-key-ecc-521.der"
#else
    #define ECC_PATH "./keys/server-key-ecc.der"
#endif


#if !defined(NO_WOLFSSH_SERVER) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_TEST_BLOCK) && \
    !defined(NO_FILESYSTEM) && defined(WOLFSSH_KEYBOARD_INTERACTIVE)

const char *testText1 = "test";
const char *testText2 = "password";

byte *kbResponses[4];
word32 kbResponseLengths[4];
word32 kbResponseCount;
byte kbMultiRound = 0;
byte currentRound = 0;
byte unbalanced = 0;

WS_UserAuthData_Keyboard promptData;


static int load_file(const char* fileName, byte* buf, word32* bufSz)
{
    WFILE* file;
    word32 fileSz;
    word32 readSz;

    if (fileName == NULL) return 0;

    if (WFOPEN(NULL, &file, fileName, "rb") != 0)
        return 0;
    WFSEEK(NULL, file, 0, WSEEK_END);
    fileSz = (word32)WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (buf == NULL || fileSz > *bufSz) {
        *bufSz = fileSz;
        WFCLOSE(NULL, file);
        return 0;
    }

    readSz = (word32)WFREAD(NULL, buf, 1, fileSz, file);
    WFCLOSE(NULL, file);

    if (readSz < fileSz) {
        fileSz = 0;
    }

    return fileSz;
}

static int load_key(byte isEcc, byte* buf, word32 bufSz)
{
    word32 sz = 0;

#ifndef NO_FILESYSTEM
    const char* bufName;
    bufName = isEcc ? ECC_PATH : "./keys/server-key-rsa.der" ;
    sz = load_file(bufName, buf, &bufSz);
#else
    /* using buffers instead */
    if (isEcc) {
        if ((word32)sizeof_ecc_key_der_256_ssh > bufSz) {
            return 0;
        }
        WMEMCPY(buf, ecc_key_der_256_ssh, sizeof_ecc_key_der_256_ssh);
        sz = sizeof_ecc_key_der_256_ssh;
    }
    else {
        if ((word32)sizeof_rsa_key_der_2048_ssh > bufSz) {
            return 0;
        }
        WMEMCPY(buf, (byte*)rsa_key_der_2048_ssh, sizeof_rsa_key_der_2048_ssh);
        sz = sizeof_rsa_key_der_2048_ssh;
    }
#endif

    return sz;
}


static int serverUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    WS_UserAuthData_Keyboard* prompts = (WS_UserAuthData_Keyboard*)ctx;

    if (ctx == NULL) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType != WOLFSSH_USERAUTH_KEYBOARD &&
            authType != WOLFSSH_USERAUTH_KEYBOARD_SETUP) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType == WOLFSSH_USERAUTH_KEYBOARD_SETUP) {
        WMEMCPY(&authData->sf.keyboard, prompts,
            sizeof(WS_UserAuthData_Keyboard));
        return WS_SUCCESS;
    }

    if (authData->sf.keyboard.responseCount != kbResponseCount) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    for (word32 resp = 0; resp < kbResponseCount; resp++) {
        if (authData->sf.keyboard.responseLengths[resp] !=
                kbResponseLengths[resp]) {
            return WOLFSSH_USERAUTH_FAILURE;

        }
        if (WSTRNCMP((const char*)authData->sf.keyboard.responses[resp],
                    (const char*)kbResponses[resp],
                    kbResponseLengths[resp]) != 0) {
            return WOLFSSH_USERAUTH_FAILURE;
        }
    }
    if (kbMultiRound && currentRound == 0) {
        currentRound++;
        kbResponses[0] = (byte*)testText2;
        kbResponseLengths[0] = 8;
        return WOLFSSH_USERAUTH_SUCCESS_ANOTHER;
    }
    return WOLFSSH_USERAUTH_SUCCESS;
}

static INLINE void SignalTcpReady(tcp_ready* ready, word16 port)
{
    pthread_mutex_lock(&ready->mutex);
    ready->ready = 1;
    ready->port = port;
    pthread_cond_signal(&ready->cond);
    pthread_mutex_unlock(&ready->mutex);
}

static THREAD_RETURN WOLFSSH_THREAD server_thread(void* args)
{
    thread_args* serverArgs;
    int ret = WS_SUCCESS;
    word16 port = 0;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
    byte* keyLoadBuf;
    int peerEcc = 1;
    word32 bufSz;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    WS_SOCKET_T clientFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t     clientAddrSz = sizeof(clientAddr);

    serverArgs = (thread_args*) args;
    serverArgs->return_code = EXIT_SUCCESS;

    promptData.promptCount = kbResponseCount;
    promptData.promptName = NULL;
    promptData.promptNameSz = 0;
    promptData.promptInstruction = NULL;
    promptData.promptInstructionSz = 0;
    promptData.promptLanguage = NULL;
    promptData.promptLanguageSz = 0;
    if (kbResponseCount) {
        promptData.prompts =
            (byte**)WMALLOC(sizeof(byte*) * kbResponseCount, NULL, 0);
        if (promptData.prompts == NULL) {
            ES_ERROR("Could not allocate prompts");
        }
        promptData.promptLengths =
            (word32*)WMALLOC(sizeof(word32) * kbResponseCount, NULL, 0);
        if (promptData.promptLengths == NULL) {
            ES_ERROR("Could not allocate promptLengths");
        }
        promptData.promptEcho =
            (byte*)WMALLOC(sizeof(byte) * kbResponseCount, NULL, 0);
        if (promptData.promptEcho == NULL) {
            ES_ERROR("Could not allocate promptEcho");
        }
        for (word32 prompt = 0; prompt < kbResponseCount; prompt++) {
            promptData.prompts[prompt] = (byte*)"Password: ";
            promptData.promptLengths[prompt] = 10;
            promptData.promptEcho[prompt] = 0;
        }
    }
    else {
        promptData.prompts = NULL;
        promptData.promptLengths = NULL;
        promptData.promptEcho = NULL;
    }


    tcp_listen(&listenFd, &port, 1);
    SignalTcpReady(serverArgs->signal, port);

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        ES_ERROR("Couldn't allocate SSH CTX data.\n");
    }

    wolfSSH_SetUserAuth(ctx, serverUserAuth);
    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        ES_ERROR("Couldn't allocate SSH data.\n");
    }
    keyLoadBuf = buf;
    bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;
    wolfSSH_SetUserAuthCtx(ssh, &promptData);

    bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
    if (bufSz == 0) {
        ES_ERROR("Couldn't load first key file.\n");
    }
    if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
                                         WOLFSSH_FORMAT_ASN1) < 0) {
        ES_ERROR("Couldn't use first key buffer.\n");
    }

    clientFd = accept(listenFd, (struct sockaddr*)&clientAddr, &clientAddrSz);
    if (clientFd == -1) {
        ES_ERROR("tcp accept failed");
    }
    wolfSSH_set_fd(ssh, (int)clientFd);

    ret = wolfSSH_accept(ssh);
    if (ret && !unbalanced) {
        ES_ERROR("wolfSSH Accept Error");
    }

    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        /* fine on shutdown */
        ret = WS_SUCCESS;
#if DEFAULT_HIGHWATER_MARK < 8000
        if (ret == WS_REKEYING) {
            ret = WS_SUCCESS;
        }
#endif
    }
    if (promptData.promptCount > 0) {
        WFREE(promptData.promptLengths, NULL, 0);
        WFREE(promptData.prompts, NULL, 0);
        WFREE(promptData.promptEcho, NULL, 0);
    }


    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    if (ret) {
        ES_ERROR("wolfSSH Shutdown Error");
    }

    WOLFSSL_RETURN_FROM_THREAD(0);
}

static int keyboardUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    (void) ctx;
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_KEYBOARD) {
        AssertIntEQ(kbResponseCount, authData->sf.keyboard.promptCount);
        for (word32 prompt = 0; prompt < kbResponseCount; prompt++) {
            AssertStrEQ("Password: ", authData->sf.keyboard.prompts[prompt]);
        }

        authData->sf.keyboard.responseCount = kbResponseCount;
        if (unbalanced) {
            authData->sf.keyboard.responseCount++;
        }
        authData->sf.keyboard.responseLengths = kbResponseLengths;
        authData->sf.keyboard.responses = (byte**)kbResponses;
        ret = WS_SUCCESS;
    }
    return ret;
}

static int basic_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port)
{
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret = WS_SUCCESS;
    char* host = (char*)wolfSshIp;
    const char* username = "test";

    if (ctx == NULL || ssh == NULL) {
        return WS_BAD_ARGUMENT;
    }

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL) {
        return WS_BAD_ARGUMENT;
    }

    wolfSSH_SetUserAuth(*ctx, keyboardUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return WS_MEMORY_E;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0){
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        return ret;
    }

    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret != WS_SUCCESS) {
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        fprintf(stderr, "line= %d\n", __LINE__);
        return ret;
    }

    ret = wolfSSH_set_fd(*ssh, (int)sockFd);
    if (ret != WS_SUCCESS) {
        fprintf(stderr, "line= %d\n", __LINE__);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        WCLOSESOCKET(sockFd);
        return ret;
    }

    ret = wolfSSH_connect(*ssh);

    return ret;
}

static void test_client(void)
{
    int ret;
    thread_args serverArgs;
    tcp_ready ready;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    THREAD_TYPE serThread;
    WS_SOCKET_T clientFd;

    serverArgs.signal = &ready;
    InitTcpReady(serverArgs.signal);
    ThreadStart(server_thread, (void*)&serverArgs, &serThread);
    WaitTcpReady(&ready);

    ret = basic_client_connect(&ctx, &ssh, ready.port);

    /* for the unbalanced auth test */
    if (unbalanced) {
        AssertIntEQ(ret, WS_FATAL_ERROR);
    }
    else {
        AssertIntEQ(ret, WS_SUCCESS);
    }

    AssertNotNull(ctx);
    AssertNotNull(ssh);
    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        /* fine on shutdown */
        ret = WS_SUCCESS;
    }
#if DEFAULT_HIGHWATER_MARK < 8000
    if (ret == WS_REKEYING) {
        ret = WS_SUCCESS;
    }
#endif

    if (!unbalanced) {
        AssertIntEQ(ret, WS_SUCCESS);
    }


    /* close client socket down */
    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    ThreadJoin(serThread);
#if DEFAULT_HIGHWATER_MARK < 8000
    if (serverArgs.return_code == WS_REKEYING) {
        serverArgs.return_code = WS_SUCCESS;
    }
#endif
    if (!unbalanced) {
        AssertIntEQ(serverArgs.return_code, WS_SUCCESS);
    }
}

static void test_basic_KeyboardInteractive(void)
{
    printf("Testing single prompt / response\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;

    test_client();
}

static void test_empty_KeyboardInteractive(void)
{
    printf("Testing empty prompt / no response\n");
    kbResponses[0] = NULL;
    kbResponseLengths[0] = 0;
    kbResponseCount = 0;

    test_client();
}

static void test_multi_prompt_KeyboardInteractive(void)
{
    printf("Testing multiple prompts\n");
    kbResponses[0] = (byte*)testText1;
    kbResponses[1] = (byte*)testText2;
    kbResponseLengths[0] = 4;
    kbResponseLengths[1] = 8;
    kbResponseCount = 2;

    test_client();
}

static void test_multi_round_KeyboardInteractive(void)
{
    printf("Testing mutliple prompt rounds\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;
    kbMultiRound = 1;

    test_client();
    AssertIntEQ(currentRound, 1);
    currentRound = 0;
    kbMultiRound = 0;
}

static void test_unbalanced_client_KeyboardInteractive(void)
{
    printf("Testing too many responses\n");
    kbResponses[0] = (byte*)testText1;
    kbResponseLengths[0] = 4;
    kbResponseCount = 1;
    unbalanced = 1;

    test_client();
    unbalanced = 0;
}
#endif /* WOLFSSH_TEST_BLOCK */

int wolfSSH_AuthTest(int argc, char** argv)
{
    (void) argc;
    (void) argv;

#if defined(NO_WOLFSSH_SERVER) || defined(NO_WOLFSSH_CLIENT) || \
    defined(SINGLE_THREADED) || defined(WOLFSSH_TEST_BLOCK) || \
    defined(NO_FILESYSTEM) || !defined(WOLFSSH_KEYBOARD_INTERACTIVE)
    return 77;
#else

#if defined(DEBUG_WOLFSSH)
    wolfSSH_Debugging_ON();
#endif

    AssertIntEQ(wolfSSH_Init(), WS_SUCCESS);

    #if defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,2)
    {
        int i;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            AssertIntEQ(wc_RunCast_fips(i), WS_SUCCESS);
        }
    }
    #endif /* HAVE_FIPS */

    /* Add test calls here */
    test_basic_KeyboardInteractive();
    test_empty_KeyboardInteractive();
    test_multi_prompt_KeyboardInteractive();
    test_multi_round_KeyboardInteractive();
    test_unbalanced_client_KeyboardInteractive();

    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
#endif
}

#ifndef NO_AUTHTEST_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfSSH_AuthTest(argc, argv);
}
#endif


