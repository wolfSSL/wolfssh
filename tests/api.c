/* api.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssh/port.h>

#include <stdio.h>
#include <string.h>
#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(WOLFSSH_ZEPHYR) && \
    !defined(USE_WINDOWS_API)
    /* mkdtemp() for staging unique, per-test out-of-jail SFTP fixtures and
     * symlink() for the symlink-escape confinement case */
    #include <stdlib.h>
    #include <unistd.h>
#endif
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#ifdef WOLFSSH_SCP
    #include <wolfssh/wolfscp.h>
#endif
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif

#if defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP)
    #define WOLFSSH_TEST_LOCKING
    #ifndef SINGLE_THREADED
        #define WOLFSSH_TEST_THREADING
    #endif
    #define WOLFSSH_TEST_SERVER
    #define WOLFSSH_TEST_ECHOSERVER
#endif
#ifndef WOLFSSH_TEST_BLOCK
    #define WOLFSSH_TEST_HEX2BIN
#endif
#include <wolfssh/test.h>
#include "tests/api.h"
#ifdef WOLFSSH_TEST_ECHOSERVER
    #include "examples/echoserver/echoserver.h"
#endif

/* for echoserver test cases */
int myoptind = 0;
char* myoptarg = NULL;


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

#define AssertNotNull(x) do {                                                  \
    PEDANTIC_EXTENSION void* _isNotNull = (void*)(x);                          \
    Assert(_isNotNull, ("%s is not null", #x), (#x " => NULL"));               \
} while (0)

#define AssertNull(x) do {                                                     \
    PEDANTIC_EXTENSION void* _isNull = (void*)(x);                             \
    Assert(!_isNull, ("%s is null", #x), (#x " => %p", _isNull));              \
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


#ifndef WOLFSSH_TEST_BLOCK

enum WS_TestEndpointTypes {
    TEST_GOOD_ENDPOINT_SERVER = WOLFSSH_ENDPOINT_SERVER,
    TEST_GOOD_ENDPOINT_CLIENT = WOLFSSH_ENDPOINT_CLIENT,
    TEST_BAD_ENDPOINT_NEXT,
    TEST_BAD_ENDPOINT_LAST = 255
};

static void test_wolfSSH_CTX_new(void)
{
    WOLFSSH_CTX* ctx;

    AssertNull(ctx = wolfSSH_CTX_new(TEST_BAD_ENDPOINT_NEXT, NULL));
    wolfSSH_CTX_free(ctx);

    AssertNull(ctx = wolfSSH_CTX_new(TEST_BAD_ENDPOINT_LAST, NULL));
    wolfSSH_CTX_free(ctx);

    AssertNotNull(ctx = wolfSSH_CTX_new(TEST_GOOD_ENDPOINT_SERVER, NULL));
    wolfSSH_CTX_free(ctx);

    AssertNotNull(ctx = wolfSSH_CTX_new(TEST_GOOD_ENDPOINT_CLIENT, NULL));
    wolfSSH_CTX_free(ctx);
}


static void test_server_wolfSSH_new(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;

    AssertNull(ssh = wolfSSH_new(NULL));
    wolfSSH_free(ssh);

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


static void test_client_wolfSSH_new(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;

    AssertNull(ssh = wolfSSH_new(NULL));
    wolfSSH_free(ssh);

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


static void test_wolfSSH_set_fd(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    WS_SOCKET_T fd = 23, check;

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));

    AssertIntNE(WS_SUCCESS, wolfSSH_set_fd(NULL, fd));
    check = wolfSSH_get_fd(NULL);
    AssertFalse(WS_SUCCESS == check);

    AssertIntEQ(WS_SUCCESS, wolfSSH_set_fd(ssh, fd));
    check = wolfSSH_get_fd(ssh);
    AssertTrue(fd == check);
    AssertTrue(0 != check);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


static void test_wolfSSH_SetUsername(void)
{
#ifndef WOLFSSH_NO_CLIENT
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    const char username[] = "johnny";
    const char empty[] = "";
    const char* name = NULL;

    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(NULL, NULL));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsernameRaw(NULL, NULL, 0));

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntEQ(WS_SUCCESS, wolfSSH_SetUsername(ssh, username));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(ssh, NULL));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(ssh, empty));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsernameRaw(ssh, NULL, 0));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsernameRaw(ssh, NULL, 23));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsernameRaw(ssh,
                (const byte*)empty, 0));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsernameRaw(ssh,
                (const byte*)username, 0));
    wolfSSH_free(ssh);
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntEQ(WS_SUCCESS, wolfSSH_SetUsername(ssh, username));
    AssertIntEQ(WS_SUCCESS, wolfSSH_SetUsernameRaw(ssh,
                (const byte*)username, (word32)strlen(username)));
    AssertNotNull((name = wolfSSH_GetUsername(ssh)));
    AssertIntEQ(0, strcmp(username, name));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#endif /* WOLFSSH_NO_CLIENT */
}


enum WS_TestFormatTypes {
    TEST_GOOD_FORMAT_ASN1 = WOLFSSH_FORMAT_ASN1,
    TEST_GOOD_FORMAT_PEM = WOLFSSH_FORMAT_PEM,
    TEST_GOOD_FORMAT_RAW = WOLFSSH_FORMAT_RAW,
    TEST_BAD_FORMAT_NEXT,
    TEST_BAD_FORMAT_LAST = 0xFFFF
};


#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static const char serverKeyEccDer[] =
    "307702010104206109990b79d25f285a0f5d15cca15654f92b3987212da77d85"
    "7bb87f38c66dd5a00a06082a8648ce3d030107a144034200048113ffa42bb79c"
    "45747a834c61f33fad26cf22cda9a3bca561b47ce662d4c2f755439a31fb8011"
    "20b5124b24f578d7fd22ef4635f005586b5f63c8da1bc4f569";
static const byte serverKeyEccCurveId = ID_ECDSA_SHA2_NISTP256;
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384)
static const char serverKeyEccDer[] =
    "3081a402010104303eadd2bbbf05a7be3a3f7c28151289de5bb3644d7011761d"
    "b56f2a0362fba64f98e64ff986dc4fb8efdb2d6b8da57142a00706052b810400"
    "22a1640362000438d62be418ff573fd0e020d48876c4e1121dfb2d6ebee4895d"
    "7724316d46a23105873f2986d5c712803a6f471ab86850eb063e108961349cf8"
    "b4c6a4cf5e97bd7e51e975e3e9217261506eb9cf3c493d3eb88d467b5f27ebab"
    "2161c00066febd";
static const byte serverKeyEccCurveId = ID_ECDSA_SHA2_NISTP384;
#elif !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
static const char serverKeyEccDer[] =
    "3081dc0201010442004ca4d86428d9400e7b2df3912eb996c195895043af92e8"
    "6de70ae4df46f22a291a6bb2748aae82580df6c39f49b3ed82f1789ece1b657d"
    "45438cff156534354575a00706052b81040023a18189038186000401f8d0a7c3"
    "c58d841957969f213a94f3da550edf76d8dd171531f35bb069c8bc300d6f6b37"
    "d18046a9717f2c6f59519c827095b29a6313306218c235769400d0f96d000a19"
    "3ba346652beb409a9a45c597a3ed932dd5aaae96bf2f317e5a7ac7458b3c6cdb"
    "aa90c355382cdfcdca7377d92eb20a5e8c74237ca5a345b19e3f1a2290b154";
static const byte serverKeyEccCurveId = ID_ECDSA_SHA2_NISTP521;
#endif

#ifndef WOLFSSH_NO_RSA
static const char serverKeyRsaDer[] =
    "308204a30201000282010100da5dad2514761559f340fd3cb86230b36dc0f9ec"
    "ec8b831e9e429cca416ad38ae15234e00d13627ed40fae5c4d04f18dfac5ad77"
    "aa5a05caeff88dabff8a29094c04c2f519cbed1fb1b429d3c36ca923dfa3a0e5"
    "08dead8c71f934886ced3bf06fa50fac59ff6b33f170fb8ca4b345228d9d777a"
    "e5295f8414d999eaeace2d51f3e358fa5b020fc9b52abcb25ed3c230bb3cb1c3"
    "ef58f35094288bc4654af700d997d96b4d8d95a18a6206b450112283b4ea2ae7"
    "d0a820474fff46aec513e1388bf854af3a4d2ff81fd78490d8930506c27d90db"
    "e39cd0c4655a03ad00ac5aa2cdda3f89583753bf2b467aac89412b5a2ee876e7"
    "5ee32985a363eae686607c2d02030100010281ff0f911e06c6aea45705405ccd"
    "3757c8a101f1ffdf23fdce1b20ad1f004c29916b1525071ff1ceaff6daa74386"
    "d0f6c94195df01bec62624c392d7e5419db5fbb6edf468f19025398248e8cf12"
    "899bf572d93e90f9c2e81cf72628ddd5dbee0d97d65dae005b6a19fa59fbf3f2"
    "d2caf4e2c1b5b80ecac76847c234c1043e38f4820159f28a6ef76b5b0abc05a9"
    "2737b9f9068054e8701ab432936bf526c786f4580543f9728fec42a03bba3562"
    "ccecf4b304a2ebae3c87408efe8fdd14bebd83c9c918ca817c06f9e3992eec29"
    "c52756ea1e93c6e80c44ca73684a7fae16251d1225142aec416925c35de6aee4"
    "59801dfabd9f3336939d88d688c95b277b0b6102818100de01abfa65d2fad26f"
    "fe3f576d757f8ce6bdfe08bdc71334620e87b27a2ca9cdca93d83191812dd668"
    "96aa25e3b87ea598a8e8153cc0cedef5ab80b1f5baafac9cc1b34334ae22f718"
    "418663a2448e1b419d2d756f0d5b10195d14aa801fee023ef8b6f6ec658e3889"
    "0d0b50e41149863982db73e53a0f1322abada0789b942102818100fbcd4c5249"
    "3f2c8094914a38ec0f4a7d3a8ebc0490152584fbd368bdefa047fece5bbf1d2a"
    "9427fc5170ffc9e9babe2ba05025d3e1a15733cc5cc77d09f6dcfb72943dca59"
    "5273e06c450ad9da30df2b33d752184101f0df1b01c1d3b79b26f81c8fffc819"
    "fd36d013a57242a3305957b4da2a09e5455a396d70220cba53268d02818100b1"
    "3cc270f093c43cf6be1311984882e11961bb0a7d800e3bf6c0c4e2df19032351"
    "44410829b2e8c650cf5fdd49f503deee86826a5a0b4fdcbe63022691184ea1ce"
    "aff18e88e330f4f5ff71ebdf233e145288ca3f03beb4e1a06e284e8a65735d85"
    "aa885f8f90f03f006352926cd1c4520d5e04177d7ca186545a9d0e0cdba02102"
    "818100eafe1b9e27b1876cb03a2f9493e9695119971facfa7261c38be92eb523"
    "aee7c1cb002089adb4fae4257559a22c3915454da5bec7d0a86be371739cd0fa"
    "bda25a20026cf02d1020086fc2b76fbc8b239b04148d0f098c302966e0eaed15"
    "4afcc14c96aed5263c042d88483d2c2773f5cd3e80e3febc334f128d29bafd39"
    "de63f9028181008b1f47a2904b823b892de96be128e5228783d0de1e0d8ccc84"
    "433d238d9d6cbcc4c6da44447920b63eefcf8ac438b0e5da45ac5acc7b62baa9"
    "731fba275c82f8ad311edef33772cb47d2cdf7f87f0039db8d2aca4ec1cee215"
    "89d63a61ae9da230a585ae38ea4674dc023aace95fa3c6734f73819056c3ce77"
    "5f5bba6c42f121";
#endif


static void test_wolfSSH_CTX_UsePrivateKey_buffer(void)
{
#ifndef WOLFSSH_NO_SERVER
    WOLFSSH_CTX* ctx;
#ifndef WOLFSSH_NO_ECDSA
    byte* eccKey;
    word32 eccKeySz;
#endif
#ifndef WOLFSSH_NO_RSA
    byte* rsaKey;
    word32 rsaKeySz;
#endif
    const byte* lastKey = NULL;
    word32 lastKeySz = 0;
    int i;

#ifndef WOLFSSH_NO_ECC
    AssertIntEQ(0,
            ConvertHexToBin(serverKeyEccDer, &eccKey, &eccKeySz,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL));
#endif
#ifndef WOLFSSH_NO_RSA
    AssertIntEQ(0,
            ConvertHexToBin(serverKeyRsaDer, &rsaKey, &rsaKeySz,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL,
                    NULL, NULL, NULL));
#endif

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    for (i = 0; i < WOLFSSH_MAX_PVT_KEYS; i++) {
        AssertNull(ctx->privateKey[i].key);
        AssertIntEQ(0, ctx->privateKey[i].keySz);
        AssertIntEQ(ID_NONE, ctx->privateKey[i].publicKeyFmt);
    }
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Fail: all NULL/BAD */
    AssertIntNE(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(NULL, NULL, 0, TEST_BAD_FORMAT_NEXT));
    AssertNull(ctx->privateKey[0].key);
    AssertIntEQ(0, ctx->privateKey[0].keySz);
    AssertIntEQ(ID_NONE, ctx->privateKey[0].publicKeyFmt);
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Fail: ctx set, others NULL/bad */
    AssertIntNE(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, NULL, 0, TEST_BAD_FORMAT_NEXT));
    AssertNull(ctx->privateKey[0].key);
    AssertIntEQ(0, ctx->privateKey[0].keySz);
    AssertIntEQ(ID_NONE, ctx->privateKey[0].publicKeyFmt);
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Fail: ctx set, key set, others bad */
    AssertIntNE(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx,
                                         lastKey, 0, TEST_BAD_FORMAT_NEXT));
    AssertNull(ctx->privateKey[0].key);
    AssertIntEQ(0, ctx->privateKey[0].keySz);
    AssertIntEQ(ID_NONE, ctx->privateKey[0].publicKeyFmt);
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Fail: ctx set, keySz set, others NULL/bad */
    AssertIntNE(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, NULL, 1, TEST_BAD_FORMAT_NEXT));
    AssertNull(ctx->privateKey[0].key);
    AssertIntEQ(0, ctx->privateKey[0].keySz);
    AssertIntEQ(ID_NONE, ctx->privateKey[0].publicKeyFmt);
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Fail: ctx set, key set, keySz set, format invalid */
    AssertIntNE(WS_SUCCESS, wolfSSH_CTX_UsePrivateKey_buffer(ctx,
                lastKey, lastKeySz, TEST_GOOD_FORMAT_PEM));
    AssertNull(ctx->privateKey[0].key);
    AssertIntEQ(0, ctx->privateKey[0].keySz);
    AssertIntEQ(ID_NONE, ctx->privateKey[0].publicKeyFmt);
    AssertIntEQ(0, ctx->privateKeyCount);

    /* Pass */
#if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
    lastKey = ctx->privateKey[ctx->privateKeyCount].key;
    lastKeySz = ctx->privateKey[ctx->privateKeyCount].keySz;

    AssertIntEQ(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, eccKey, eccKeySz,
                                         TEST_GOOD_FORMAT_ASN1));
    AssertIntEQ(1, ctx->privateKeyCount);
    AssertNotNull(ctx->privateKey[0].key);
    AssertIntNE(0, ctx->privateKey[0].keySz);
    AssertIntEQ(serverKeyEccCurveId, ctx->privateKey[0].publicKeyFmt);

    AssertIntEQ(0, (lastKey == ctx->privateKey[0].key));
    AssertIntNE(lastKeySz, ctx->privateKey[0].keySz);
#endif

#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    lastKey = ctx->privateKey[ctx->privateKeyCount].key;
    lastKeySz = ctx->privateKey[ctx->privateKeyCount].keySz;

    AssertIntEQ(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, rsaKey, rsaKeySz,
                                         TEST_GOOD_FORMAT_ASN1));
    AssertIntNE(0, ctx->privateKeyCount);
    AssertNotNull(ctx->privateKey[0].key);
    AssertIntNE(0, ctx->privateKey[0].keySz);

    AssertIntEQ(0, (lastKey == ctx->privateKey[0].key));
    AssertIntNE(lastKeySz, ctx->privateKey[0].keySz);
#endif

    /* Add the same keys again. This should succeed. */
#if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
    AssertIntEQ(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, eccKey, eccKeySz,
                                         TEST_GOOD_FORMAT_ASN1));
#endif
#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    AssertIntEQ(WS_SUCCESS,
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, rsaKey, rsaKeySz,
                                         TEST_GOOD_FORMAT_ASN1));
#endif

    wolfSSH_CTX_free(ctx);
#if !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP384) || \
    !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP521)
    FreeBins(eccKey, NULL, NULL, NULL);
#endif
#ifndef WOLFSSH_NO_RSA
    FreeBins(rsaKey, NULL, NULL, NULL);
#endif
#endif /* WOLFSSH_NO_SERVER */
}


#ifdef WOLFSSH_CERTS
static int load_file(const char* filename, byte** buf, word32* bufSz)
{
    FILE* f = NULL;
    int ret = 0;

    if (filename == NULL || buf == NULL || bufSz == NULL)
        ret = -1;

    if (ret == 0) {
        f = fopen(filename, "rb");
        if (f == NULL)
            ret = -2;
    }

    if (ret == 0) {
        ret = fseek(f, 0, XSEEK_END);
        if (ret < 0)
            ret = -3;
    }

    if (ret == 0) {
        long sz = ftell(f);
        if (sz < 0)
            ret = -4;
        else
            *bufSz = (word32)sz;
    }

    if (ret == 0) {
        ret = fseek(f, 0, XSEEK_SET);
        if (ret < 0)
            ret = -8;
    }

    if (ret == 0) {
        *buf = (byte*)malloc(*bufSz);
        if (*buf == NULL)
            ret = -5;
    }

    if (ret == 0) {
        size_t readSz;
        readSz = fread(*buf, 1, *bufSz, f);
        if (readSz < *bufSz)
            ret = -6;
    }

    if (f != NULL) {
        ret = fclose(f);
        if (ret < 0)
            ret = -7;
    }

    return ret;
}
#endif


static void test_wolfSSH_CTX_UseCert_buffer(void)
{
#ifdef WOLFSSH_CERTS

    WOLFSSH_CTX* ctx = NULL;
    byte* cert = NULL;
    word32 certSz = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    AssertIntEQ(0, load_file("./keys/server-cert.pem", &cert, &certSz));
    AssertNotNull(cert);
    AssertIntNE(0, certSz);

    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_UseCert_buffer(NULL, cert, certSz, WOLFSSH_FORMAT_PEM));
    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_UseCert_buffer(ctx, NULL, certSz, WOLFSSH_FORMAT_PEM));
    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_UseCert_buffer(ctx, NULL, 0, WOLFSSH_FORMAT_PEM));

    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, WOLFSSH_FORMAT_PEM));

    AssertIntEQ(WS_BAD_FILETYPE_E,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, WOLFSSH_FORMAT_ASN1));
    AssertIntEQ(WS_BAD_FILETYPE_E,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, WOLFSSH_FORMAT_RAW));
    AssertIntEQ(WS_BAD_FILETYPE_E,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, 99));

    free(cert);
    cert = NULL;

    AssertIntEQ(0, load_file("./keys/server-cert.der", &cert, &certSz));
    AssertNotNull(cert);
    AssertIntNE(0, certSz);

    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, WOLFSSH_FORMAT_ASN1));

    wolfSSH_CTX_free(ctx);
    free(cert);
#endif /* WOLFSSH_CERTS */
}


static void test_wolfSSH_CTX_UsePrivateKey_buffer_pem(void)
{
#if defined(WOLFSSH_CERTS) && !defined(WOLFSSH_NO_SERVER)
    WOLFSSH_CTX* ctx = NULL;
    byte* key = NULL;
    word32 keySz = 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

#ifndef WOLFSSH_NO_RSA
    AssertIntEQ(0, load_file("./keys/server-key-rsa.pem", &key, &keySz));
    AssertNotNull(key);
    AssertIntNE(0, keySz);

    /* PEM private key should load successfully */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UsePrivateKey_buffer(ctx, key, keySz,
                                             WOLFSSH_FORMAT_PEM));

    free(key);
    key = NULL;
#endif /* WOLFSSH_NO_RSA */

#ifndef WOLFSSH_NO_ECDSA
    AssertIntEQ(0, load_file("./keys/server-key-ecc.pem", &key, &keySz));
    AssertNotNull(key);
    AssertIntNE(0, keySz);

    /* PEM ECC private key should load successfully */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UsePrivateKey_buffer(ctx, key, keySz,
                                             WOLFSSH_FORMAT_PEM));

    free(key);
    key = NULL;
#endif /* WOLFSSH_NO_ECDSA */

    wolfSSH_CTX_free(ctx);
#endif /* WOLFSSH_CERTS && !WOLFSSH_NO_SERVER */
}


static void test_wolfSSH_CTX_SetWindowPacketSize(void)
{
    WOLFSSH_CTX* ctx = NULL;

    /* NULL ctx must be rejected. */
    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_SetWindowPacketSize(NULL, 0, 0));

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Both zero: should default without error. */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_SetWindowPacketSize(ctx, 0, 0));

    /* windowSz exactly at upper bound: must succeed and be stored. */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_SetWindowPacketSize(ctx, WINDOW_SZ_UPPER_BOUND, 0));
    AssertIntEQ(WINDOW_SZ_UPPER_BOUND, (int)ctx->windowSz);

    /* windowSz one above upper bound: must fail. */
    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_SetWindowPacketSize(ctx,
                    WINDOW_SZ_UPPER_BOUND + 1, 0));

    /* maxPacketSz exactly at transport limit: must succeed and be stored. */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_SetWindowPacketSize(ctx, 0, MAX_PACKET_SZ));
    AssertIntEQ(MAX_PACKET_SZ, (int)ctx->maxPacketSz);

    /* maxPacketSz one above transport limit: must fail. */
    AssertIntEQ(WS_BAD_ARGUMENT,
            wolfSSH_CTX_SetWindowPacketSize(ctx, 0, MAX_PACKET_SZ + 1));

    /* Both valid non-zero values: must succeed and be stored. */
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_SetWindowPacketSize(ctx,
                    DEFAULT_WINDOW_SZ, DEFAULT_MAX_PACKET_SZ));
    AssertIntEQ(DEFAULT_WINDOW_SZ, (int)ctx->windowSz);
    AssertIntEQ(DEFAULT_MAX_PACKET_SZ, (int)ctx->maxPacketSz);

    wolfSSH_CTX_free(ctx);
}


static void test_wolfSSH_CertMan(void)
{
#ifdef WOLFSSH_CERTMAN
    /* This chunk of test is checking the innards of the WOLFSSH_CERTMAN
     * struct which has a private declaration at the moment. */
    {
        WOLFSSH_CERTMAN* cm = NULL;

        cm = wolfSSH_CERTMAN_new(NULL);
        AssertNotNull(cm);
        AssertNull(cm->heap);

        wolfSSH_CERTMAN_free(cm);
    }
    {
        WOLFSSH_CERTMAN cm;
        WOLFSSH_CERTMAN* cmRef;
        byte fakeHeap[32];

        cmRef = wolfSSH_CERTMAN_init(&cm, NULL);
        AssertNotNull(cmRef);
        AssertNull(cmRef->heap);

        cmRef = wolfSSH_CERTMAN_init(&cm, fakeHeap);
        AssertNotNull(cmRef);
        AssertNotNull(cmRef->heap);
        AssertEQ(cmRef->heap, fakeHeap);
    }
#endif /* WOLFSSH_CERTMAN */

#ifdef WOLFSSH_CERTS
    {
        /* VerifyCerts_buffer must reject certsCount == 0; otherwise the
         * inner loops short-circuit and the function returns WS_SUCCESS
         * without verifying anything. */
        WOLFSSH_CERTMAN* cm;
        unsigned char dummy[1] = { 0 };

        cm = wolfSSH_CERTMAN_new(NULL);
        AssertNotNull(cm);

        AssertIntEQ(WS_BAD_ARGUMENT,
                wolfSSH_CERTMAN_VerifyCerts_buffer(cm, dummy, sizeof(dummy), 0));
        AssertIntEQ(WS_BAD_ARGUMENT,
                wolfSSH_CERTMAN_VerifyCerts_buffer(NULL, dummy, sizeof(dummy), 1));
        AssertIntEQ(WS_BAD_ARGUMENT,
                wolfSSH_CERTMAN_VerifyCerts_buffer(cm, NULL, 0, 1));

        wolfSSH_CERTMAN_free(cm);
    }
#endif /* WOLFSSH_CERTS */
}


#define KEY_BUF_SZ 2048

#ifndef WOLFSSH_NO_RSA

const char id_rsa[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
    "NhAAAAAwEAAQAAAQEAy2cigZDlpBT+X2MJHAoHnfeFf6+LHm6BDkAT8V9ejHA4dY0Aepb6\n"
    "NbV6u/oYZlueKPeAZ3GNztR9szoL6FSlMvkd9oqvfoxjTGu71T0981ybJelqqGATGtevHU\n"
    "6Jko/I0+lgSQFKWQJ7D3Dj2zlZpIXB2Q7xl/i9kFZgaIqFhUHdWO9JMOwCFwoDrhd8v5xk\n"
    "y1v3OIIZDxiYxVIKbf2J07WbwiSFAxXfiX8TjUBDLFmtqt1AF6LjAyGyaRICXkaGJQ/QJ9\n"
    "sX85h9bkiPlGNAtQGQtNUg3tC9GqOkZ9tCKY1Efh/r0zosOA7ufxg6ymLpq1C4LU/4ENGH\n"
    "kuRPAKvu8wAAA8gztJfmM7SX5gAAAAdzc2gtcnNhAAABAQDLZyKBkOWkFP5fYwkcCged94\n"
    "V/r4seboEOQBPxX16McDh1jQB6lvo1tXq7+hhmW54o94BncY3O1H2zOgvoVKUy+R32iq9+\n"
    "jGNMa7vVPT3zXJsl6WqoYBMa168dTomSj8jT6WBJAUpZAnsPcOPbOVmkhcHZDvGX+L2QVm\n"
    "BoioWFQd1Y70kw7AIXCgOuF3y/nGTLW/c4ghkPGJjFUgpt/YnTtZvCJIUDFd+JfxONQEMs\n"
    "Wa2q3UAXouMDIbJpEgJeRoYlD9An2xfzmH1uSI+UY0C1AZC01SDe0L0ao6Rn20IpjUR+H+\n"
    "vTOiw4Du5/GDrKYumrULgtT/gQ0YeS5E8Aq+7zAAAAAwEAAQAAAQEAvbdBiQXkGyn1pHST\n"
    "/5IfTqia3OCX6td5ChicQUsJvgXBs2rDopQFZmkRxBjd/0K+/0jyfAl/EgZCBBRFHPsuZp\n"
    "/S4ayzSV6aE6J8vMT1bnLWxwKyl7+csjGwRK6HRKtVzsnjI9TPSrw0mc9ax5PzV6/mgZUd\n"
    "o/i+nszh+UASj5mYrBGqMiINspzX6YC+qoUHor3rEJOd9p1aO+N5+1fDKiDnlkM5IO0Qsz\n"
    "GktuwL0fzv9zBnGfnWVJz3CorfP1OW5KCtrDn7BnkQf1eBeVLzq/uoglUjS4DNnVfLA67D\n"
    "O4ZfwtnoW8Gr2R+KdvnypvHnDeY5X51r5PDgL4+7z47pWQAAAIBNFcAzHHE19ISGN8YRHk\n"
    "23/r/3zfvzHU68GSKR1Xj/Y4LSdRTpSm3wBrdQ17f5B4V7RVl2CJvoPekTggnBDQlLJ7fU\n"
    "NU93/nZrY9teYdrNh03buL54VVb5tUM+KN+27zERlTj0/LmYJupN97sZXmlgKsvLbcsnM2\n"
    "i7HuQQaFnsIQAAAIEA5wqFVatT9yovt8pS7rAyYUL/cqc50TZ/5Nwfy5uasRyf1BphHwEW\n"
    "LEimBemVc+VrNwAkt6MFWuloK5ssqb1ubvtRI8Mntd15rRfZtq/foS3J8FJxueXLDWlECy\n"
    "PmVyfVN1Vv4ZeirBy9BTYLiSuxMes+HYks3HucQhxIN1j8SA0AAACBAOFgRjfWXv1/93Jp\n"
    "6CCJ5c98MWP+zu1FbLIlklxPb85osZqlazXHNPPEtblC4z+OqRGMCsv2683anU4ZzcTFIk\n"
    "JS3lzeJ3tdAH4osQ5etKkV4mcdCmeRpjudB9VbaziVhPX02qkPWpM0ckPrgB3hVNUDPz89\n"
    "GtJd3mlhyY5IfFL/AAAADWJvYkBsb2NhbGhvc3QBAgMEBQ==\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

const char id_rsa_pub[] =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLZyKBkOWkFP5fYwkcCged94V/r4seboEO"
    "QBPxX16McDh1jQB6lvo1tXq7+hhmW54o94BncY3O1H2zOgvoVKUy+R32iq9+jGNMa7vVPT3z"
    "XJsl6WqoYBMa168dTomSj8jT6WBJAUpZAnsPcOPbOVmkhcHZDvGX+L2QVmBoioWFQd1Y70kw"
    "7AIXCgOuF3y/nGTLW/c4ghkPGJjFUgpt/YnTtZvCJIUDFd+JfxONQEMsWa2q3UAXouMDIbJp"
    "EgJeRoYlD9An2xfzmH1uSI+UY0C1AZC01SDe0L0ao6Rn20IpjUR+H+vTOiw4Du5/GDrKYumr"
    "ULgtT/gQ0YeS5E8Aq+7z bob@localhost\n";

#endif /* WOLFSSH_NO_RSA */

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256

const char id_ecdsa[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTAqdBgCp8bYSq2kQQ48/Ud8Iy6Mjnb\n"
    "/fpB3LfSE/1kx9VaaE4FL3i9Gg2vDV0eLGM3PWksFNPhULxtcYJyjaBjAAAAqJAeleSQHp\n"
    "XkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCp0GAKnxthKraR\n"
    "BDjz9R3wjLoyOdv9+kHct9IT/WTH1VpoTgUveL0aDa8NXR4sYzc9aSwU0+FQvG1xgnKNoG\n"
    "MAAAAgPrOgktioNqad/wHNC/rt/zVrpNqDnOwg9tNDFMOTwo8AAAANYm9iQGxvY2FsaG9z\n"
    "dAECAw==\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

const char id_ecdsa_pub[] =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABB"
    "BMCp0GAKnxthKraRBDjz9R3wjLoyOdv9+kHct9IT/WTH1VpoTgUveL0aDa8NXR4sYzc9aSwU"
    "0+FQvG1xgnKNoGM= bob@localhost\n";

/* Same as id_ecdsa but with the last pad byte changed from 0x03 to 0x04,
 * so the padding sequence 1,2,3 is broken at position 3. */
const char id_ecdsa_bad_pad[] =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"
    "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTAqdBgCp8bYSq2kQQ48/Ud8Iy6Mjnb\n"
    "/fpB3LfSE/1kx9VaaE4FL3i9Gg2vDV0eLGM3PWksFNPhULxtcYJyjaBjAAAAqJAeleSQHp\n"
    "XkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCp0GAKnxthKraR\n"
    "BDjz9R3wjLoyOdv9+kHct9IT/WTH1VpoTgUveL0aDa8NXR4sYzc9aSwU0+FQvG1xgnKNoG\n"
    "MAAAAgPrOgktioNqad/wHNC/rt/zVrpNqDnOwg9tNDFMOTwo8AAAANYm9iQGxvY2FsaG9z\n"
    "dAECBA==\n"
    "-----END OPENSSH PRIVATE KEY-----\n";

#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */

static void test_wolfSSH_ReadKey(void)
{
#if !defined(WOLFSSH_NO_RSA) || !defined(WOLFSSH_NO_ECDSA_SHA2_NISTP256)
    byte *key, *keyCheck, *derKey;
    const byte* keyType;
    word32 keySz, keyTypeSz, derKeySz;
    int ret;
#endif

#ifndef WOLFSSH_NO_RSA

    /* OpenSSH Format, ssh-rsa, private, need alloc */
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = wolfSSH_ReadKey_buffer((const byte*)id_rsa, (word32)WSTRLEN(id_rsa),
            WOLFSSH_FORMAT_OPENSSH, &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ssh-rsa");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ssh-rsa"));
    WFREE(key, NULL, DYNTYPE_FILE);

    /* SSL PEM Format, ssh-rsa, private, need alloc */
    derKey = NULL;
    derKeySz = 0;
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = ConvertHexToBin(serverKeyRsaDer, &derKey, &derKeySz,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    AssertIntEQ(ret, 0);
    ret = wolfSSH_ReadKey_buffer(derKey, derKeySz, WOLFSSH_FORMAT_ASN1,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ssh-rsa");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ssh-rsa"));
    WFREE(key, NULL, DYNTYPE_FILE);
    WFREE(derKey, NULL, 0);

    /* OpenSSH Format, ssh-rsa, public, need alloc */
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = wolfSSH_ReadKey_buffer((const byte*)id_rsa_pub,
            (word32)WSTRLEN(id_rsa_pub), WOLFSSH_FORMAT_SSH,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ssh-rsa");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ssh-rsa"));
    WFREE(key, NULL, DYNTYPE_FILE);

    /* OpenSSH Format, ssh-rsa, private, no alloc */
    keyCheck = (byte*)WMALLOC(KEY_BUF_SZ, NULL, DYNTYPE_FILE);
    AssertNotNull(keyCheck);
    key = keyCheck;
    keySz = KEY_BUF_SZ;
    keyType = NULL;
    keyTypeSz = 0;
    ret = wolfSSH_ReadKey_buffer((const byte*)id_rsa, (word32)WSTRLEN(id_rsa),
            WOLFSSH_FORMAT_OPENSSH, &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertTrue(key == keyCheck);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ssh-rsa");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ssh-rsa"));
    WFREE(keyCheck, NULL, DYNTYPE_FILE);

#endif /* WOLFSSH_NO_RSA */

#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256

    /* OpenSSH Format, ecdsa-sha2-nistp256, private, need alloc */
    (void)keyCheck;
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = wolfSSH_ReadKey_buffer((const byte*)id_ecdsa,
            (word32)WSTRLEN(id_ecdsa), WOLFSSH_FORMAT_OPENSSH,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ecdsa-sha2-nistp256");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ecdsa-sha2-nistp256"));
    WFREE(key, NULL, DYNTYPE_FILE);

    /* SSL DER Format, ecdsa-sha2-nistp256, private, need alloc */
    derKey = NULL;
    derKeySz = 0;
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = ConvertHexToBin(serverKeyEccDer, &derKey, &derKeySz,
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    ret = wolfSSH_ReadKey_buffer(derKey, derKeySz, WOLFSSH_FORMAT_ASN1,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ecdsa-sha2-nistp256");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ecdsa-sha2-nistp256"));
    WFREE(key, NULL, DYNTYPE_FILE);
    WFREE(derKey, NULL, 0);

    /* OpenSSH Format, ecdsa-sha2-nistp256, public, need alloc */
    key = NULL;
    keySz = 0;
    keyType = NULL;
    keyTypeSz = 0;
    ret = wolfSSH_ReadKey_buffer((const byte*)id_ecdsa_pub,
            (word32)WSTRLEN(id_ecdsa_pub), WOLFSSH_FORMAT_SSH,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertNotNull(key);
    AssertIntGT(keySz, 0);
    AssertStrEQ(keyType, "ecdsa-sha2-nistp256");
    AssertIntEQ(keyTypeSz, (word32)WSTRLEN("ecdsa-sha2-nistp256"));
    WFREE(key, NULL, DYNTYPE_FILE);

#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */
}


static void test_wolfSSH_ReadKey_badPad(void)
{
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    byte* key = NULL;
    word32 keySz = 0;
    const byte* keyType = NULL;
    word32 keyTypeSz = 0;
    int ret;

    ret = wolfSSH_ReadKey_buffer((const byte*)id_ecdsa_bad_pad,
            (word32)WSTRLEN(id_ecdsa_bad_pad), WOLFSSH_FORMAT_OPENSSH,
            &key, &keySz, &keyType, &keyTypeSz, NULL);
    AssertIntEQ(ret, WS_KEY_FORMAT_E);
    /* DoOpenSshKey never assigns *outSz, *outType, or *outTypeSz
     * on the error branch (only on success),
     * these assertions will catch any future regression
     * where the API partially writes output before failing. */
    AssertNull(key);
    AssertIntEQ(keySz, 0);
    AssertNull(keyType);
    AssertIntEQ(keyTypeSz, 0);
#endif
}


#ifdef WOLFSSH_SCP

static int my_ScpRecv(WOLFSSH* ssh, int state, const char* basePath,
    const char* fileName, int fileMode, word64 mTime, word64 aTime,
    word32 totalFileSz, byte* buf, word32 bufSz, word32 fileOffset,
    void* ctx)
{
    (void)ssh;

    printf("calling scp recv cb with state %d\n", state);
    printf("\tbase path = %s\n", basePath);
    printf("\tfile name = %s\n", fileName);
    printf("\tfile mode = %d\n", fileMode);
    printf("\tfile size = %d\n", totalFileSz);
    printf("\tfile offset = %d\n", fileOffset);

    (void)mTime;
    (void)aTime;
    (void)buf;
    (void)bufSz;
    (void)ctx;

    return WS_SCP_ABORT; /* error out for test function */
}


static void test_wolfSSH_SCP_CB(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int i = 3, j = 4; /* arbitrary value */
    const char err[] = "test setting error msg";

    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(NULL, NULL));

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    wolfSSH_SetScpRecv(ctx, my_ScpRecv);
    AssertNotNull(ssh = wolfSSH_new(ctx));

    wolfSSH_SetScpRecvCtx(ssh, (void*)&i);
    AssertIntEQ(i, *(int*)wolfSSH_GetScpRecvCtx(ssh));

    wolfSSH_SetScpSendCtx(ssh, (void*)&j);
    AssertIntEQ(j, *(int*)wolfSSH_GetScpSendCtx(ssh));
    AssertIntNE(j, *(int*)wolfSSH_GetScpRecvCtx(ssh));

    AssertIntEQ(wolfSSH_SetScpErrorMsg(ssh, err), WS_SUCCESS);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#else /* WOLFSSH_SCP */
static void test_wolfSSH_SCP_CB(void) { ; }
#endif /* WOLFSSH_SCP */

#ifdef WOLFSSH_AGENT
typedef struct AgentTestCtx {
    int partialWrite;
    byte response[128];
    word32 responseSz;
    int writeCalls;
    int readCalls;
} AgentTestCtx;

static int test_agent_cb(WS_AgentCbAction action, void* ctx)
{
    (void)ctx;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP ||
            action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        return WS_AGENT_SUCCESS;
    }

    return WS_AGENT_INVALID_ACTION;
}

static void put_uint32(byte* dst, word32 value)
{
    dst[0] = (byte)((value >> 24) & 0xff);
    dst[1] = (byte)((value >> 16) & 0xff);
    dst[2] = (byte)((value >> 8) & 0xff);
    dst[3] = (byte)(value & 0xff);
}

static void build_agent_message(byte* out, word32* outSz, byte id,
        const byte* body, word32 bodySz)
{
    word32 payloadSz = 1 + bodySz;

    put_uint32(out, payloadSz);
    out[4] = id;
    if (bodySz > 0)
        memcpy(out + 5, body, bodySz);
    *outSz = payloadSz + LENGTH_SZ;
}

static void build_sign_response(AgentTestCtx* ctx, const byte* sig,
        word32 sigSz)
{
    byte body[4 + 64];

    AssertTrue(sigSz <= 64);
    put_uint32(body, sigSz);
    if (sigSz > 0)
        memcpy(body + LENGTH_SZ, sig, sigSz);
    build_agent_message(ctx->response, &ctx->responseSz,
        MSGID_AGENT_SIGN_RESPONSE, body, LENGTH_SZ + sigSz);
}

static void build_simple_response(AgentTestCtx* ctx, byte id)
{
    build_agent_message(ctx->response, &ctx->responseSz, id, NULL, 0);
}

static int test_agent_io_cb(WS_AgentIoCbAction action, void* buf, word32 bufSz,
        void* ctx)
{
    AgentTestCtx* io = (AgentTestCtx*)ctx;

    if (action == WOLFSSH_AGENT_IO_WRITE) {
        io->writeCalls++;
        if (io->partialWrite && bufSz > 0) {
            io->partialWrite = 0;
            return (int)(bufSz - 1);
        }
        return (int)bufSz;
    }

    io->readCalls++;
    if (io->responseSz == 0 || bufSz < io->responseSz)
        return 0;
    memcpy(buf, io->response, io->responseSz);
    return (int)io->responseSz;
}

static void setup_agent_test(WOLFSSH_CTX** ctx, WOLFSSH** ssh, AgentTestCtx* io)
{
    AssertNotNull(*ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertIntEQ(wolfSSH_CTX_AGENT_enable(*ctx, 1), WS_SUCCESS);
    AssertIntEQ(wolfSSH_CTX_set_agent_cb(*ctx, test_agent_cb,
        test_agent_io_cb), WS_SUCCESS);
    AssertNotNull(*ssh = wolfSSH_new(*ctx));
    AssertNotNull((*ssh)->agent = wolfSSH_AGENT_new((*ctx)->heap));
    AssertIntEQ(wolfSSH_set_agent_cb_ctx(*ssh, io), WS_SUCCESS);
    AssertIntEQ(wolfSSH_AGENT_enable(*ssh, 1), WS_SUCCESS);
}

static void cleanup_agent_test(WOLFSSH_CTX* ctx, WOLFSSH* ssh)
{
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

static void test_wolfSSH_agent_signrequest_partial_write(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    AgentTestCtx io;
    byte digest[16] = {0};
    byte keyBlob[8] = {0};
    byte sig[8];
    word32 sigSz = sizeof(sig);
    int ret;

    memset(&io, 0, sizeof(io));
    io.partialWrite = 1;
    setup_agent_test(&ctx, &ssh, &io);

    ret = wolfSSH_AGENT_SignRequest(ssh, digest, sizeof(digest),
        sig, &sigSz, keyBlob, sizeof(keyBlob), 0);
    AssertIntEQ(ret, WS_AGENT_CXN_FAIL);
    AssertIntEQ(sigSz, 0);
    AssertIntEQ(io.writeCalls, 1);
    AssertIntEQ(io.readCalls, 0);

    cleanup_agent_test(ctx, ssh);
}

static void test_wolfSSH_agent_signrequest_wrong_message(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    AgentTestCtx io;
    byte digest[16] = {0};
    byte keyBlob[8] = {0};
    byte sig[16];
    word32 sigSz = sizeof(sig);
    int ret;

    memset(&io, 0, sizeof(io));
    build_simple_response(&io, MSGID_AGENT_SUCCESS);
    setup_agent_test(&ctx, &ssh, &io);

    ret = wolfSSH_AGENT_SignRequest(ssh, digest, sizeof(digest),
        sig, &sigSz, keyBlob, sizeof(keyBlob), 0);
    AssertIntEQ(ret, WS_AGENT_NO_KEY_E);
    AssertIntEQ(sigSz, 0);
    AssertIntEQ(io.writeCalls, 1);
    AssertIntEQ(io.readCalls, 1);

    cleanup_agent_test(ctx, ssh);
}

static void test_wolfSSH_agent_signrequest_signature_too_large(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    AgentTestCtx io;
    byte digest[16] = {0};
    byte keyBlob[8] = {0};
    byte signatureData[12];
    byte sig[8];
    word32 sigSz = sizeof(sig);
    int ret;

    memset(signatureData, 0x5a, sizeof(signatureData));
    memset(&io, 0, sizeof(io));
    build_sign_response(&io, signatureData, sizeof(signatureData));
    setup_agent_test(&ctx, &ssh, &io);

    ret = wolfSSH_AGENT_SignRequest(ssh, digest, sizeof(digest),
        sig, &sigSz, keyBlob, sizeof(keyBlob), 0);
    AssertIntEQ(ret, WS_BUFFER_E);
    AssertIntEQ(sigSz, 0);
    AssertIntEQ(io.writeCalls, 1);
    AssertIntEQ(io.readCalls, 1);

    cleanup_agent_test(ctx, ssh);
}

static void test_wolfSSH_agent_signrequest_success(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    AgentTestCtx io;
    byte digest[16] = {0};
    byte keyBlob[8] = {0};
    byte signatureData[8];
    byte sig[16];
    word32 sigSz = sizeof(sig);
    int ret;

    memset(signatureData, 0xa5, sizeof(signatureData));
    memset(&io, 0, sizeof(io));
    build_sign_response(&io, signatureData, sizeof(signatureData));
    setup_agent_test(&ctx, &ssh, &io);

    ret = wolfSSH_AGENT_SignRequest(ssh, digest, sizeof(digest),
        sig, &sigSz, keyBlob, sizeof(keyBlob), 0);
    AssertIntEQ(ret, WS_SUCCESS);
    AssertIntEQ(sigSz, sizeof(signatureData));
    AssertTrue(memcmp(sig, signatureData, sizeof(signatureData)) == 0);
    AssertIntEQ(io.writeCalls, 1);
    AssertIntEQ(io.readCalls, 1);

    cleanup_agent_test(ctx, ssh);
}
#endif /* WOLFSSH_AGENT */


#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED)

byte userPassword[256];

static int sftpUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* defaultPassword = (const char*)ctx;
        word32 passwordSz;

        ret = WOLFSSH_USERAUTH_SUCCESS;
        if (defaultPassword != NULL) {
            passwordSz = (word32)strlen(defaultPassword);
            memcpy(userPassword, defaultPassword, passwordSz);
        }
        else {
            printf("Expecting password set for test cases\n");
            return ret;
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz = passwordSz;
        }
    }
    return ret;
}

static int AcceptAnyServerHostKey(const byte* pubKey, word32 pubKeySz,
        void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;
    return 0;
}

/* performs connection to port, sets WOLFSSH_CTX and WOLFSSH on success
 * caller needs to free ctx and ssh when done
 */
static void sftp_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port)
{
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    char* host = (char*)wolfSshIp;
    const char* username = "jill";
    const char* password = "upthehill";

    if (ctx == NULL || ssh == NULL) {
        return;
    }

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL) {
        return;
    }

    wolfSSH_CTX_SetPublicKeyCheck(*ctx, AcceptAnyServerHostKey);
    wolfSSH_SetUserAuth(*ctx, sftpUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    if (sockFd < 0) {
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0){
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    wolfSSH_SetUserAuthCtx(*ssh, (void*)password);
    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret == WS_SUCCESS)
        ret = wolfSSH_set_fd(*ssh, (int)sockFd);

    if (ret == WS_SUCCESS)
        ret = wolfSSH_SFTP_connect(*ssh);

    if (ret != WS_SUCCESS){
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }
}


static void test_wolfSSH_SFTP_SendReadPacket(void)
{
    func_args ser;
    tcp_ready ready;
    int argsCount;
    WS_SOCKET_T clientFd;

    const char* args[10];
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;

    THREAD_TYPE serThread;

    WMEMSET(&ser, 0, sizeof(func_args));

    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    ser.argv   = (char**)args;
    ser.argc    = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    sftp_client_connect(&ctx, &ssh, ready.port);
    AssertNotNull(ctx);
    AssertNotNull(ssh);

    {
        WS_SFTPNAME* tmp;
        WS_SFTPNAME* current;
        byte handle[WOLFSSH_MAX_HANDLE];
        word32 handleSz = WOLFSSH_MAX_HANDLE;
        const char* currentDir = ".";
        byte* out = NULL;
        int outSz = 18;
        int rxSz;
        const word32 ofst[2] = {0};

        current = wolfSSH_SFTP_LS(ssh, (char*)currentDir);
        tmp = current;
        while (tmp != NULL) {
            if ((tmp->atrb.sz[0] > 0) &&
                    (tmp->atrb.flags & WOLFSSH_FILEATRB_PERM) &&
                    !(tmp->atrb.per & 040000)) {
                break;
            }
            tmp = tmp->next;
        }

        if (tmp != NULL) {
            /* Allocate buffer large enough for maximum read size */
            word32 allocSz = tmp->atrb.sz[0];
            if (allocSz < WOLFSSH_MAX_SFTP_RW)
                allocSz = WOLFSSH_MAX_SFTP_RW;
            out = (byte*)malloc(allocSz);
            AssertNotNull(out);
            AssertIntEQ(wolfSSH_SFTP_Open(ssh, tmp->fName, WOLFSSH_FXF_READ,
                        NULL, handle, &handleSz), WS_SUCCESS);

            /*
             * Since errors are negative, and valid return values are greater
             * than 0, the following wolfSSH_SFTP_SendReadPacket() calls
             * shall return greater than 0 and less-than-equal-to the amount
             * requested, outSz. While this endpoint may request any amount of
             * file data, the peer must not respond with more than requested.
             */

            /* read 18 bytes */
            if (tmp->atrb.sz[0] >= 18) {
                outSz = 18;
                rxSz = wolfSSH_SFTP_SendReadPacket(ssh, handle, handleSz,
                        ofst, out, outSz);
                AssertIntGT(rxSz, 0);
                AssertIntLE(rxSz, outSz);
            }

            /* partial read */
            outSz = WOLFSSH_MAX_SFTP_RW / 2;
            rxSz = wolfSSH_SFTP_SendReadPacket(ssh, handle, handleSz,
                    ofst, out, outSz);
            if (wolfSSH_get_error(ssh) != WS_REKEYING) {
                AssertIntGT(rxSz, 0);
                AssertIntLE(rxSz, outSz);
            }

            /* read all */
            outSz = WOLFSSH_MAX_SFTP_RW;
            rxSz = wolfSSH_SFTP_SendReadPacket(ssh, handle, handleSz,
                    ofst, out, outSz);
            if (wolfSSH_get_error(ssh) != WS_REKEYING) {
                AssertIntGT(rxSz, 0);
                AssertIntLE(rxSz, outSz);
            }

            free(out);
            wolfSSH_SFTP_Close(ssh, handle, handleSz);
        }
        wolfSSH_SFTPNAME_list_free(current);
    }

    /* take care of re-keying state before shutdown call */
    while (wolfSSH_get_error(ssh) == WS_REKEYING) {
        wolfSSH_worker(ssh, NULL);
    }

    argsCount = wolfSSH_shutdown(ssh);
    if (argsCount == WS_SOCKET_ERROR_E) {
        /* If the socket is closed on shutdown, peer is gone, this is OK. */
        argsCount = WS_SUCCESS;
    }

#if DEFAULT_HIGHWATER_MARK < 8000
    if (argsCount == WS_REKEYING) {
        /* in cases where highwater mark is really small a re-key could happen */
        argsCount = WS_SUCCESS;
    }
#endif

    AssertIntEQ(argsCount, WS_SUCCESS);

    /* close client socket down */
    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_ZEPHYR
    /* Weird deadlock without this sleep */
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serThread);
}

/* Upper bound on non-blocking retry iterations. A legitimate LS/shutdown across
 * forced rekeys completes in well under this; the bound keeps a regression from
 * hanging CI by tripping the AssertNotNull/AssertIntEQ below instead. */
#define SFTP_REKEY_MAX_TRIES 100

static void sftp_rekey_test(int nonBlock)
{
    func_args ser;
    tcp_ready ready;
    int argsCount;
    int err;
    int tries;
    WS_SOCKET_T clientFd;
    WS_SFTPNAME* ls;
    int i;

    const char* args[10];
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;

    THREAD_TYPE serThread;

    WMEMSET(&ser, 0, sizeof(func_args));

    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    ser.argv   = (char**)args;
    ser.argc    = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    sftp_client_connect(&ctx, &ssh, ready.port);
    AssertNotNull(ctx);
    AssertNotNull(ssh);

    /* Handshake completed in blocking mode; switch to non-blocking so the
     * LS/rekey phase exercises the WS_WANT_READ/WS_WANT_WRITE early-return
     * path in buffer_send/buffer_read. */
    clientFd = wolfSSH_get_fd(ssh);
    if (nonBlock) {
        tcp_set_nonblocking(&clientFd);
    }

    /* Low threshold makes the client cross its own highwater mid-SFTP and fire
     * the default highwater callback (wsHighwater -> TriggerKeyExchange), so the
     * client initiates a rekey. In blocking mode the buffer_read/buffer_send
     * fixes drive it internally; in non-blocking mode the retry loop below
     * advances it on WS_WANT_READ/WS_WANT_WRITE/WS_REKEYING. */
    AssertIntEQ(wolfSSH_SetHighwater(ssh, 256), WS_SUCCESS);

    ls = NULL;
    for (i = 0; i < 3; i++) {
        /* The retry loop only applies to non-blocking. In blocking mode the
         * buffer_read/buffer_send fixes must handle the rekey transparently, so
         * a single LS call returns the listing; gating on nonBlock keeps the
         * blocking path from masking a regression that exposes WS_REKEYING. */
        tries = 0;
        do {
            ls  = wolfSSH_SFTP_LS(ssh, (char*)".");
            err = wolfSSH_get_error(ssh);
            /* tcp_select() waits for receive-readiness; on WS_WANT_WRITE it has
             * no write event to wait on, so its 1s timeout is the intended
             * (rare) fallback that yields the CPU instead of busy-spinning. */
            if (nonBlock && ls == NULL && (err == WS_WANT_READ
                        || err == WS_WANT_WRITE || err == WS_REKEYING)) {
                tcp_select(clientFd, 1);
            }
            tries++;
        } while (nonBlock && ls == NULL && (err == WS_WANT_READ
                    || err == WS_WANT_WRITE || err == WS_REKEYING)
                && tries <= SFTP_REKEY_MAX_TRIES);
        /* Fails fast (instead of hanging CI) if a regression keeps the LS stuck
         * in a want/rekey state past the retry bound. The loop cap is one above
         * the assert threshold so a legitimate success on the last allowed
         * iteration is not misreported as a hang. */
        AssertIntLE(tries, SFTP_REKEY_MAX_TRIES);
        AssertNotNull(ls);
        wolfSSH_SFTPNAME_list_free(ls);
        ls = NULL;
    }

    tries = 0;
    do {
        argsCount = wolfSSH_shutdown(ssh);
        err = wolfSSH_get_error(ssh);
        if (argsCount != WS_SUCCESS && (err == WS_WANT_READ
                    || err == WS_WANT_WRITE || err == WS_REKEYING)) {
            tcp_select(clientFd, 1);
        }
        tries++;
    } while (argsCount != WS_SUCCESS && (err == WS_WANT_READ
                || err == WS_WANT_WRITE || err == WS_REKEYING)
            && tries <= SFTP_REKEY_MAX_TRIES);
    /* Fails fast if shutdown stays stuck in a want/rekey state past the bound,
     * before the WS_REKEYING fixup below could otherwise mask it. The loop cap
     * is one above the assert threshold to leave last-iteration headroom. */
    AssertIntLE(tries, SFTP_REKEY_MAX_TRIES);
    if (argsCount == WS_SOCKET_ERROR_E) {
        argsCount = WS_SUCCESS;
    }
#if DEFAULT_HIGHWATER_MARK < 8000
    if (argsCount == WS_REKEYING) {
        /* in cases where highwater mark is really small a re-key could happen */
        argsCount = WS_SUCCESS;
    }
#endif
    AssertIntEQ(argsCount, WS_SUCCESS);

    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_ZEPHYR
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serThread);
}

static void test_wolfSSH_SFTP_ReKey(void)
{
    sftp_rekey_test(0);
}

static void test_wolfSSH_SFTP_ReKey_NonBlock(void)
{
    sftp_rekey_test(1);
}

static void test_wolfSSH_SFTP_Confinement(void)
{
    func_args        ser;
    tcp_ready        ready;
    int              argsCount;
    WS_SOCKET_T      clientFd;
    const char*      args[10];
    WOLFSSH_CTX*     ctx = NULL;
    WOLFSSH*         ssh = NULL;
    THREAD_TYPE      serThread;
    WS_SFTPNAME*     ls = NULL;
    WS_SFTP_FILEATRB atr;
    byte             handle[WOLFSSH_MAX_HANDLE];
    word32           handleSz;
    int              ret;
    char             curDir[]    = ".";
    char             inJailDir[] = "confine_injail_dir";
    /* The server is confined to its working directory (".").  Every "escape"
     * targets an absolute, out-of-jail path.  None of these are real system
     * files, so a confinement bypass can never damage anything important. */
#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
    /* On hosted POSIX, stage real out-of-jail targets under a unique per-test
     * temporary directory created with mkdtemp().  Fixed /tmp names race
     * against parallel test jobs and against stale paths owned by another
     * user, producing false failures unrelated to confinement; a private
     * mkdtemp() directory we own avoids both.  Because the fixtures exist on
     * disk, a confinement bypass for read/stat/delete/rename would actually
     * succeed and trip the assertions below - not merely fail with ENOENT.
     * escMkdir/escDest are left absent so a leaked create also trips an
     * assertion.
     *
     * The echoserver's jail is its working directory (".", which here is the
     * test process's own cwd).  If the temp root resolves inside that jail
     * (e.g. the suite is run from within /tmp), the "escape" paths would fall
     * in-jail and the rejection assertions would invert; that case is detected
     * below and skipped.  The in-jail positive case is covered by the repeated
     * wolfSSH_SFTP_LS(ssh, ".") below, which must succeed after each reject.
     * Blocking-mode LS handles any in-progress rekey transparently
     * (buffer_read/buffer_send), so no manual rekey-drive helper is needed. */
    char             escRoot[]   = "/tmp/wolfssh_confine_XXXXXX";
    char             escFile[WOLFSSH_MAX_FILENAME];
    char             escDir[WOLFSSH_MAX_FILENAME];
    char             escMkdir[WOLFSSH_MAX_FILENAME];
    char             escDest[WOLFSSH_MAX_FILENAME];
    char             jailCwd[WOLFSSH_MAX_FILENAME];
    /* a relative ".." traversal that resolves to the same real out-of-jail
     * file as escFile, exercising the post-RealPath containment check on the
     * relative-escape path (not just absolute paths) */
    char             escRel[WOLFSSH_MAX_FILENAME];
    /* a real sibling directory whose name is the jail's name with a distinctive
     * suffix appended directly (no separator); its resolved path matches the
     * jail for the full prefix length but the next byte is not a delimiter, so
     * only GetAndCleanPath's boundary check (not a plain prefix compare) rejects
     * it.  The suffix is test-specific so it will not collide with real user
     * directories, and it is only created/removed when this run actually staged
     * it.  Empty when the cwd could not be resolved, the name would truncate, or
     * such a directory already exists (the sub-test is then skipped rather than
     * touching unrelated data). */
    char             escSibling[WOLFSSH_MAX_FILENAME];
#ifdef WOLFSSH_HAVE_SYMLINK
    /* an in-jail symlink pointing at the out-of-jail temp root, and a path
     * that traverses it; both must be rejected even though they resolve to an
     * in-jail string, since wolfSSH_RealPath does not follow links.  Guarded by
     * WOLFSSH_HAVE_SYMLINK to match the server-side check's feature gate: on
     * POSIX builds that compile the check out (e.g. WOLFSSH_USER_FILESYSTEM)
     * the link would be followed as designed, so these assertions must not
     * run. */
    char             escSymlink[] = "confine_symlink";
    char             escSymThru[WOLFSSH_MAX_FILENAME];
#endif
    WFILE*           fp = NULL;
    int              snLen;
#else
    /* Zephyr (and Windows, which does not run this via "make check") lack the
     * getcwd()/fopen() wrappers to stage out-of-jail files, so fall back to
     * non-existent out-of-jail paths.  A leaked MKDIR still trips its
     * assertion; read/stat/delete bypasses are not detectable here. */
    char             escFile[]   = "/wolfssh_confine_test_file";
    char             escDir[]    = "/wolfssh_confine_test_dir";
    char             escMkdir[]  = "/wolfssh_confine_test_mkdir";
    char             escDest[]   = "/wolfssh_confine_test_renamed";
#endif

    /* best effort removal of anything a previous aborted run may have left */
    WRMDIR(NULL, inJailDir);
#if defined(WOLFSSH_ZEPHYR) || defined(USE_WINDOWS_API)
    WREMOVE(NULL, escFile);
    WRMDIR(NULL, escDir);
    WRMDIR(NULL, escMkdir);
    WREMOVE(NULL, escDest);
#else
    /* Create a private, unique temp directory to hold the out-of-jail
     * fixtures, then derive the individual escape paths from it. */
    AssertNotNull(mkdtemp(escRoot));

    /* If the temp root resolves inside the jail (the test process's cwd),
     * the "escape" paths would actually be in-jail and the rejection
     * assertions would invert; skip the staged-fixture checks in that
     * unusual case rather than report a bogus confinement failure. */
    WMEMSET(jailCwd, 0, sizeof(jailCwd));
    escSibling[0] = '\0';
    if (WGETCWD(NULL, jailCwd, sizeof(jailCwd) - 1) != NULL) {
        size_t jailLen = WSTRLEN(jailCwd);
        if (WSTRLEN(escRoot) >= jailLen &&
                WSTRNCMP(escRoot, jailCwd, jailLen) == 0) {
            WRMDIR(NULL, escRoot);
            return;
        }
        /* "<cwd>_wolfssh_confine_sibling" - a sibling of the jail sharing its
         * name as a string prefix, with a distinctive test-specific suffix so
         * it will not match a real user directory.  The first byte past the
         * jail prefix is '_' (not a delimiter), so the boundary check rejects
         * it.  If the name would truncate, leave escSibling empty so the
         * boundary-check case is skipped rather than staged at a wrong path. */
        snLen = WSNPRINTF(escSibling, sizeof(escSibling),
                "%s_wolfssh_confine_sibling", jailCwd);
        if (snLen < 0 || (size_t)snLen >= sizeof(escSibling)) {
            escSibling[0] = '\0';
        }
    }

    WSNPRINTF(escFile,  sizeof(escFile),  "%s/real_file", escRoot);
    WSNPRINTF(escDir,   sizeof(escDir),   "%s/real_dir",  escRoot);
    WSNPRINTF(escMkdir, sizeof(escMkdir), "%s/mkdir",     escRoot);
    WSNPRINTF(escDest,  sizeof(escDest),  "%s/renamed",   escRoot);
    /* climb to filesystem root with a generous ".." count (RealPath clamps the
     * excess at root) then re-descend to escFile, so this relative path
     * resolves to the very same out-of-jail file the absolute escFile does */
    snLen = WSNPRINTF(escRel, sizeof(escRel),
        "../../../../../../../../../../../../../../../../%s", escFile + 1);
    AssertIntGE(snLen, 0);
    AssertIntLT(snLen, (int)sizeof(escRel));
#ifdef WOLFSSH_HAVE_SYMLINK
    /* a path that traverses the in-jail symlink out to the staged real file */
    WSNPRINTF(escSymThru, sizeof(escSymThru), "%s/real_file", escSymlink);
#endif

    /* stage the real out-of-jail file and directory */
    AssertIntEQ(WFOPEN(NULL, &fp, escFile, "wb"), 0);
    AssertNotNull(fp);
    WFCLOSE(NULL, fp);
    AssertIntEQ(WMKDIR(NULL, escDir, 0755), 0);

    /* stage the sibling so a boundary-check regression would actually
     * enumerate it (rather than fail with ENOENT).  Never remove a pre-existing
     * directory: only create it when absent, and if creation fails (e.g. it
     * already exists, possibly user data despite the distinctive name), clear
     * escSibling so the sub-test is skipped and cleanup leaves it untouched.
     * escSibling is thus non-empty only when this run created the directory. */
    if (escSibling[0] != '\0') {
        if (WMKDIR(NULL, escSibling, 0755) != 0) {
            escSibling[0] = '\0';
        }
    }

#ifdef WOLFSSH_HAVE_SYMLINK
    /* stage an in-jail symlink pointing at the out-of-jail temp root */
    WREMOVE(NULL, escSymlink);
    AssertIntEQ(symlink(escRoot, escSymlink), 0);
#endif
#endif

    WMEMSET(&ser, 0, sizeof(func_args));
    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    ser.argv = (char**)args;
    ser.argc = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    sftp_client_connect(&ctx, &ssh, ready.port);
    AssertNotNull(ctx);
    AssertNotNull(ssh);

    /* The client API maps PERMISSION and FAILURE both to WS_FATAL_ERROR;
     * assert != WS_SUCCESS and verify the session stays alive afterward. */

    /* Remove: out-of-jail absolute path -> rejected, session survives */
    ret = wolfSSH_SFTP_Remove(ssh, escFile);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* Remove: relative ".." traversal resolving to the same real out-of-jail
     * file -> rejected by the post-RealPath containment check, session
     * survives.  escFile still exists afterward (a bypass would have deleted
     * it, failing the absolute-path assertions on a re-run).  escRel/fp are
     * staged only on hosted POSIX (mkdtemp/fopen), so this case is POSIX-only;
     * on Zephyr/Windows the absolute-path rejection above already covers the
     * Remove sink. */
#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
    ret = wolfSSH_SFTP_Remove(ssh, escRel);
    AssertIntNE(ret, WS_SUCCESS);
    AssertIntEQ(WFOPEN(NULL, &fp, escFile, "rb"), 0);
    AssertNotNull(fp);
    WFCLOSE(NULL, fp);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;
#endif

    /* RMDIR: out-of-jail path -> rejected, session survives */
    ret = wolfSSH_SFTP_RMDIR(ssh, escDir);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* MKDIR: out-of-jail path -> rejected, session survives */
    WMEMSET(&atr, 0, sizeof(atr));
    ret = wolfSSH_SFTP_MKDIR(ssh, escMkdir, &atr);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* Open: out-of-jail path -> rejected, session survives */
    handleSz = WOLFSSH_MAX_HANDLE;
    ret = wolfSSH_SFTP_Open(ssh, escFile, WOLFSSH_FXF_READ, NULL,
            handle, &handleSz);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* LS (OpenDir): out-of-jail path -> rejected, session survives */
    ls = wolfSSH_SFTP_LS(ssh, escDir);
    AssertNull(ls);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
    /* LS (OpenDir) on the "<jail>_wolfssh_confine_sibling" sibling: its resolved
     * path shares the jail prefix exactly but the next byte is '_' (not a
     * delimiter), so it must be rejected by the boundary check even though a
     * plain prefix compare would accept it.  The dir really exists, so a
     * regression would return a non-NULL listing. */
    if (escSibling[0] != '\0') {
        ls = wolfSSH_SFTP_LS(ssh, escSibling);
        AssertNull(ls);
        ls = wolfSSH_SFTP_LS(ssh, curDir);
        AssertNotNull(ls);
        wolfSSH_SFTPNAME_list_free(ls);
        ls = NULL;
    }
#endif

    /* Rename: out-of-jail path -> rejected, session survives */
    ret = wolfSSH_SFTP_Rename(ssh, escFile, escDest);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* STAT: out-of-jail path -> rejected, session survives */
    WMEMSET(&atr, 0, sizeof(atr));
    ret = wolfSSH_SFTP_STAT(ssh, escFile, &atr);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* LSTAT: out-of-jail path -> rejected, session survives */
    WMEMSET(&atr, 0, sizeof(atr));
    ret = wolfSSH_SFTP_LSTAT(ssh, escFile, &atr);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* SetSTAT: out-of-jail path -> rejected, session survives */
    WMEMSET(&atr, 0, sizeof(atr));
    ret = wolfSSH_SFTP_SetSTAT(ssh, escFile, &atr);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API) && \
        defined(WOLFSSH_HAVE_SYMLINK)
    /* Symlink escape: an in-jail symlink to the out-of-jail tree resolves to
     * an in-jail path string, so the prefix check alone would pass; the
     * per-component link check must reject both listing the link itself and
     * opening a file through it.  Without the fix these would follow the link
     * and succeed, escaping the jail.  Guarded to match the POSIX-only staging
     * above (mkdtemp/symlink) and WOLFSSH_HAVE_SYMLINK so it only runs where
     * both the fixtures and the server-side link check exist. */
    ls = wolfSSH_SFTP_LS(ssh, escSymlink);
    AssertNull(ls);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    handleSz = WOLFSSH_MAX_HANDLE;
    ret = wolfSSH_SFTP_Open(ssh, escSymThru, WOLFSSH_FXF_READ, NULL,
            handle, &handleSz);
    AssertIntNE(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;
#endif

    /* Positive case: a relative write op that resolves inside the jail must be
     * allowed.  This guards the GetAndCleanPath prefix-compare allow path (and
     * the s[dpLen] boundary check) against an over-restrictive regression that
     * would only be caught by the broader CI shell scripts otherwise.  MKDIR
     * the in-jail name, assert success, then RMDIR it back to a clean state. */
    WMEMSET(&atr, 0, sizeof(atr));
    ret = wolfSSH_SFTP_MKDIR(ssh, inJailDir, &atr);
    AssertIntEQ(ret, WS_SUCCESS);
    ret = wolfSSH_SFTP_RMDIR(ssh, inJailDir);
    AssertIntEQ(ret, WS_SUCCESS);
    ls = wolfSSH_SFTP_LS(ssh, curDir);
    AssertNotNull(ls);
    wolfSSH_SFTPNAME_list_free(ls);
    ls = NULL;

    /* Drain any pending rekey before shutdown. */
    while (wolfSSH_get_error(ssh) == WS_REKEYING)
        wolfSSH_worker(ssh, NULL);

    ret = wolfSSH_shutdown(ssh);
    if (ret == WS_SOCKET_ERROR_E) {
        ret = WS_SUCCESS;
    }
#if DEFAULT_HIGHWATER_MARK < 8000
    if (ret == WS_REKEYING) {
        ret = WS_SUCCESS;
    }
#endif
    AssertIntEQ(ret, WS_SUCCESS);
    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_ZEPHYR
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serThread);

    /* remove staged targets; escMkdir/escDest only exist if confinement
     * leaked, and inJailDir only if the positive-case RMDIR did not run, so
     * their removal is best effort */
    WREMOVE(NULL, escFile);
    WRMDIR(NULL, escDir);
    WRMDIR(NULL, escMkdir);
    WREMOVE(NULL, escDest);
    WRMDIR(NULL, inJailDir);
#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
#ifdef WOLFSSH_HAVE_SYMLINK
    WREMOVE(NULL, escSymlink);
#endif
    WRMDIR(NULL, escRoot);
    /* escSibling is non-empty only if this run created it (see staging above),
     * so this never removes a pre-existing directory belonging to the user */
    if (escSibling[0] != '\0') {
        WRMDIR(NULL, escSibling);
    }
#endif
}


/* Direct unit coverage for wolfSSH_SFTP_SetDefaultPath, exercising the new
 * canonicalization and error branches that test_wolfSSH_SFTP_Confinement only
 * reaches indirectly (it always passes an already-absolute realpath):
 * NULL ssh, the too-long-path guard, NULL path (no change), absolute-path
 * canonicalization, the repeated-call free path, and relative-path resolution
 * against the canonicalized cwd. */
static void test_wolfSSH_SFTP_SetDefaultPath(void)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    char         longPath[WOLFSSH_MAX_FILENAME + 4];
#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
    char         cwdBuf[WOLFSSH_MAX_FILENAME];
    char         cwdReal[WOLFSSH_MAX_FILENAME];
    char         expect[WOLFSSH_MAX_FILENAME];
    char         rel[]   = "sdp_rel_seg";
#endif

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));

    /* NULL ssh is rejected */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(NULL, "/"), WS_BAD_ARGUMENT);

    /* NULL path leaves the (still unset) default path unchanged */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, NULL), WS_SUCCESS);
    AssertNull(ssh->sftpDefaultPath);

    /* A path that does not fit the working buffer is rejected up front and
     * does not store anything */
    WMEMSET(longPath, 'a', sizeof(longPath));
    longPath[0] = '/';
    longPath[WOLFSSH_MAX_FILENAME + 1] = '\0'; /* length == MAX_FILENAME + 1 */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, longPath), WS_BUFFER_E);
    AssertNull(ssh->sftpDefaultPath);

    /* An absolute path is stored in lexically canonical form */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, "/tmp/../tmp/sdp"),
            WS_SUCCESS);
    AssertNotNull(ssh->sftpDefaultPath);
    AssertStrEQ(ssh->sftpDefaultPath, "/tmp/sdp");

    /* A repeated call frees the previous path (no leak) and stores the new
     * one - the wolfsshd "/" then home-dir sequence */
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, "/var/sdp2"), WS_SUCCESS);
    AssertNotNull(ssh->sftpDefaultPath);
    AssertStrEQ(ssh->sftpDefaultPath, "/var/sdp2");

#if !defined(WOLFSSH_ZEPHYR) && !defined(USE_WINDOWS_API)
    /* A relative path is resolved against the canonicalized cwd, so the stored
     * path is absolute and matches cwd + "/seg" rather than a lexical "/seg" -
     * confirming the relative branch ran.  The expected value is built with
     * the same two RealPath passes the implementation uses. */
    AssertNotNull(WGETCWD(NULL, cwdBuf, sizeof(cwdBuf) - 1));
    AssertIntEQ(wolfSSH_RealPath(NULL, cwdBuf, cwdReal, sizeof(cwdReal)),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_RealPath(cwdReal, rel, expect, sizeof(expect)),
            WS_SUCCESS);
    AssertIntEQ(wolfSSH_SFTP_SetDefaultPath(ssh, "sdp_rel_seg"), WS_SUCCESS);
    AssertNotNull(ssh->sftpDefaultPath);
    AssertStrEQ(ssh->sftpDefaultPath, expect);
#endif

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}

#else /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */
static void test_wolfSSH_SFTP_SendReadPacket(void) { ; }
static void test_wolfSSH_SFTP_ReKey(void) { ; }
static void test_wolfSSH_SFTP_ReKey_NonBlock(void) { ; }
static void test_wolfSSH_SFTP_Confinement(void) { ; }
static void test_wolfSSH_SFTP_SetDefaultPath(void) { ; }
#endif /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */


#if defined(WOLFSSH_SCP) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED) && !defined(NO_FILESYSTEM) && \
    !defined(WOLFSSH_SCP_USER_CALLBACKS) && !defined(WOLFSSH_ZEPHYR)

/* Upper bound on non-blocking retry iterations. A legitimate transfer across a
 * forced rekey completes in well under this; the bound keeps a regression from
 * hanging CI by tripping the AssertIntLE below instead. */
#define SCP_REKEY_MAX_TRIES 100

/* Payload larger than the forced highwater so the transfer straddles it. */
#define SCP_REKEY_FILE_SZ 2048

static byte scpUserPassword[256];

static int scpUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* password = (const char*)ctx;
        word32 passwordSz;

        if (password != NULL) {
            passwordSz = (word32)WSTRLEN(password);
            if (passwordSz > (word32)sizeof(scpUserPassword))
                passwordSz = (word32)sizeof(scpUserPassword);
            WMEMCPY(scpUserPassword, password, passwordSz);
            authData->sf.password.password = scpUserPassword;
            authData->sf.password.passwordSz = passwordSz;
            ret = WOLFSSH_USERAUTH_SUCCESS;
        }
    }

    return ret;
}

static int scpAcceptAnyServerHostKey(const byte* pubKey, word32 pubKeySz,
        void* ctx)
{
    (void)pubKey;
    (void)pubKeySz;
    (void)ctx;
    return 0;
}

/* Writes sz bytes of buf to name. Returns 0 on success. */
static int scpWriteTestFile(const char* name, const byte* buf, word32 sz)
{
    WFILE* fp = NULL;
    int ret = 0;

    if (WFOPEN(NULL, &fp, name, "wb") != 0 || fp == NULL)
        return -1;

    if (WFWRITE(NULL, buf, 1, sz, fp) != sz)
        ret = -1;

    WFCLOSE(NULL, fp);
    return ret;
}

/* Returns 0 if the first sz bytes of name match expect. */
static int scpFilesMatch(const char* name, const byte* expect, word32 sz)
{
    WFILE* fp = NULL;
    byte got[SCP_REKEY_FILE_SZ];
    int ret = 0;

    if (sz > sizeof(got))
        return -1;

    if (WFOPEN(NULL, &fp, name, "rb") != 0 || fp == NULL)
        return -1;

    if (WFREAD(NULL, got, 1, sz, fp) != sz)
        ret = -1;

    if (ret == 0 && XMEMCMP(got, expect, sz) != 0)
        ret = -1;

    WFCLOSE(NULL, fp);
    return ret;
}

/* Connects an SCP client to port, completes the SSH handshake and opens the
 * exec channel carrying cmd, leaving ssh ready for wolfSSH_SCP_to/from. Doing
 * the handshake here (rather than inside the transfer call) lets the caller set
 * a low highwater before the data phase so a rekey fires mid-transfer.
 */
static void scp_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port,
        const char* cmd)
{
    WS_SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    char* host = (char*)wolfSshIp;
    const char* username = "jill";
    const char* password = "upthehill";

    if (ctx == NULL || ssh == NULL)
        return;

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL)
        return;

    wolfSSH_CTX_SetPublicKeyCheck(*ctx, scpAcceptAnyServerHostKey);
    wolfSSH_SetUserAuth(*ctx, scpUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    if (sockFd < 0) {
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0) {
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    wolfSSH_SetUserAuthCtx(*ssh, (void*)password);
    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret == WS_SUCCESS)
        ret = wolfSSH_SetChannelType(*ssh, WOLFSSH_SESSION_EXEC, (byte*)cmd,
                (word32)WSTRLEN(cmd));
    if (ret == WS_SUCCESS)
        ret = wolfSSH_set_fd(*ssh, (int)sockFd);
    if (ret == WS_SUCCESS)
        ret = wolfSSH_connect(*ssh);

    if (ret != WS_SUCCESS) {
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }
}

/* Drives an SCP transfer with a forced mid-transfer rekey.
 *
 * toServer == 0: client SINK (wolfSSH_SCP_from), exercises ScpStreamRead, the
 *                confirmed hang path. toServer == 1: client SOURCE
 *                (wolfSSH_SCP_to), exercises the ScpStreamSend rekey/window
 *                drain loop. nonBlock drives the non-blocking retry path.
 */
static void scp_rekey_test(int nonBlock, int toServer)
{
    func_args ser;
    tcp_ready ready;
    int argsCount;
    int ret;
    int err;
    int tries;
    word32 i;
    WS_SOCKET_T clientFd;
#ifdef USE_WINDOWS_API
    DWORD rcvTimeout = 20000;
#else
    struct timeval rcvTimeout;
#endif
    byte fileData[SCP_REKEY_FILE_SZ];
    char cmd[64];
    const char* args[10];
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;
    /* Fixed names used for filesystem create/verify/cleanup. The *Buf copies
     * are what get passed to the SCP API, which rewrites the path in place
     * (rename/clean), so they cannot be reused to name the file afterward. The
     * leading "./" keeps a directory component so the base-dir open succeeds,
     * as the real scpclient passes $PWD-prefixed paths. */
    const char* srcName  = "./scp_rekey_src.txt";
    const char* fromName = "./scp_rekey_from.txt";
    const char* toName   = "./scp_rekey_to.txt";
    char srcBuf[32];
    char fromBuf[32];
    char toBuf[32];
    const char* verifyName;

    THREAD_TYPE serThread;

    /* mutable copies for the SCP API (rewritten in place during the transfer) */
    WSTRNCPY(srcBuf, srcName, sizeof(srcBuf));
    WSTRNCPY(fromBuf, fromName, sizeof(fromBuf));
    WSTRNCPY(toBuf, toName, sizeof(toBuf));

    /* deterministic source content */
    for (i = 0; i < SCP_REKEY_FILE_SZ; i++)
        fileData[i] = (byte)(i & 0xff);
    AssertIntEQ(scpWriteTestFile(srcName, fileData, SCP_REKEY_FILE_SZ), 0);

    WMEMSET(&ser, 0, sizeof(func_args));
    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    ser.argv   = (char**)args;
    ser.argc   = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    /* -f: server is source (client SINK); -t: server is sink (client SOURCE) */
    if (toServer) {
        WSNPRINTF(cmd, sizeof(cmd), "scp -t %s", toName);
        verifyName = toName;
    }
    else {
        WSNPRINTF(cmd, sizeof(cmd), "scp -f %s", srcName);
        verifyName = fromName;
    }

    scp_client_connect(&ctx, &ssh, ready.port, cmd);
    AssertNotNull(ctx);
    AssertNotNull(ssh);

    /* handshake done in blocking mode; switch to non-blocking for the data
     * phase so the WS_WANT_READ/WS_WANT_WRITE retry path is exercised */
    clientFd = wolfSSH_get_fd(ssh);
    if (nonBlock)
        tcp_set_nonblocking(&clientFd);

    /* Bound the blocking-mode recv so a KEXINIT/rekey deadlock regression fails
     * the AssertIntEQ below instead of hanging CI forever. The
     * SCP_REKEY_MAX_TRIES bound only covers the non-blocking retry loop; a
     * non-blocking socket never blocks in recv, so this is a no-op there. */
#ifdef USE_WINDOWS_API
    (void)setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO,
            (const char*)&rcvTimeout, sizeof(rcvTimeout));
#else
    rcvTimeout.tv_sec = 20;
    rcvTimeout.tv_usec = 0;
    (void)setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO,
            &rcvTimeout, sizeof(rcvTimeout));
#endif

    /* 256 is well below the 2 KB payload, so the highwater check fires partway
     * through and the ScpStreamRead/ScpStreamSend rekey handling must carry the
     * transfer to completion. */
    AssertIntEQ(wolfSSH_SetHighwater(ssh, 256), WS_SUCCESS);

    /* The retry loop only applies to non-blocking. In blocking mode the
     * ScpStreamRead/ScpStreamSend fixes must carry the rekey transparently, so
     * a single call completes the transfer; gating on nonBlock keeps the
     * blocking path from masking a regression that leaves WS_REKEYING set. */
    tries = 0;
    do {
        if (toServer)
            ret = wolfSSH_SCP_to(ssh, srcBuf, toBuf);
        else
            ret = wolfSSH_SCP_from(ssh, srcBuf, fromBuf);
        err = wolfSSH_get_error(ssh);
        /* tcp_select() waits for receive-readiness; on WS_WANT_WRITE it has no
         * write event to wait on, so its 1s timeout is the intended (rare)
         * fallback that yields the CPU instead of busy-spinning. */
        if (nonBlock && ret != WS_SUCCESS && (err == WS_WANT_READ
                    || err == WS_WANT_WRITE || err == WS_REKEYING
                    || err == WS_CHAN_RXD))
            tcp_select(clientFd, 1);
        tries++;
    } while (nonBlock && ret != WS_SUCCESS && (err == WS_WANT_READ
                || err == WS_WANT_WRITE || err == WS_REKEYING
                || err == WS_CHAN_RXD)
            && tries <= SCP_REKEY_MAX_TRIES);
    /* Fails fast (instead of hanging CI) if a regression keeps the transfer
     * stuck in a want/rekey state past the retry bound. */
    AssertIntLE(tries, SCP_REKEY_MAX_TRIES);
    AssertIntEQ(ret, WS_SUCCESS);

    /* best-effort shutdown; the completed transfer above is the real assertion */
    ret = wolfSSH_shutdown(ssh);
    (void)ret;

    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    ThreadJoin(serThread);

    /* verify the transferred file matches the source once the server is done */
    AssertIntEQ(scpFilesMatch(verifyName, fileData, SCP_REKEY_FILE_SZ), 0);

    WREMOVE(NULL, srcName);
    WREMOVE(NULL, verifyName);
}

static void test_wolfSSH_SCP_ReKey(void)
{
    scp_rekey_test(0, 0);
}

static void test_wolfSSH_SCP_ReKey_NonBlock(void)
{
    scp_rekey_test(1, 0);
}

static void test_wolfSSH_SCP_ReKey_ToServer(void)
{
    scp_rekey_test(0, 1);
}

static void test_wolfSSH_SCP_ReKey_ToServer_NonBlock(void)
{
    scp_rekey_test(1, 1);
}

#else /* WOLFSSH_SCP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED &&
       * !NO_FILESYSTEM && !WOLFSSH_SCP_USER_CALLBACKS && !WOLFSSH_ZEPHYR */
static void test_wolfSSH_SCP_ReKey(void) { ; }
static void test_wolfSSH_SCP_ReKey_NonBlock(void) { ; }
static void test_wolfSSH_SCP_ReKey_ToServer(void) { ; }
static void test_wolfSSH_SCP_ReKey_ToServer_NonBlock(void) { ; }
#endif


#ifdef USE_WINDOWS_API
static byte color_test[] = {
    0x1B, 0x5B, 0x34, 0x6D, 0x75, 0x6E, 0x64, 0x65,
    0x72, 0x6C, 0x69, 0x6E, 0x65, 0x1B, 0x1B, 0x5B,
    0x1B, 0x5B, 0x30, 0x6D, 0x0A, 0x1B, 0x5B, 0x33,
    0x31, 0x6D, 0x72, 0x65, 0x64, 0x0A, 0x1B, 0x5B,
    0x33, 0x32, 0x6D, 0x67, 0x72, 0x65, 0x65, 0x6E,
    0x0A, 0x1B, 0x5B, 0x33, 0x33, 0x6D, 0x79, 0x65,
    0x6C, 0x6C, 0x6F, 0x77, 0x0A, 0x1B, 0x5B, 0x32,
    0x32, 0x6D, 0x69, 0x6E, 0x74, 0x65, 0x6E, 0x73,
    0x65, 0x0A, 0x1B, 0x5B, 0x31, 0x6D, 0x62, 0x6F,
    0x6C, 0x64, 0x0A, 0x1B, 0x5B, 0x33, 0x34, 0x6D,
    0x62, 0x6C, 0x75, 0x65, 0x0A, 0x1B, 0x5B, 0x33,
    0x35, 0x6D, 0x6D, 0x61, 0x67, 0x65, 0x6E, 0x74,
    0x61, 0x0A, 0x1B, 0x5B, 0x33, 0x36, 0x6D, 0x63,
    0x79, 0x61, 0x6E, 0x0A, 0x1B, 0x5B, 0x33, 0x37,
    0x6D, 0x77, 0x68, 0x69, 0x74, 0x65, 0x0A, 0x1B,
    0x5B, 0x30, 0x6D, 0x6E, 0x6F, 0x72, 0x6D, 0x61,
    0x6C, 0x0A, 0x1B, 0x5B, 0x34, 0x30, 0x6D, 0x62,
    0x6C, 0x61, 0x63, 0x6B, 0x20, 0x62, 0x67, 0x0A,
    0x1B, 0x5B, 0x34, 0x31, 0x6D, 0x72, 0x65, 0x64,
    0x20, 0x62, 0x67, 0x0A, 0x1B, 0x5B, 0x34, 0x32,
    0x6D, 0x67, 0x72, 0x65, 0x65, 0x6E, 0x20, 0x62,
    0x67, 0x0A, 0x1B, 0x5B, 0x34, 0x33, 0x6D, 0x62,
    0x72, 0x6F, 0x77, 0x6E, 0x20, 0x62, 0x67, 0x0A,
    0x1B, 0x5B, 0x34, 0x34, 0x6D, 0x62, 0x6C, 0x75,
    0x65, 0x20, 0x62, 0x67, 0x0A, 0x1B, 0x5B, 0x34,
    0x35, 0x6D, 0x6D, 0x61, 0x67, 0x65, 0x6E, 0x74,
    0x61, 0x20, 0x62, 0x67, 0x0A, 0x1B, 0x5B, 0x34,
    0x36, 0x6D, 0x63, 0x79, 0x61, 0x6E, 0x20, 0x62,
    0x67, 0x0A, 0x1B, 0x5B, 0x34, 0x37, 0x6D, 0x77,
    0x68, 0x69, 0x74, 0x65, 0x20, 0x62, 0x67, 0x0A,
    0x1B, 0x5B, 0x34, 0x39, 0x6D, 0x64, 0x65, 0x66,
    0x61, 0x75, 0x6C, 0x74, 0x20, 0x62, 0x67, 0x0A,
};
#endif /* USE_WINDOWS_API */


static void test_wolfSSH_ConvertConsole(void)
{
#ifdef USE_WINDOWS_API
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    int i = 3, j = 4; /* arbitrary value */
    const char err[] = "test setting error msg";
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(NULL, NULL));

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));

    /* parameter tests */
    AssertIntEQ(wolfSSH_ConvertConsole(NULL, stdoutHandle, color_test,
                sizeof(color_test)), WS_BAD_ARGUMENT);
    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, NULL,
                sizeof(color_test)), WS_BAD_ARGUMENT);

    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, color_test, 1),
            WS_WANT_READ);
    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, color_test + 1, 1),
            WS_WANT_READ);
    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, color_test + 2,
                sizeof(color_test) - 2), WS_SUCCESS);

    /* bad esc esc command */
    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, color_test, 1),
            WS_WANT_READ);
    AssertIntEQ(wolfSSH_ConvertConsole(ssh, stdoutHandle, color_test, 1),
            WS_SUCCESS); /* should skip over unknown console code */

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#endif /* USE_WINDOWS_API */
}


static void test_wstrcat(void)
{
#ifndef WSTRING_USER
    char dst[5];

    WSTRNCPY(dst, "12", sizeof(dst));
    AssertNull(wstrncat(dst, "345", sizeof(dst)));
    AssertStrEQ(dst, "12");
    AssertNotNull(wstrncat(dst, "67", sizeof(dst)));
    AssertStrEQ(dst, "1267");
#endif /* WSTRING_USER */
}


#if (defined(WOLFSSH_SFTP) || defined(WOLFSSH_SCP)) && \
    !defined(NO_WOLFSSH_SERVER)
struct RealPathTestCase {
    const char* in;
    const char* exp;
};

/* On Zephyr, wolfSSH_RealPath preserves the trailing slash after a drive-root
 * colon (e.g. /C:/) rather than stripping it (e.g. /C:), due to the
 * WOLFSSH_ZEPHYR guard in the ".." handler. */
#ifdef WOLFSSH_ZEPHYR
#define WOLFSSH_TEST_DRIVE_ROOT "/C:/"
#else
#define WOLFSSH_TEST_DRIVE_ROOT "/C:"
#endif

struct RealPathTestCase realPathDefault[] = {
    { ".", "/C:/Users/fred" },
    { "", "/C:/Users/fred" },
    { "/C:/Users/fred/..", "/C:/Users" },
    { "..", "/C:/Users" },
    { "../..", WOLFSSH_TEST_DRIVE_ROOT },
    { "../barney", "/C:/Users/barney" },
    { "/C:/Users/..", WOLFSSH_TEST_DRIVE_ROOT },
    { "/C:/..", "/" },
    { "/C:/../../../../../../../..", "/" },
    { "/", "/" },
    { "/C:/Users/fred/../..", WOLFSSH_TEST_DRIVE_ROOT },
    { "/C:/Users/fred/././././.", "/C:/Users/fred" },
    { "/C:/Users/fred/../././..", WOLFSSH_TEST_DRIVE_ROOT },
    { "./.ssh", "/C:/Users/fred/.ssh" },
    { "./.ssh/../foo", "/C:/Users/fred/foo" },
    { "./.ssh/../foo", "/C:/Users/fred/foo" },
    { "///home//////////fred///", "/home/fred" },
    { "/home/C:/ok", "/home/C:/ok" },
    { "/home/fred/frob/frizz/../../../barney/bar/baz/./././../..",
        "/home/barney" },
    { "/home/fred/sample.", "/home/fred/sample." },
    { "/home/fred/sample.jpg", "/home/fred/sample.jpg" },
    { "/home/fred/sample./other", "/home/fred/sample./other" },
    { "/home/fred/sample.dir/other", "/home/fred/sample.dir/other" },
    { "./sample.", "/C:/Users/fred/sample." },
    { "./sample.jpg", "/C:/Users/fred/sample.jpg" },
    { "./sample./other", "/C:/Users/fred/sample./other" },
    { "./sample.dir/other", "/C:/Users/fred/sample.dir/other" },
    { "\\C:\\Users\\fred\\Documents\\junk.txt",
        "/C:/Users/fred/Documents/junk.txt" },
    { "C:\\Users\\fred\\Documents\\junk.txt",
        "/C:/Users/fred/Documents/junk.txt" },
    { "/C:\\Users\\fred/Documents\\junk.txt",
        "/C:/Users/fred/Documents/junk.txt" },
    /* Root-preservation / canonicalization of leading ".." */
    { "/../etc/passwd", "/etc/passwd" },
    { "/../../../etc/passwd", "/etc/passwd" },
    { "/C:/../../etc/passwd", "/etc/passwd" },
};

struct RealPathTestCase realPathNull[] = {
    { ".", "/" },
    { "", "/" },
    { "..", "/" },
    { "../barney", "/barney" },
    { "/../etc/passwd", "/etc/passwd" },
    { "/../../../etc/passwd", "/etc/passwd" },
};

static void DoRealPathTestCase(const char* path, struct RealPathTestCase* tc)
{
    char testPath[128];
    char checkPath[128];
    int err;

    WSTRNCPY(testPath, tc->in, sizeof(testPath) - 1);
    testPath[sizeof(testPath) - 1] = 0;
    WMEMSET(checkPath, 0, sizeof checkPath);
    err = wolfSSH_RealPath(path, testPath,
            checkPath, sizeof checkPath);
    AssertIntEQ(err, WS_SUCCESS);
    AssertStrEQ(tc->exp, checkPath);
}


struct RealPathTestFailCase {
    const char* defaultPath;
    const char* in;
    word32 checkPathSz;
    int expErr;
};
struct RealPathTestFailCase realPathFail[] = {
    /* Output size less than default path length. */
    { "12345678", "12345678", 4, WS_INVALID_PATH_E },
    /* Output size equal to default path length. */
    { "12345678", "12345678", 8, WS_INVALID_PATH_E },
    /* Copy segment will not fit in output. */
    { "1234567", "12345678", 8, WS_INVALID_PATH_E },
};

static void DoRealPathTestFailCase(struct RealPathTestFailCase* tc)
{
    char testPath[128];
    char checkPath[128];
    int err;

    WSTRNCPY(testPath, tc->in, sizeof(testPath) - 1);
    testPath[sizeof(testPath) - 1] = 0;
    WMEMSET(checkPath, 0, sizeof checkPath);
    err = wolfSSH_RealPath(tc->defaultPath, testPath,
            checkPath, tc->checkPathSz);
    AssertIntEQ(err, tc->expErr);
}


static void test_wolfSSH_RealPath(void)
{
    word32 testCount;
    word32 i;

    testCount = (sizeof realPathDefault)/(sizeof(struct RealPathTestCase));
    for (i = 0; i < testCount; i++) {
        DoRealPathTestCase("/C:/Users/fred", realPathDefault + i);
    }

    testCount = (sizeof realPathNull)/(sizeof(struct RealPathTestCase));
    for (i = 0; i < testCount; i++) {
        DoRealPathTestCase(NULL, realPathNull + i);
    }

    testCount = (sizeof realPathFail)/(sizeof(struct RealPathTestFailCase));
    for (i = 0; i < testCount; i++) {
        DoRealPathTestFailCase(realPathFail + i);
    }
}
#else
static void test_wolfSSH_RealPath(void) { ; }
#endif


static void test_wolfSSH_SetAlgoList(void)
{
    const char* newKexList = "diffie-hellman-group1-sha1,ecdh-sha2-nistp521";
    const char* newKeyList = "rsa-sha2-512,ecdsa-sha2-nistp521";
    const char* newCipherList = "aes128-ctr,aes128-cbc";
    const char* newMacList = "hmac-sha1";
    const char* newKeyAccList = "ssh-rsa";
    const char* defaultKexList = NULL;
    const char* defaultKeyList = NULL;
    const char* defaultCipherList = NULL;
    const char* defaultMacList = NULL;
    const char* defaultKeyAccList = NULL;
    const char* checkKexList = NULL;
    const char* checkKeyList = NULL;
    const char* checkCipherList = NULL;
    const char* checkMacList = NULL;
    const char* checkKeyAccList = NULL;
    const char* rawKey = NULL;
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;
    byte* key;
    word32 keySz;

    /* Create a ctx object. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    /* Check that the ctx's default algo lists are not null */
    defaultKexList = wolfSSH_CTX_GetAlgoListKex(ctx);
    AssertNotNull(defaultKexList);

    defaultKeyList = wolfSSH_CTX_GetAlgoListKey(ctx);
    AssertNotNull(defaultKeyList);

    defaultCipherList = wolfSSH_CTX_GetAlgoListCipher(ctx);
    AssertNotNull(defaultCipherList);

    defaultMacList = wolfSSH_CTX_GetAlgoListMac(ctx);
    AssertNotNull(defaultMacList);

    defaultKeyAccList = wolfSSH_CTX_GetAlgoListKeyAccepted(ctx);
    AssertNotNull(defaultKeyAccList);

    /* Create a new ssh object. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* Check that the ssh's default algo lists match the ctx's algo lists. */
    checkKexList = wolfSSH_GetAlgoListKex(ssh);
    AssertPtrEq(checkKexList, defaultKexList);

    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertPtrEq(checkKeyList, defaultKeyList);

    checkCipherList = wolfSSH_GetAlgoListCipher(ssh);
    AssertPtrEq(checkCipherList, defaultCipherList);

    checkMacList = wolfSSH_GetAlgoListMac(ssh);
    AssertPtrEq(checkMacList, defaultMacList);

    checkKeyAccList = wolfSSH_GetAlgoListKeyAccepted(ssh);
    AssertPtrEq(checkKeyAccList, defaultKeyAccList);

    /* Set the ssh's algo lists, check they match new value. */
    wolfSSH_SetAlgoListKex(ssh, newKexList);
    checkKexList = wolfSSH_GetAlgoListKex(ssh);
    AssertPtrEq(checkKexList, newKexList);

    wolfSSH_SetAlgoListKey(ssh, newKeyList);
    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertPtrEq(checkKeyList, newKeyList);

    wolfSSH_SetAlgoListCipher(ssh, newCipherList);
    checkCipherList = wolfSSH_GetAlgoListCipher(ssh);
    AssertPtrEq(checkCipherList, newCipherList);

    wolfSSH_SetAlgoListMac(ssh, newMacList);
    checkMacList = wolfSSH_GetAlgoListMac(ssh);
    AssertPtrEq(checkMacList, newMacList);

    wolfSSH_SetAlgoListKeyAccepted(ssh, newKeyAccList);
    checkKeyAccList = wolfSSH_GetAlgoListKeyAccepted(ssh);
    AssertPtrEq(checkKeyAccList, newKeyAccList);

    /* Delete the ssh. */
    wolfSSH_free(ssh);

    /* Set new algo lists on the ctx. */
    wolfSSH_CTX_SetAlgoListKex(ctx, newKexList);
    defaultKexList = wolfSSH_CTX_GetAlgoListKex(ctx);
    AssertPtrEq(defaultKexList, newKexList);

    wolfSSH_CTX_SetAlgoListKey(ctx, newKeyList);
    defaultKeyList = wolfSSH_CTX_GetAlgoListKey(ctx);
    AssertPtrEq(checkKeyList, newKeyList);

    wolfSSH_CTX_SetAlgoListCipher(ctx, newCipherList);
    defaultCipherList = wolfSSH_CTX_GetAlgoListCipher(ctx);
    AssertNotNull(defaultCipherList);

    wolfSSH_CTX_SetAlgoListMac(ctx, newMacList);
    defaultMacList = wolfSSH_CTX_GetAlgoListMac(ctx);
    AssertNotNull(defaultMacList);

    wolfSSH_CTX_SetAlgoListKeyAccepted(ctx, newKeyAccList);
    defaultKeyAccList = wolfSSH_CTX_GetAlgoListKeyAccepted(ctx);
    AssertNotNull(defaultKeyAccList);

    /* Create a new ssh object. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* Check that the ssh's default algo lists match the ctx's algo lists. */
    checkKexList = wolfSSH_GetAlgoListKex(ssh);
    AssertPtrEq(checkKexList, defaultKexList);

    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertPtrEq(checkKeyList, defaultKeyList);

    checkCipherList = wolfSSH_GetAlgoListCipher(ssh);
    AssertPtrEq(checkCipherList, defaultCipherList);

    checkMacList = wolfSSH_GetAlgoListMac(ssh);
    AssertPtrEq(checkMacList, defaultMacList);

    checkKeyAccList = wolfSSH_GetAlgoListKeyAccepted(ssh);
    AssertPtrEq(checkKeyAccList, defaultKeyAccList);

    /* Cleanup */
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    /* Create a ctx object. */
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    AssertNotNull(ctx);

    /* Check server ctx's key list is NULL. */
    defaultKeyList = wolfSSH_CTX_GetAlgoListKey(ctx);
    AssertNull(defaultKeyList);
    defaultKeyAccList = wolfSSH_CTX_GetAlgoListKeyAccepted(ctx);
    AssertNotNull(defaultKeyAccList);

    /* Create a new ssh object. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* Check server ssh's key list is NULL. */
    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertNull(checkKeyList);

    /* Delete the ssh. */
    wolfSSH_free(ssh);

    /* Set key on ctx. */
#if !defined(WOLFSSH_NO_ECDSA)
    rawKey = serverKeyEccDer;
#elif !defined(WOLFSSH_NO_RSA)
    rawKey = serverKeyRsaDer;
#endif
    AssertNotNull(rawKey);
    AssertIntEQ(0,
            ConvertHexToBin(rawKey, &key, &keySz,
                NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL));
    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UsePrivateKey_buffer(ctx,
                key, keySz, WOLFSSH_FORMAT_ASN1));

    /* Check ctx's key algo list is still null. */
    checkKeyList = wolfSSH_CTX_GetAlgoListKey(ctx);
    AssertNull(checkKeyList);

    /* Create a new ssh object. */
    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    /* Check ssh's key algo list is null. */
    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertNull(checkKeyList);

    /* Set a new list on ssh. */
    wolfSSH_SetAlgoListKey(ssh, newKeyList);
    checkKeyList = wolfSSH_GetAlgoListKey(ssh);
    AssertPtrEq(checkKeyList, newKeyList);

    /* Cleanup */
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    FreeBins(key, NULL, NULL, NULL);
}


static void test_wolfSSH_QueryAlgoList(void)
{
    const char* name;
    word32 i, j;
    int k;

    i = 0;
    name = NULL;
    do {
        name = wolfSSH_QueryKex(&i);
        AssertIntNE(i, 0);
    } while (name != NULL);

    i = 0;
    name = NULL;
    do {
        name = wolfSSH_QueryKey(&i);
        AssertIntNE(i, 0);
    } while (name != NULL);

    i = 0;
    name = NULL;
    do {
        name = wolfSSH_QueryCipher(&i);
        AssertIntNE(i, 0);
    } while (name != NULL);

    i = 0;
    name = NULL;
    do {
        name = wolfSSH_QueryMac(&i);
        AssertIntNE(i, 0);
    } while (name != NULL);

    /* This test case picks up where the index left off. */
    j = i;
    name = wolfSSH_QueryKex(&i);
    AssertNull(name);
    i = j;
    name = wolfSSH_QueryKey(&i);
    AssertNull(name);
    i = j;
    name = wolfSSH_QueryCipher(&i);
    AssertNull(name);
    i = j;
    name = wolfSSH_QueryMac(&i);
    AssertNull(name);

    k = wolfSSH_CheckAlgoName("ssh-rsa");
#ifndef WOLFSSH_NO_SSH_RSA_SHA1
    AssertIntEQ(WS_SUCCESS, k);
#else
    AssertIntEQ(WS_INVALID_ALGO_ID, k);
#endif /* WOLFSSH_NO_SSH_RSA_SHA1 */

    k = wolfSSH_CheckAlgoName("ecdsa-sha2-nistp256");
#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
    AssertIntEQ(WS_SUCCESS, k);
#else
    AssertIntEQ(WS_INVALID_ALGO_ID, k);
#endif /* WOLFSSH_NO_ECDSA_SHA2_NISTP256 */

    k = wolfSSH_CheckAlgoName("diffie-hellman-group14-sha256");
#ifndef WOLFSSH_NO_DH_GROUP14_SHA256
    AssertIntEQ(WS_SUCCESS, k);
#else
    AssertIntEQ(WS_INVALID_ALGO_ID, k);
#endif /* WOLFSSH_NO_DH_GROUP14_SHA256 */

    k = wolfSSH_CheckAlgoName("server-sig-algs");
    AssertIntEQ(WS_SUCCESS, k);

    k = wolfSSH_CheckAlgoName("nistp256");
    AssertIntEQ(WS_SUCCESS, k);

    k = wolfSSH_CheckAlgoName("not-an-algo@wolfssl.com");
    AssertIntEQ(WS_INVALID_ALGO_ID, k);
}

#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED)

static byte* kbResponse = (byte*)"test";
static word32 kbResponseLength = 4;

static int keyboardUserAuth(byte authType, WS_UserAuthData* authData, void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    (void)ctx;

    if (authType == WOLFSSH_USERAUTH_KEYBOARD) {
        AssertIntEQ(1, authData->sf.keyboard.promptCount);
        AssertStrEQ("KB Auth Password: ",
                    (const char*)authData->sf.keyboard.prompts[0]);

        authData->sf.keyboard.responseCount = 1;
        authData->sf.keyboard.responseLengths = &kbResponseLength;
        authData->sf.keyboard.responses = (byte**)&kbResponse;
        ret = WS_SUCCESS;
    }
    return ret;
}


static void keyboard_client_connect(WOLFSSH_CTX** ctx, WOLFSSH** ssh, int port)
{
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret;
    char* host = (char*)wolfSshIp;
    const char* username = "test";

    if (ctx == NULL || ssh == NULL) {
        return;
    }

    *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (*ctx == NULL) {
        return;
    }

    wolfSSH_CTX_SetPublicKeyCheck(*ctx, AcceptAnyServerHostKey);
    wolfSSH_SetUserAuth(*ctx, keyboardUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    if (sockFd < 0) {
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0){
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }

    ret = wolfSSH_SetUsername(*ssh, username);
    if (ret == WS_SUCCESS)
        ret = wolfSSH_set_fd(*ssh, (int)sockFd);

    if (ret == WS_SUCCESS)
        ret = wolfSSH_connect(*ssh);

    if (ret != WS_SUCCESS){
        WCLOSESOCKET(sockFd);
        wolfSSH_free(*ssh);
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        *ssh = NULL;
        return;
    }
}

static void test_wolfSSH_KeyboardInteractive(void)
{
    func_args ser;
    tcp_ready ready;
    int argsCount;
    WS_SOCKET_T clientFd;

    const char* args[10];
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH*     ssh = NULL;

    THREAD_TYPE serThread;

    WMEMSET(&ser, 0, sizeof(func_args));

    argsCount = 0;
    args[argsCount++] = ".";
    args[argsCount++] = "-1";
    args[argsCount++] = "-i";
    args[argsCount++] = "test:test";
#ifndef USE_WINDOWS_API
    args[argsCount++] = "-p";
    args[argsCount++] = "0";
#endif
    ser.argv   = (char**)args;
    ser.argc    = argsCount;
    ser.signal = &ready;
    InitTcpReady(ser.signal);
    ThreadStart(echoserver_test, (void*)&ser, &serThread);
    WaitTcpReady(&ready);

    keyboard_client_connect(&ctx, &ssh, ready.port);
    AssertNotNull(ctx);
    AssertNotNull(ssh);


    argsCount = wolfSSH_shutdown(ssh);
    if (argsCount == WS_SOCKET_ERROR_E) {
        /* If the socket is closed on shutdown, peer is gone, this is OK. */
        argsCount = WS_SUCCESS;
    }

#if DEFAULT_HIGHWATER_MARK < 8000
    if (argsCount == WS_REKEYING) {
        /* in cases where highwater mark is really small a re-key could happen */
        argsCount = WS_SUCCESS;
    }
#endif

    AssertIntEQ(argsCount, WS_SUCCESS);

    /* close client socket down */
    clientFd = wolfSSH_get_fd(ssh);
    WCLOSESOCKET(clientFd);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#ifdef WOLFSSH_ZEPHYR
    /* Weird deadlock without this sleep */
    k_sleep(Z_TIMEOUT_TICKS(100));
#endif
    ThreadJoin(serThread);
}

#else /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */
static void test_wolfSSH_KeyboardInteractive(void) { ; }
#endif /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */
#endif /* WOLFSSH_KEYBOARD_INTERACTIVE */

#endif /* WOLFSSH_TEST_BLOCK */


int wolfSSH_ApiTest(int argc, char** argv)
{
    (void)argc;
    (void)argv;

#ifdef WOLFSSH_TEST_BLOCK
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

    test_wstrcat();
    test_wolfSSH_CTX_new();
    test_server_wolfSSH_new();
    test_client_wolfSSH_new();
    test_wolfSSH_set_fd();
    test_wolfSSH_SetUsername();
    test_wolfSSH_ConvertConsole();
    test_wolfSSH_CTX_UsePrivateKey_buffer();
    test_wolfSSH_CTX_UseCert_buffer();
    test_wolfSSH_CTX_UsePrivateKey_buffer_pem();
    test_wolfSSH_CTX_SetWindowPacketSize();
    test_wolfSSH_CertMan();
    test_wolfSSH_ReadKey();
    test_wolfSSH_ReadKey_badPad();
    test_wolfSSH_QueryAlgoList();
    test_wolfSSH_SetAlgoList();
#ifdef WOLFSSH_AGENT
    test_wolfSSH_agent_signrequest_partial_write();
    test_wolfSSH_agent_signrequest_wrong_message();
    test_wolfSSH_agent_signrequest_signature_too_large();
    test_wolfSSH_agent_signrequest_success();
#endif
#ifdef WOLFSSH_KEYBOARD_INTERACTIVE
    test_wolfSSH_KeyboardInteractive();
#endif

    /* SCP tests */
    test_wolfSSH_SCP_CB();
    test_wolfSSH_SCP_ReKey();
    test_wolfSSH_SCP_ReKey_NonBlock();
    test_wolfSSH_SCP_ReKey_ToServer();
    test_wolfSSH_SCP_ReKey_ToServer_NonBlock();

    /* SFTP tests */
    test_wolfSSH_SFTP_SendReadPacket();
    test_wolfSSH_SFTP_ReKey();
    test_wolfSSH_SFTP_ReKey_NonBlock();
    test_wolfSSH_SFTP_Confinement();
    test_wolfSSH_SFTP_SetDefaultPath();

    /* Either SCP or SFTP */
    test_wolfSSH_RealPath();
    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
#endif
}


#ifndef NO_APITEST_MAIN_DRIVER
int main(int argc, char** argv)
{
    return wolfSSH_ApiTest(argc, argv);
}
#endif
