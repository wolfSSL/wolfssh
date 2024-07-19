/* api.c
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
#ifdef WOLFSSH_SCP
    #include <wolfssh/wolfscp.h>
#endif

#ifdef WOLFSSH_SFTP
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
        fseek(f, 0, XSEEK_END);
        *bufSz = (word32)ftell(f);
        rewind(f);
    }

    if (ret == 0) {
        *buf = (byte*)malloc(*bufSz);
        if (*buf == NULL)
            ret = -3;
    }

    if (ret == 0) {
        int readSz;
        readSz = (int)fread(*buf, 1, *bufSz, f);
        if (readSz < (int)*bufSz)
            ret = -4;
    }

    if (f != NULL)
        fclose(f);

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

    AssertIntEQ(0, load_file("./keys/server-cert.der", &cert, &certSz));
    AssertNotNull(cert);
    AssertIntNE(0, certSz);

    AssertIntEQ(WS_SUCCESS,
            wolfSSH_CTX_UseCert_buffer(ctx, cert, certSz, WOLFSSH_FORMAT_ASN1));

    wolfSSH_CTX_free(ctx);
    free(cert);
#endif /* WOLFSSH_CERTS */
}


static void test_wolfSSH_CertMan(void)
{
#ifdef WOLFSSH_CERTMAN
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
#endif
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


#if defined(WOLFSSH_SFTP) && !defined(NO_WOLFSSH_CLIENT) && \
    !defined(SINGLE_THREADED)

#include "examples/echoserver/echoserver.h"

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

/* preforms connection to port, sets WOLFSSH_CTX and WOLFSSH on success
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

    wolfSSH_SetUserAuth(*ctx, sftpUserAuth);
    *ssh = wolfSSH_new(*ctx);
    if (*ssh == NULL) {
        wolfSSH_CTX_free(*ctx);
        *ctx = NULL;
        return;
    }

    build_addr(&clientAddr, host, port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0){
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
                    !(tmp->atrb.per & 0x4000)) {
                break;
            }
            tmp = tmp->next;
        }

        if (tmp != NULL) {
            out = (byte*)malloc(tmp->atrb.sz[0]);
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
            AssertIntGT(rxSz, 0);
            AssertIntLE(rxSz, outSz);

            /* read all */
            outSz = WOLFSSH_MAX_SFTP_RW;
            rxSz = wolfSSH_SFTP_SendReadPacket(ssh, handle, handleSz,
                    ofst, out, outSz);
            if (rxSz != WS_REKEYING) {
                AssertIntGT(rxSz, 0);
                AssertIntLE(rxSz, outSz);
            }

            free(out);
            wolfSSH_SFTP_Close(ssh, handle, handleSz);
            wolfSSH_SFTPNAME_list_free(current);
        }
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

#else /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */
static void test_wolfSSH_SFTP_SendReadPacket(void) { ; }
#endif /* WOLFSSH_SFTP && !NO_WOLFSSH_CLIENT && !SINGLE_THREADED */


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

struct RealPathTestCase realPathDefault[] = {
    { ".", "/C:/Users/fred" },
    { "", "/C:/Users/fred" },
    { "/C:/Users/fred/..", "/C:/Users" },
    { "..", "/C:/Users" },
    { "../..", "/C:" },
    { "../barney", "/C:/Users/barney" },
    { "/C:/Users/..", "/C:" },
    { "/C:/..", "/" },
    { "/C:/../../../../../../../..", "/" },
    { "/", "/" },
    { "/C:/Users/fred/../..", "/C:" },
    { "/C:/Users/fred/././././.", "/C:/Users/fred" },
    { "/C:/Users/fred/../././..", "/C:" },
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
};

struct RealPathTestCase realPathNull[] = {
    { ".", "/" },
    { "", "/" },
    { "..", "/" },
    { "../barney", "/barney" },
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
    if (err || WSTRCMP(tc->exp, checkPath) != 0) {
        fprintf(stderr, "RealPath failure (%d)\n"
                        "    defaultPath: %s\n"
                        "          input: %s\n"
                        "       expected: %s\n"
                        "         output: %s\n", err,
                        path, tc->in, tc->exp, checkPath);
    }
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
    if (err != tc->expErr) {
        fprintf(stderr, "RealPath fail check failure (%d)\n"
                        "    defaultPath: %s\n"
                        "          input: %s\n"
                        "    checkPathSz: %u\n"
                        "       expected: %d\n", err,
                        tc->defaultPath, tc->in, tc->checkPathSz, tc->expErr);
    }
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
    AssertIntEQ(WS_SUCCESS, k);

    k = wolfSSH_CheckAlgoName("not-an-algo@wolfssl.com");
    AssertIntEQ(WS_INVALID_ALGO_ID, k);
}


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
    test_wolfSSH_CertMan();
    test_wolfSSH_ReadKey();
    test_wolfSSH_QueryAlgoList();
    test_wolfSSH_SetAlgoList();

    /* SCP tests */
    test_wolfSSH_SCP_CB();

    /* SFTP tests */
    test_wolfSSH_SFTP_SendReadPacket();

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
