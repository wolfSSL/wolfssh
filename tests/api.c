/* api.c
 *
 * Copyright (C) 2014-2017 wolfSSL Inc.
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


#include <stdio.h>
#include <wolfssh/ssh.h>
#ifdef WOLFSSH_SCP
    #include <wolfssh/wolfscp.h>
#endif


#define Fail(description, result) do {                                         \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
    abort();                                                                   \
} while(0)

#define Assert(test, description, result) if (!(test)) Fail(description, result)

#define AssertTrue(x)    Assert( (x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert( (x), ("%s is not null", #x), (#x " => NULL"))

#define AssertNull(x) do {                                                     \
    void* _x = (void *) (x);                                                   \
                                                                               \
    Assert(!_x, ("%s is null", #x), (#x " => %p", _x));                        \
} while(0)

#define AssertInt(x, y, op, er) do {                                           \
    int _x = x;                                                                \
    int _y = y;                                                                \
                                                                               \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%d " #er " %d", _x, _y));    \
} while(0)

#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
#define AssertIntNE(x, y) AssertInt(x, y, !=, ==)
#define AssertIntGT(x, y) AssertInt(x, y,  >, <=)
#define AssertIntLT(x, y) AssertInt(x, y,  <, >=)
#define AssertIntGE(x, y) AssertInt(x, y, >=,  <)
#define AssertIntLE(x, y) AssertInt(x, y, <=,  >)

#define AssertStr(x, y, op, er) do {                                           \
    const char* _x = x;                                                        \
    const char* _y = y;                                                        \
    int   _z = strcmp(_x, _y);                                                 \
                                                                               \
    Assert(_z op 0, ("%s " #op " %s", #x, #y),                                 \
                                            ("\"%s\" " #er " \"%s\"", _x, _y));\
} while(0)

#define AssertStrEQ(x, y) AssertStr(x, y, ==, !=)
#define AssertStrNE(x, y) AssertStr(x, y, !=, ==)
#define AssertStrGT(x, y) AssertStr(x, y,  >, <=)
#define AssertStrLT(x, y) AssertStr(x, y,  <, >=)
#define AssertStrGE(x, y) AssertStr(x, y, >=,  <)
#define AssertStrLE(x, y) AssertStr(x, y, <=,  >)


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

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
}


static void test_client_wolfSSH_new(void)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));

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


    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(NULL, NULL));

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(ssh, username));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

    AssertNotNull(ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL));
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(ssh, NULL));
    AssertIntNE(WS_SUCCESS, wolfSSH_SetUsername(ssh, empty));
    wolfSSH_free(ssh);
    AssertNotNull(ssh = wolfSSH_new(ctx));
    AssertIntEQ(WS_SUCCESS, wolfSSH_SetUsername(ssh, username));
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
#endif /* WOLFSSH_NO_CLIENT */
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
#endif


static void test_wolfSSH_SCP_CB(void)
{
#ifdef WOLFSSH_SCP
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
#endif /* WOLFSSH_NO_CLIENT */
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


int main(void)
{
    AssertIntEQ(wolfSSH_Init(), WS_SUCCESS);

    test_wstrcat();
    test_wolfSSH_CTX_new();
    test_server_wolfSSH_new();
    test_client_wolfSSH_new();
    test_wolfSSH_SetUsername();

    /* SCP tests */
    test_wolfSSH_SCP_CB();

    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
}
