/* api.c
 *
 * Copyright (C) 2014-2019 wolfSSL Inc.
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


int main(void)
{
    AssertIntEQ(wolfSSH_Init(), WS_SUCCESS);

    test_wstrcat();
    test_wolfSSH_CTX_new();
    test_server_wolfSSH_new();
    test_client_wolfSSH_new();
    test_wolfSSH_set_fd();
    test_wolfSSH_SetUsername();
    test_wolfSSH_ConvertConsole();

    /* SCP tests */
    test_wolfSSH_SCP_CB();

    AssertIntEQ(wolfSSH_Cleanup(), WS_SUCCESS);

    return 0;
}
