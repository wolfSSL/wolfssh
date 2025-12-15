/* regress.c
 *
 * Regression coverage for message ordering / keying state handling.
 *
 * Copyright (C) 2025 wolfSSL Inc.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <wolfssh/port.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include "apps/wolfssh/common.h"

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

#define Fail(description, result) do {                                         \
    PrintError(description, result);                                           \
    WABORT();                                                                  \
} while(0)

#define Assert(test, description, result) if (!(test)) Fail(description, result)

#define AssertTrue(x)    Assert((x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert((x), ("%s is not null", #x), (#x " => NULL"))
#define AssertIntEQ(x, y) do { int _x = (int)(x); int _y = (int)(y);           \
    Assert(_x == _y, ("%s == %s", #x, #y), ("%d != %d", _x, _y)); } while (0)


static void ResetSession(WOLFSSH* ssh)
{
    if (ssh->handshake != NULL) {
        WFREE(ssh->handshake, ssh->ctx->heap, DYNTYPE_HS);
        ssh->handshake = NULL;
    }
    ssh->isKeying = 0;
    ssh->connectState = CONNECT_BEGIN;
    ssh->error = 0;
}


static HandshakeInfo* AllocHandshake(WOLFSSH* ssh)
{
    HandshakeInfo* hs;

    hs = (HandshakeInfo*)WMALLOC(sizeof(HandshakeInfo), ssh->ctx->heap,
            DYNTYPE_HS);
    AssertNotNull(hs);
    WMEMSET(hs, 0, sizeof(HandshakeInfo));
    hs->blockSz = MIN_BLOCK_SZ;
    hs->eSz = (word32)sizeof(hs->e);
    hs->xSz = (word32)sizeof(hs->x);

    return hs;
}

/* Build a minimal SSH binary packet carrying only a message ID.
 * Layout: uint32 packetLen, byte padLen, payload[msgId], pad[padLen].
 * Choose padLen so total is 8-byte aligned for the clear transport case. */
static word32 BuildPacket(byte msgId, byte* out, word32 outSz)
{
    byte padLen = 6; /* 1 (msgId) +1 (padLen) +6 = 8 */
    word32 packetLen = 1 + 1 + padLen; /* payload + padLen field + pad */
    word32 need = 4 + packetLen;

    AssertTrue(outSz >= need);
    out[0] = (byte)(packetLen >> 24);
    out[1] = (byte)(packetLen >> 16);
    out[2] = (byte)(packetLen >> 8);
    out[3] = (byte)(packetLen);
    out[4] = padLen;
    out[5] = msgId;
    WMEMSET(out + 6, 0, padLen);
    return need;
}

static byte ParseMsgId(const byte* pkt, word32 sz)
{
    AssertTrue(sz >= 6);
    return pkt[5];
}

/* Simple in-memory transport harness */
typedef struct {
    byte* in;      /* data to feed into client */
    word32 inSz;
    word32 inOff;
    byte* out;     /* data written by client */
    word32 outSz;
    word32 outCap;
} MemIo;

/* Minimal send/recv helpers for future transport-level tests; keep them static
 * and unused for now to avoid warnings when Werror is on. */
#ifdef WOLFSSH_TEST_MEMIO
static int MemRecv(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh;
    MemIo* io = (MemIo*)ctx;
    word32 remain = io->inSz - io->inOff;
    if (remain == 0)
        return WS_CBIO_ERR_WANT_READ;
    if (sz > remain)
        sz = remain;
    WMEMCPY(buf, io->in + io->inOff, sz);
    io->inOff += sz;
    return (int)sz;
}

static int MemSend(WOLFSSH* ssh, void* buf, word32 sz, void* ctx)
{
    (void)ssh;
    MemIo* io = (MemIo*)ctx;
    if (io->outSz + sz > io->outCap) {
        return WS_CBIO_ERR_GENERAL;
    }
    WMEMCPY(io->out + io->outSz, buf, sz);
    io->outSz += sz;
    return (int)sz;
}

static void MemIoInit(MemIo* io, byte* in, word32 inSz, byte* out, word32 outCap)
{
    io->in = in;
    io->inSz = inSz;
    io->inOff = 0;
    io->out = out;
    io->outSz = 0;
    io->outCap = outCap;
}
#endif


/* Reject auth messages while the peer is still keying and the client
 * expects the KEX reply. */
static void TestAuthMessageBlockedDuringKeying(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_FAILURE,
            WS_MSG_RECV);
    AssertFalse(allowed);

    /* The expected message must be allowed and clear the expectation. */
    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXDH_REPLY,
            WS_MSG_RECV);
    AssertTrue(allowed);
    AssertIntEQ(ssh->handshake->expectMsgId, MSGID_NONE);
}

/* Reject USERAUTH_FAILURE with password list during keying (password-leak PoC). */
static void TestUserauthFailureDuringKeying(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Expect an abort/error to be set when password-leak sequence hits during keying. */
static void TestPasswordLeakAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_CLIENT_KEXDH_INIT_SENT;
    ssh->handshake = AllocHandshake(ssh);
    ssh->handshake->expectMsgId = MSGID_KEXDH_REPLY;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertTrue(ssh->error != 0); /* should set an error / abort path */
}


/* Reject USERAUTH_SUCCESS before the client has even sent a userauth request. */
static void TestPrematureUserauthSuccess(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_USERAUTH_SUCCESS,
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Reject a spoofed sequence: bogus USERAUTH_SUCCESS followed by channel msgs. */
static void TestChannelSpoofSequence(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_OPEN_CONF, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_DATA, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Expect abort/error on spoofed auth+channel sequence. */
static void TestChannelSpoofAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_SUCCESS, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    sz = BuildPacket(MSGID_CHANNEL_OPEN_CONF, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);

    AssertTrue(ssh->error != 0);
}


/* Reject USERAUTH_FAILURE(publickey) before any auth request (static-signature PoC). */
static void TestPublicKeyFailureBeforeRequest(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Expect abort/error when publickey failure arrives before any request. */
static void TestPublicKeyFailureAborts(WOLFSSH* ssh)
{
    byte buf[32];
    word32 sz;
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    sz = BuildPacket(MSGID_USERAUTH_FAILURE, buf, sizeof(buf));
    allowed = wolfSSH_TestIsMessageAllowed(ssh, ParseMsgId(buf, sz),
            WS_MSG_RECV);
    AssertFalse(allowed);
    AssertTrue(ssh->error != 0);
}


/* Reject channel messages before user authentication completes. */
static void TestChannelBlockedBeforeAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_KEYED;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertFalse(allowed);
}


/* Allow channel messages after user authentication completes. */
static void TestChannelAllowedAfterAuth(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->connectState = CONNECT_SERVER_USERAUTH_ACCEPT_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_CHANNEL_OPEN,
            WS_MSG_RECV);
    AssertTrue(allowed);
}


/* Reject a peer KEXINIT once keying is in progress. */
static void TestKexInitRejectedWhenKeying(WOLFSSH* ssh)
{
    int allowed;

    ResetSession(ssh);
    ssh->isKeying = WOLFSSH_PEER_IS_KEYING;
    ssh->connectState = CONNECT_SERVER_KEXINIT_DONE;

    allowed = wolfSSH_TestIsMessageAllowed(ssh, MSGID_KEXINIT, WS_MSG_RECV);
    AssertFalse(allowed);
}

/* Ensure client buffer cleanup tolerates multiple invocations after allocs. */
static void TestClientBuffersIdempotent(void)
{
    int ret;

    ret = ClientUsePubKey("keys/gretel-key-rsa.pub");
    AssertIntEQ(ret, 0);
    ret = ClientSetPrivateKey("keys/gretel-key-rsa.pem");
    AssertIntEQ(ret, 0);

    ClientFreeBuffers();
    /* Should be safe to call again without double free. */
    ClientFreeBuffers();
}

/* Simulate Ctrl+D (stdin EOF) during password prompt; expect failure but no crash. */
static void TestPasswordEofNoCrash(void)
{
    WS_UserAuthData auth;
    int savedStdin, devNull, ret;

    WMEMSET(&auth, 0, sizeof(auth));

    savedStdin = dup(STDIN_FILENO);
    devNull = open("/dev/null", O_RDONLY);
    AssertTrue(devNull >= 0);
    AssertTrue(dup2(devNull, STDIN_FILENO) >= 0);

    ret = ClientUserAuth(WOLFSSH_USERAUTH_PASSWORD, &auth, NULL);
    AssertIntEQ(ret, WOLFSSH_USERAUTH_FAILURE);

    close(devNull);
    dup2(savedStdin, STDIN_FILENO);
    close(savedStdin);

    ClientFreeBuffers();
}


int main(int argc, char** argv)
{
    WOLFSSH_CTX* ctx;
    WOLFSSH* ssh;

    (void)argc;
    (void)argv;

    wolfSSH_Init();

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    AssertNotNull(ctx);

    ssh = wolfSSH_new(ctx);
    AssertNotNull(ssh);

    TestAuthMessageBlockedDuringKeying(ssh);
    TestUserauthFailureDuringKeying(ssh);
    TestPasswordLeakAborts(ssh);
    TestPrematureUserauthSuccess(ssh);
    TestChannelSpoofSequence(ssh);
    TestChannelSpoofAborts(ssh);
    TestPublicKeyFailureBeforeRequest(ssh);
    TestPublicKeyFailureAborts(ssh);
    TestChannelBlockedBeforeAuth(ssh);
    TestChannelAllowedAfterAuth(ssh);
    TestKexInitRejectedWhenKeying(ssh);
    TestClientBuffersIdempotent();
    TestPasswordEofNoCrash();

    /* TODO: add app-level regressions that simulate stdin EOF/password
     * prompts and mid-session socket closes once the test harness can
     * drive the wolfssh client without real sockets/tty. */

    ResetSession(ssh);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    wolfSSH_Cleanup();

    printf("regress: PASS\n");
    return 0;
}
